"""Capability IA opt-in #2 — suggerimenti di entity-resolution.

Passo 1 (deterministico, nessun LLM): genera coppie di entità candidate a
essere lo stesso soggetto, tramite similarità del valore o attributo
condiviso. I duplicati esatti sono già risolti a monte da
link_analysis.resolve_entities() (stesso _stable_id -> stesso nodo), quindi
qui arrivano solo coppie AMBIGUE — mandare all'LLM tutte le coppie possibili
sarebbe costoso e inutile.

Passo 2 (LLM): per ogni coppia candidata, un verdetto same_entity/confidence/
rationale. Un verdetto su una coppia non inviata viene SCARTATO (non è un
hard-fail come in narrative_synthesis — qui il costo di un falso negativo è
basso, si perde solo un suggerimento) e riportato come dropped_hallucinated.

Il merge non è MAI applicato automaticamente: entity_resolution_ai produce
solo suggerimenti, la conferma è un'azione umana separata (vedi
web.py:handle_ai_entity_decide, che scrive in entity_merge_decisions senza
mai toccare link_analysis.resolve_entities() o l'Investigation salvata).
"""
from __future__ import annotations

import difflib
from dataclasses import dataclass, field
from urllib.parse import urlparse

from . import ai_context, llm_client
from .link_analysis import EntityGraph, GraphNode

JSON_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "verdicts": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "entity_id_a": {"type": "string"},
                    "entity_id_b": {"type": "string"},
                    "same_entity": {"type": "boolean"},
                    "confidence": {"type": "number"},
                    "rationale": {"type": "string"},
                },
                "required": ["entity_id_a", "entity_id_b", "same_entity", "confidence", "rationale"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["verdicts"],
    "additionalProperties": False,
}

_SYSTEM_PROMPT_TEMPLATE = """Sei un analista OSINT che valuta se due entità osservate in un'indagine sono probabilmente lo stesso soggetto.

Regole non negoziabili:
1. Non affermare mai certezza assoluta su una persona reale — la confidence deve riflettere l'incertezza reale (0.0-1.0).
2. Motiva il verdetto SOLO con gli attributi ed evidenze forniti per quella coppia — non inventare informazioni.
3. Restituisci un verdetto per OGNI coppia numerata fornita, citando esattamente gli entity_id dati. Non inventare mai un entity_id che non è nell'elenco.
4. Rispondi SOLO nella lingua richiesta: {lang_name}.
5. Restituisci ESCLUSIVAMENTE l'oggetto strutturato richiesto — nessun testo fuori schema.
"""

_LANG_NAMES = {"it": "italiano", "en": "inglese (English)"}


@dataclass
class EntityPairCandidate:
    entity_a: GraphNode
    entity_b: GraphNode
    score: float
    reason: str


@dataclass
class CandidatePairsResult:
    pairs: list[EntityPairCandidate]
    total_available: int
    truncated: bool


def _domain_of_email(value: str) -> str:
    return value.rsplit("@", 1)[-1].lower() if "@" in value else ""


def _host_of(value: str) -> str:
    try:
        parsed = urlparse(value if "://" in value else f"//{value}")
        return (parsed.netloc or "").lower()
    except ValueError:
        return ""


def _digits(value: str) -> str:
    return "".join(ch for ch in value if ch.isdigit())


def _shared_attribute_reason(a: GraphNode, b: GraphNode) -> str:
    """Segnali deboli ma concreti di possibile stesso soggetto, oltre alla
    somiglianza testuale del valore."""
    if a.kind == "email" and b.kind == "email":
        da, db = _domain_of_email(a.value), _domain_of_email(b.value)
        if da and da == db:
            return "same_email_domain"
    if a.kind in ("url", "domain") and b.kind in ("url", "domain"):
        ha, hb = _host_of(a.value), _host_of(b.value)
        if ha and ha == hb:
            return "same_host"
    if a.kind == "phone" and b.kind == "phone":
        da, db = _digits(a.value), _digits(b.value)
        if len(da) >= 6 and len(db) >= 6 and da[:6] == db[:6]:
            return "same_phone_prefix"
    if set(a.sources) & set(b.sources):
        return "shared_evidence_source"
    return ""


def _similarity(a: GraphNode, b: GraphNode) -> tuple[float, str]:
    va = (a.label or a.value or "").strip().lower()
    vb = (b.label or b.value or "").strip().lower()
    ratio = difflib.SequenceMatcher(None, va, vb).ratio() if va and vb else 0.0
    if ratio > 0.55:
        return ratio, "similar_value"
    reason = _shared_attribute_reason(a, b)
    if reason:
        return 0.6, reason
    return 0.0, ""


def candidate_pairs(graph: EntityGraph, max_pairs: int = 40) -> CandidatePairsResult:
    """Coppie ambigue (stesso kind, valore simile o attributo condiviso).
    I duplicati esatti non arrivano qui: resolve_entities() li ha già
    fusi in un unico nodo a monte."""
    nodes = graph.nodes()
    candidates: list[EntityPairCandidate] = []
    for i in range(len(nodes)):
        for j in range(i + 1, len(nodes)):
            a, b = nodes[i], nodes[j]
            if a.kind != b.kind or a.id == b.id:
                continue
            score, reason = _similarity(a, b)
            if score > 0:
                candidates.append(EntityPairCandidate(entity_a=a, entity_b=b, score=score, reason=reason))
    candidates.sort(key=lambda c: -c.score)
    total = len(candidates)
    truncated = total > max_pairs
    return CandidatePairsResult(pairs=candidates[:max_pairs], total_available=total, truncated=truncated)


@dataclass
class ValidationResult:
    ok: bool
    verdicts: list[dict] = field(default_factory=list)
    dropped_hallucinated: int = 0
    error: str = ""


def validate(parsed: dict | None, known_pairs: set[frozenset[str]]) -> ValidationResult:
    if not isinstance(parsed, dict):
        return ValidationResult(ok=False, error="Risposta non è un oggetto JSON.")
    kept: list[dict] = []
    dropped = 0
    for v in parsed.get("verdicts") or []:
        if not isinstance(v, dict):
            dropped += 1
            continue
        a = str(v.get("entity_id_a", ""))
        b = str(v.get("entity_id_b", ""))
        if not a or not b or frozenset((a, b)) not in known_pairs:
            dropped += 1
            continue
        try:
            confidence = max(0.0, min(1.0, float(v.get("confidence", 0.5))))
        except (TypeError, ValueError):
            confidence = 0.5
        kept.append({
            "entity_id_a": a, "entity_id_b": b,
            "same_entity": bool(v.get("same_entity")),
            "confidence": confidence,
            "rationale": str(v.get("rationale", ""))[:500],
        })
    return ValidationResult(ok=True, verdicts=kept, dropped_hallucinated=dropped)


def _describe_entity(n: GraphNode) -> str:
    attrs = ", ".join(f"{k}={v}" for k, v in list(n.attributes.items())[:5])
    sources = ", ".join(n.sources[:3])
    return (
        f"id={n.id} | type={n.kind} | value={n.value[:120]} | confidence={n.confidence:.2f} | "
        f"attributi=[{attrs}] | evidenze=[{sources}]"
    )


def build_prompt(pairs: list[EntityPairCandidate], *, lang: str) -> tuple[str, str]:
    lang = lang if lang in _LANG_NAMES else "it"
    system_prompt = _SYSTEM_PROMPT_TEMPLATE.format(lang_name=_LANG_NAMES[lang])
    lines = []
    for idx, pair in enumerate(pairs, start=1):
        lines.append(
            f"Coppia {idx} (segnale: {pair.reason}, score={pair.score:.2f}):\n"
            f"  A: {_describe_entity(pair.entity_a)}\n"
            f"  B: {_describe_entity(pair.entity_b)}"
        )
    user_prompt = (
        "Valuta ciascuna delle seguenti coppie di entità e restituisci un verdetto per ognuna, "
        "citando esattamente gli entity_id mostrati:\n\n" + "\n\n".join(lines)
    )
    return system_prompt, user_prompt


def generate(
    *, case_id: str, lang: str = "it", provider: str, model: str, api_key: str,
    base_url: str = "", max_pairs: int = 40,
) -> tuple[llm_client.LLMResponse | None, ValidationResult, CandidatePairsResult]:
    graph = ai_context.collect_case_entities(case_id)
    collected = candidate_pairs(graph, max_pairs=max_pairs)
    if not collected.pairs:
        return None, ValidationResult(ok=True, verdicts=[]), collected

    known_pairs = {frozenset((p.entity_a.id, p.entity_b.id)) for p in collected.pairs}
    system_prompt, user_prompt = build_prompt(collected.pairs, lang=lang)
    response = llm_client.complete(
        provider=provider, model=model, api_key=api_key, base_url=base_url,
        system_prompt=system_prompt, user_prompt=user_prompt, json_schema=JSON_SCHEMA,
    )
    if not response.ok:
        return response, ValidationResult(ok=False, error=response.error), collected

    validation = validate(response.parsed, known_pairs)
    return response, validation, collected


__all__ = [
    "JSON_SCHEMA", "EntityPairCandidate", "CandidatePairsResult", "ValidationResult",
    "candidate_pairs", "validate", "build_prompt", "generate",
]
