"""Capability IA opt-in #3 — triage/prioritizzazione finding.

Per casi con centinaia di finding, l'LLM assegna un bucket di priorità
INVESTIGATIVA (azionabilità, lacune di corroborazione, sensibilità del dato,
potenziale di pivot) — non solo la severity tecnica già presente sui finding.

Batching: ≤120 finding per chiamata, cap di 6 batch (~720 finding/run). Oltre
il cap, o per un finding che il modello omette/inventa un id diverso, resta
il fallback DETERMINISTICO mappato dalla severity del finding — mai un
finding senza ranking, mai un troncamento silenzioso (vedi il dict
`coverage` restituito). collect_case_findings (ai_context.py) ordina già i
finding per grading.severity_rank prima del batching, così i batch inviati
per primi (quelli con più probabilità di rientrare nel cap) sono quelli a
priorità tecnica più alta.

Triage è sempre e solo un ordinamento/badge consultivo: non filtra, non
nasconde, non modifica alcun finding. Ogni export (PDF/MD/JSON/STIX/MISP)
continua a includere il 100% dei finding indipendentemente dal bucket.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import ai_context, llm_client

JSON_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "rankings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "finding_id": {"type": "string"},
                    "priority_bucket": {
                        "type": "string",
                        "enum": ["critical_now", "high", "medium", "low", "noise"],
                    },
                    "rationale": {"type": "string"},
                },
                "required": ["finding_id", "priority_bucket", "rationale"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["rankings"],
    "additionalProperties": False,
}

_SYSTEM_PROMPT_TEMPLATE = """Sei un analista OSINT che assegna priorità investigativa ai finding di un caso.

Regole non negoziabili:
1. Valuta priorità INVESTIGATIVA — azionabilità, lacune di corroborazione, sensibilità del dato esposto, potenziale di pivot verso ulteriori indagini — non solo la severity tecnica già presente sul finding.
2. Bucket ammessi, esattamente questi: critical_now, high, medium, low, noise.
3. Un rationale per ogni finding, massimo 160 caratteri.
4. Devi restituire ESATTAMENTE un elemento per ogni finding_id fornito nell'elenco, usando l'id esatto copiato dall'elenco. Non inventare mai un finding_id nuovo. Non ometterne mai uno.
5. Rispondi SOLO nella lingua richiesta: {lang_name}.
6. Restituisci ESCLUSIVAMENTE l'oggetto strutturato richiesto — nessun testo fuori schema.
"""

_LANG_NAMES = {"it": "italiano", "en": "inglese (English)"}

_BATCH_SIZE = 120
_MAX_BATCHES = 6

_VALID_BUCKETS = {"critical_now", "high", "medium", "low", "noise"}
_FALLBACK_BUCKET = {
    "critical": "critical_now", "high": "high", "medium": "medium",
    "low": "low", "info": "noise", "": "noise",
}


def _fallback_bucket_for(severity: str) -> str:
    return _FALLBACK_BUCKET.get(severity, "noise")


def split_into_batches(refs: list[ai_context.CaseFindingRef]) -> list[list[ai_context.CaseFindingRef]]:
    """Batch di ≤120 finding, troncati a _MAX_BATCHES batch. Ciò che resta
    fuori non viene mai inviato all'LLM — riceve il fallback deterministico
    in generate(), riportato in coverage['fallback_ranked']. Pubblica (non
    _-prefixed): web.py la richiama per ricostruire gli stessi batch ai fini
    del conteggio byte nell'audit, senza duplicare la logica di slicing."""
    batches: list[list[ai_context.CaseFindingRef]] = []
    for i in range(0, len(refs), _BATCH_SIZE):
        batches.append(refs[i:i + _BATCH_SIZE])
        if len(batches) >= _MAX_BATCHES:
            break
    return batches


@dataclass
class ValidationResult:
    ok: bool
    rankings: list[dict] = field(default_factory=list)
    dropped_hallucinated: int = 0


def validate(parsed: dict | None, known_ids: set[str]) -> ValidationResult:
    if not isinstance(parsed, dict):
        return ValidationResult(ok=False)
    kept: list[dict] = []
    dropped = 0
    for r in parsed.get("rankings") or []:
        if not isinstance(r, dict):
            dropped += 1
            continue
        fid = str(r.get("finding_id", ""))
        if fid not in known_ids:
            dropped += 1
            continue
        bucket = str(r.get("priority_bucket", "")).strip()
        if bucket not in _VALID_BUCKETS:
            bucket = "noise"
        kept.append({
            "finding_id": fid, "priority_bucket": bucket,
            "rationale": str(r.get("rationale", ""))[:200], "fallback": False,
        })
    return ValidationResult(ok=True, rankings=kept, dropped_hallucinated=dropped)


def _build_findings_list(batch: list[ai_context.CaseFindingRef]) -> str:
    lines = []
    for ref in batch:
        f = ref.finding
        notes = (f.notes or "")[:150].replace("\n", " ")
        lines.append(
            f"{ref.finding_id} | kind={f.kind} | value={f.value[:100]} | "
            f"severity={f.severity or '-'} | confidence={f.confidence:.2f} | notes={notes}"
        )
    return "\n".join(lines)


def build_prompt(batch: list[ai_context.CaseFindingRef], *, lang: str) -> tuple[str, str]:
    lang = lang if lang in _LANG_NAMES else "it"
    system_prompt = _SYSTEM_PROMPT_TEMPLATE.format(lang_name=_LANG_NAMES[lang])
    user_prompt = (
        f"Elenco finding da valutare ({len(batch)}):\n{_build_findings_list(batch)}\n\n"
        "Restituisci un ranking per OGNI id elencato sopra."
    )
    return system_prompt, user_prompt


@dataclass
class TriageResult:
    rankings: list[dict]
    coverage: dict
    responses: list[llm_client.LLMResponse]
    collected: ai_context.CollectResult


def generate(
    *, case_id: str, job_id: str = "", lang: str = "it", provider: str, model: str,
    api_key: str, base_url: str = "", max_findings: int = 720,
) -> TriageResult:
    collected = ai_context.collect_case_findings(case_id, job_id=job_id, max_findings=max_findings)
    batches = split_into_batches(collected.refs)

    all_rankings: dict[str, dict] = {}
    dropped_total = 0
    responses: list[llm_client.LLMResponse] = []

    for batch in batches:
        known_ids = {ref.finding_id for ref in batch}
        system_prompt, user_prompt = build_prompt(batch, lang=lang)
        response = llm_client.complete(
            provider=provider, model=model, api_key=api_key, base_url=base_url,
            system_prompt=system_prompt, user_prompt=user_prompt, json_schema=JSON_SCHEMA,
        )
        responses.append(response)
        if not response.ok:
            continue  # questo batch resta scoperto -> fallback deterministico sotto
        validation = validate(response.parsed, known_ids)
        for ranking in validation.rankings:
            all_rankings[ranking["finding_id"]] = ranking
        dropped_total += validation.dropped_hallucinated

    final_rankings: list[dict] = []
    ai_ranked = 0
    fallback_ranked = 0
    for ref in collected.refs:
        existing = all_rankings.get(ref.finding_id)
        if existing:
            final_rankings.append(existing)
            ai_ranked += 1
        else:
            final_rankings.append({
                "finding_id": ref.finding_id,
                "priority_bucket": _fallback_bucket_for(ref.finding.severity),
                "rationale": "",
                "fallback": True,
            })
            fallback_ranked += 1

    coverage = {
        "ai_ranked": ai_ranked, "fallback_ranked": fallback_ranked,
        "total": len(collected.refs), "dropped_hallucinated": dropped_total,
        "batches_sent": len(batches), "batches_available": (len(collected.refs) + _BATCH_SIZE - 1) // _BATCH_SIZE
                       if collected.refs else 0,
    }
    return TriageResult(rankings=final_rankings, coverage=coverage, responses=responses, collected=collected)


__all__ = [
    "JSON_SCHEMA", "ValidationResult", "TriageResult", "validate", "build_prompt",
    "generate", "split_into_batches", "_fallback_bucket_for",
]
