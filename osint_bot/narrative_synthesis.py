"""Capability IA opt-in #1 — sintesi narrativa del caso.

Trasforma i finding grezzi di un caso in prosa investigativa con citazioni
verso i finding sorgente. Non scrive mai sul report statico su disco (fase 1,
vedi ReportContext.ai_narrative in forensic_report.py per l'hook fase 2) —
il chiamante (web.py) decide dove mostrare l'output.

Principio guida: ogni frase fattuale deve citare un finding_id esistente.
Un ID citato che non è tra quelli inviati è un errore hard, non un dettaglio
da ignorare — un analista che si fida di una citazione falsa è peggio di un
analista senza sintesi.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import ai_context, llm_client

JSON_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "summary_paragraph": {"type": "string"},
        "sections": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "heading": {"type": "string"},
                    "body": {"type": "string"},
                    "citations": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["heading", "body", "citations"],
                "additionalProperties": False,
            },
        },
        "citations_used": {"type": "array", "items": {"type": "string"}},
        "caveats": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["summary_paragraph", "sections", "citations_used", "caveats"],
    "additionalProperties": False,
}

_SYSTEM_PROMPT_TEMPLATE = """Sei un analista OSINT che scrive la sintesi narrativa di un'indagine per un altro analista.

Regole non negoziabili:
1. Ogni frase fattuale deve terminare con una citazione nel formato [F#<finding_id>], copiata ESATTAMENTE da uno degli ID nella tabella fornita. Non inventare mai un finding_id che non è nella tabella.
2. Se l'evidenza per un punto è debole o ambigua, dillo esplicitamente nel testo invece di abbellire o generalizzare.
3. Non trarre conclusioni che i finding forniti non supportano.
4. Rispondi SOLO nella lingua richiesta: {lang_name}.
5. Restituisci ESCLUSIVAMENTE l'oggetto strutturato richiesto — nessun testo fuori schema, nessun markdown fence.
"""

_LANG_NAMES = {"it": "italiano", "en": "inglese (English)"}


@dataclass
class ValidationResult:
    ok: bool
    parsed: dict | None
    dropped_hallucinated: list[str] = field(default_factory=list)
    error: str = ""


def _extract_citation_ids(parsed: dict) -> set[str]:
    ids: set[str] = set(parsed.get("citations_used") or [])
    for section in parsed.get("sections") or []:
        ids.update(section.get("citations") or [])
    return ids


def validate(parsed: dict, known_ids: set[str]) -> ValidationResult:
    """Ogni ID citato deve appartenere a known_ids. Nessuna tolleranza: un
    finding_id inventato è un hard-fail (il chiamante decide se ritentare),
    non uno scarto silenzioso — mostrare prosa con citazioni non verificabili
    è peggio che non mostrare nulla."""
    if not isinstance(parsed, dict):
        return ValidationResult(ok=False, parsed=None, error="Risposta non è un oggetto JSON.")
    cited = _extract_citation_ids(parsed)
    hallucinated = sorted(cited - known_ids)
    if hallucinated:
        return ValidationResult(
            ok=False, parsed=parsed, dropped_hallucinated=hallucinated,
            error=f"Il modello ha citato {len(hallucinated)} finding inesistenti: {hallucinated[:5]}.",
        )
    if not cited:
        return ValidationResult(
            ok=False, parsed=parsed,
            error="La narrativa non contiene nessuna citazione verificabile.",
        )
    return ValidationResult(ok=True, parsed=parsed)


def _build_findings_table(refs: list[ai_context.CaseFindingRef]) -> str:
    lines = ["finding_id | kind | value | confidence | severity | admiralty | notes"]
    for ref in refs:
        f = ref.finding
        notes = (f.notes or "")[:200].replace("\n", " ").replace("|", "/")
        admiralty = f"{f.source_reliability}{f.info_credibility}"
        lines.append(
            f"{ref.finding_id} | {f.kind} | {f.value[:120]} | {f.confidence:.2f} | "
            f"{f.severity or '-'} | {admiralty} | {notes}"
        )
    return "\n".join(lines)


def build_prompt(refs: list[ai_context.CaseFindingRef], *, case_title: str, lang: str) -> tuple[str, str]:
    lang = lang if lang in _LANG_NAMES else "it"
    system_prompt = _SYSTEM_PROMPT_TEMPLATE.format(lang_name=_LANG_NAMES[lang])
    table = _build_findings_table(refs)
    user_prompt = (
        f"Caso: {case_title}\n\n"
        f"Tabella finding disponibili (cita SOLO questi ID):\n{table}\n\n"
        "Scrivi la sintesi narrativa dell'indagine seguendo lo schema richiesto."
    )
    return system_prompt, user_prompt


def generate(
    *, case_id: str, case_title: str, job_id: str = "", lang: str = "it",
    provider: str, model: str, api_key: str, base_url: str = "",
    max_findings: int = 150,
) -> tuple[llm_client.LLMResponse, ValidationResult, ai_context.CollectResult]:
    """Orchestratore: raccoglie i finding, costruisce il prompt, chiama l'LLM,
    valida. Un id citato ma non esistente -> un retry con l'errore in prompt,
    poi il chiamante (web.py) decide come rispondere (502 esplicito)."""
    collected = ai_context.collect_case_findings(case_id, job_id=job_id, max_findings=max_findings)
    known_ids = {ref.finding_id for ref in collected.refs}
    system_prompt, user_prompt = build_prompt(collected.refs, case_title=case_title, lang=lang)

    response = llm_client.complete(
        provider=provider, model=model, api_key=api_key, base_url=base_url,
        system_prompt=system_prompt, user_prompt=user_prompt, json_schema=JSON_SCHEMA,
    )
    if not response.ok:
        return response, ValidationResult(ok=False, parsed=None, error=response.error), collected

    result = validate(response.parsed, known_ids)
    if result.ok:
        return response, result, collected

    # Un solo retry "di riparazione": rimando l'errore di validazione al modello.
    repair_user_prompt = (
        f"{user_prompt}\n\n--- La tua risposta precedente citava ID inesistenti ---\n"
        f"ID non validi: {result.dropped_hallucinated}\n"
        "Rispondi di nuovo, citando SOLO gli ID presenti nella tabella sopra."
    )
    retry_response = llm_client.complete(
        provider=provider, model=model, api_key=api_key, base_url=base_url,
        system_prompt=system_prompt, user_prompt=repair_user_prompt, json_schema=JSON_SCHEMA,
    )
    if not retry_response.ok:
        return retry_response, ValidationResult(ok=False, parsed=None, error=retry_response.error), collected
    retry_result = validate(retry_response.parsed, known_ids)
    return retry_response, retry_result, collected


__all__ = ["JSON_SCHEMA", "ValidationResult", "validate", "build_prompt", "generate"]
