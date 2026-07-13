"""Spiegabilita' (Phase 7) — perche' un finding e' collegato e cosa manca per
confermarlo.

E' la cosa che differenzia un motore OSINT serio da una vetrina di tool: ogni
risultato deve dichiarare ``why_linked`` (motivo del collegamento) e ``gaps``
(cosa servirebbe per innalzare la confidence). Argo aveva gia' confidence
trasparente (Fase 4: exact/fuzzy/source/recency/contradictions con rationale),
provenance (tool + timestamp + actor + case_id) e Admiralty grade (A-F/1-6).
Manca solo cucire la narrativa.

Il modulo e' puro: dato un Finding (+ contesto), produce due liste di stringhe
italiane leggibili. Nessun side effect. Idempotente.
"""
from __future__ import annotations

from .grading import classify_evidence_level
from .models import Finding

# Categorie di "kind" che richiedono corroborazione da fonte indipendente per
# essere considerati attendibili. Per ognuno spieghiamo cosa cercare.
_KIND_CORROBORATION_HINT = {
    "contact_email":            "una seconda fonte indipendente che confermi l'email (es. WHOIS, sito ufficiale)",
    "redacted_contact_email":   "una seconda fonte indipendente per de-redact + conferma",
    "phone_format":             "una seconda menzione del numero su fonte indipendente",
    "related_domain":           "DNS check live + WHOIS recente",
    "web_presence":             "fingerprint HTTP attuale (httpx/Wayback) per verifica esistenza",
    "darkweb_onion_reference":  "verifica passiva del riferimento onion senza interazione",
}


def explain_finding(
    finding: Finding,
    *,
    target: str = "",
    target_type: str = "",
    siblings: list[Finding] | None = None,
) -> Finding:
    """Calcola ``why_linked`` e ``gaps`` per un Finding, in place.

    Argomenti:
      ``target``/``target_type``: il target dell'investigation (per
                                  contestualizzare il "perché collegato").
      ``siblings``: altri finding dello stesso job (per cercare corroborazioni
                    o contraddizioni).

    La funzione e' idempotente: se ``why_linked`` o ``gaps`` sono gia' popolati
    NON li sovrascrive, solo li integra. Restituisce lo stesso oggetto.
    """
    why = list(finding.why_linked)
    gaps = list(finding.gaps)
    siblings = siblings or []

    # ---------- why_linked: motivi tecnici del collegamento ----------
    if target and finding.value:
        if finding.value.casefold() == target.casefold():
            why.append(f"valore identico al target «{target}» (match esatto)")
        elif finding.value.casefold() in target.casefold() or target.casefold() in finding.value.casefold():
            why.append(f"valore sovrapposto al target «{target}» (sottostringa)")

    if finding.provenance and finding.provenance.tool:
        why.append(f"raccolto da «{finding.provenance.tool}» il {finding.provenance.collected_at or '—'}")

    # Conta corroborazioni: altri finding con stesso (kind, value) o stesso URL.
    corroborations = sum(
        1 for s in siblings
        if s is not finding
        and (s.kind == finding.kind and s.value.casefold() == finding.value.casefold())
    )
    if corroborations:
        why.append(f"corroborato da {corroborations} altra/e evidenza/e nello stesso job")

    grade = f"{(finding.source_reliability or 'F').upper()}{int(finding.info_credibility or 6)}"
    level = classify_evidence_level(finding.source_reliability, finding.info_credibility)
    why.append(f"grado Admiralty {grade} ({level})")

    # ---------- gaps: cosa manca per confermare ----------
    if level == "non_disponibile":
        gaps.append("nessuna fonte verificata: serve un riscontro indipendente prima di trattarlo come fatto")
    elif level == "non_verificato":
        gaps.append("fonte di affidabilità bassa: cerca una seconda fonte di categoria A o B per corroborare")

    # Gap specifici per kind
    hint = _KIND_CORROBORATION_HINT.get(finding.kind)
    if hint and corroborations == 0:
        gaps.append(f"manca corroborazione: {hint}")

    # Provenance incompleto
    if finding.provenance:
        if not finding.provenance.collected_at:
            gaps.append("manca timestamp di cattura nella provenance")
        if not finding.provenance.command_hash:
            gaps.append("manca command_hash nella provenance (riproducibilità non garantita)")
    else:
        gaps.append("provenance assente: il risultato non è riproducibile (tool/timestamp/case_id ignoti)")

    # Confidence bassa senza spiegazione
    if finding.confidence < 0.4 and not finding.notes:
        gaps.append("confidence bassa senza note esplicative: aggiungi contesto o scarta")

    # Contraddizioni: altro finding stesso kind, valore DIVERSO
    contradictions = sum(
        1 for s in siblings
        if s is not finding
        and s.kind == finding.kind
        and s.value.casefold() != finding.value.casefold()
    )
    if contradictions:
        gaps.append(f"esistono {contradictions} evidenze in conflitto (stessa categoria, valore diverso): risolvi prima di considerarlo certo")

    # Evidence URL mancanti
    if not finding.evidence:
        gaps.append("nessun link-evidenza cliccabile: aggiungi almeno una URL di supporto")

    # Dedupe preservando ordine
    finding.why_linked = list(dict.fromkeys(why))
    finding.gaps = list(dict.fromkeys(gaps))
    return finding


def enrich_investigation_explanations(investigation) -> None:
    """Applica ``explain_finding`` a tutti i finding di una Investigation.

    Idempotente: i campi vengono ricalcolati da zero (preservando l'esistente
    grazie al merge dentro explain_finding).
    """
    siblings = list(investigation.findings)
    for f in investigation.findings:
        explain_finding(
            f,
            target=investigation.target,
            target_type=investigation.target_type,
            siblings=siblings,
        )


__all__ = ["explain_finding", "enrich_investigation_explanations"]
