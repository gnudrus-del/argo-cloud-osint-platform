"""Aggregazione dati di caso per le 3 capability IA opt-in
(narrative_synthesis / entity_resolution_ai / triage_ai).

Unica fonte di verità per cosa significa un finding_id, così la costruzione
del prompt e la validazione delle citazioni non possono mai disallinearsi
(vedi finding_id_for/parse_finding_id).

I Finding non hanno un id stabile persistito (osint_bot.models.Finding non
ha campo id) — qui ne costruiamo uno deterministico e non persistito dalla
posizione del finding nella lista già scritta su disco per quel job:
'<job_id>#<index>'. Nessuna migrazione necessaria, funziona retroattivamente
su ogni job JSON storico.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .grading import severity_rank
from .models import Evidence, Finding

_SEP = "#"


def finding_id_for(job_id: str, index: int) -> str:
    return f"{job_id}{_SEP}{index}"


def parse_finding_id(fid: str) -> tuple[str, int] | None:
    if _SEP not in fid:
        return None
    job_id, _, idx_str = fid.rpartition(_SEP)
    if not job_id or not idx_str.isdigit():
        return None
    return job_id, int(idx_str)


@dataclass
class CaseFindingRef:
    job_id: str
    index: int
    finding_id: str
    finding: Finding


def _findings_from_json_path(job_id: str, json_path: str) -> list[Finding]:
    """Stesso pattern di ricostruzione di web.py:handle_graph_get — legge il
    report JSON del job e ricostruisce oggetti Finding difensivamente (un
    finding malformato viene scartato, non fa fallire l'intero caso)."""
    path = Path(json_path)
    if not path.exists():
        return []
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    findings: list[Finding] = []
    for fd in report.get("findings") or []:
        try:
            ev_list = [Evidence(**e) for e in (fd.get("evidence") or [])]
            findings.append(Finding(
                kind=fd.get("kind", ""),
                value=fd.get("value", ""),
                confidence=float(fd.get("confidence", 0.5)),
                evidence=ev_list,
                notes=fd.get("notes", ""),
                source_reliability=fd.get("source_reliability", "F"),
                info_credibility=int(fd.get("info_credibility", 6)),
                severity=fd.get("severity", ""),
                attck_ttps=list(fd.get("attck_ttps") or []),
                remediation=fd.get("remediation", ""),
                why_linked=list(fd.get("why_linked") or []),
                gaps=list(fd.get("gaps") or []),
            ))
        except Exception:
            continue
    return findings


@dataclass
class CollectResult:
    refs: list[CaseFindingRef]
    total_available: int
    truncated: bool


def collect_case_findings(
    case_id: str, *, job_id: str = "", max_findings: int = 400,
) -> CollectResult:
    """Raccoglie i finding del caso (o di un singolo job se job_id è dato),
    ordinati per priorità (severity desc, confidence desc) e troncati a
    max_findings — il troncamento è SEMPRE segnalato (mai uno scarto silenzioso)."""
    from .web import get_storage  # import locale: evita un ciclo a livello modulo

    store = get_storage()
    if job_id:
        job = store.get_job(job_id)
        jobs = [job] if job else []
    else:
        jobs = store.list_jobs_by_case(case_id)

    all_refs: list[CaseFindingRef] = []
    for job in jobs:
        if not job or job.get("status") != "complete":
            continue
        jid = job.get("id", "")
        json_path = job.get("json_path")
        if not jid or not json_path:
            continue
        findings = _findings_from_json_path(jid, json_path)
        for idx, finding in enumerate(findings):
            all_refs.append(CaseFindingRef(
                job_id=jid, index=idx,
                finding_id=finding_id_for(jid, idx),
                finding=finding,
            ))

    all_refs.sort(
        key=lambda r: (-severity_rank(r.finding.severity), -r.finding.confidence)
    )
    total = len(all_refs)
    truncated = total > max_findings
    return CollectResult(refs=all_refs[:max_findings], total_available=total, truncated=truncated)


def collect_case_entities(case_id: str):
    """Unisce il grafo entità di ogni job del caso in un unico EntityGraph.
    Gli id delle entità sono hash stabili del valore normalizzato
    (link_analysis._stable_id), quindi coerenti tra job diversi dello stesso
    caso — GraphNode.merge() (chiamato da add_node su id già presente) fonde
    correttamente i duplicati invece di crearne una copia."""
    from .link_analysis import EntityGraph, resolve_entities
    from .web import get_storage

    store = get_storage()
    jobs = store.list_jobs_by_case(case_id)
    merged = EntityGraph()
    for job in jobs:
        if not job or job.get("status") != "complete":
            continue
        jid = job.get("id", "")
        json_path = job.get("json_path")
        if not jid or not json_path:
            continue
        findings = _findings_from_json_path(jid, json_path)
        graph = resolve_entities(findings)
        for node in graph.nodes():
            merged.add_node(node)
        for edge in graph.edges():
            merged.add_edge(edge)
    return merged


def estimate_prompt_bytes(system_prompt: str, user_prompt: str) -> int:
    return len(system_prompt.encode("utf-8")) + len(user_prompt.encode("utf-8"))


__all__ = [
    "finding_id_for", "parse_finding_id", "CaseFindingRef", "CollectResult",
    "collect_case_findings", "collect_case_entities", "estimate_prompt_bytes",
]
