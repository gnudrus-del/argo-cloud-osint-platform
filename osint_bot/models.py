from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class SearchResult:
    title: str
    url: str
    snippet: str = ""
    provider: str = "manual"


@dataclass
class Page:
    url: str
    status: int
    title: str = ""
    description: str = ""
    text: str = ""
    links: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    error: str = ""


@dataclass
class Evidence:
    url: str
    title: str = ""
    quote: str = ""


@dataclass(frozen=True)
class Provenance:
    """Pillar 0.3: origin record attached to a Finding or artifact.

    Carries enough information to reproduce the collection step exactly and
    to verify that the artifact has not been altered since capture.
    """
    tool: str
    collected_at: str
    actor: str = "system"
    case_id: str = ""
    command_hash: str = ""  # SHA-256 of JSON-encoded argv list


@dataclass
class Finding:
    kind: str
    value: str
    confidence: float
    evidence: list[Evidence] = field(default_factory=list)
    notes: str = ""
    # Admiralty/NATO grade (Pillar 0.5). Defaults to F6 ("cannot be judged")
    # so legacy callers keep working; agents/analyzers should set it explicitly.
    source_reliability: str = "F"
    info_credibility: int = 6
    # Pillar 0.3: optional provenance — set by plugin layer when case_id is present.
    provenance: Provenance | None = None
    # Pillar 2.5: severity + ATT&CK mapping for red-team findings.
    severity: str = ""          # info | low | medium | high | critical
    attck_ttps: list[str] = field(default_factory=list)  # e.g. ["T1589.002"]
    remediation: str = ""
    # Explainability (Phase 7): what differenziates Argo dalle vetrine OSINT.
    # ``why_linked``: 1..N frasi in italiano sul motivo del collegamento al
    # target (es. "stessa email vista su 2 fonti indipendenti",
    # "username canonicalizzato identico"). Vuoto = sconosciuto.
    why_linked: list[str] = field(default_factory=list)
    # ``gaps``: cosa MANCA per confermare il finding. Es. "manca corroborazione
    # da fonte categoria A/B", "manca timestamp di cattura", "necessaria
    # verifica DNS aggiornata". L'utente legge questo e capisce subito cosa
    # serve fare per innalzare la confidence.
    gaps: list[str] = field(default_factory=list)


@dataclass
class AgentResult:
    name: str
    status: str
    summary: str
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class Entity:
    id: str
    type: str
    value: str
    display_value: str = ""
    confidence: float = 0.5
    sources: list[str] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)
    # Best grade seen across all findings that mention this entity (Pillar 0.5).
    source_reliability: str = "F"
    info_credibility: int = 6


@dataclass
class Relationship:
    source: str
    target: str
    kind: str
    confidence: float = 0.5
    evidence_url: str = ""


@dataclass
class Investigation:
    target: str
    target_type: str
    generated_at: str
    safety_note: str
    queries: list[str]
    search_results: list[SearchResult]
    pages: list[Page]
    findings: list[Finding]
    agent_results: list[AgentResult] = field(default_factory=list)
    skipped_urls: list[str] = field(default_factory=list)
    entities: list[Entity] = field(default_factory=list)
    relationships: list[Relationship] = field(default_factory=list)

    @classmethod
    def create(
        cls,
        target: str,
        target_type: str,
        safety_note: str,
        queries: list[str],
        search_results: list[SearchResult],
        pages: list[Page],
        findings: list[Finding],
        agent_results: list[AgentResult] | None = None,
        skipped_urls: list[str] | None = None,
        entities: list[Entity] | None = None,
        relationships: list[Relationship] | None = None,
    ) -> Investigation:
        return cls(
            target=target,
            target_type=target_type,
            generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            safety_note=safety_note,
            queries=queries,
            search_results=search_results,
            pages=pages,
            findings=findings,
            agent_results=agent_results or [],
            skipped_urls=skipped_urls or [],
            entities=entities or [],
            relationships=relationships or [],
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
