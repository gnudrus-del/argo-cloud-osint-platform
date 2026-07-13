"""Pillar 4 integration — full external recon pipeline.

Orchestrates:
  Passive connectors → red_team analysis → defensive analysis → link graph

Usage:
    from osint_bot.external_recon import run_recon_pipeline, ReconReport
    from osint_bot.connectors import build_default_registry

    registry = build_default_registry()
    report = run_recon_pipeline(registry, target="example.com", target_type="domain",
                                api_keys={"shodan": "...", ...}, actor="analyst")
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

from .connector import ConnectorContext, ConnectorRegistry
from .defensive import (
    ImpersonationSignal,
    IOCEnrichment,
    assess_brand_impersonation,
    enrich_ioc,
    score_digital_footprint,
)
from .link_analysis import EntityGraph, export_d3_json, resolve_entities
from .models import Finding
from .red_team import (
    ScanDiff,
    assess_takeover_candidates,
    diff_scan_findings,
    scan_credential_exposure,
)


@dataclass
class StageResult:
    stage: str
    connector: str
    duration_s: float
    findings: list[Finding]
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.error == ""


@dataclass
class ReconReport:
    target: str
    target_type: str
    started_at: float
    finished_at: float
    actor: str
    case_id: str

    # Raw findings from each connector
    connector_results: list[StageResult] = field(default_factory=list)

    # Red-team enrichment
    takeover_findings: list[Finding] = field(default_factory=list)
    credential_findings: list[Finding] = field(default_factory=list)
    scan_diff: ScanDiff | None = None

    # Defensive enrichment
    impersonation_signals: list[ImpersonationSignal] = field(default_factory=list)
    ioc_enrichments: list[IOCEnrichment] = field(default_factory=list)
    footprint_score: dict[str, Any] = field(default_factory=dict)

    # Link graph
    graph: EntityGraph | None = None

    @property
    def all_findings(self) -> list[Finding]:
        results: list[Finding] = []
        for sr in self.connector_results:
            results.extend(sr.findings)
        results.extend(self.takeover_findings)
        results.extend(self.credential_findings)
        return results

    @property
    def duration_s(self) -> float:
        return self.finished_at - self.started_at

    def summary(self) -> dict[str, Any]:
        total = len(self.all_findings)
        by_severity: dict[str, int] = {}
        for f in self.all_findings:
            sev = f.severity or "info"
            by_severity[sev] = by_severity.get(sev, 0) + 1

        connectors_ok = sum(1 for r in self.connector_results if r.ok)
        connectors_err = len(self.connector_results) - connectors_ok

        return {
            "target": self.target,
            "target_type": self.target_type,
            "duration_s": round(self.duration_s, 2),
            "actor": self.actor,
            "case_id": self.case_id,
            "total_findings": total,
            "by_severity": by_severity,
            "connectors_run": len(self.connector_results),
            "connectors_ok": connectors_ok,
            "connectors_error": connectors_err,
            "takeover_findings": len(self.takeover_findings),
            "credential_findings": len(self.credential_findings),
            "impersonation_signals": len(self.impersonation_signals),
            "ioc_enrichments": len(self.ioc_enrichments),
            "footprint_score": self.footprint_score.get("score"),
            "footprint_risk": self.footprint_score.get("risk_level"),
            "graph_nodes": self.graph.node_count() if self.graph else 0,
            "graph_edges": self.graph.edge_count() if self.graph else 0,
        }

    def to_dict(self) -> dict[str, Any]:
        d = self.summary()
        d["connector_stages"] = [
            {
                "stage": r.stage,
                "connector": r.connector,
                "duration_s": round(r.duration_s, 2),
                "findings": len(r.findings),
                "error": r.error,
            }
            for r in self.connector_results
        ]
        d["impersonation_signals"] = [
            {
                "kind": s.kind,
                "value": s.value,
                "similarity": s.similarity,
                "technique": s.technique,
            }
            for s in self.impersonation_signals
        ]
        if self.graph:
            d["graph"] = export_d3_json(self.graph)
        return d


# Passive-only connectors that run unconditionally (no sensitive PII targets)
_PASSIVE_CONNECTORS = [
    "crt_sh",
    "rdap",
    "urlscan",
    "wayback",
    "github_search",
    "leakix",
    "shodan",
    "virustotal",
    "abuseipdb",
]

# PII-gated: run only when `allow_pii=True`
_PII_CONNECTORS = ["hibp", "hunter"]


def run_recon_pipeline(
    registry: ConnectorRegistry,
    *,
    target: str,
    target_type: str = "domain",
    api_keys: dict[str, str] | None = None,
    actor: str = "system",
    case_id: str = "",
    allow_pii: bool = False,
    baseline_findings: list[Finding] | None = None,
    brand_name: str = "",
    extra_domains: list[str] | None = None,
    extra_handles: list[str] | None = None,
    timeout: int = 20,
) -> ReconReport:
    """Run the full passive recon pipeline against a target.

    Args:
        registry: ConnectorRegistry with all connectors registered.
        target: The primary target (domain, IP, email, …).
        target_type: One of domain | ip | email | url | company | file_hash.
        api_keys: Dict of {connector_name: api_key}.
        actor: Username performing the investigation (for audit/provenance).
        case_id: Optional case identifier for provenance stamping.
        allow_pii: If True, also run PII-gated connectors (HIBP, Hunter).
        baseline_findings: Previous findings for diff-based monitoring.
        brand_name: If provided, run brand impersonation checks.
        extra_domains: Additional observed domains for brand check.
        extra_handles: Additional observed handles for brand check.
        timeout: Per-connector HTTP timeout in seconds.
    """
    keys = api_keys or {}
    started_at = time.time()
    report = ReconReport(
        target=target,
        target_type=target_type,
        started_at=started_at,
        finished_at=started_at,
        actor=actor,
        case_id=case_id,
    )

    # --- Stage 1: passive connectors ---
    connectors_to_run = list(_PASSIVE_CONNECTORS)
    if allow_pii:
        connectors_to_run.extend(_PII_CONNECTORS)

    for name in connectors_to_run:
        try:
            connector = registry.get(name)
        except KeyError:
            continue
        spec = connector.spec
        # Skip if target_type not compatible
        if target_type not in spec.input_types:
            continue
        # Skip if API key required but missing
        if spec.required_key and not keys.get(spec.required_key, ""):
            report.connector_results.append(StageResult(
                stage="connector",
                connector=name,
                duration_s=0.0,
                findings=[],
                error=f"API key '{spec.required_key}' mancante — connettore saltato.",
            ))
            continue

        ctx = ConnectorContext(
            target=target,
            target_type=target_type,
            api_key=keys.get(spec.required_key or "", ""),
            timeout=timeout,
            actor=actor,
            case_id=case_id,
        )

        t0 = time.time()
        try:
            result = connector.run(ctx)
            report.connector_results.append(StageResult(
                stage="connector",
                connector=name,
                duration_s=time.time() - t0,
                findings=result.findings,
                error=result.error or "",
            ))
        except Exception as exc:
            report.connector_results.append(StageResult(
                stage="connector",
                connector=name,
                duration_s=time.time() - t0,
                findings=[],
                error=str(exc),
            ))

    all_findings = report.all_findings

    # --- Stage 2: red team analysis ---
    # 2a. Takeover candidates from findings
    candidate_hosts: dict[str, list] = {}
    for f in all_findings:
        if f.kind in {"subdomain", "cname_target", "crt_domain"}:
            candidate_hosts.setdefault(f.value.strip(), [])

    if candidate_hosts:
        report.takeover_findings = assess_takeover_candidates(candidate_hosts)

    # 2b. Credential exposure scan
    # Convert notes from any finding into page-like objects expected by scan_credential_exposure
    pages: list[SimpleNamespace] = []
    search_results: list[SimpleNamespace] = []
    for f in all_findings:
        if f.notes:
            pages.append(SimpleNamespace(url=f.value, text=f.notes, title="", error=""))

    if pages or search_results:
        report.credential_findings = scan_credential_exposure(target, pages, search_results)

    # 2c. Diff against baseline
    if baseline_findings is not None:
        report.scan_diff = diff_scan_findings(baseline_findings, report.all_findings)

    # --- Stage 3: defensive analysis ---
    # 3a. Brand impersonation
    if brand_name:
        obs_domains = list(extra_domains or []) + [
            f.value for f in all_findings if f.kind in {"subdomain", "crt_domain"}
        ]
        obs_handles = list(extra_handles or [])
        if obs_domains or obs_handles:
            report.impersonation_signals = assess_brand_impersonation(
                brand_name, obs_domains, obs_handles
            )

    # 3b. IOC enrichment for high/critical IP findings
    seen_iocs: set[str] = set()
    for f in all_findings:
        if f.severity in {"high", "critical"} and f.kind in {
            "abuseipdb_score", "leakix_leak", "leakix_service",
            "vt_detection", "urlscan_malicious",
        }:
            ioc_val = f.value.split(" ")[0]  # strip trailing notes
            if ioc_val not in seen_iocs:
                seen_iocs.add(ioc_val)
                try:
                    enrichment = enrich_ioc(ioc_val, ioc_type="auto")
                    report.ioc_enrichments.append(enrichment)
                except Exception:
                    pass

    # 3c. Digital footprint score
    report.footprint_score = score_digital_footprint(report.all_findings)

    # --- Stage 4: link graph ---
    report.graph = resolve_entities(report.all_findings)

    report.finished_at = time.time()
    return report
