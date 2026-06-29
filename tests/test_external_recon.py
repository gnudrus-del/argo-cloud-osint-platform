"""Tests for external_recon.py — full pipeline integration."""
from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import pytest

from osint_bot.connector import (
    ACTION_PASSIVE,
    BaseConnector,
    ConnectorContext,
    ConnectorRegistry,
    ConnectorResult,
    ConnectorSpec,
    RateLimit,
)
from osint_bot.external_recon import ReconReport, StageResult, run_recon_pipeline
from osint_bot.models import Evidence, Finding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding(kind: str, value: str, severity: str = "info", notes: str = "") -> Finding:
    return Finding(
        kind=kind,
        value=value,
        confidence=0.80,
        severity=severity,
        evidence=[Evidence(url="https://example.com", title="test")],
        notes=notes,
    )


class _OkConnector(BaseConnector):
    def __init__(self, name: str, input_types: tuple, findings: list[Finding]):
        super().__init__()
        self._findings = findings
        self.spec = ConnectorSpec(
            name=name,
            label=name,
            action_class=ACTION_PASSIVE,
            input_types=input_types,
            output_categories=("test",),
            required_key="",
            cache_ttl=0,
            rate_limit=RateLimit(per_minute=60),
            legal_note="test",
        )

    def _fetch(self, ctx: ConnectorContext) -> ConnectorResult:
        return ConnectorResult(connector=self.spec.name, status="ok", findings=self._findings)


class _ErrorConnector(BaseConnector):
    def __init__(self, name: str):
        super().__init__()
        self.spec = ConnectorSpec(
            name=name,
            label=name,
            action_class=ACTION_PASSIVE,
            input_types=("domain",),
            output_categories=("test",),
            required_key="",
            cache_ttl=0,
            rate_limit=RateLimit(per_minute=60),
            legal_note="test",
        )

    def _fetch(self, ctx: ConnectorContext) -> ConnectorResult:
        return ConnectorResult(connector=self.spec.name, status="error", error="timeout simulato")


def _registry(*connectors) -> ConnectorRegistry:
    reg = ConnectorRegistry()
    for c in connectors:
        reg.register(c)
    return reg


# ---------------------------------------------------------------------------
# ReconReport
# ---------------------------------------------------------------------------

class TestReconReport:
    def _make_report(self, findings=None, takeover=None, cred=None):
        r = ReconReport(
            target="example.com",
            target_type="domain",
            started_at=time.time(),
            finished_at=time.time() + 1.5,
            actor="test",
            case_id="c1",
        )
        if findings is not None:
            r.connector_results.append(StageResult(
                stage="connector", connector="mock", duration_s=0.5, findings=findings
            ))
        r.takeover_findings = takeover or []
        r.credential_findings = cred or []
        return r

    def test_all_findings_aggregates_all_sources(self):
        f1 = _finding("crt_domain", "sub.example.com")
        f2 = _finding("takeover_risk", "cdn.example.com", severity="high")
        r = self._make_report(findings=[f1], takeover=[f2])
        assert len(r.all_findings) == 2
        assert f1 in r.all_findings
        assert f2 in r.all_findings

    def test_duration_s(self):
        r = ReconReport(
            target="x.com", target_type="domain",
            started_at=1000.0, finished_at=1005.5,
            actor="a", case_id="",
        )
        assert abs(r.duration_s - 5.5) < 0.01

    def test_summary_counts(self):
        f1 = _finding("crt_domain", "a.example.com", severity="info")
        f2 = _finding("takeover_risk", "cdn.example.com", severity="high")
        r = self._make_report(findings=[f1], takeover=[f2])
        s = r.summary()
        assert s["total_findings"] == 2
        assert s["by_severity"]["info"] == 1
        assert s["by_severity"]["high"] == 1

    def test_summary_connector_counts(self):
        r = self._make_report(findings=[])
        r.connector_results.append(StageResult(
            stage="connector", connector="failed", duration_s=0.1,
            findings=[], error="timeout"
        ))
        s = r.summary()
        assert s["connectors_run"] == 2
        assert s["connectors_ok"] == 1
        assert s["connectors_error"] == 1

    def test_to_dict_has_graph_key_when_graph_set(self):
        r = self._make_report(findings=[_finding("crt_domain", "a.example.com")])
        from osint_bot.link_analysis import resolve_entities
        r.graph = resolve_entities(r.all_findings)
        d = r.to_dict()
        assert "graph" in d

    def test_to_dict_no_graph_when_none(self):
        r = self._make_report()
        d = r.to_dict()
        assert "graph" not in d

    def test_summary_no_findings(self):
        r = ReconReport(
            target="test.com", target_type="domain",
            started_at=0.0, finished_at=0.1, actor="a", case_id=""
        )
        s = r.summary()
        assert s["total_findings"] == 0
        assert s["connectors_run"] == 0


# ---------------------------------------------------------------------------
# run_recon_pipeline
# ---------------------------------------------------------------------------

class TestRunReconPipeline:
    def test_empty_registry_produces_empty_report(self):
        reg = ConnectorRegistry()
        report = run_recon_pipeline(reg, target="example.com", target_type="domain")
        assert isinstance(report, ReconReport)
        assert report.all_findings == []
        assert report.connector_results == []

    def test_compatible_connector_runs(self):
        findings = [_finding("crt_domain", "api.example.com")]
        conn = _OkConnector("crt_sh", ("domain",), findings)
        reg = _registry(conn)
        report = run_recon_pipeline(reg, target="example.com", target_type="domain")
        assert len(report.connector_results) == 1
        assert report.connector_results[0].connector == "crt_sh"
        assert report.connector_results[0].ok
        assert len(report.all_findings) >= 1

    def test_incompatible_target_type_skips_connector(self):
        # ip-only connector should be skipped when target_type=domain
        conn = _OkConnector("abuseipdb", ("ip",), [_finding("abuseipdb_score", "90")])
        reg = _registry(conn)
        report = run_recon_pipeline(reg, target="example.com", target_type="domain")
        assert report.connector_results == []

    def test_error_connector_recorded_in_results(self):
        conn = _ErrorConnector("rdap")
        reg = _registry(conn)
        report = run_recon_pipeline(reg, target="example.com", target_type="domain")
        assert len(report.connector_results) == 1
        assert not report.connector_results[0].ok
        assert "timeout simulato" in report.connector_results[0].error

    def test_missing_api_key_skips_connector(self):
        class _KeyedConnector(BaseConnector):
            spec = ConnectorSpec(
                name="shodan", label="Shodan", action_class=ACTION_PASSIVE,
                input_types=("domain",), output_categories=("network",),
                required_key="shodan", cache_ttl=0,
                rate_limit=RateLimit(per_minute=10), legal_note="test",
            )

            def _fetch(self, ctx: ConnectorContext) -> ConnectorResult:
                return ConnectorResult(connector="shodan", status="ok", findings=[])

        conn = _KeyedConnector()
        reg = _registry(conn)
        report = run_recon_pipeline(reg, target="example.com", target_type="domain",
                                    api_keys={})  # no shodan key
        # Should have a StageResult with an error about missing key
        assert len(report.connector_results) == 1
        assert not report.connector_results[0].ok
        assert "mancante" in report.connector_results[0].error

    def test_takeover_candidates_extracted(self):
        findings = [
            _finding("cname_target", "acme.github.io"),
            _finding("cname_target", "acme.s3.amazonaws.com", severity="info"),
        ]
        conn = _OkConnector("crt_sh", ("domain",), findings)
        reg = _registry(conn)
        report = run_recon_pipeline(reg, target="acme.com", target_type="domain")
        # takeover findings should include github.io + s3 candidates
        assert len(report.takeover_findings) >= 2
        severities = {f.severity for f in report.takeover_findings}
        # s3 should be critical
        assert "critical" in severities

    def test_credential_scan_runs_when_pages_present(self):
        notes = "Found AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE in config"
        findings = [_finding("wayback_url_count", "42", notes=notes)]
        conn = _OkConnector("wayback", ("domain",), findings)
        reg = _registry(conn)
        report = run_recon_pipeline(reg, target="example.com", target_type="domain")
        # credentials scan should pick up the AWS key in notes
        assert len(report.credential_findings) >= 1

    def test_scan_diff_when_baseline_provided(self):
        f_old = _finding("crt_domain", "old.example.com")
        f_new = _finding("crt_domain", "new.example.com")
        conn = _OkConnector("crt_sh", ("domain",), [f_new])
        reg = _registry(conn)
        report = run_recon_pipeline(
            reg, target="example.com", target_type="domain",
            baseline_findings=[f_old],
        )
        assert report.scan_diff is not None
        assert report.scan_diff.has_changes

    def test_no_diff_when_baseline_not_provided(self):
        conn = _OkConnector("crt_sh", ("domain",), [_finding("crt_domain", "a.example.com")])
        reg = _registry(conn)
        report = run_recon_pipeline(reg, target="example.com", target_type="domain")
        assert report.scan_diff is None

    def test_brand_impersonation_when_brand_name_set(self):
        # subdomains from connector become observed_domains for brand check
        findings = [
            _finding("crt_domain", "myacme-login.com"),
            _finding("crt_domain", "myacme.io"),
        ]
        conn = _OkConnector("crt_sh", ("domain",), findings)
        reg = _registry(conn)
        report = run_recon_pipeline(
            reg, target="acme.com", target_type="domain",
            brand_name="acme",
        )
        assert len(report.impersonation_signals) >= 1

    def test_no_brand_check_when_no_brand_name(self):
        conn = _OkConnector("crt_sh", ("domain",), [_finding("crt_domain", "x.example.com")])
        reg = _registry(conn)
        report = run_recon_pipeline(reg, target="example.com", target_type="domain")
        assert report.impersonation_signals == []

    def test_ioc_enrichment_on_high_findings(self):
        # abuseipdb_score finding with high severity
        findings = [_finding("abuseipdb_score", "85", severity="high")]
        conn = _OkConnector("abuseipdb", ("ip",), findings)
        reg = _registry(conn)
        report = run_recon_pipeline(reg, target="1.2.3.4", target_type="ip")
        assert len(report.ioc_enrichments) >= 1

    def test_footprint_score_always_computed(self):
        conn = _OkConnector("crt_sh", ("domain",), [_finding("crt_domain", "a.example.com")])
        reg = _registry(conn)
        report = run_recon_pipeline(reg, target="example.com", target_type="domain")
        assert "score" in report.footprint_score
        assert "risk_level" in report.footprint_score

    def test_graph_built_from_all_findings(self):
        findings = [
            _finding("crt_domain", "api.example.com"),
            _finding("crt_domain", "mail.example.com"),
        ]
        conn = _OkConnector("crt_sh", ("domain",), findings)
        reg = _registry(conn)
        report = run_recon_pipeline(reg, target="example.com", target_type="domain")
        assert report.graph is not None
        assert report.graph.node_count() >= 2

    def test_multiple_connectors_all_run(self):
        f1 = [_finding("crt_domain", "a.example.com")]
        f2 = [_finding("urlscan_domain", "example.com")]
        c1 = _OkConnector("crt_sh", ("domain",), f1)
        c2 = _OkConnector("urlscan", ("domain", "url", "ip"), f2)
        reg = _registry(c1, c2)
        report = run_recon_pipeline(reg, target="example.com", target_type="domain")
        names = {r.connector for r in report.connector_results}
        assert "crt_sh" in names
        assert "urlscan" in names

    def test_pii_connectors_skipped_without_allow_pii(self):
        pii_conn = _OkConnector("hibp", ("email", "domain"), [_finding("hibp_breach", "Adobe")])
        reg = _registry(pii_conn)
        # hibp requires required_key="hibp" and is in _PII_CONNECTORS
        # Without allow_pii, it should not run
        report = run_recon_pipeline(reg, target="example.com", target_type="domain",
                                    allow_pii=False)
        names = {r.connector for r in report.connector_results}
        assert "hibp" not in names

    def test_timing_fields_populated(self):
        reg = ConnectorRegistry()
        report = run_recon_pipeline(reg, target="example.com", target_type="domain")
        assert report.started_at > 0
        assert report.finished_at >= report.started_at
        assert report.duration_s >= 0

    def test_actor_and_case_id_propagated(self):
        reg = ConnectorRegistry()
        report = run_recon_pipeline(
            reg, target="example.com", target_type="domain",
            actor="investigator1", case_id="CASE-99"
        )
        assert report.actor == "investigator1"
        assert report.case_id == "CASE-99"

    def test_exception_in_connector_recorded(self):
        class _BrokenConnector(BaseConnector):
            spec = ConnectorSpec(
                name="crt_sh", label="crt_sh", action_class=ACTION_PASSIVE,
                input_types=("domain",), output_categories=("test",),
                required_key="", cache_ttl=0, rate_limit=RateLimit(per_minute=60), legal_note="test",
            )

            def __init__(self):
                super().__init__()

            def _fetch(self, ctx):
                raise RuntimeError("rete irraggiungibile")

        conn = _BrokenConnector()
        reg = _registry(conn)
        report = run_recon_pipeline(reg, target="example.com", target_type="domain")
        assert len(report.connector_results) == 1
        assert not report.connector_results[0].ok
        assert "rete irraggiungibile" in report.connector_results[0].error
