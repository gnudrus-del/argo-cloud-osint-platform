"""Tests for redteam_report.py — Red Team variant of the forensic report."""
from __future__ import annotations

import pytest

from osint_bot.forensic_report import CaseContext, ProviderUsage
from osint_bot.models import Evidence, Finding, Investigation
from osint_bot.redteam_report import (
    RedTeamContext, ToolExecution, build_redteam_report, sanitize_command,
)
from osint_bot.target_classifier import classify_target


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ctx(**overrides):
    case = overrides.pop("case", CaseContext(
        case_id="RT-1", title="Red team Acme", owner="alice",
        legal_basis_type="contract", legal_basis_reference="BB-2026-1",
    ))
    target = overrides.pop("target", classify_target("acme.com"))
    investigation = overrides.pop("investigation", Investigation.create(
        target="acme.com", target_type="domain", safety_note="",
        queries=[], search_results=[], pages=[], findings=[],
    ))
    return RedTeamContext(
        case=case, target=target, investigation=investigation,
        ranked_results=[], generated_at="2026-06-27T19:00:00Z",
        **overrides,
    )


# ---------------------------------------------------------------------------
# Sanitize command — no secrets leak
# ---------------------------------------------------------------------------

class TestSanitizeCommand:
    def test_bearer_token_redacted(self):
        cmd = "curl -H 'Authorization: Bearer ghp_abc123def456' https://api.github.com"
        out = sanitize_command(cmd)
        assert "ghp_abc123def456" not in out
        assert "REDACTED" in out

    def test_api_key_param_redacted(self):
        cmd = ["myapi", "--api-key=re_secret123xyz"]
        out = sanitize_command(cmd)
        assert "re_secret123xyz" not in out
        assert "REDACTED" in out

    def test_password_redacted(self):
        cmd = ["mysql", "-u", "admin", "--password=supersecret"]
        out = sanitize_command(cmd)
        assert "supersecret" not in out

    def test_clean_command_unchanged(self):
        cmd = ["subfinder", "-d", "example.com"]
        out = sanitize_command(cmd)
        assert "subfinder" in out
        assert "example.com" in out

    def test_list_serialized_with_quotes(self):
        out = sanitize_command(["nuclei", "-u", "https://example.com/path with space"])
        assert "nuclei" in out
        assert "with space" in out  # quoted


# ---------------------------------------------------------------------------
# Structure: stessa shape del forensic (19 sezioni)
# ---------------------------------------------------------------------------

class TestStructure:
    def test_still_19_sections(self):
        report = build_redteam_report(_ctx())
        assert len(report.sections) == 19
        assert [s.number for s in report.sections] == list(range(1, 20))

    def test_section_8_is_redteam_summary(self):
        report = build_redteam_report(_ctx())
        sec = next(s for s in report.sections if s.number == 8)
        assert "Red Team" in sec.title or "red team" in sec.title.lower()

    def test_section_11_is_tool_executions(self):
        report = build_redteam_report(_ctx())
        sec = next(s for s in report.sections if s.number == 11)
        assert "tool" in sec.title.lower() or "esecuzioni" in sec.title.lower()


# ---------------------------------------------------------------------------
# Severity matrix
# ---------------------------------------------------------------------------

class TestSeverityMatrix:
    def test_critical_findings_highlighted(self):
        findings = [
            Finding(kind="nuclei_finding", value="exposed-env", confidence=0.9, severity="critical"),
            Finding(kind="nuclei_finding", value="xss", confidence=0.8, severity="high"),
            Finding(kind="opsec_possible_token", value="leak", confidence=0.7, severity="medium"),
        ]
        ctx = _ctx(redteam_findings=findings)
        report = build_redteam_report(ctx)
        sec = next(s for s in report.sections if s.number == 8).body_markdown
        assert "critical" in sec.lower()
        assert "CRITICAL" in sec or "critical" in sec
        assert "1" in sec  # 1 critical

    def test_empty_says_no_activity(self):
        ctx = _ctx()
        report = build_redteam_report(ctx)
        sec = next(s for s in report.sections if s.number == 8).body_markdown.lower()
        assert "nessuna" in sec or "no" in sec


# ---------------------------------------------------------------------------
# Findings table
# ---------------------------------------------------------------------------

class TestFindingsTable:
    def test_includes_ttps_when_present(self):
        f = Finding(
            kind="nuclei_finding", value="cve-2024-1234", confidence=0.9,
            severity="high", attck_ttps=["T1190", "T1059"],
            evidence=[Evidence(url="https://acme.com/x", title="nuclei")],
        )
        report = build_redteam_report(_ctx(redteam_findings=[f]))
        sec = next(s for s in report.sections if s.number == 9).body_markdown
        assert "T1190" in sec or "T1059" in sec
        assert "cve-2024-1234" in sec

    def test_orders_by_severity(self):
        findings = [
            Finding(kind="x", value="low_finding", confidence=0.9, severity="low"),
            Finding(kind="x", value="crit_finding", confidence=0.7, severity="critical"),
        ]
        report = build_redteam_report(_ctx(redteam_findings=findings))
        sec = next(s for s in report.sections if s.number == 9).body_markdown
        assert sec.index("crit_finding") < sec.index("low_finding")

    def test_finding_id_assigned(self):
        f = Finding(kind="x", value="y", confidence=0.5, severity="high")
        report = build_redteam_report(_ctx(redteam_findings=[f]))
        sec = next(s for s in report.sections if s.number == 9).body_markdown
        assert "RT-001-" in sec  # format RT-###-HASH


# ---------------------------------------------------------------------------
# Tool executions table
# ---------------------------------------------------------------------------

class TestToolExecutions:
    def test_executions_listed(self):
        exec1 = ToolExecution(
            tool="subfinder", kind="passive_recon", target="acme.com",
            started_at="2026-06-27T19:00:00Z", finished_at="2026-06-27T19:00:30Z",
            return_code=0, duration_ms=30000, findings_count=42,
            command_sanitized="subfinder -d acme.com -silent",
        )
        report = build_redteam_report(_ctx(tool_executions=[exec1]))
        sec = next(s for s in report.sections if s.number == 11).body_markdown
        assert "subfinder" in sec
        assert "42" in sec
        assert "30000" in sec

    def test_errors_section_when_failures(self):
        exec1 = ToolExecution(
            tool="nuclei", kind="vuln_scan", target="acme.com",
            started_at="t", finished_at="t", return_code=None,
            duration_ms=0, error="Timeout dopo 120s.",
            command_sanitized="nuclei -u https://acme.com",
        )
        report = build_redteam_report(_ctx(tool_executions=[exec1]))
        sec = next(s for s in report.sections if s.number == 11).body_markdown
        assert "Timeout" in sec
        assert "nuclei" in sec


# ---------------------------------------------------------------------------
# IoC section dedicata Red Team
# ---------------------------------------------------------------------------

class TestRedTeamIoCs:
    def test_subdomain_takeover_isolato(self):
        findings = [
            Finding(kind="red_team_takeover_candidate", value="x.acme.com", confidence=0.8,
                    severity="critical"),
            Finding(kind="subdomain", value="api.acme.com", confidence=0.9),
        ]
        report = build_redteam_report(_ctx(redteam_findings=findings))
        sec = next(s for s in report.sections if s.number == 16).body_markdown
        assert "Subdomain takeover" in sec or "takeover" in sec.lower()
        assert "Sottodomini" in sec

    def test_no_findings_says_empty(self):
        report = build_redteam_report(_ctx())
        sec = next(s for s in report.sections if s.number == 16).body_markdown.lower()
        assert "nessun" in sec
