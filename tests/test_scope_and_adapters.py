"""Tests for scope.py + tool_adapter.py — scope enforcement and adapter contract."""
from __future__ import annotations

import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from osint_bot.scope import (
    CaseScope, ENTRY_CIDR, ENTRY_DOMAIN, ENTRY_HANDLE, ENTRY_IP, ENTRY_URL,
    ENTRY_WILDCARD, OutOfScopeError, ScopeEntry, assert_in_scope,
    audit_scope_attempt, in_scope, parse_entry,
)
from osint_bot.target_classifier import classify_target
from osint_bot.tool_adapter import (
    KIND_DAST, KIND_PASSIVE_RECON, KIND_VULN_SCAN, AmassAdapter, NucleiAdapter,
    SubfinderAdapter, ToolAdapter, ZAPBaselineAdapter, get_adapter,
    list_adapters, register,
)


# ============================================================================
# scope.parse_entry
# ============================================================================

class TestParseEntry:
    def test_empty(self):
        assert parse_entry("") is None

    def test_plain_domain(self):
        e = parse_entry("example.com")
        assert e.kind == ENTRY_DOMAIN
        assert e.value == "example.com"

    def test_wildcard_domain(self):
        e = parse_entry("*.example.com")
        assert e.kind == ENTRY_WILDCARD
        assert e.value == "example.com"

    def test_ipv4(self):
        e = parse_entry("192.168.1.1")
        assert e.kind == ENTRY_IP
        assert e.value == "192.168.1.1"

    def test_cidr(self):
        e = parse_entry("10.0.0.0/24")
        assert e.kind == ENTRY_CIDR
        assert e.value == "10.0.0.0/24"

    def test_url(self):
        e = parse_entry("https://example.com/api")
        assert e.kind == ENTRY_URL
        assert e.value == "https://example.com/api/"

    def test_handle(self):
        e = parse_entry("@alice")
        assert e.kind == ENTRY_HANDLE
        assert e.value == "alice"

    def test_invalid_returns_none(self):
        assert parse_entry("not-a-thing-at-all") is None

    def test_metadata_carried(self):
        e = parse_entry("example.com", note="bug bounty", added_by="alice",
                        added_at="2026-06-27T10:00:00Z")
        assert e.note == "bug bounty"
        assert e.added_by == "alice"


# ============================================================================
# scope.in_scope / assert_in_scope
# ============================================================================

class TestInScope:
    def test_empty_scope_denies(self):
        scope = CaseScope(case_id="c1")
        target = classify_target("example.com")
        decision = in_scope(target, scope)
        assert decision.allowed is False
        assert "Scope vuoto" in decision.rationale

    def test_exact_domain_match(self):
        scope = CaseScope(case_id="c1")
        scope.add(parse_entry("example.com"))
        target = classify_target("example.com")
        assert in_scope(target, scope).allowed is True

    def test_wildcard_includes_subdomain(self):
        scope = CaseScope(case_id="c1")
        scope.add(parse_entry("*.example.com"))
        target = classify_target("api.example.com")
        assert in_scope(target, scope).allowed is True

    def test_wildcard_includes_apex(self):
        scope = CaseScope(case_id="c1")
        scope.add(parse_entry("*.example.com"))
        target = classify_target("example.com")
        assert in_scope(target, scope).allowed is True

    def test_subdomain_not_matched_by_apex_only(self):
        scope = CaseScope(case_id="c1")
        scope.add(parse_entry("example.com"))
        target = classify_target("api.example.com")
        # api.example.com has apex=example.com, so the ENTRY_DOMAIN matches apex.
        assert in_scope(target, scope).allowed is True

    def test_unrelated_domain_denied(self):
        scope = CaseScope(case_id="c1")
        scope.add(parse_entry("example.com"))
        target = classify_target("other.net")
        assert in_scope(target, scope).allowed is False

    def test_ip_match(self):
        scope = CaseScope(case_id="c1")
        scope.add(parse_entry("8.8.8.8"))
        target = classify_target("8.8.8.8")
        assert in_scope(target, scope).allowed is True

    def test_cidr_includes_ip(self):
        scope = CaseScope(case_id="c1")
        scope.add(parse_entry("10.0.0.0/24"))
        target = classify_target("10.0.0.42")
        assert in_scope(target, scope).allowed is True

    def test_cidr_excludes_outside(self):
        scope = CaseScope(case_id="c1")
        scope.add(parse_entry("10.0.0.0/24"))
        target = classify_target("10.0.1.1")
        assert in_scope(target, scope).allowed is False

    def test_url_prefix(self):
        scope = CaseScope(case_id="c1")
        scope.add(parse_entry("https://example.com/api"))
        target = classify_target("https://example.com/api/users/42")
        assert in_scope(target, scope).allowed is True

    def test_handle_match(self):
        scope = CaseScope(case_id="c1")
        scope.add(parse_entry("@alice"))
        target = classify_target("@alice")
        assert in_scope(target, scope).allowed is True

    def test_decision_includes_matched_entry(self):
        scope = CaseScope(case_id="c1")
        scope.add(parse_entry("example.com"))
        target = classify_target("example.com")
        d = in_scope(target, scope)
        assert d.matched_entry is not None
        assert d.matched_entry.value == "example.com"


class TestAssertInScope:
    def test_passes_when_allowed(self):
        scope = CaseScope(case_id="c1")
        scope.add(parse_entry("example.com"))
        target = classify_target("example.com")
        assert_in_scope(target, scope)  # no exception

    def test_raises_when_denied(self):
        scope = CaseScope(case_id="c1")
        scope.add(parse_entry("example.com"))
        target = classify_target("other.net")
        with pytest.raises(OutOfScopeError):
            assert_in_scope(target, scope)


class TestAuditHelper:
    def test_allowed_event_name(self):
        scope = CaseScope(case_id="c1")
        scope.add(parse_entry("example.com"))
        target = classify_target("example.com")
        d = in_scope(target, scope)
        entry = audit_scope_attempt(actor="alice", case_id="c1", target=target, decision=d)
        assert entry["event"] == "scope_allowed"

    def test_denied_event_name(self):
        scope = CaseScope(case_id="c1")
        target = classify_target("example.com")
        d = in_scope(target, scope)
        entry = audit_scope_attempt(actor="alice", case_id="c1", target=target, decision=d)
        assert entry["event"] == "scope_denied"
        assert entry["payload"]["matched_entry"] is None


# ============================================================================
# tool_adapter
# ============================================================================

class TestRegistry:
    def test_subfinder_registered(self):
        assert get_adapter("subfinder") is not None

    def test_nuclei_registered(self):
        assert get_adapter("nuclei") is not None

    def test_amass_registered(self):
        assert get_adapter("amass") is not None

    def test_zap_baseline_registered(self):
        assert get_adapter("zap_baseline") is not None

    def test_list_returns_adapters(self):
        names = [a.name for a in list_adapters()]
        assert {"subfinder", "nuclei", "amass", "zap_baseline"}.issubset(set(names))


class TestAmassAdapter:
    def setup_method(self):
        self.adapter = AmassAdapter()

    def test_kind_passive(self):
        assert self.adapter.kind == KIND_PASSIVE_RECON

    def test_build_command_passive_default(self):
        target = classify_target("example.com")
        cmd = self.adapter.build_command(target, {})
        assert "enum" in cmd
        assert "-d" in cmd
        assert "example.com" in cmd
        assert "-passive" in cmd

    def test_build_command_active_when_opted_in(self):
        target = classify_target("example.com")
        cmd = self.adapter.build_command(target, {"active": True})
        assert "-passive" not in cmd
        assert "-d" in cmd

    def test_build_command_subdomain_uses_apex(self):
        target = classify_target("api.example.com")
        cmd = self.adapter.build_command(target, {})
        assert "example.com" in cmd

    def test_non_domain_empty_command(self):
        target = classify_target("@alice")
        cmd = self.adapter.build_command(target, {})
        assert cmd == []

    def test_parse_skips_log_lines(self):
        raw = (
            "INFO: starting enumeration\n"
            "api.example.com\n"
            "ERROR: something\n"
            "mail.example.com\n"
            "\n"
        )
        findings = self.adapter.parse_output(raw, classify_target("example.com"))
        values = sorted(f.value for f in findings)
        assert "api.example.com" in values
        assert "mail.example.com" in values
        assert all(f.kind == "subdomain" for f in findings)

    def test_parse_dedup(self):
        raw = "x.example.com\nx.example.com\ny.example.com\n"
        findings = self.adapter.parse_output(raw, classify_target("example.com"))
        assert sorted(f.value for f in findings) == ["x.example.com", "y.example.com"]


class TestZAPBaselineAdapter:
    def setup_method(self):
        self.adapter = ZAPBaselineAdapter()

    def test_kind_is_dast(self):
        assert self.adapter.kind == KIND_DAST

    def test_build_command_for_url(self):
        target = classify_target("https://example.com/")
        cmd = self.adapter.build_command(target, {})
        assert "-t" in cmd
        assert "https://example.com/" in cmd
        assert "-J" in cmd  # JSON report flag

    def test_build_command_for_domain_prefixes_https(self):
        target = classify_target("example.com")
        cmd = self.adapter.build_command(target, {})
        assert any("https://example.com" in c for c in cmd)

    def test_build_command_non_web_empty(self):
        target = classify_target("@alice")
        cmd = self.adapter.build_command(target, {})
        assert cmd == []

    def test_parse_warn_alert(self):
        raw = (
            "spider running...\n"
            "WARN-NEW: Content Security Policy header missing [10038] x 3\n"
            "FAIL-NEW: SQL Injection [40018] x 1\n"
        )
        findings = self.adapter.parse_output(raw, classify_target("https://acme.com/"))
        assert len(findings) == 2
        # WARN-NEW → medium, FAIL-NEW → high
        severities = sorted(f.severity for f in findings)
        assert severities == ["high", "medium"]

    def test_parse_ignores_unrelated(self):
        raw = "spider scan complete.\npassive rules ok.\n"
        findings = self.adapter.parse_output(raw, classify_target("https://acme.com/"))
        assert findings == []

    def test_detect_without_binary(self):
        with patch("shutil.which", return_value=None):
            status = self.adapter.detect()
        assert status.installed is False
        assert "non trovato" in status.error.lower()


class TestSubfinderAdapter:
    def setup_method(self):
        self.adapter = SubfinderAdapter()

    def test_build_command_for_domain(self):
        target = classify_target("example.com")
        cmd = self.adapter.build_command(target, {})
        assert "-d" in cmd
        assert "example.com" in cmd
        assert "-silent" in cmd

    def test_build_command_for_subdomain_uses_apex(self):
        target = classify_target("api.example.com")
        cmd = self.adapter.build_command(target, {})
        assert "example.com" in cmd  # apex, not the subdomain

    def test_build_command_for_non_domain_empty(self):
        target = classify_target("@alice")
        cmd = self.adapter.build_command(target, {})
        assert cmd == []

    def test_parse_output_extracts_unique_subdomains(self):
        raw = "api.example.com\nwww.example.com\napi.example.com\n\nstaging.example.com\n"
        target = classify_target("example.com")
        findings = self.adapter.parse_output(raw, target)
        values = sorted(f.value for f in findings)
        assert values == ["api.example.com", "staging.example.com", "www.example.com"]
        assert all(f.kind == "subdomain" for f in findings)

    def test_parse_output_handles_garbage(self):
        raw = "not a domain\nempty\n\n"
        findings = self.adapter.parse_output(raw, classify_target("example.com"))
        # Lines without "." are dropped.
        assert findings == []


class TestNucleiAdapter:
    def setup_method(self):
        self.adapter = NucleiAdapter()

    def test_build_command_for_url(self):
        target = classify_target("https://example.com/api")
        cmd = self.adapter.build_command(target, {})
        assert "-u" in cmd
        assert "https://example.com/api" in cmd
        assert "-json" in cmd

    def test_build_command_for_domain_prefixes_https(self):
        target = classify_target("example.com")
        cmd = self.adapter.build_command(target, {})
        assert "https://example.com" in cmd

    def test_parse_output_jsonl(self):
        raw = "\n".join([
            json.dumps({
                "template-id": "exposed-config",
                "info": {"name": "Exposed config file", "severity": "high",
                         "description": "Config file accessible.", "remediation": "Block public access."},
                "matched-at": "https://example.com/.env",
            }),
            "not json",
            json.dumps({
                "template-id": "xss",
                "info": {"name": "XSS", "severity": "medium"},
                "host": "https://example.com/search?q=",
            }),
        ])
        target = classify_target("https://example.com/")
        findings = self.adapter.parse_output(raw, target)
        assert len(findings) == 2
        severities = sorted(f.severity for f in findings)
        assert "high" in severities and "medium" in severities


class TestAdapterScopeEnforcement:
    def test_out_of_scope_blocks_execution(self):
        adapter = SubfinderAdapter()
        scope = CaseScope(case_id="c1")
        scope.add(parse_entry("authorized.com"))
        target = classify_target("evil.com")
        run = adapter.run(target, scope=scope)
        assert run.return_code is None
        assert "scope" in run.error.lower()

    def test_in_scope_proceeds(self):
        """In scope but binary missing — should fail at 'not installed', not at scope."""
        adapter = SubfinderAdapter()
        scope = CaseScope(case_id="c1")
        scope.add(parse_entry("example.com"))
        target = classify_target("example.com")
        with patch("shutil.which", return_value=None):
            run = adapter.run(target, scope=scope)
        assert "non installato" in run.error.lower() or "non trovato" in run.error.lower()


class TestAdapterDetect:
    def test_binary_not_found(self):
        adapter = SubfinderAdapter()
        with patch("shutil.which", return_value=None):
            status = adapter.detect()
        assert status.installed is False
        assert "non trovato" in status.error.lower()

    def test_binary_found_with_version(self):
        adapter = SubfinderAdapter()
        with patch("shutil.which", return_value="/usr/bin/subfinder"), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="subfinder v2.6.0\n", stderr="", returncode=0,
            )
            status = adapter.detect()
        assert status.installed is True
        assert "v2.6.0" in status.version
