"""Tests for Pillar 3 — defensive.py."""
from __future__ import annotations

import unittest

from osint_bot.defensive import (
    TakedownCase,
    assess_brand_impersonation,
    enrich_ioc,
    monitor_surface,
    score_digital_footprint,
)
from osint_bot.models import Finding

# ---------------------------------------------------------------------------
# monitor_surface
# ---------------------------------------------------------------------------

def _f(kind: str, value: str, severity: str = "medium") -> Finding:
    return Finding(kind=kind, value=value, confidence=0.7, severity=severity)


class MonitorSurfaceTests(unittest.TestCase):
    def test_new_exposure_detected(self):
        baseline = [_f("subdomain_ct", "old.example.com")]
        current = [_f("subdomain_ct", "old.example.com"),
                   _f("shodan_open_port", "1.2.3.4:22/tcp", "high")]
        report = monitor_surface("example.com", baseline, current)
        self.assertEqual(len(report.new_exposures), 1)
        self.assertEqual(report.new_exposures[0].kind, "shodan_open_port")

    def test_resolved_exposure_detected(self):
        baseline = [_f("shodan_vuln", "CVE-2021-41773", "high"),
                    _f("subdomain_ct", "api.example.com")]
        current = [_f("subdomain_ct", "api.example.com")]
        report = monitor_surface("example.com", baseline, current)
        self.assertEqual(len(report.resolved_exposures), 1)

    def test_risk_delta_positive_on_new_critical(self):
        report = monitor_surface(
            "example.com",
            [],
            [_f("red_team_aws_access_key", "AKIAIOSFODNN7EXAMPLE", "critical")],
        )
        self.assertGreater(report.risk_delta, 0)

    def test_risk_delta_negative_on_all_resolved(self):
        baseline = [_f("shodan_vuln", "CVE-2021-44228", "critical")]
        report = monitor_surface("example.com", baseline, [])
        self.assertLess(report.risk_delta, 0)

    def test_no_change_produces_empty_lists(self):
        f = _f("subdomain_ct", "api.example.com")
        report = monitor_surface("example.com", [f], [f])
        self.assertEqual(report.new_exposures, [])
        self.assertEqual(report.resolved_exposures, [])

    def test_summary_reports_new_count(self):
        report = monitor_surface(
            "example.com",
            [],
            [_f("shodan_open_port", "1.2.3.4:80/tcp")],
        )
        self.assertIn("+1", report.summary())

    def test_summary_no_change(self):
        report = monitor_surface("example.com", [], [])
        self.assertIn("Nessuna variazione", report.summary())

    def test_checked_at_is_iso(self):
        report = monitor_surface("example.com", [], [])
        # Must not raise ValueError
        from datetime import datetime
        datetime.fromisoformat(report.checked_at.replace("Z", "+00:00"))


# ---------------------------------------------------------------------------
# assess_brand_impersonation
# ---------------------------------------------------------------------------

class BrandImpersonationTests(unittest.TestCase):
    def test_typosquat_detected(self):
        signals = assess_brand_impersonation("acme", ["acme-login.com"], [])
        self.assertTrue(signals)
        self.assertEqual(signals[0].kind, "typosquat")
        self.assertGreaterEqual(signals[0].similarity, 0.70)

    def test_exact_match_excluded(self):
        # acme.com is the brand — should NOT produce a signal for itself
        signals = assess_brand_impersonation("acme", ["acme.com"], [])
        exact = [s for s in signals if s.value == "acme.com" and s.similarity == 1.0]
        self.assertEqual(exact, [])

    def test_lookalike_handle_detected(self):
        signals = assess_brand_impersonation("acme", [], ["@acme_official"])
        self.assertTrue(signals)
        self.assertEqual(signals[0].kind, "lookalike_handle")

    def test_sorted_by_similarity_descending(self):
        domains = ["acme-login.com", "acmee.com", "acme.xyz"]
        signals = assess_brand_impersonation("acme", domains, [])
        sims = [s.similarity for s in signals]
        self.assertEqual(sims, sorted(sims, reverse=True))

    def test_unrelated_domain_excluded(self):
        signals = assess_brand_impersonation("acme", ["totallyunrelated.com"], [])
        self.assertEqual(signals, [])

    def test_to_finding_produces_valid_finding(self):
        signals = assess_brand_impersonation("acme", ["acme-secure.com"], [])
        self.assertTrue(signals)
        f = signals[0].to_finding()
        self.assertIn("brand_", f.kind)
        self.assertTrue(f.severity)
        self.assertTrue(f.attck_ttps)

    def test_tld_swap_high_similarity(self):
        signals = assess_brand_impersonation("acme", ["acme.io", "acme.xyz"], [])
        tld_swaps = [s for s in signals if s.technique == "tld_swap"]
        self.assertTrue(tld_swaps)
        self.assertGreaterEqual(tld_swaps[0].similarity, 0.90)


# ---------------------------------------------------------------------------
# enrich_ioc
# ---------------------------------------------------------------------------

class IOCEnrichmentTests(unittest.TestCase):
    def test_ipv4_detected(self):
        result = enrich_ioc("1.2.3.4")
        self.assertEqual(result.ioc_type, "ipv4")
        self.assertTrue(result.hunt_queries)

    def test_sha256_detected(self):
        sha = "a" * 64
        result = enrich_ioc(sha)
        self.assertEqual(result.ioc_type, "sha256")

    def test_domain_detected(self):
        result = enrich_ioc("evil.example.com")
        self.assertEqual(result.ioc_type, "domain")

    def test_url_detected(self):
        result = enrich_ioc("https://malicious.example.com/payload")
        self.assertEqual(result.ioc_type, "url")

    def test_cve_detected(self):
        result = enrich_ioc("CVE-2021-41773")
        self.assertEqual(result.ioc_type, "cve")

    def test_attck_ttps_not_empty(self):
        for ioc, expected_type in [
            ("1.2.3.4", "ipv4"), ("evil.example.com", "domain"),
            ("a" * 32, "md5"), ("https://x.com/p", "url"),
        ]:
            result = enrich_ioc(ioc)
            self.assertTrue(result.attck_ttps, msg=f"No TTPs for {ioc!r} ({expected_type})")

    def test_explicit_type_override(self):
        result = enrich_ioc("not-an-ip", ioc_type="ipv4")
        self.assertEqual(result.ioc_type, "ipv4")

    def test_unknown_ioc_lower_confidence(self):
        result = enrich_ioc("random-junk-!@#$")
        self.assertEqual(result.ioc_type, "unknown")
        self.assertLess(result.confidence, 0.6)

    def test_to_finding_produces_valid_finding(self):
        result = enrich_ioc("1.2.3.4")
        f = result.to_finding()
        self.assertEqual(f.kind, "ioc_ipv4")
        self.assertEqual(f.value, "1.2.3.4")
        self.assertTrue(f.attck_ttps)


# ---------------------------------------------------------------------------
# TakedownCase
# ---------------------------------------------------------------------------

class TakedownCaseTests(unittest.TestCase):
    def _case(self) -> TakedownCase:
        return TakedownCase(
            id="tc-001",
            kind="phishing",
            target_url="https://phishing.example.com/login",
            brand="ExampleCorp",
        )

    def test_default_status_is_draft(self):
        self.assertEqual(self._case().status, "draft")

    def test_advance_changes_status(self):
        tc = self._case()
        tc.advance("evidence_collected", "Screenshot archived")
        self.assertEqual(tc.status, "evidence_collected")

    def test_advance_appends_note(self):
        tc = self._case()
        tc.advance("evidence_collected", "Screenshot archived")
        self.assertTrue(any("Screenshot" in n for n in tc.notes))

    def test_invalid_status_raises(self):
        tc = self._case()
        with self.assertRaises(ValueError):
            tc.advance("imaginary_status")

    def test_contact_for_known_platform(self):
        tc = self._case()
        contact = tc.contact_for("cloudflare.com")
        self.assertIn("name", contact)

    def test_contact_for_unknown_platform_returns_empty(self):
        tc = self._case()
        self.assertEqual(tc.contact_for("unknown-registrar.zzz"), {})

    def test_to_dict_includes_required_keys(self):
        tc = self._case()
        d = tc.to_dict()
        for key in ("id", "kind", "target_url", "brand", "status", "created_at"):
            self.assertIn(key, d)

    def test_created_at_auto_set(self):
        tc = self._case()
        self.assertTrue(tc.created_at)


# ---------------------------------------------------------------------------
# score_digital_footprint
# ---------------------------------------------------------------------------

class FootprintScoringTests(unittest.TestCase):
    def test_clean_surface_scores_100(self):
        result = score_digital_footprint([])
        self.assertEqual(result["score"], 100)

    def test_aws_key_lowers_score_significantly(self):
        f = Finding(kind="red_team_aws_access_key", value="AKIA...", confidence=0.9,
                    severity="critical")
        result = score_digital_footprint([f])
        self.assertLess(result["score"], 30)

    def test_risk_level_critical_below_20(self):
        findings = [
            Finding(kind="red_team_aws_access_key", value="k", confidence=0.9, severity="critical"),
            Finding(kind="red_team_private_key_header", value="k", confidence=0.9, severity="critical"),
            Finding(kind="red_team_connection_string", value="k", confidence=0.9, severity="critical"),
        ]
        result = score_digital_footprint(findings)
        self.assertLessEqual(result["score"], 20)
        self.assertEqual(result["risk_level"], "critical")

    def test_info_severity_finding_minimal_penalty(self):
        f = Finding(kind="subdomain_ct", value="sub.example.com", confidence=0.8, severity="info")
        result = score_digital_footprint([f])
        self.assertGreaterEqual(result["score"], 99)

    def test_breakdown_included(self):
        f = Finding(kind="shodan_vuln", value="CVE-x", confidence=0.7, severity="high")
        result = score_digital_footprint([f])
        self.assertIn("shodan_vuln", result["breakdown"])

    def test_finding_count_correct(self):
        findings = [_f("subdomain_ct", f"sub{i}.example.com") for i in range(5)]
        result = score_digital_footprint(findings)
        self.assertEqual(result["finding_count"], 5)


if __name__ == "__main__":
    unittest.main()
