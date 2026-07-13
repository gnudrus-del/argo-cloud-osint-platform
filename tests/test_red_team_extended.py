"""Tests for Pillar 2 — red_team.py: TAKEOVER_DB, credential exposure, diff."""
from __future__ import annotations

import unittest

from osint_bot.models import Evidence, Finding, Page, SearchResult
from osint_bot.red_team import (
    TAKEOVER_DB,
    TakeoverVendor,
    assess_takeover_candidates,
    diff_scan_findings,
    scan_credential_exposure,
)

# ---------------------------------------------------------------------------
# TAKEOVER_DB structure tests
# ---------------------------------------------------------------------------

class TakeoverDBTests(unittest.TestCase):
    def test_db_has_entries(self):
        self.assertGreater(len(TAKEOVER_DB), 20)

    def test_all_entries_are_takeover_vendor(self):
        for suffix, vendor in TAKEOVER_DB.items():
            self.assertIsInstance(vendor, TakeoverVendor, msg=f"Bad entry for {suffix}")

    def test_severity_values_are_valid(self):
        valid = {"info", "low", "medium", "high", "critical"}
        for suffix, vendor in TAKEOVER_DB.items():
            self.assertIn(vendor.severity, valid, msg=f"Invalid severity for {suffix}")

    def test_attck_ttps_not_empty(self):
        for suffix, vendor in TAKEOVER_DB.items():
            self.assertTrue(vendor.attck_ttps, msg=f"No ATT&CK TTPs for {suffix}")

    def test_remediation_not_empty(self):
        for suffix, vendor in TAKEOVER_DB.items():
            self.assertTrue(vendor.remediation.strip(), msg=f"No remediation for {suffix}")

    def test_s3_is_critical(self):
        self.assertEqual(TAKEOVER_DB["s3.amazonaws.com"].severity, "critical")

    def test_github_io_is_high(self):
        self.assertEqual(TAKEOVER_DB["github.io"].severity, "high")


# ---------------------------------------------------------------------------
# assess_takeover_candidates
# ---------------------------------------------------------------------------

class AssessTakeoverTests(unittest.TestCase):
    def _ev(self, url: str = "https://example.com") -> list[Evidence]:
        return [Evidence(url=url, title="Test page")]

    def test_known_vendor_produces_enriched_finding(self):
        hosts = {"blog-example.github.io": self._ev()}
        findings = assess_takeover_candidates(hosts)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.kind, "red_team_takeover_candidate")
        self.assertEqual(f.value, "blog-example.github.io")
        self.assertEqual(f.severity, "high")
        self.assertIn("T1584.001", f.attck_ttps)
        self.assertTrue(f.remediation)

    def test_unknown_vendor_produces_low_finding(self):
        hosts = {"sub.unknown-vendor.xyz": self._ev()}
        findings = assess_takeover_candidates(hosts)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "low")

    def test_s3_produces_critical(self):
        hosts = {"assets.s3.amazonaws.com": self._ev()}
        findings = assess_takeover_candidates(hosts)
        self.assertEqual(findings[0].severity, "critical")

    def test_multiple_hosts_produce_multiple_findings(self):
        hosts = {
            "blog.github.io": self._ev(),
            "shop.myshopify.com": self._ev(),
        }
        findings = assess_takeover_candidates(hosts)
        self.assertEqual(len(findings), 2)

    def test_evidence_truncated_to_three(self):
        evs = [Evidence(url=f"https://example.com/{i}", title="p") for i in range(10)]
        hosts = {"sub.netlify.app": evs}
        findings = assess_takeover_candidates(hosts)
        self.assertLessEqual(len(findings[0].evidence), 3)

    def test_empty_input_returns_empty_list(self):
        self.assertEqual(assess_takeover_candidates({}), [])


# ---------------------------------------------------------------------------
# scan_credential_exposure
# ---------------------------------------------------------------------------

class CredentialExposureTests(unittest.TestCase):
    def _page(self, text: str, url: str = "https://example.com/page") -> Page:
        return Page(url=url, status=200, title="Test", text=text)

    def _sr(self, snippet: str, url: str = "https://results.com/r") -> SearchResult:
        return SearchResult(title="Result", url=url, snippet=snippet)

    def test_aws_access_key_in_page(self):
        page = self._page("config: AKIAIOSFODNN7EXAMPLE")
        findings = scan_credential_exposure("example.com", [page], [])
        kinds = {f.kind for f in findings}
        self.assertIn("red_team_aws_access_key", kinds)

    def test_private_key_header_in_page(self):
        page = self._page("-----BEGIN RSA PRIVATE KEY-----\nMIIE...")
        findings = scan_credential_exposure("example.com", [page], [])
        kinds = {f.kind for f in findings}
        self.assertIn("red_team_private_key_header", kinds)

    def test_connection_string_in_page(self):
        page = self._page("mongodb://user:password123@db.example.com:27017/prod")
        findings = scan_credential_exposure("example.com", [page], [])
        kinds = {f.kind for f in findings}
        self.assertIn("red_team_connection_string", kinds)

    def test_github_token_in_page(self):
        token = "ghp_" + "a" * 36
        page = self._page(f"TOKEN={token}")
        findings = scan_credential_exposure("example.com", [page], [])
        kinds = {f.kind for f in findings}
        self.assertIn("red_team_github_token", kinds)

    def test_aws_key_in_search_snippet(self):
        sr = self._sr("aws_access_key = AKIAIOSFODNN7EXAMPLE in config.py")
        findings = scan_credential_exposure("example.com", [], [sr])
        kinds = {f.kind for f in findings}
        self.assertIn("red_team_aws_access_key", kinds)

    def test_breach_mention_in_search_result(self):
        sr = self._sr("example.com found in breach database on haveibeenpwned")
        findings = scan_credential_exposure("example.com", [], [sr])
        kinds = {f.kind for f in findings}
        self.assertIn("red_team_breach_mention", kinds)

    def test_breach_mention_confidence_lower_than_key(self):
        sr_breach = self._sr("example.com pastebin leaked", "https://r.com/1")
        sr_key = self._sr("AKIAIOSFODNN7EXAMPLE in config", "https://r.com/2")
        findings = scan_credential_exposure("example.com", [], [sr_breach, sr_key])
        breach = next(f for f in findings if f.kind == "red_team_breach_mention")
        key = next(f for f in findings if f.kind == "red_team_aws_access_key")
        self.assertLess(breach.confidence, key.confidence)

    def test_deduplication_across_pages(self):
        key = "AKIAIOSFODNN7EXAMPLE"
        pages = [self._page(key, f"https://example.com/{i}") for i in range(3)]
        findings = scan_credential_exposure("example.com", pages, [])
        aws_findings = [f for f in findings if f.kind == "red_team_aws_access_key"]
        self.assertEqual(len(aws_findings), 1)

    def test_error_page_skipped(self):
        page = Page(url="https://x.com", status=0, title="", text="AKIAIOSFODNN7EXAMPLE",
                    error="timeout")
        findings = scan_credential_exposure("x.com", [page], [])
        self.assertEqual(findings, [])

    def test_all_findings_have_severity_and_ttps(self):
        page = self._page("mongodb://u:pass@db.example.com/prod AKIAIOSFODNN7EXAMPLE")
        findings = scan_credential_exposure("example.com", [page], [])
        for f in findings:
            self.assertTrue(f.severity, msg=f"{f.kind} has no severity")
            self.assertTrue(f.attck_ttps, msg=f"{f.kind} has no ATT&CK TTPs")

    def test_clean_page_returns_empty(self):
        page = self._page("Hello world, this is a benign page about cats.")
        findings = scan_credential_exposure("example.com", [page], [])
        self.assertEqual(findings, [])


# ---------------------------------------------------------------------------
# diff_scan_findings
# ---------------------------------------------------------------------------

class DiffScanTests(unittest.TestCase):
    def _f(self, kind: str, value: str) -> Finding:
        return Finding(kind=kind, value=value, confidence=0.5)

    def test_all_new_when_empty_baseline(self):
        current = [self._f("subdomain_ct", "api.example.com")]
        diff = diff_scan_findings([], current)
        self.assertEqual(len(diff.new_findings), 1)
        self.assertEqual(len(diff.removed_findings), 0)

    def test_all_removed_when_empty_current(self):
        baseline = [self._f("subdomain_ct", "api.example.com")]
        diff = diff_scan_findings(baseline, [])
        self.assertEqual(len(diff.removed_findings), 1)
        self.assertEqual(len(diff.new_findings), 0)

    def test_unchanged_when_identical(self):
        f = self._f("subdomain_ct", "api.example.com")
        diff = diff_scan_findings([f], [f])
        self.assertEqual(len(diff.unchanged_findings), 1)
        self.assertEqual(len(diff.new_findings), 0)
        self.assertEqual(len(diff.removed_findings), 0)

    def test_has_changes_flag(self):
        f1 = self._f("a", "x")
        f2 = self._f("b", "y")
        diff = diff_scan_findings([f1], [f2])
        self.assertTrue(diff.has_changes)

    def test_no_change_flag_when_equal(self):
        f = self._f("a", "x")
        diff = diff_scan_findings([f], [f])
        self.assertFalse(diff.has_changes)

    def test_case_insensitive_dedup(self):
        baseline = [self._f("subdomain_ct", "API.EXAMPLE.COM")]
        current = [self._f("subdomain_ct", "api.example.com")]
        diff = diff_scan_findings(baseline, current)
        self.assertEqual(len(diff.unchanged_findings), 1)
        self.assertFalse(diff.has_changes)

    def test_confidence_change_is_not_a_diff(self):
        f1 = Finding(kind="x", value="y", confidence=0.3)
        f2 = Finding(kind="x", value="y", confidence=0.9)
        diff = diff_scan_findings([f1], [f2])
        self.assertFalse(diff.has_changes)

    def test_summary_reports_counts(self):
        f1 = self._f("a", "x")
        f2 = self._f("b", "y")
        diff = diff_scan_findings([f1], [f2])
        summary = diff.summary()
        self.assertIn("1 nuovi", summary)
        self.assertIn("1 spariti", summary)

    def test_summary_no_changes(self):
        diff = diff_scan_findings([], [])
        self.assertIn("Nessuna variazione", diff.summary())


if __name__ == "__main__":
    unittest.main()
