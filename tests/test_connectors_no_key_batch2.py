"""Offline tests (no network) for the three new no-key connectors added
alongside ConnectorSweepAgent: ripe_stat, hackertarget, wikipedia_search.
Mocks osint_bot._safe_http's GET helpers to simulate upstream responses."""
from __future__ import annotations

import unittest
from unittest.mock import patch

from osint_bot.connector import ConnectorContext
from osint_bot.connectors import build_default_registry


class RipeStatConnectorTests(unittest.TestCase):
    def setUp(self):
        self.reg = build_default_registry()
        self.conn = self.reg.get("ripe_stat")

    def test_registered_passive_ip(self):
        self.assertEqual(self.conn.spec.action_class, "passive")
        self.assertEqual(self.conn.spec.input_types, ("ip",))
        self.assertEqual(self.conn.spec.required_key, "")

    def test_invalid_ip_is_error(self):
        ctx = ConnectorContext(target="not-an-ip", target_type="ip", timeout=5)
        res = self.conn._fetch(ctx)
        self.assertEqual(res.status, "error")

    def test_valid_ip_extracts_prefix_asn_abuse(self):
        def fake_get_json(url, **kwargs):
            if "network-info" in url:
                return {"data": {"prefix": "8.8.8.0/24", "asns": [15169]}}
            if "abuse-contact-finder" in url:
                return {"data": {"abuse_contacts": ["abuse@google.com"]}}
            raise AssertionError(f"unexpected url {url}")

        with patch("osint_bot._safe_http.get_json", side_effect=fake_get_json):
            ctx = ConnectorContext(target="8.8.8.8", target_type="ip", timeout=5, lang="it")
            res = self.conn._fetch(ctx)

        self.assertEqual(res.status, "ok")
        kinds = {f.kind: f.value for f in res.findings}
        self.assertEqual(kinds.get("network_prefix"), "8.8.8.0/24")
        self.assertEqual(kinds.get("asn"), "AS15169")
        self.assertEqual(kinds.get("abuse_contact_email"), "abuse@google.com")

    def test_both_endpoints_failing_is_error(self):
        with patch("osint_bot._safe_http.get_json", side_effect=Exception("network down")):
            ctx = ConnectorContext(target="8.8.8.8", target_type="ip", timeout=5)
            res = self.conn._fetch(ctx)
        self.assertEqual(res.status, "error")


class HackerTargetConnectorTests(unittest.TestCase):
    def setUp(self):
        self.reg = build_default_registry()
        self.conn = self.reg.get("hackertarget")

    def test_registered_passive_ip(self):
        self.assertEqual(self.conn.spec.action_class, "passive")
        self.assertEqual(self.conn.spec.input_types, ("ip",))
        self.assertEqual(self.conn.spec.required_key, "")

    def test_invalid_ip_is_error(self):
        ctx = ConnectorContext(target="nope", target_type="ip", timeout=5)
        res = self.conn._fetch(ctx)
        self.assertEqual(res.status, "error")

    def test_cohosted_domains_extracted(self):
        with patch("osint_bot._safe_http.get_text", return_value="a.example.com\nb.example.com\n"):
            ctx = ConnectorContext(target="1.2.3.4", target_type="ip", timeout=5)
            res = self.conn._fetch(ctx)
        self.assertEqual(res.status, "ok")
        values = {f.value for f in res.findings}
        self.assertEqual(values, {"a.example.com", "b.example.com"})

    def test_api_error_marker_yields_zero_findings_not_a_bogus_host(self):
        with patch("osint_bot._safe_http.get_text", return_value="error check your search parameter"):
            ctx = ConnectorContext(target="1.2.3.4", target_type="ip", timeout=5)
            res = self.conn._fetch(ctx)
        self.assertEqual(res.status, "ok")
        self.assertEqual(res.findings, [])

    def test_rate_limit_marker_yields_zero_findings(self):
        with patch("osint_bot._safe_http.get_text", return_value="API count exceeded - Increase Quota"):
            ctx = ConnectorContext(target="1.2.3.4", target_type="ip", timeout=5)
            res = self.conn._fetch(ctx)
        self.assertEqual(res.status, "ok")
        self.assertEqual(res.findings, [])


class WikipediaSearchConnectorTests(unittest.TestCase):
    def setUp(self):
        self.reg = build_default_registry()
        self.conn = self.reg.get("wikipedia_search")

    def test_registered_passive_company_person(self):
        self.assertEqual(self.conn.spec.action_class, "passive")
        self.assertEqual(self.conn.spec.input_types, ("company", "person"))
        self.assertEqual(self.conn.spec.required_key, "")

    def test_empty_target_is_error(self):
        ctx = ConnectorContext(target="", target_type="company", timeout=5)
        res = self.conn._fetch(ctx)
        self.assertEqual(res.status, "error")

    def test_finds_article_in_primary_language(self):
        payload = {"pages": [{"title": "Example Corp", "key": "Example_Corp", "excerpt": "An example company"}]}
        with patch("osint_bot._safe_http.get_json", return_value=payload):
            ctx = ConnectorContext(target="Example Corp", target_type="company", timeout=5, lang="it")
            res = self.conn._fetch(ctx)
        self.assertEqual(res.status, "ok")
        self.assertEqual(len(res.findings), 1)
        self.assertEqual(res.findings[0].value, "Example Corp")
        self.assertIn("it.wikipedia.org", res.findings[0].evidence[0].url)

    def test_falls_back_to_second_language_when_primary_has_no_hits(self):
        calls = []

        def fake_get_json(url, **kwargs):
            calls.append(url)
            if "it.wikipedia.org" in url:
                return {"pages": []}
            return {"pages": [{"title": "Example Corp", "key": "Example_Corp", "excerpt": "..."}]}

        with patch("osint_bot._safe_http.get_json", side_effect=fake_get_json):
            ctx = ConnectorContext(target="Example Corp", target_type="company", timeout=5, lang="it")
            res = self.conn._fetch(ctx)

        self.assertEqual(res.status, "ok")
        self.assertEqual(len(res.findings), 1)
        self.assertIn("en.wikipedia.org", res.findings[0].evidence[0].url)
        self.assertEqual(len(calls), 2)  # tried it, then fell back to en

    def test_no_match_in_either_language_is_ok_with_no_findings(self):
        with patch("osint_bot._safe_http.get_json", return_value={"pages": []}):
            ctx = ConnectorContext(target="zzzznonexistent", target_type="person", timeout=5)
            res = self.conn._fetch(ctx)
        self.assertEqual(res.status, "ok")
        self.assertEqual(res.findings, [])


if __name__ == "__main__":
    unittest.main()
