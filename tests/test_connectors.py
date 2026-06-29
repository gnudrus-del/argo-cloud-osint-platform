"""Tests for Pillar 1 — Connector SDK and connector implementations.

All tests are offline: network calls are monkey-patched with golden fixture
payloads.  No external API keys are needed to run the suite.
"""
from __future__ import annotations

import json
import unittest
from unittest.mock import MagicMock, patch

from osint_bot.connector import (
    ACTION_PASSIVE,
    BaseConnector,
    ConnectorContext,
    ConnectorRegistry,
    ConnectorResult,
    ConnectorSpec,
    RateLimit,
)
from osint_bot.connectors.crt_sh import CrtShConnector
from osint_bot.connectors.rdap import RdapConnector
from osint_bot.connectors.shodan import ShodanConnector

# ---------------------------------------------------------------------------
# Golden fixtures
# ---------------------------------------------------------------------------

CRT_SH_FIXTURE = json.dumps([
    {"issuer_ca_id": 1, "name_value": "api.example.com\nwww.example.com", "not_before": "2024-01-01"},
    {"issuer_ca_id": 2, "name_value": "*.example.com\nmail.example.com", "not_before": "2024-06-01"},
])

RDAP_FIXTURE = json.dumps({
    "handle": "EXAMPLE123",
    "ldhName": "example.com",
    "status": ["active"],
    "nameservers": [{"ldhName": "ns1.example.com"}, {"ldhName": "ns2.example.com"}],
    "entities": [
        {
            "roles": ["registrar"],
            "vcardArray": ["vcard", [
                ["version", {}, "text", "4.0"],
                ["fn", {}, "text", "Example Registrar Inc."],
            ]],
        }
    ],
    "events": [
        {"eventAction": "registration", "eventDate": "2000-01-01T00:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"},
    ],
})

SHODAN_FIXTURE = json.dumps({
    "ip_str": "93.184.216.34",
    "ports": [80, 443],
    "hostnames": ["example.com"],
    "country_code": "US",
    "org": "EDGECAST",
    "isp": "MCI Communications Services",
    "asn": "AS15133",
    "os": None,
    "last_update": "2024-06-01T00:00:00Z",
    "data": [
        {
            "port": 80,
            "transport": "tcp",
            "product": "Apache",
            "version": "2.4.51",
            "cpe": ["cpe:/a:apache:http_server:2.4.51"],
            "vulns": {"CVE-2021-41773": {"cvss": 7.5}},
        },
        {
            "port": 443,
            "transport": "tcp",
            "product": "Apache",
            "version": "2.4.51",
            "cpe": [],
            "vulns": {},
        },
    ],
})


def _mock_urlopen(fixture: str):
    """Return a context manager whose read() yields *fixture* bytes."""
    mock_resp = MagicMock()
    mock_resp.read.return_value = fixture.encode("utf-8")
    mock_resp.status = 200
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


def _ctx(target: str = "example.com", target_type: str = "domain",
         api_key: str = "") -> ConnectorContext:
    return ConnectorContext(
        target=target,
        target_type=target_type,
        actor="analyst",
        case_id="case-test",
        api_key=api_key,
    )


# ---------------------------------------------------------------------------
# SDK unit tests
# ---------------------------------------------------------------------------

class RegistryTests(unittest.TestCase):
    def _make_dummy(self) -> BaseConnector:
        class Dummy(BaseConnector):
            spec = ConnectorSpec(
                name="dummy",
                label="Dummy",
                action_class=ACTION_PASSIVE,
                input_types=("domain",),
                output_categories=("network_identifiers",),
                required_key="",
                cache_ttl=0,
                rate_limit=RateLimit(per_minute=100),
            )
            def _fetch(self, context):
                return ConnectorResult(connector="dummy", status="ok",
                                       findings=[], raw={"hit": True})
        return Dummy()

    def test_register_and_run(self):
        reg = ConnectorRegistry()
        reg.register(self._make_dummy())
        result = reg.run("dummy", _ctx())
        self.assertEqual(result.status, "ok")

    def test_run_unknown_returns_missing(self):
        reg = ConnectorRegistry()
        result = reg.run("nonexistent", _ctx())
        self.assertEqual(result.status, "missing")

    def test_by_input_type_filters_correctly(self):
        reg = ConnectorRegistry()
        reg.register(self._make_dummy())
        names = reg.by_input_type("domain")
        self.assertIn("dummy", names)
        names_ip = reg.by_input_type("ip")
        self.assertNotIn("dummy", names_ip)

    def test_duplicate_registration_raises(self):
        reg = ConnectorRegistry()
        reg.register(self._make_dummy())
        with self.assertRaises(ValueError):
            reg.register(self._make_dummy())

    def test_catalog_includes_required_fields(self):
        reg = ConnectorRegistry()
        reg.register(self._make_dummy())
        entries = reg.catalog()
        self.assertEqual(len(entries), 1)
        for key in ("name", "label", "action_class", "input_types",
                    "output_categories", "required_key", "cache_ttl"):
            self.assertIn(key, entries[0])


class RateLimitTests(unittest.TestCase):
    def test_rate_limit_blocks_excess_calls(self):
        class Counting(BaseConnector):
            calls = 0
            spec = ConnectorSpec(
                name="counting",
                label="Counting",
                action_class=ACTION_PASSIVE,
                input_types=("domain",),
                output_categories=(),
                required_key="",
                cache_ttl=0,
                rate_limit=RateLimit(per_minute=3, per_day=1000),
            )
            def _fetch(self, ctx):
                Counting.calls += 1
                return ConnectorResult(connector="counting", status="ok")

        connector = Counting()
        ctx = _ctx()
        for _ in range(3):
            connector.run(ctx)
        # 4th call must be rate-limited
        result = connector.run(ctx)
        self.assertEqual(result.status, "rate_limited")
        self.assertEqual(Counting.calls, 3)


class CacheTests(unittest.TestCase):
    def test_second_call_is_cached(self):
        class Once(BaseConnector):
            calls = 0
            spec = ConnectorSpec(
                name="once",
                label="Once",
                action_class=ACTION_PASSIVE,
                input_types=("domain",),
                output_categories=(),
                required_key="",
                cache_ttl=300,
                rate_limit=RateLimit(per_minute=100),
            )
            def _fetch(self, ctx):
                Once.calls += 1
                return ConnectorResult(connector="once", status="ok")

        conn = Once()
        ctx = _ctx()
        conn.run(ctx)
        conn.run(ctx)
        self.assertEqual(Once.calls, 1)
        result = conn.run(ctx)
        self.assertEqual(result.status, "cached")
        self.assertTrue(result.cached)


class MissingKeyTests(unittest.TestCase):
    def test_missing_key_returns_missing_key_status(self):
        shodan = ShodanConnector()
        # No api_key provided
        result = shodan.run(_ctx(api_key=""))
        self.assertEqual(result.status, "missing_key")
        self.assertIn("Chiavi API", result.error)


class ProvenanceTests(unittest.TestCase):
    def test_provenance_stamped_on_findings_when_case_set(self):
        with patch("urllib.request.urlopen") as mock_open:
            mock_open.return_value = _mock_urlopen(CRT_SH_FIXTURE)
            conn = CrtShConnector()
            ctx = _ctx()
            ctx.case_id = "case-test"
            result = conn.run(ctx)

        self.assertIsNotNone(result.provenance)
        self.assertEqual(result.provenance.case_id, "case-test")
        for finding in result.findings:
            self.assertIsNotNone(finding.provenance)
            self.assertEqual(finding.provenance.tool, "crt_sh")

    def test_no_provenance_when_no_case(self):
        with patch("urllib.request.urlopen") as mock_open:
            mock_open.return_value = _mock_urlopen(CRT_SH_FIXTURE)
            conn = CrtShConnector()
            ctx = _ctx()
            ctx.case_id = ""
            result = conn.run(ctx)

        self.assertIsNone(result.provenance)
        for finding in result.findings:
            self.assertIsNone(finding.provenance)


# ---------------------------------------------------------------------------
# crt_sh connector
# ---------------------------------------------------------------------------

class CrtShTests(unittest.TestCase):
    def test_spec_is_passive(self):
        self.assertEqual(CrtShConnector.spec.action_class, ACTION_PASSIVE)
        self.assertIn("domain", CrtShConnector.spec.input_types)

    def test_extracts_subdomains_skips_wildcards(self):
        with patch("urllib.request.urlopen") as mock_open:
            mock_open.return_value = _mock_urlopen(CRT_SH_FIXTURE)
            result = CrtShConnector().run(_ctx())

        self.assertEqual(result.status, "ok")
        values = [f.value for f in result.findings]
        # Must include the concrete subdomains
        self.assertIn("api.example.com", values)
        self.assertIn("www.example.com", values)
        self.assertIn("mail.example.com", values)
        # Must NOT include the wildcard
        self.assertNotIn("*.example.com", values)

    def test_all_findings_are_subdomain_ct_kind(self):
        with patch("urllib.request.urlopen") as mock_open:
            mock_open.return_value = _mock_urlopen(CRT_SH_FIXTURE)
            result = CrtShConnector().run(_ctx())

        for f in result.findings:
            self.assertEqual(f.kind, "subdomain_ct")

    def test_deduplication(self):
        # Same name appearing twice in two entries must produce one finding.
        fixture = json.dumps([
            {"issuer_ca_id": 1, "name_value": "sub.example.com", "not_before": "2024-01-01"},
            {"issuer_ca_id": 2, "name_value": "sub.example.com", "not_before": "2024-06-01"},
        ])
        with patch("urllib.request.urlopen") as mock_open:
            mock_open.return_value = _mock_urlopen(fixture)
            result = CrtShConnector().run(_ctx())

        self.assertEqual(len(result.findings), 1)

    def test_error_on_bad_response(self):
        with patch("urllib.request.urlopen") as mock_open:
            mock_open.return_value = _mock_urlopen('{"error": "not json list"}')
            result = CrtShConnector().run(_ctx())

        self.assertEqual(result.status, "error")


# ---------------------------------------------------------------------------
# RDAP connector
# ---------------------------------------------------------------------------

class RdapTests(unittest.TestCase):
    def test_spec_is_passive(self):
        self.assertEqual(RdapConnector.spec.action_class, ACTION_PASSIVE)
        self.assertIn("domain", RdapConnector.spec.input_types)

    def test_extracts_registrar_nameservers_dates(self):
        with patch("urllib.request.urlopen") as mock_open:
            mock_open.return_value = _mock_urlopen(RDAP_FIXTURE)
            result = RdapConnector().run(_ctx())

        self.assertEqual(result.status, "ok")
        kinds = {f.kind for f in result.findings}
        self.assertIn("whois_registrar", kinds)
        self.assertIn("whois_nameserver", kinds)
        self.assertIn("whois_created", kinds)
        self.assertIn("whois_expiry", kinds)
        self.assertIn("whois_status", kinds)

    def test_registrar_name_is_correct(self):
        with patch("urllib.request.urlopen") as mock_open:
            mock_open.return_value = _mock_urlopen(RDAP_FIXTURE)
            result = RdapConnector().run(_ctx())

        registrars = [f.value for f in result.findings if f.kind == "whois_registrar"]
        self.assertIn("Example Registrar Inc.", registrars)

    def test_two_nameservers_found(self):
        with patch("urllib.request.urlopen") as mock_open:
            mock_open.return_value = _mock_urlopen(RDAP_FIXTURE)
            result = RdapConnector().run(_ctx())

        ns = [f.value for f in result.findings if f.kind == "whois_nameserver"]
        self.assertEqual(set(ns), {"ns1.example.com", "ns2.example.com"})


# ---------------------------------------------------------------------------
# Shodan connector
# ---------------------------------------------------------------------------

class ShodanTests(unittest.TestCase):
    def test_spec_is_passive(self):
        self.assertEqual(ShodanConnector.spec.action_class, ACTION_PASSIVE)
        self.assertIn("ip", ShodanConnector.spec.input_types)
        self.assertIn("domain", ShodanConnector.spec.input_types)

    def test_extracts_ports_cpes_vulns_hostname(self):
        with patch("urllib.request.urlopen") as mock_open:
            mock_open.return_value = _mock_urlopen(SHODAN_FIXTURE)
            with patch("socket.getaddrinfo", return_value=[(None, None, None, None, ("93.184.216.34", 0))]):
                result = ShodanConnector().run(_ctx(api_key="TESTKEY"))

        self.assertEqual(result.status, "ok")
        kinds = {f.kind for f in result.findings}
        self.assertIn("shodan_open_port", kinds)
        self.assertIn("shodan_cpe", kinds)
        self.assertIn("shodan_vuln", kinds)
        self.assertIn("shodan_hostname", kinds)

    def test_port_values_correct(self):
        with patch("urllib.request.urlopen") as mock_open:
            mock_open.return_value = _mock_urlopen(SHODAN_FIXTURE)
            with patch("socket.getaddrinfo", return_value=[(None, None, None, None, ("93.184.216.34", 0))]):
                result = ShodanConnector().run(_ctx(api_key="TESTKEY"))

        ports = [f.value for f in result.findings if f.kind == "shodan_open_port"]
        self.assertIn("93.184.216.34:80/tcp", ports)
        self.assertIn("93.184.216.34:443/tcp", ports)

    def test_cve_finding(self):
        with patch("urllib.request.urlopen") as mock_open:
            mock_open.return_value = _mock_urlopen(SHODAN_FIXTURE)
            with patch("socket.getaddrinfo", return_value=[(None, None, None, None, ("93.184.216.34", 0))]):
                result = ShodanConnector().run(_ctx(api_key="TESTKEY"))

        vulns = [f.value for f in result.findings if f.kind == "shodan_vuln"]
        self.assertIn("CVE-2021-41773", vulns)

    def test_ip_directly_without_dns_resolve(self):
        with patch("urllib.request.urlopen") as mock_open:
            mock_open.return_value = _mock_urlopen(SHODAN_FIXTURE)
            result = ShodanConnector().run(_ctx(
                target="93.184.216.34", target_type="ip", api_key="TESTKEY"
            ))

        self.assertEqual(result.status, "ok")


if __name__ == "__main__":
    unittest.main()
