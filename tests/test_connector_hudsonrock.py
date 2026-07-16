"""Test offline (nessuna rete) per il connettore hudsonrock (Hudson Rock
Cavalier — corpus breach infostealer): mocka ``_safe_http.open_url`` per
simulare le risposte JSON dell'API pubblica e valida la mappa di severity."""
import json
import unittest
from unittest.mock import patch

from osint_bot.connector import ConnectorContext
from osint_bot.connectors import build_default_registry


def _mock_open_url(payload: dict):
    """Simula il valore di ritorno di ``_safe_http.open_url``: (status, body, headers)."""
    return (200, json.dumps(payload).encode("utf-8"), {})


class HudsonRockConnectorTests(unittest.TestCase):
    def setUp(self):
        self.reg = build_default_registry()
        self.conns = getattr(self.reg, "_connectors", {})

    def _fetch(self, target, ttype):
        ctx = ConnectorContext(target=target, target_type=ttype, timeout=5, case_id="T")
        return self.conns["hudsonrock"]._fetch(ctx)

    def test_registered(self):
        self.assertIn("hudsonrock", self.conns)

    def test_empty_target_is_error(self):
        res = self._fetch("", "domain")
        self.assertEqual(res.status, "error")

    def test_domain_employees_10_is_critical(self):
        payload = {
            "total": 40, "employees": 15, "users": 20, "third_parties": 5,
            "data": {
                "employees_urls": [{"occurrence": 1, "type": "login", "url": "*****.example.com"}],
                "clients_urls": [],
                "stealer_families": [{"_key": "RedLine", "_value": 10}, {"_key": "Lumma", "_value": 5}],
            },
        }
        with patch("osint_bot._safe_http.open_url", return_value=_mock_open_url(payload)):
            res = self._fetch("example.com", "domain")
        self.assertEqual(res.status, "ok")
        self.assertEqual(len(res.findings), 1)
        f = res.findings[0]
        self.assertEqual(f.severity, "critical")
        self.assertEqual(f.kind, "breach_corpus_domain_critical")

    def test_domain_employees_3_is_high(self):
        payload = {
            "total": 10, "employees": 3, "users": 1, "third_parties": 0,
            "data": {"employees_urls": [], "clients_urls": [], "stealer_families": []},
        }
        with patch("osint_bot._safe_http.open_url", return_value=_mock_open_url(payload)):
            res = self._fetch("example.com", "domain")
        self.assertEqual(res.status, "ok")
        f = res.findings[0]
        self.assertEqual(f.severity, "high")
        self.assertEqual(f.kind, "breach_corpus_domain_high")

    def test_domain_employees_0_users_2_is_medium(self):
        payload = {
            "total": 2, "employees": 0, "users": 2, "third_parties": 0,
            "data": {"employees_urls": [], "clients_urls": [], "stealer_families": []},
        }
        with patch("osint_bot._safe_http.open_url", return_value=_mock_open_url(payload)):
            res = self._fetch("example.com", "domain")
        self.assertEqual(res.status, "ok")
        f = res.findings[0]
        self.assertEqual(f.severity, "medium")
        self.assertEqual(f.kind, "breach_corpus_domain_medium")

    def test_domain_total_0_has_no_negative_finding(self):
        payload = {"total": 0, "employees": 0, "users": 0, "third_parties": 0, "data": {}}
        with patch("osint_bot._safe_http.open_url", return_value=_mock_open_url(payload)):
            res = self._fetch("example.com", "domain")
        self.assertEqual(res.status, "ok")
        severities = [f.severity for f in res.findings]
        self.assertNotIn("critical", severities)
        self.assertNotIn("high", severities)
        self.assertNotIn("medium", severities)

    def test_email_found_is_high(self):
        payload = {"stealers": ["RedLine"], "message": ""}
        with patch("osint_bot._safe_http.open_url", return_value=_mock_open_url(payload)):
            res = self._fetch("user@example.com", "email")
        self.assertEqual(res.status, "ok")
        f = res.findings[0]
        self.assertEqual(f.severity, "high")
        self.assertEqual(f.kind, "breach_corpus_email_found")

    def test_email_not_found_has_no_negative_finding(self):
        payload = {"stealers": None, "message": "This email is not associated to any computer infected"}
        with patch("osint_bot._safe_http.open_url", return_value=_mock_open_url(payload)):
            res = self._fetch("user@example.com", "email")
        self.assertEqual(res.status, "ok")
        severities = [f.severity for f in res.findings]
        self.assertNotIn("high", severities)

    def test_email_target_type_auto_detected_from_at_sign(self):
        payload = {"stealers": ["Vidar"]}
        with patch("osint_bot._safe_http.open_url", return_value=_mock_open_url(payload)):
            res = self._fetch("user@example.com", "auto")
        self.assertEqual(res.status, "ok")
        self.assertEqual(res.findings[0].kind, "breach_corpus_email_found")

    def test_http_error_returns_error_status(self):
        with patch("osint_bot._safe_http.open_url", side_effect=Exception("HTTP 429: Too Many Requests")):
            res = self._fetch("example.com", "domain")
        self.assertEqual(res.status, "error")
        self.assertTrue(res.error)


if __name__ == "__main__":
    unittest.main()
