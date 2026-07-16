"""Test offline (nessuna rete) per il connettore contactout (BYOK,
LinkedIn/email -> email/telefono personali): mocka ``_safe_http.open_url``
per simulare le risposte JSON dell'API e valida l'estrazione difensiva."""
import json
import unittest
from unittest.mock import patch

from osint_bot.connector import ConnectorContext
from osint_bot.connectors import build_default_registry


def _mock_open_url(payload: dict, status: int = 200):
    return (status, json.dumps(payload).encode("utf-8"), {})


class ContactOutConnectorTests(unittest.TestCase):
    def setUp(self):
        self.reg = build_default_registry()
        self.conns = getattr(self.reg, "_connectors", {})

    def _fetch(self, target, api_key="fake-key", ttype="url"):
        ctx = ConnectorContext(target=target, target_type=ttype, timeout=5, case_id="T", api_key=api_key)
        return self.conns["contactout"]._fetch(ctx)

    def test_registered(self):
        self.assertIn("contactout", self.conns)

    def test_spec_is_pii_gated_byok(self):
        spec = self.conns["contactout"].spec
        self.assertEqual(spec.action_class, "pii-gated")
        self.assertEqual(spec.required_key, "contactout")

    def test_missing_key_returns_missing_key(self):
        res = self._fetch("https://www.linkedin.com/in/example/", api_key="")
        self.assertEqual(res.status, "missing_key")

    def test_empty_target_is_error(self):
        res = self._fetch("")
        self.assertEqual(res.status, "error")

    def test_invalid_target_is_error(self):
        res = self._fetch("not-a-url-or-email")
        self.assertEqual(res.status, "error")

    def test_linkedin_url_contact_info_nested(self):
        payload = {
            "profile": {"full_name": "Jane Doe"},
            "contact_info": {"emails": ["jane@example.com"], "phones": ["+1 555 0100"]},
        }
        with patch("osint_bot._safe_http.open_url", return_value=_mock_open_url(payload)):
            res = self._fetch("https://www.linkedin.com/in/janedoe/")
        self.assertEqual(res.status, "ok")
        kinds = {f.kind: f.value for f in res.findings}
        self.assertEqual(kinds.get("email_address"), "jane@example.com")
        self.assertEqual(kinds.get("phone"), "+1 555 0100")
        self.assertEqual(kinds.get("display_name"), "Jane Doe")

    def test_email_target_routes_to_email_endpoint(self):
        payload = {"emails": ["jane@example.com"]}
        with patch("osint_bot._safe_http.open_url", return_value=_mock_open_url(payload)) as m:
            res = self._fetch("jane@example.com", ttype="email")
        self.assertEqual(res.status, "ok")
        called_url = m.call_args[0][0]
        self.assertIn("people/email", called_url)

    def test_no_match_returns_ok_empty(self):
        with patch("osint_bot._safe_http.open_url", return_value=_mock_open_url({}, status=404)):
            res = self._fetch("https://www.linkedin.com/in/nomatch/")
        self.assertEqual(res.status, "ok")
        self.assertEqual(res.findings, [])

    def test_auth_error_returns_error_status(self):
        with patch("osint_bot._safe_http.open_url", return_value=_mock_open_url({}, status=401)):
            res = self._fetch("https://www.linkedin.com/in/example/")
        self.assertEqual(res.status, "error")

    def test_rate_limited(self):
        with patch("osint_bot._safe_http.open_url", return_value=_mock_open_url({}, status=429)):
            res = self._fetch("https://www.linkedin.com/in/example/")
        self.assertEqual(res.status, "rate_limited")

    def test_unreachable_returns_error(self):
        with patch("osint_bot._safe_http.open_url", side_effect=Exception("boom")):
            res = self._fetch("https://www.linkedin.com/in/example/")
        self.assertEqual(res.status, "error")

    def test_no_contacts_no_findings(self):
        payload = {"profile": {}, "contact_info": {"emails": [], "phones": []}}
        with patch("osint_bot._safe_http.open_url", return_value=_mock_open_url(payload)):
            res = self._fetch("https://www.linkedin.com/in/empty/")
        self.assertEqual(res.status, "ok")
        self.assertEqual(res.findings, [])


if __name__ == "__main__":
    unittest.main()
