"""Test offline per il connettore theHarvester (parsing report + graceful)."""
import json
import os
import tempfile
import unittest

from osint_bot.connector import ConnectorContext
from osint_bot.connectors import build_default_registry
from osint_bot.connectors.theharvester import _parse_report, _DOMAIN_RE


class TheHarvesterTests(unittest.TestCase):
    def setUp(self):
        self.conns = getattr(build_default_registry(), "_connectors", {})

    def test_registered(self):
        self.assertIn("theharvester", self.conns)

    def test_domain_regex(self):
        self.assertTrue(_DOMAIN_RE.match("example.com"))
        self.assertTrue(_DOMAIN_RE.match("sub.example.co.uk"))
        self.assertFalse(_DOMAIN_RE.match("not a domain"))
        self.assertFalse(_DOMAIN_RE.match("nodot"))

    def test_parse_report(self):
        data = {
            "emails": ["a@example.com", "b@example.com"],
            "hosts": ["www.example.com", "mail.example.com"],
            "ips": ["93.184.216.34"],
            "interesting_urls": ["https://example.com/admin"],
        }
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "th.json")
            json.dump(data, open(p, "w", encoding="utf-8"))
            parsed = _parse_report(p)
        self.assertEqual(len(parsed["emails"]), 2)
        self.assertEqual(len(parsed["hosts"]), 2)
        self.assertEqual(parsed["ips"], ["93.184.216.34"])
        self.assertEqual(len(parsed["urls"]), 1)

    def test_parse_missing_keys_safe(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "th.json")
            json.dump({"emails": None}, open(p, "w", encoding="utf-8"))
            parsed = _parse_report(p)
        self.assertEqual(parsed["emails"], [])
        self.assertEqual(parsed["hosts"], [])

    def test_missing_config(self):
        for k in ("THEHARVESTER_CMD", "THEHARVESTER_PYTHON"):
            os.environ.pop(k, None)
        ctx = ConnectorContext(target="example.com", target_type="domain", timeout=5, case_id="T")
        res = self.conns["theharvester"]._fetch(ctx)
        self.assertEqual(res.status, "missing_key")

    def test_invalid_domain(self):
        os.environ["THEHARVESTER_CMD"] = "/fake/theHarvester"
        try:
            ctx = ConnectorContext(target="not a domain", target_type="domain", timeout=5, case_id="T")
            res = self.conns["theharvester"]._fetch(ctx)
            self.assertEqual(res.status, "error")
        finally:
            os.environ.pop("THEHARVESTER_CMD", None)


if __name__ == "__main__":
    unittest.main()
