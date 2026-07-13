"""Test offline per i connettori reverse-lookup (Fase 16-17) + estensione holehe."""
import os
import unittest

from osint_bot.connector import ConnectorContext
from osint_bot.connectors import build_default_registry


class ReverseConnectorsTests(unittest.TestCase):
    def setUp(self):
        self.conns = getattr(build_default_registry(), "_connectors", {})

    def _fetch(self, name, target, ttype):
        ctx = ConnectorContext(target=target, target_type=ttype, timeout=5, case_id="T")
        return self.conns[name]._fetch(ctx)

    def test_all_registered(self):
        for n in ("theharvester", "phone_footprint", "ignorant", "ghunt", "toutatis"):
            self.assertIn(n, self.conns)

    # ---- phone_footprint (nativo, sempre attivo) ----
    def test_phone_footprint_generates_urls(self):
        res = self._fetch("phone_footprint", "+16502530000", "phone")
        self.assertEqual(res.status, "ok")
        self.assertGreater(len(res.findings), 5)
        # deve contenere pivot Google e WhatsApp
        vals = " ".join(f.value for f in res.findings)
        self.assertIn("google.com/search", vals)
        self.assertIn("wa.me", vals)

    def test_phone_footprint_invalid(self):
        res = self._fetch("phone_footprint", "abc", "phone")
        self.assertEqual(res.status, "error")

    # ---- ignorant (cred/tool-gated) ----
    def test_ignorant_missing_tool(self):
        for k in ("IGNORANT_CMD", "IGNORANT_PYTHON"):
            os.environ.pop(k, None)
        res = self._fetch("ignorant", "+16502530000", "phone")
        self.assertEqual(res.status, "missing_key")

    def test_ignorant_parse(self):
        from osint_bot.connectors.ignorant import _parse_stdout, _split_number
        out = "[+] instagram.com\n[+] amazon.com\n[+] Phone used, [-] not used\n"
        self.assertEqual(set(_parse_stdout(out)), {"instagram.com", "amazon.com"})
        # split valido (numero US)
        s = _split_number("+16502530000")
        self.assertIsNotNone(s)
        self.assertEqual(s[0], "1")

    # ---- ghunt (cred-gated) ----
    def test_ghunt_missing(self):
        for k in ("GHUNT_CMD", "GHUNT_PYTHON", "GHUNT_HOME"):
            os.environ.pop(k, None)
        res = self._fetch("ghunt", "x@gmail.com", "email")
        self.assertEqual(res.status, "missing_key")

    # ---- toutatis (session-gated) ----
    def test_toutatis_missing(self):
        for k in ("TOUTATIS_CMD", "TOUTATIS_PYTHON", "TOUTATIS_SESSION"):
            os.environ.pop(k, None)
        res = self._fetch("toutatis", "someuser", "handle")
        self.assertEqual(res.status, "missing_key")

    def test_toutatis_parse(self):
        from osint_bot.connectors.toutatis import _parse
        sample = ("Full name : Mario Rossi\nUser ID : 123456\n"
                  "Obfuscated email : m****@g****.com\nObfuscated phone : +39 *** *** 12\n")
        p = _parse(sample)
        self.assertEqual(p.get("user_id"), "123456")
        self.assertIn("email_obfuscated", p)
        self.assertIn("phone_obfuscated", p)

    # ---- holehe recovery CSV ----
    def test_holehe_recovery_csv(self):
        import csv
        import tempfile

        from osint_bot.connectors.holehe import _parse_recovery_csv
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "holehe_x.csv")
            with open(p, "w", encoding="utf-8", newline="") as fh:
                w = csv.DictWriter(fh, fieldnames=["name", "domain", "exists", "emailrecovery", "phoneNumber"])
                w.writeheader()
                w.writerow({"name": "twitter", "domain": "twitter.com", "exists": "True",
                            "emailrecovery": "m***@gmail.com", "phoneNumber": ""})
                w.writerow({"name": "amazon", "domain": "amazon.com", "exists": "True",
                            "emailrecovery": "", "phoneNumber": "+39****12"})
                w.writerow({"name": "nope", "domain": "nope.com", "exists": "False",
                            "emailrecovery": "x***@x.com", "phoneNumber": ""})
            hits = _parse_recovery_csv(d)
        kinds = {(h["kind"], h["domain"]) for h in hits}
        self.assertIn(("email_recovery_hint", "twitter.com"), kinds)
        self.assertIn(("phone_recovery_hint", "amazon.com"), kinds)
        # la riga exists=False NON deve produrre hint
        self.assertNotIn(("email_recovery_hint", "nope.com"), kinds)


if __name__ == "__main__":
    unittest.main()
