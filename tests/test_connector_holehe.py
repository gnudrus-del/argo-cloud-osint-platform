"""Test offline per il connettore holehe (parsing + graceful)."""
import os
import unittest

from osint_bot.connector import ConnectorContext
from osint_bot.connectors import build_default_registry
from osint_bot.connectors.holehe import _parse_stdout

# Output realistico di holehe --only-used (con banner e legenda da NON parsare).
SAMPLE_STDOUT = """Twitter : @palenath
Github : https://github.com/megadose/holehe
***********************
   testuser@gmail.com
***********************
[+] amazon.com
[+] firefox.com
[+] office365.com
[+] spotify.com
[+] twitter.com
[+] Email used, [-] Email not used, [x] Rate limit
121 websites checked in 10.61 seconds
"""


class HoleheConnectorTests(unittest.TestCase):
    def setUp(self):
        self.conns = getattr(build_default_registry(), "_connectors", {})

    def test_registered(self):
        self.assertIn("holehe", self.conns)

    def test_parse_stdout_extracts_domains(self):
        domains = _parse_stdout(SAMPLE_STDOUT)
        self.assertEqual(
            set(domains),
            {"amazon.com", "firefox.com", "office365.com", "spotify.com", "twitter.com"},
        )

    def test_parse_ignores_legend_line(self):
        # La riga "[+] Email used, ..." NON deve diventare un dominio.
        domains = _parse_stdout(SAMPLE_STDOUT)
        self.assertNotIn("email", domains)
        self.assertTrue(all("." in d for d in domains))

    def test_parse_dedupes(self):
        domains = _parse_stdout("[+] a.com\n[+] a.com\n[+] b.io\n")
        self.assertEqual(domains, ["a.com", "b.io"])

    def test_missing_config_returns_missing_key(self):
        for k in ("HOLEHE_CMD", "HOLEHE_PYTHON"):
            os.environ.pop(k, None)
        ctx = ConnectorContext(target="x@gmail.com", target_type="email", timeout=5, case_id="T")
        res = self.conns["holehe"]._fetch(ctx)
        self.assertEqual(res.status, "missing_key")

    def test_invalid_email(self):
        os.environ["HOLEHE_CMD"] = "/fake/holehe"
        try:
            ctx = ConnectorContext(target="notanemail", target_type="email", timeout=5, case_id="T")
            res = self.conns["holehe"]._fetch(ctx)
            self.assertEqual(res.status, "error")
        finally:
            os.environ.pop("HOLEHE_CMD", None)


if __name__ == "__main__":
    unittest.main()
