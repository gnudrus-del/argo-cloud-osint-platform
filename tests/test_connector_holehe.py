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

# Hit "ricchi": holehe (core.py::print_result) appende emailrecovery/
# phoneNumber/FullName/data di creazione alla STESSA riga "[+] dominio"
# quando disponibili — regression coverage per il bug dove questi venivano
# scartati per intero da un regex ancorato a fine riga.
SAMPLE_STDOUT_RICH = """[+] adobe.com
[+] amazon.com em***l@example.com
[+] en.gravatar.com em***l@example.com / FullName Mario Rossi
[+] protonmail.ch / FullName Anna Verdi / Date, time of the creation 2019-01-01
"""


class HoleheConnectorTests(unittest.TestCase):
    def setUp(self):
        self.conns = getattr(build_default_registry(), "_connectors", {})

    def test_registered(self):
        self.assertIn("holehe", self.conns)

    def test_parse_stdout_extracts_domains(self):
        hits = _parse_stdout(SAMPLE_STDOUT)
        self.assertEqual(
            {h["domain"] for h in hits},
            {"amazon.com", "firefox.com", "office365.com", "spotify.com", "twitter.com"},
        )

    def test_parse_ignores_legend_line(self):
        # La riga "[+] Email used, ..." NON deve diventare un dominio.
        hits = _parse_stdout(SAMPLE_STDOUT)
        domains = [h["domain"] for h in hits]
        self.assertNotIn("email", domains)
        self.assertTrue(all("." in d for d in domains))

    def test_parse_dedupes(self):
        hits = _parse_stdout("[+] a.com\n[+] a.com\n[+] b.io\n")
        self.assertEqual([h["domain"] for h in hits], ["a.com", "b.io"])

    def test_parse_keeps_hits_with_trailing_data_regression(self):
        # Prima del fix, ogni riga con contenuto dopo il dominio (recovery
        # hint, FullName, ...) veniva scartata per intero: 0 finding invece
        # di 1, anche per l'hit più ricco di informazioni.
        hits = _parse_stdout(SAMPLE_STDOUT_RICH)
        domains = {h["domain"] for h in hits}
        self.assertEqual(
            domains,
            {"adobe.com", "amazon.com", "en.gravatar.com", "protonmail.ch"},
        )

    def test_parse_extracts_full_name_from_rich_hit(self):
        hits = _parse_stdout(SAMPLE_STDOUT_RICH)
        by_domain = {h["domain"]: h["full_name"] for h in hits}
        self.assertEqual(by_domain["en.gravatar.com"], "Mario Rossi")
        self.assertEqual(by_domain["protonmail.ch"], "Anna Verdi")
        self.assertEqual(by_domain["adobe.com"], "")
        self.assertEqual(by_domain["amazon.com"], "")

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
