"""Test offline (nessuna rete) per i connector Phase 12: validano gli input
e i percorsi di errore/missing_key in modo deterministico."""
import unittest

from osint_bot.connector import ConnectorContext
from osint_bot.connectors import build_default_registry


class Phase12ConnectorTests(unittest.TestCase):
    def setUp(self):
        self.reg = build_default_registry()
        self.conns = getattr(self.reg, "_connectors", {})

    def _fetch(self, name, target, ttype="auto"):
        ctx = ConnectorContext(target=target, target_type=ttype, timeout=5, case_id="T")
        return self.conns[name]._fetch(ctx)

    def test_all_four_registered(self):
        for name in ("shodan_internetdb", "overpass", "threatfox", "misp"):
            self.assertIn(name, self.conns)

    def test_shodan_internetdb_rejects_bad_ip(self):
        res = self._fetch("shodan_internetdb", "not-an-ip", "ip")
        self.assertEqual(res.status, "error")

    def test_overpass_rejects_bad_geo(self):
        res = self._fetch("overpass", "nonsense", "geo")
        self.assertEqual(res.status, "error")

    def test_overpass_parses_coordinates(self):
        # non facciamo rete: verifichiamo solo che il parsing accetti il formato
        from osint_bot.connectors.overpass import _parse_geo
        self.assertEqual(_parse_geo("41.9,12.5"), (41.9, 12.5, 250))
        self.assertEqual(_parse_geo("41.9, 12.5, 500"), (41.9, 12.5, 500))
        self.assertIsNone(_parse_geo("999,999"))

    def test_misp_missing_key_without_env(self):
        import os
        # Assicura che l'env non sia settato in test
        os.environ.pop("MISP_URL", None)
        os.environ.pop("MISP_KEY", None)
        res = self._fetch("misp", "8.8.8.8", "ip")
        self.assertEqual(res.status, "missing_key")

    def test_threatfox_empty_target(self):
        res = self._fetch("threatfox", "", "ip")
        self.assertEqual(res.status, "error")

    def test_registry_has_39_connectors(self):
        self.assertGreaterEqual(len(self.conns), 39)


if __name__ == "__main__":
    unittest.main()
