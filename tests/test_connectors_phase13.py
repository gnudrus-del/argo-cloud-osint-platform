"""Test offline (nessuna rete) per i connettori nativi Fase 13."""
import unittest

from osint_bot.connector import ConnectorContext
from osint_bot.connectors import build_default_registry


class Phase13Tests(unittest.TestCase):
    def setUp(self):
        self.conns = getattr(build_default_registry(), "_connectors", {})

    def _fetch(self, name, target, ttype="auto"):
        ctx = ConnectorContext(target=target, target_type=ttype, timeout=3, case_id="T")
        return self.conns[name]._fetch(ctx)

    def test_all_registered(self):
        for name in ("content_discovery", "port_scan", "subdomain_enum",
                     "dnstwist_native", "secret_scan", "url_harvest", "holehe_native"):
            self.assertIn(name, self.conns)

    def test_registry_count_at_least_46(self):
        self.assertGreaterEqual(len(self.conns), 46)

    def test_active_connectors_are_action_gated(self):
        from osint_bot.connector import ACTION_ACTIVE_GATED
        self.assertEqual(self.conns["port_scan"].spec.action_class, ACTION_ACTIVE_GATED)
        self.assertEqual(self.conns["content_discovery"].spec.action_class, ACTION_ACTIVE_GATED)

    def test_error_paths(self):
        self.assertEqual(self._fetch("content_discovery", "", "domain").status, "error")
        self.assertEqual(self._fetch("port_scan", "", "ip").status, "error")
        self.assertEqual(self._fetch("subdomain_enum", "nodot", "domain").status, "error")
        self.assertEqual(self._fetch("holehe_native", "bad", "email").status, "error")

    # ---- logica deterministica ----
    def test_dnstwist_permutations(self):
        from osint_bot.connectors.dnstwist_native import _permutations
        perms = _permutations("example.com")
        self.assertGreater(len(perms), 10)
        self.assertNotIn("example.com", perms)  # non include l'originale
        # TLD swap presente
        self.assertTrue(any(p.startswith("example.") and not p.endswith(".com") for p in perms))

    def test_secret_regex_catalog_matches(self):
        from osint_bot.connectors.secret_scan import _SECRET_PATTERNS
        samples = {
            "AWS Access Key": "AKIAIOSFODNN7EXAMPLE",
            "GitHub Token": "ghp_" + "a" * 36,
            "Private Key Block": "-----BEGIN RSA PRIVATE KEY-----",
            "Anthropic API Key": "sk-ant-" + "a" * 30,
        }
        for name, pattern, _sev in _SECRET_PATTERNS:
            if name in samples:
                self.assertTrue(pattern.search(samples[name]), f"{name} non matcha il sample")

    def test_secret_redact(self):
        from osint_bot.connectors.secret_scan import _redact
        r = _redact("AKIAIOSFODNN7EXAMPLE")
        self.assertIn("…", r)
        self.assertNotEqual(r, "AKIAIOSFODNN7EXAMPLE")

    def test_holehe_disposable_and_gmail_canonical(self):
        res = self._fetch("holehe_native", "test@mailinator.com", "email")
        kinds = {f.kind for f in res.findings}
        self.assertIn("email_disposable", kinds)

    def test_content_discovery_wordlist_nonempty(self):
        from osint_bot.connectors.content_discovery import _PATHS
        self.assertGreater(len(_PATHS), 20)
        self.assertIn(".env", _PATHS)

    def test_port_scan_portmap(self):
        from osint_bot.connectors.port_scan import _PORTS, _RISKY
        self.assertIn(22, _PORTS)
        self.assertIn(6379, _RISKY)  # redis flagged risky

    def test_url_harvest_interesting_regex(self):
        from osint_bot.connectors.url_harvest import _INTERESTING_RE
        self.assertTrue(_INTERESTING_RE.search("https://x.com/api/users?token=abc"))
        self.assertFalse(_INTERESTING_RE.search("https://x.com/about"))

    # ---- sherlock_lite hardening: solo siti affidabili, niente SPA ----
    def test_sherlock_lite_only_reliable_sites(self):
        from osint_bot.connectors.sherlock_lite import _SITES, _DELEGATED_TO_MAIGRET
        names = {s[0] for s in _SITES}
        methods = {s[2] for s in _SITES}
        # niente siti SPA/login noti tra quelli sondati
        for spa in ("Instagram", "Twitter/X", "Twitter", "Twitch", "Pinterest", "TikTok"):
            self.assertNotIn(spa, names)
        # ogni sito usa una detection deterministica
        self.assertTrue(methods <= {"404", "marker"})
        # gli SPA sono documentati come delegati a maigret
        self.assertIn("Instagram", _DELEGATED_TO_MAIGRET)

    def test_sherlock_lite_marker_sites_have_marker(self):
        from osint_bot.connectors.sherlock_lite import _SITES
        for name, url, method, marker in _SITES:
            if method == "marker":
                self.assertTrue(marker, f"{name} method=marker ma marker vuoto")

    # ---- maigret connector ----
    def test_maigret_registered(self):
        self.assertIn("maigret", self.conns)

    def test_maigret_missing_config(self):
        import os
        for k in ("MAIGRET_PYTHON", "MAIGRET_CMD"):
            os.environ.pop(k, None)
        res = self._fetch("maigret", "testuser", "handle")
        self.assertEqual(res.status, "missing_key")

    def test_maigret_invalid_username(self):
        import os
        os.environ["MAIGRET_PYTHON"] = "/fake/python"
        try:
            res = self._fetch("maigret", "bad user/name", "handle")
            self.assertEqual(res.status, "error")
        finally:
            os.environ.pop("MAIGRET_PYTHON", None)

    def test_maigret_parse_report(self):
        import json, tempfile, os
        from osint_bot.connectors.maigret import _parse_report
        data = {
            "Instagram": {"status": {"status": "Claimed"}, "url_user": "https://instagram.com/testuser"},
            "Fiverr": {"status": {"status": "Claimed"}, "url_user": "https://www.fiverr.com/testuser"},
            "Twitter": {"status": {"status": "Available"}, "url_user": "https://twitter.com/testuser"},
        }
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "report_testuser_simple.json")
            json.dump(data, open(p, "w", encoding="utf-8"))
            claimed = _parse_report(p)
        urls = {c["url"] for c in claimed}
        self.assertIn("https://instagram.com/testuser", urls)
        self.assertIn("https://www.fiverr.com/testuser", urls)
        self.assertEqual(len(claimed), 2)  # 'Available' escluso


if __name__ == "__main__":
    unittest.main()
