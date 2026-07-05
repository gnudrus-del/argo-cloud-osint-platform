"""Test regressione dell'offuscamento admin.

Verifica che capabilities() nasconda tool/connectors/providers quando
admin_unlocked=False e li riveli quando True.
"""
import unittest


class ObfuscationTests(unittest.TestCase):
    def setUp(self):
        from osint_bot import web
        self.web = web

    def test_non_admin_gets_locked_placeholders(self):
        caps = self.web.capabilities(actor="", admin_unlocked=False)
        self.assertFalse(caps.get("admin_unlocked"))
        tools = caps.get("tools", [])
        self.assertEqual(len(tools), 1)
        self.assertTrue(tools[0].get("hidden"))
        conns = caps.get("connectors", [])
        self.assertEqual(len(conns), 1)
        self.assertEqual(conns[0].get("status"), "locked")
        providers = caps.get("search_providers", [])
        self.assertTrue(all(p.get("hidden") for p in providers) if providers else True)

    def test_admin_gets_full_lists(self):
        caps = self.web.capabilities(actor="", admin_unlocked=True)
        self.assertTrue(caps.get("admin_unlocked"))
        # Molti connettori registrati e non nascosti.
        conns = caps.get("connectors", [])
        self.assertGreater(len(conns), 20)
        self.assertFalse(any(c.get("hidden") for c in conns))

    def test_locked_placeholders_contain_no_names(self):
        """La versione offuscata NON deve leakare nomi di tool/connettori/servizi."""
        caps = self.web.capabilities(actor="", admin_unlocked=False)
        # Rendo tutto stringa e cerco nomi noti che NON devono comparire.
        blob = repr(caps)
        for banned in ("maigret", "holehe", "ghunt", "toutatis", "shodan",
                       "virustotal", "hibp"):
            self.assertNotIn(banned, blob.lower(),
                             f"Nome '{banned}' leaked nella capabilities offuscata.")


if __name__ == "__main__":
    unittest.main()
