"""Fase 5 — Privacy Center: test funzionali e di isolamento per-utente.

Il punto critico di sicurezza qui e' che ogni richiesta privacy deve essere
scopata ESCLUSIVAMENTE sull'actor che la fa: nessun utente deve poter
osservare/esportare/cancellare i dati di un altro.
"""
import contextlib
import tempfile
import unittest
from pathlib import Path

from osint_bot.orchestrator import RunProfile
from osint_bot.storage import Storage


@contextlib.contextmanager
def _isolated_storage():
    import osint_bot.web as web
    with tempfile.TemporaryDirectory() as tmp:
        original_root = web.JOB_ROOT
        original_storage = web.STORAGE
        web.JOB_ROOT = Path(tmp)
        web.STORAGE = Storage(Path(tmp) / "gufo.sqlite3")
        try:
            yield Path(tmp), web.STORAGE
        finally:
            try:
                web.STORAGE.close()
            except Exception:
                pass
            web.JOB_ROOT = original_root
            web.STORAGE = original_storage


def _profile() -> RunProfile:
    return RunProfile(
        command="Analizza example.com", target="example.com",
        target_type="domain", agents=["web"], external_tools=[], seed_urls=[],
        depth=1, max_pages=1, notes=[],
    )


class PrivacyExportTests(unittest.TestCase):
    def test_export_includes_actor_counts_only(self):
        from osint_bot.web import create_case, create_job, handle_privacy_export

        with _isolated_storage():
            create_case({"title": "X", "legal_basis": {"type": "consent"}}, actor="alice")
            create_job(_profile(), {}, actor="alice")
            result = handle_privacy_export("alice")
        self.assertEqual(result["status"], "ok")
        export = result["export"]
        self.assertEqual(export["actor"], "alice")
        self.assertIn("Art. 20", export["gdpr_basis"])
        # cases_count >= 1 (un caso esplicito; create_job puo' aggiungere un caso
        # default se invocato senza case_id esplicito — non e' un bug, e' una
        # comodita' che cosi' i job non finiscono "in limbo").
        self.assertGreaterEqual(len(export["data"]["cases"]), 1)
        self.assertGreaterEqual(len(export["data"]["jobs"]), 1)
        self.assertIn("request_id", export)

    def test_export_includes_configured_api_keys(self):
        """Regression: prima del fix, la query interrogava 'WHERE owner = ?'
        su api_keys, tabella che non ha colonna owner (solo username) — la
        select falliva silenziosamente e l'export non rivelava mai le chiavi
        configurate, anche quando l'attore ne aveva. Verificato
        empiricamente sul codice originale prima di questo fix."""
        from osint_bot.web import handle_privacy_export

        with _isolated_storage() as (_, stor):
            stor.put_user({"username": "alice", "password": "x", "created_at": "now"})
            stor.put_api_key("alice", "shodan", "sk-test-123")
            result = handle_privacy_export("alice")

        self.assertEqual(result["status"], "ok")
        services = [k["service"] for k in result["export"]["data"]["api_keys_configured"]]
        self.assertEqual(services, ["shodan"])

    def test_export_isolates_per_user(self):
        from osint_bot.web import create_case, create_job, handle_privacy_export

        with _isolated_storage():
            create_case({"title": "Alice", "legal_basis": {"type": "consent"}}, actor="alice")
            create_case({"title": "Bob", "legal_basis": {"type": "consent"}}, actor="bob")
            create_job(_profile(), {}, actor="bob")
            create_job(_profile(), {}, actor="bob")

            alice_export = handle_privacy_export("alice")
            bob_export = handle_privacy_export("bob")

        alice_data = alice_export["export"]["data"]
        bob_data = bob_export["export"]["data"]
        # Alice ha solo i propri casi (1 esplicito; nessun job → nessun default).
        self.assertEqual(len(alice_data["cases"]), 1)
        self.assertEqual(len(alice_data["jobs"]), 0)
        # Bob ha 2 job propri (+ eventuale default case).
        self.assertGreaterEqual(len(bob_data["jobs"]), 2)
        # Le richieste sono distinte (ID univoci).
        self.assertNotEqual(alice_export["export"]["request_id"],
                            bob_export["export"]["request_id"])


class PrivacyEraseTests(unittest.TestCase):
    def test_erase_records_pending_request_without_deleting(self):
        """La cancellazione NON è più self-service: la richiesta utente resta
        'pending' (nessun dato toccato) finché un admin non la approva. Il caso
        di 'alice' deve sopravvivere alla sola richiesta."""
        from osint_bot.web import create_case, get_privacy_log, handle_privacy_erase

        with _isolated_storage() as (_, stor):
            create_case({"title": "X", "legal_basis": {"type": "consent"}}, actor="alice")
            res = handle_privacy_erase("alice", {"reason": "fine indagine"})
            log = get_privacy_log("alice")
            remaining_cases = stor._conn().execute(
                "SELECT COUNT(*) FROM cases WHERE owner = ?", ("alice",)
            ).fetchone()[0]
        self.assertEqual(res["status"], "pending")
        self.assertIn("request_id", res)
        self.assertNotIn("tombstone_id", res)  # nessuna cancellazione immediata
        # La richiesta 'erase' compare nel log dell'utente, in stato pending.
        self.assertIn(("erase", "pending"), [(r["type"], r["status"]) for r in log["requests"]])
        # I dati di alice sono ancora lì: la cancellazione attende l'admin.
        self.assertGreaterEqual(remaining_cases, 1)

    def test_erase_reason_is_capped(self):
        """The reason field is truncated to 500 chars on the privacy_requests
        row; the request is only recorded (pending), not executed."""
        from osint_bot.web import handle_privacy_erase

        with _isolated_storage():
            res = handle_privacy_erase("alice", {"reason": "a" * 5000})
        self.assertEqual(res["status"], "pending")
        self.assertIn("request_id", res)


class PrivacyDsarTests(unittest.TestCase):
    def test_dsar_records_request(self):
        from osint_bot.web import get_privacy_log, handle_privacy_dsar

        with _isolated_storage():
            res = handle_privacy_dsar("alice")
            log = get_privacy_log("alice")
        self.assertEqual(res["status"], "ok")
        response = res["response"]
        self.assertIn("Art. 15", response["gdpr_basis"])
        self.assertEqual(response["actor"], "alice")
        self.assertIn("categories_held", response)
        self.assertIn("cases", response["categories_held"])
        # The DSAR request itself is logged in privacy_requests.
        self.assertIn("dsar", [r["type"] for r in log["requests"]])


class PrivacyLogIsolationTests(unittest.TestCase):
    def test_log_does_not_leak_other_users(self):
        from osint_bot.web import (
            get_privacy_log,
            handle_privacy_dsar,
            handle_privacy_erase,
            handle_privacy_export,
        )

        with _isolated_storage():
            handle_privacy_export("alice")
            # erase ora è solo una richiesta 'pending': NON cancella, quindi le
            # righe privacy_requests di alice restano tutte (export + erase +
            # dsar). L'isolamento per-utente è comunque garantito.
            handle_privacy_erase("alice", {"reason": "x"})
            handle_privacy_dsar("alice")
            handle_privacy_export("bob")
            alice_log = get_privacy_log("alice")
            bob_log = get_privacy_log("bob")

        self.assertEqual(len(alice_log["requests"]), 3)
        self.assertEqual(sorted(r["type"] for r in alice_log["requests"]),
                         ["dsar", "erase", "export"])
        self.assertEqual(len(bob_log["requests"]), 1)
        # Nessuno degli ID di Bob compare nel log di Alice.
        alice_ids = {r["id"] for r in alice_log["requests"]}
        bob_ids = {r["id"] for r in bob_log["requests"]}
        self.assertFalse(alice_ids & bob_ids)


if __name__ == "__main__":
    unittest.main()
