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
        self.assertEqual(result["summary"]["actor"], "alice")
        # cases_count >= 1 (un caso esplicito; create_job puo' aggiungere un caso
        # default se invocato senza case_id esplicito — non e' un bug, e' una
        # comodita' che cosi' i job non finiscono "in limbo").
        self.assertGreaterEqual(result["summary"]["cases_count"], 1)
        self.assertGreaterEqual(result["summary"]["jobs_count"], 1)
        self.assertIn("request_id", result["summary"])

    def test_export_isolates_per_user(self):
        from osint_bot.web import create_case, create_job, handle_privacy_export

        with _isolated_storage():
            create_case({"title": "Alice", "legal_basis": {"type": "consent"}}, actor="alice")
            create_case({"title": "Bob", "legal_basis": {"type": "consent"}}, actor="bob")
            create_job(_profile(), {}, actor="bob")
            create_job(_profile(), {}, actor="bob")

            alice_export = handle_privacy_export("alice")
            bob_export = handle_privacy_export("bob")

        # Alice ha solo i propri casi (1 esplicito; nessun job → nessun default).
        self.assertEqual(alice_export["summary"]["cases_count"], 1)
        self.assertEqual(alice_export["summary"]["jobs_count"], 0)
        # Bob ha 2 job propri (+ eventuale default case).
        self.assertGreaterEqual(bob_export["summary"]["jobs_count"], 2)
        # Le richieste sono distinte (ID univoci).
        self.assertNotEqual(alice_export["summary"]["request_id"],
                            bob_export["summary"]["request_id"])


class PrivacyEraseTests(unittest.TestCase):
    def test_erase_records_request_with_reason(self):
        from osint_bot.web import get_privacy_log, handle_privacy_erase

        with _isolated_storage():
            res = handle_privacy_erase("alice", {"reason": "fine indagine"})
            log = get_privacy_log("alice")
        self.assertEqual(res["status"], "ok")
        self.assertIn("ID", res["message"])
        types = [r["type"] for r in log["requests"]]
        self.assertIn("erase", types)
        reasons = [r["reason"] for r in log["requests"] if r["type"] == "erase"]
        self.assertEqual(reasons[0], "fine indagine")

    def test_erase_reason_is_capped(self):
        from osint_bot.web import get_privacy_log, handle_privacy_erase

        with _isolated_storage():
            handle_privacy_erase("alice", {"reason": "a" * 5000})
            log = get_privacy_log("alice")
        stored = next(r["reason"] for r in log["requests"] if r["type"] == "erase")
        self.assertLessEqual(len(stored), 500)


class PrivacyDsarTests(unittest.TestCase):
    def test_dsar_records_request(self):
        from osint_bot.web import get_privacy_log, handle_privacy_dsar

        with _isolated_storage():
            res = handle_privacy_dsar("alice")
            log = get_privacy_log("alice")
        self.assertEqual(res["status"], "ok")
        self.assertIn("Art. 15", res["message"])
        self.assertIn("dsar", [r["type"] for r in log["requests"]])


class PrivacyLogIsolationTests(unittest.TestCase):
    def test_log_does_not_leak_other_users(self):
        from osint_bot.web import (
            get_privacy_log, handle_privacy_dsar, handle_privacy_erase,
            handle_privacy_export,
        )

        with _isolated_storage():
            handle_privacy_export("alice")
            handle_privacy_erase("alice", {"reason": "x"})
            handle_privacy_dsar("alice")
            handle_privacy_export("bob")
            alice_log = get_privacy_log("alice")
            bob_log = get_privacy_log("bob")

        # Alice ha 3 richieste (export+erase+dsar), Bob 1 (export).
        self.assertEqual(len(alice_log["requests"]), 3)
        self.assertEqual(len(bob_log["requests"]), 1)
        # Nessuno degli ID di Bob compare nel log di Alice.
        alice_ids = {r["id"] for r in alice_log["requests"]}
        bob_ids = {r["id"] for r in bob_log["requests"]}
        self.assertFalse(alice_ids & bob_ids)


if __name__ == "__main__":
    unittest.main()
