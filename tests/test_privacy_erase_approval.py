"""GDPR art. 17 — flusso di approvazione admin delle cancellazioni profilo.

La cancellazione richiesta da un utente non è più self-service: resta
'pending' finché un amministratore non la approva (esegue) o rifiuta. Questi
test coprono i nuovi handler ``handle_admin_privacy_pending/approve/reject`` e
i metodi storage di supporto, sia il percorso felice sia i casi d'errore e
l'isolamento (approvare la richiesta di un utente non tocca gli altri).
"""
from __future__ import annotations

import contextlib
import tempfile
import unittest
from http import HTTPStatus
from pathlib import Path


@contextlib.contextmanager
def _isolated_storage():
    import osint_bot.web as web
    from osint_bot.storage import Storage

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


def _seed_user_with_case(stor, actor: str) -> None:
    from osint_bot.web import create_case

    stor.put_user({"username": actor, "password": "x", "created_at": "now"})
    create_case({"title": f"case-{actor}", "legal_basis": {"type": "consent"}}, actor=actor)


class EraseRequestIsPendingTests(unittest.TestCase):
    def test_request_is_pending_and_audited(self):
        from osint_bot.web import handle_privacy_erase

        with _isolated_storage() as (_, stor):
            _seed_user_with_case(stor, "alice")
            res = handle_privacy_erase("alice", {"reason": "fine caso"})
            actions = [r["action"] for r in stor.all_audit_events()]
        self.assertEqual(res["status"], "pending")
        self.assertIn("request_id", res)
        self.assertIn("privacy_erase_requested", actions)


class AdminPendingListTests(unittest.TestCase):
    def test_pending_lists_only_erase_requests_with_owner(self):
        from osint_bot.web import (
            handle_admin_privacy_pending,
            handle_privacy_dsar,
            handle_privacy_erase,
            handle_privacy_export,
        )

        with _isolated_storage() as (_, stor):
            _seed_user_with_case(stor, "alice")
            _seed_user_with_case(stor, "bob")
            handle_privacy_export("alice")  # auto-processed, non deve comparire
            handle_privacy_dsar("bob")       # idem
            handle_privacy_erase("alice", {"reason": "a"})
            handle_privacy_erase("bob", {"reason": "b"})
            pending = handle_admin_privacy_pending()["pending"]

        owners = sorted(p["owner"] for p in pending)
        self.assertEqual(owners, ["alice", "bob"])
        self.assertTrue(all(p["type"] == "erase" for p in pending))
        self.assertTrue(all(p["status"] == "pending" for p in pending))


class AdminApproveTests(unittest.TestCase):
    def test_approve_executes_erasure_for_the_owner(self):
        from osint_bot.web import (
            handle_admin_privacy_approve,
            handle_privacy_erase,
        )

        with _isolated_storage() as (_, stor):
            _seed_user_with_case(stor, "alice")
            req = handle_privacy_erase("alice", {"reason": "x"})
            res = handle_admin_privacy_approve("admin", req["request_id"])

            post_cases = stor._conn().execute(
                "SELECT COUNT(*) FROM cases WHERE owner = ?", ("alice",)
            ).fetchone()[0]
            actions = [r["action"] for r in stor.all_audit_events()]
            chain_ok = stor.verify_audit_chain()  # dentro il with: la tempdir è viva

        self.assertEqual(res["status"], "ok")
        self.assertEqual(res["owner"], "alice")
        self.assertTrue(res["tombstone_id"].startswith("TOMB-"))
        self.assertEqual(post_cases, 0)  # dati cancellati solo dopo approvazione
        self.assertIn("privacy_erase_approved", actions)
        self.assertIn("account_erased_dsar", actions)
        self.assertTrue(chain_ok)

    def test_approve_does_not_touch_other_users(self):
        from osint_bot.web import handle_admin_privacy_approve, handle_privacy_erase

        with _isolated_storage() as (_, stor):
            _seed_user_with_case(stor, "alice")
            _seed_user_with_case(stor, "bob")
            req = handle_privacy_erase("alice", {"reason": "x"})
            handle_admin_privacy_approve("admin", req["request_id"])
            bob_cases = stor._conn().execute(
                "SELECT COUNT(*) FROM cases WHERE owner = ?", ("bob",)
            ).fetchone()[0]
        self.assertGreaterEqual(bob_cases, 1)  # bob intatto

    def test_approve_unknown_request_raises_404(self):
        from osint_bot.web import WebError, handle_admin_privacy_approve

        with _isolated_storage():
            with self.assertRaises(WebError) as ctx:
                handle_admin_privacy_approve("admin", "does-not-exist")
        self.assertEqual(ctx.exception.status, HTTPStatus.NOT_FOUND)

    def test_approve_already_handled_raises_409(self):
        from osint_bot.web import (
            WebError,
            handle_admin_privacy_approve,
            handle_admin_privacy_reject,
            handle_privacy_erase,
        )

        with _isolated_storage() as (_, stor):
            _seed_user_with_case(stor, "alice")
            req = handle_privacy_erase("alice", {"reason": "x"})
            handle_admin_privacy_reject("admin", req["request_id"], "cambiato idea")
            with self.assertRaises(WebError) as ctx:
                handle_admin_privacy_approve("admin", req["request_id"])
        self.assertEqual(ctx.exception.status, HTTPStatus.CONFLICT)


class AdminRejectTests(unittest.TestCase):
    def test_reject_marks_rejected_and_keeps_data(self):
        from osint_bot.web import (
            get_privacy_log,
            handle_admin_privacy_reject,
            handle_privacy_erase,
        )

        with _isolated_storage() as (_, stor):
            _seed_user_with_case(stor, "alice")
            req = handle_privacy_erase("alice", {"reason": "x"})
            res = handle_admin_privacy_reject("admin", req["request_id"], "non autorizzata")

            row = stor.get_privacy_request(req["request_id"])
            cases = stor._conn().execute(
                "SELECT COUNT(*) FROM cases WHERE owner = ?", ("alice",)
            ).fetchone()[0]
            actions = [r["action"] for r in stor.all_audit_events()]
            user_log = get_privacy_log("alice")

        self.assertEqual(res["status"], "ok")
        self.assertEqual(row["status"], "rejected")
        self.assertEqual(row["resolved_by"], "admin")
        self.assertGreaterEqual(cases, 1)  # nessun dato toccato
        self.assertIn("privacy_erase_rejected", actions)
        # L'utente vede la propria richiesta come rifiutata.
        self.assertIn(("erase", "rejected"),
                      [(r["type"], r["status"]) for r in user_log["requests"]])

    def test_reject_unknown_request_raises_404(self):
        from osint_bot.web import WebError, handle_admin_privacy_reject

        with _isolated_storage():
            with self.assertRaises(WebError) as ctx:
                handle_admin_privacy_reject("admin", "nope", "")
        self.assertEqual(ctx.exception.status, HTTPStatus.NOT_FOUND)


class StorageHelperTests(unittest.TestCase):
    def test_list_admin_filters_by_status_and_type(self):
        with _isolated_storage() as (_, stor):
            stor.log_privacy_request({"id": "r1", "owner": "a", "type": "erase",
                                      "status": "pending", "reason": "", "created_at": "2026-01-01"})
            stor.log_privacy_request({"id": "r2", "owner": "b", "type": "export",
                                      "status": "processed", "reason": "", "created_at": "2026-01-02"})
            stor.log_privacy_request({"id": "r3", "owner": "c", "type": "erase",
                                      "status": "rejected", "reason": "", "created_at": "2026-01-03"})

            pend_erase = stor.list_privacy_requests_admin(status="pending", req_type="erase")
            all_reqs = stor.list_privacy_requests_admin()

        self.assertEqual([r["id"] for r in pend_erase], ["r1"])
        self.assertEqual({r["id"] for r in all_reqs}, {"r1", "r2", "r3"})
        # owner è incluso nella vista admin (a differenza di list_privacy_requests).
        self.assertEqual(pend_erase[0]["owner"], "a")

    def test_resolve_sets_status_and_resolver(self):
        with _isolated_storage() as (_, stor):
            stor.log_privacy_request({"id": "r1", "owner": "a", "type": "erase",
                                      "status": "pending", "reason": "", "created_at": "2026-01-01"})
            stor.resolve_privacy_request("r1", "rejected", "admin")
            row = stor.get_privacy_request("r1")
        self.assertEqual(row["status"], "rejected")
        self.assertEqual(row["resolved_by"], "admin")
        self.assertTrue(row["processed_at"])


if __name__ == "__main__":
    unittest.main()
