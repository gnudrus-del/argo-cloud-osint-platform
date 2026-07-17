"""GDPR art. 17 — verify that the erase-approval flow performs a *real*
atomic erasure: writes a tombstone, appends an audit_events entry with
a valid hash chain, and removes the actor's business rows.

Since the deletion is now admin-gated, the user request only records a
'pending' row and it's the admin approval that actually erases — so these
tests drive both steps via ``_erase_via_admin`` and assert on the result of
the approval. The erasure logic itself (``Storage.erase_actor_data``) is
unchanged; only its trigger moved. These tests are the contract that the H3
hardening promise is met."""
from __future__ import annotations

import contextlib
import tempfile
import unittest
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


def _erase_via_admin(actor: str, reason: str = "erase") -> dict:
    """Nuovo flusso a due passi: l'utente RICHIEDE la cancellazione (rimane
    'pending', nessun dato toccato), poi un amministratore la approva — ed è
    l'approvazione che esegue l'erasure reale. Ritorna il risultato
    dell'approvazione (stessa forma del vecchio handle_privacy_erase: status
    ok, tombstone_id, selector_sha256, erased_at)."""
    from osint_bot.web import handle_admin_privacy_approve, handle_privacy_erase

    req = handle_privacy_erase(actor, {"reason": reason})
    assert req["status"] == "pending", req
    return handle_admin_privacy_approve("admin", req["request_id"])


class DsarErasureTests(unittest.TestCase):
    def test_erase_writes_tombstone(self):
        from osint_bot.web import create_case

        with _isolated_storage() as (_, stor):
            create_case({"title": "X", "legal_basis": {"type": "consent"}}, actor="alice")
            res = _erase_via_admin("alice", "end of engagement")
            self.assertEqual(res["status"], "ok")
            self.assertIn("tombstone_id", res)

            tombs = stor._conn().execute(
                "SELECT id, selector_sha256, audit_hash FROM dsar_tombstones "
                "ORDER BY erased_at DESC LIMIT 1"
            ).fetchall()
            self.assertEqual(len(tombs), 1)
            tomb_id, selector, audit_hash = tombs[0]
            self.assertEqual(tomb_id, res["tombstone_id"])
            self.assertEqual(len(selector), 64)  # sha256 hex
            self.assertEqual(len(audit_hash), 64)

    def test_erase_appends_audit_event(self):
        from osint_bot.web import create_case

        with _isolated_storage() as (_, stor):
            create_case({"title": "X", "legal_basis": {"type": "consent"}}, actor="alice")
            _erase_via_admin("alice", "test")

            rows = stor._conn().execute(
                "SELECT action, actor FROM audit_events "
                "WHERE action = 'account_erased_dsar' ORDER BY seq DESC LIMIT 1"
            ).fetchall()
            self.assertEqual(len(rows), 1)
            action, actor = rows[0]
            self.assertEqual(action, "account_erased_dsar")
            # The event is written as 'system', not the erased actor.
            self.assertEqual(actor, "system")

    def test_erase_removes_business_data(self):
        from osint_bot.orchestrator import RunProfile
        from osint_bot.web import (
            create_case,
            create_job,
        )

        with _isolated_storage() as (_, stor):
            create_case({"title": "X", "legal_basis": {"type": "consent"}}, actor="alice")
            create_job(RunProfile(
                command="X", target="example.com", target_type="domain",
                agents=["web"], external_tools=[], seed_urls=[],
                depth=1, max_pages=1, notes=[],
            ), {}, actor="alice")

            # Baseline
            pre_cases = stor._conn().execute(
                "SELECT COUNT(*) FROM cases WHERE owner = ?", ("alice",)
            ).fetchone()[0]
            pre_jobs = stor._conn().execute(
                "SELECT COUNT(*) FROM jobs WHERE owner = ?", ("alice",)
            ).fetchone()[0]
            self.assertGreaterEqual(pre_cases, 1)
            self.assertGreaterEqual(pre_jobs, 1)

            _erase_via_admin("alice", "erase")

            post_cases = stor._conn().execute(
                "SELECT COUNT(*) FROM cases WHERE owner = ?", ("alice",)
            ).fetchone()[0]
            post_jobs = stor._conn().execute(
                "SELECT COUNT(*) FROM jobs WHERE owner = ?", ("alice",)
            ).fetchone()[0]
            self.assertEqual(post_cases, 0)
            self.assertEqual(post_jobs, 0)

    def test_erase_returns_selector_sha256(self):
        with _isolated_storage():
            res = _erase_via_admin("alice", "x")
            self.assertEqual(res["status"], "ok")
            # SHA-256 of 'user:alice' (lowercased)
            import hashlib
            expected = hashlib.sha256(b"user:alice").hexdigest()
            self.assertEqual(res["selector_sha256"], expected)

    def test_erase_preserves_audit_chain_integrity(self):
        """Regression: prima del fix, ogni cancellazione GDPR rompeva
        silenziosamente verify_audit_chain() — l'evento account_erased_dsar
        veniva hashato con uno schema diverso (stringa pipe-concatenata) da
        quello ricalcolato in fase di verifica (event_hash su dict
        JSON-canonico), e la redazione di eventi passati non aggiornava il
        loro hash memorizzato. Verificato empiricamente sul codice originale
        prima di questo fix — non un problema ipotetico."""
        from osint_bot.web import create_case

        with _isolated_storage() as (_, stor):
            create_case({"title": "X", "legal_basis": {"type": "consent"}}, actor="alice")
            stor.append_audit_event("alice", "login_success", {"note": "alice logged in"})
            stor.append_audit_event("bob", "login_success", {"note": "bob logged in too"})
            self.assertTrue(stor.verify_audit_chain())

            res = _erase_via_admin("alice", "test")
            self.assertEqual(res["status"], "ok")

            self.assertTrue(
                stor.verify_audit_chain(),
                "la catena audit deve restare valida dopo una cancellazione GDPR legittima",
            )

    def test_verify_audit_chain_still_detects_real_tampering(self):
        """Il fix non deve indebolire la rilevazione di manomissione vera:
        solo le righe redatte da un tombstone documentato sono escluse dal
        controllo di auto-hash."""
        from osint_bot.web import create_case

        with _isolated_storage() as (_, stor):
            create_case({"title": "X", "legal_basis": {"type": "consent"}}, actor="alice")
            stor.append_audit_event("bob", "login_success", {"note": "bob logged in"})
            _erase_via_admin("alice", "test")
            self.assertTrue(stor.verify_audit_chain())

            # manomissione vera, mai passata da erase_actor_data/un tombstone
            stor._conn().execute(
                "UPDATE audit_events SET actor = 'mallory' WHERE action = 'login_success' AND actor = 'bob'"
            )
            self.assertFalse(stor.verify_audit_chain())


if __name__ == "__main__":
    unittest.main()
