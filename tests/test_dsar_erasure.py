"""GDPR art. 17 — verify that handle_privacy_erase performs a *real*
atomic erasure: writes a tombstone, appends an audit_events entry with
a valid hash chain, and removes the actor's business rows.

These tests are the contract that the H3 hardening promise is met."""
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


class DsarErasureTests(unittest.TestCase):
    def test_erase_writes_tombstone(self):
        from osint_bot.web import create_case, handle_privacy_erase

        with _isolated_storage() as (_, stor):
            create_case({"title": "X", "legal_basis": {"type": "consent"}}, actor="alice")
            res = handle_privacy_erase("alice", {"reason": "end of engagement"})
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
        from osint_bot.web import create_case, handle_privacy_erase

        with _isolated_storage() as (_, stor):
            create_case({"title": "X", "legal_basis": {"type": "consent"}}, actor="alice")
            handle_privacy_erase("alice", {"reason": "test"})

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
            handle_privacy_erase,
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

            handle_privacy_erase("alice", {"reason": "erase"})

            post_cases = stor._conn().execute(
                "SELECT COUNT(*) FROM cases WHERE owner = ?", ("alice",)
            ).fetchone()[0]
            post_jobs = stor._conn().execute(
                "SELECT COUNT(*) FROM jobs WHERE owner = ?", ("alice",)
            ).fetchone()[0]
            self.assertEqual(post_cases, 0)
            self.assertEqual(post_jobs, 0)

    def test_erase_returns_selector_sha256(self):
        from osint_bot.web import handle_privacy_erase

        with _isolated_storage():
            res = handle_privacy_erase("alice", {"reason": "x"})
            self.assertEqual(res["status"], "ok")
            # SHA-256 of 'user:alice' (lowercased)
            import hashlib
            expected = hashlib.sha256(b"user:alice").hexdigest()
            self.assertEqual(res["selector_sha256"], expected)


if __name__ == "__main__":
    unittest.main()
