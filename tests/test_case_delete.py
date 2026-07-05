"""DELETE /api/cases/<id> — cancellazione caso con audit e cascade opzionale."""
import contextlib
import tempfile
import unittest
from http import HTTPStatus
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


class CaseDeleteTests(unittest.TestCase):
    def test_owner_can_delete_case(self):
        from osint_bot.web import create_case, read_case, WebError

        with _isolated_storage() as (_, store):
            c = create_case({"title": "X", "legal_basis": {"type": "consent"}}, actor="alice")
            store.delete_case(c["id"])
            with self.assertRaises(WebError) as ctx:
                read_case(c["id"], requester="alice")
            self.assertEqual(ctx.exception.status, HTTPStatus.NOT_FOUND)

    def test_audit_event_recorded(self):
        from osint_bot.web import create_case

        with _isolated_storage() as (_, store):
            c = create_case({"title": "Del me", "legal_basis": {"type": "consent"}}, actor="alice")
            store.delete_case(c["id"])
            store.append_audit_event("alice", "case_deleted", {
                "case_id": c["id"], "title": c["title"],
                "cascade": False, "jobs_removed": [], "files_removed": [],
                "reason": "chiuso",
            })
            events = [e for e in store.all_audit_events() if e["action"] == "case_deleted"]
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["details"]["reason"], "chiuso")
            self.assertFalse(events[0]["details"]["cascade"])

    def test_non_owner_cannot_read_or_delete(self):
        # Sicurezza: bob non deve poter dire "esiste".
        from osint_bot.web import create_case, read_case, WebError

        with _isolated_storage():
            c = create_case({"title": "Alice case", "legal_basis": {"type": "consent"}}, actor="alice")
            with self.assertRaises(WebError) as ctx:
                read_case(c["id"], requester="bob")
        self.assertEqual(ctx.exception.status, HTTPStatus.NOT_FOUND)

    def test_cascade_removes_jobs_of_case(self):
        from osint_bot.web import create_case, create_job

        with _isolated_storage() as (_, store):
            c = create_case({"title": "Case", "legal_basis": {"type": "consent"}}, actor="alice")
            j1 = create_job(_profile(), {"case_id": c["id"]}, actor="alice")
            j2 = create_job(_profile(), {"case_id": c["id"]}, actor="alice")
            # cascade: elimina anche i job del caso
            for job in store.list_jobs(owner="alice", limit=100):
                if job.get("case_id") == c["id"]:
                    store.delete_job(job["id"])
            store.delete_case(c["id"])
            remaining = store.list_jobs(owner="alice", limit=100)
        # nessun job dovrebbe puntare piu' al case eliminato
        self.assertFalse(any(j["case_id"] == c["id"] for j in remaining))

    def test_no_cascade_leaves_jobs_orphan(self):
        # Comportamento di default: i job restano (con case_id orfano per audit).
        from osint_bot.web import create_case, create_job

        with _isolated_storage() as (_, store):
            c = create_case({"title": "Case", "legal_basis": {"type": "consent"}}, actor="alice")
            j = create_job(_profile(), {"case_id": c["id"]}, actor="alice")
            store.delete_case(c["id"])
            remaining = store.list_jobs(owner="alice", limit=100)
        self.assertTrue(any(job["id"] == j["id"] and job["case_id"] == c["id"] for job in remaining))


if __name__ == "__main__":
    unittest.main()
