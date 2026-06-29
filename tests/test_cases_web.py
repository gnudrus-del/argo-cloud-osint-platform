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
        command="Analizza example.com",
        target="example.com",
        target_type="domain",
        agents=["web"],
        external_tools=[],
        seed_urls=[],
        depth=1, max_pages=1, notes=[],
    )


class CaseEndpointTests(unittest.TestCase):
    def test_create_case_requires_title(self):
        from osint_bot.web import WebError, create_case

        with _isolated_storage():
            with self.assertRaises(WebError) as ctx:
                create_case({}, actor="alice")
        self.assertEqual(ctx.exception.status, HTTPStatus.BAD_REQUEST)

    def test_create_case_audit_event(self):
        from osint_bot.web import create_case

        with _isolated_storage() as (_, store):
            case = create_case({"title": "Audit smoke", "legal_basis": {"type": "consent"}}, actor="alice")
            actions = [e["action"] for e in store.all_audit_events()]
            self.assertIn("case_created", actions)
            self.assertEqual(case["title"], "Audit smoke")

    def test_create_job_attaches_to_default_case_when_not_specified(self):
        from osint_bot.web import create_job, list_cases_for

        with _isolated_storage():
            job = create_job(_profile(), {}, actor="alice")
            self.assertTrue(job["case_id"])
            cases = list_cases_for("alice")
            # Default case lazily created.
            self.assertTrue(any(c["title"] == "Caso default" for c in cases))
            self.assertEqual(job["case_id"], next(c["id"] for c in cases if c["title"] == "Caso default"))

    def test_create_job_with_explicit_case_id_uses_it(self):
        from osint_bot.web import create_case, create_job

        with _isolated_storage():
            case = create_case({"title": "Op X"}, actor="alice")
            job = create_job(_profile(), {"case_id": case["id"]}, actor="alice")
            self.assertEqual(job["case_id"], case["id"])

    def test_create_job_with_unknown_case_id_is_rejected(self):
        from osint_bot.web import WebError, create_job

        with _isolated_storage():
            # Valid hex id that simply does not exist in the DB.
            with self.assertRaises(WebError) as ctx:
                create_job(_profile(), {"case_id": "0" * 32}, actor="alice")
        self.assertEqual(ctx.exception.status, HTTPStatus.NOT_FOUND)

    def test_create_job_with_malformed_case_id_is_rejected(self):
        from osint_bot.web import WebError, create_job

        with _isolated_storage():
            with self.assertRaises(WebError) as ctx:
                create_job(_profile(), {"case_id": "z" * 32}, actor="alice")
        self.assertEqual(ctx.exception.status, HTTPStatus.BAD_REQUEST)

    def test_other_user_cannot_target_case_of_alice(self):
        from osint_bot.web import WebError, create_case, create_job

        with _isolated_storage():
            case = create_case({"title": "Op alice"}, actor="alice")
            # Bob cannot create a job in alice's case.
            with self.assertRaises(WebError) as ctx:
                create_job(_profile(), {"case_id": case["id"]}, actor="bob")
        self.assertEqual(ctx.exception.status, HTTPStatus.NOT_FOUND)

    def test_legacy_migration_links_orphan_jobs_per_owner(self):
        from osint_bot.web import recover_legacy_jobs_into_cases

        with _isolated_storage() as (_, store):
            # Pre-seed two orphan jobs for two owners.
            for owner in ("alice", "bob"):
                for i in range(2):
                    jid = f"{owner[0]*30}{i:02d}"
                    store.put_job(jid, {
                        "id": jid, "owner": owner, "status": "complete",
                        "created_at": "x", "updated_at": "x", "profile": {},
                    })

            migrated = recover_legacy_jobs_into_cases()
            self.assertEqual(migrated, 4)
            # Each owner now has exactly one legacy case with their jobs.
            for owner in ("alice", "bob"):
                cases = store.list_cases(owner=owner)
                legacy = [c for c in cases if c["title"] == "Caso legacy"]
                self.assertEqual(len(legacy), 1)
                jobs = store.list_jobs_by_case(legacy[0]["id"])
                self.assertEqual(len(jobs), 2)
                self.assertTrue(all(j["owner"] == owner for j in jobs))

            # Re-running is a no-op (idempotent).
            self.assertEqual(recover_legacy_jobs_into_cases(), 0)

    def test_read_case_returns_404_for_other_owner(self):
        from osint_bot.web import WebError, create_case, read_case

        with _isolated_storage():
            case = create_case({"title": "Op alice"}, actor="alice")
            read_case(case["id"], requester="alice")
            with self.assertRaises(WebError) as ctx:
                read_case(case["id"], requester="bob")
        self.assertEqual(ctx.exception.status, HTTPStatus.NOT_FOUND)

    def test_collaborator_can_read_case(self):
        from osint_bot.web import create_case, read_case

        with _isolated_storage():
            case = create_case({"title": "Shared", "collaborators": ["bob"]}, actor="alice")
            # Bob is in the collaborator list, so he can read.
            self.assertEqual(read_case(case["id"], requester="bob")["id"], case["id"])


if __name__ == "__main__":
    unittest.main()
