import contextlib
import json
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


class BuildCaseProfileTests(unittest.TestCase):
    """Regression tests for build_case_profile (GET .../profile.json's
    logic). Before this fix: 0 completed jobs meant a 404 the frontend
    only console.warn'd, and even when jobs DID complete, agent_results
    (why a connector returned nothing — missing key, policy_denied,
    cached, ...) never reached the aggregate case view at all. A user
    with unconfigured BYOK keys saw "0 evidenze" indistinguishable from
    "there's genuinely nothing online about this person"."""

    def test_no_jobs_returns_empty_report_not_404(self):
        from osint_bot.web import build_case_profile, create_case

        with _isolated_storage():
            case = create_case({"title": "Empty case"}, actor="alice")
            report = build_case_profile(case["id"], case)
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["job_status_summary"], {})
        self.assertEqual(report["failed_jobs"], [])

    def test_error_job_surfaces_in_failed_jobs_without_leaking_target(self):
        from osint_bot.web import build_case_profile, create_case, write_job

        with _isolated_storage():
            case = create_case({"title": "T"}, actor="alice")
            write_job("a" * 32, {
                "id": "a" * 32, "owner": "alice", "case_id": case["id"],
                "status": "error", "error": "boom: connector crashed",
                "profile": {"target": "secret@example.com", "target_type": "email"},
                "settings": {},
            })
            report = build_case_profile(case["id"], case)
        self.assertEqual(report["job_status_summary"], {"error": 1})
        self.assertEqual(len(report["failed_jobs"]), 1)
        self.assertEqual(report["failed_jobs"][0]["job_id"], "a" * 32)
        self.assertIn("boom", report["failed_jobs"][0]["error"])
        self.assertNotIn("target", report["failed_jobs"][0])

    def test_complete_job_merges_findings_and_agent_results(self):
        from osint_bot.web import build_case_profile, create_case, write_job

        with _isolated_storage() as (tmp, _store):
            case = create_case({"title": "T"}, actor="alice")
            report_dir = tmp / "job1"
            report_dir.mkdir()
            json_path = report_dir / "report.json"
            json_path.write_text(json.dumps({
                "target": "example.com", "target_type": "domain",
                "findings": [
                    {"kind": "email_registered", "value": "a@example.com", "confidence": 0.8},
                ],
                "agent_results": [{
                    "name": "connectors", "status": "ok", "summary": "5/12 ok",
                    "notes": ["cached=1,error=2,missing_key=3,ok=5,policy_denied=1"],
                    "findings": [],
                }],
            }), encoding="utf-8")
            write_job("b" * 32, {
                "id": "b" * 32, "owner": "alice", "case_id": case["id"],
                "status": "complete", "json_path": str(json_path),
                "settings": {"include_contact": True},
            })
            report = build_case_profile(case["id"], case)
        self.assertEqual(len(report["findings"]), 1)
        self.assertEqual(report["findings"][0]["value"], "a@example.com")
        self.assertEqual(len(report["agent_results"]), 1)
        self.assertEqual(report["agent_results"][0]["name"], "connectors")
        self.assertIn("cached=1", report["agent_results"][0]["notes"][0])
        self.assertEqual(report["job_status_summary"], {"complete": 1})

    def test_mixed_statuses_all_counted(self):
        from osint_bot.web import build_case_profile, create_case, write_job

        with _isolated_storage():
            case = create_case({"title": "T"}, actor="alice")
            write_job("c" * 32, {"id": "c" * 32, "owner": "alice", "case_id": case["id"], "status": "queued"})
            write_job("d" * 32, {"id": "d" * 32, "owner": "alice", "case_id": case["id"], "status": "running"})
            write_job("e" * 32, {"id": "e" * 32, "owner": "alice", "case_id": case["id"], "status": "error", "error": "x"})
            report = build_case_profile(case["id"], case)
        self.assertEqual(report["job_status_summary"], {"queued": 1, "running": 1, "error": 1})
        self.assertEqual(len(report["failed_jobs"]), 1)


if __name__ == "__main__":
    unittest.main()
