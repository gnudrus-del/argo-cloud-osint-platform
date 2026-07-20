"""DELETE /api/jobs/<id>: cancellazione granulare di un singolo report.

Punti critici testati:
  - Solo l'owner puo' cancellare (404 a chi non possiede, no leak di esistenza).
  - I file su disco vengono rimossi.
  - Il record DB viene rimosso.
  - L'audit log REGISTRA la cancellazione (no "anti-forensics": cancello
    i DATI, non l'azione di cancellazione).
"""
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


class DeleteJobTests(unittest.TestCase):
    def test_artifacts_helper_removes_existing_files_only(self):
        from osint_bot.web import delete_job_artifacts

        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            md = tmp / "report.md"; md.write_text("x")
            jsn = tmp / "report.json"; jsn.write_text("{}")
            removed = delete_job_artifacts({
                "markdown_path": str(md),
                "json_path": str(jsn),
                "pdf_path": "",          # vuoto: ignorato
                "forensic_json_path": str(tmp / "missing.json"),  # non esiste: ignorato
            })
        self.assertIn(str(md), removed)
        self.assertIn(str(jsn), removed)
        self.assertFalse(md.exists())
        self.assertFalse(jsn.exists())

    def test_storage_delete_job_returns_rowcount(self):
        from osint_bot.web import create_job

        with _isolated_storage() as (_, store):
            job = create_job(_profile(), {}, actor="alice")
            self.assertEqual(store.delete_job(job["id"]), 1)
            # Idempotente: cancellare due volte non lancia, restituisce 0.
            self.assertEqual(store.delete_job(job["id"]), 0)

    def test_audit_event_recorded_on_delete(self):
        # Simula il flusso del handler senza HTTP: storage + audit.
        from osint_bot.web import create_job, delete_job_artifacts

        with _isolated_storage() as (_, store):
            job = create_job(_profile(), {}, actor="alice")
            removed = delete_job_artifacts(job)
            rows = store.delete_job(job["id"])
            store.append_audit_event("alice", "job_deleted", {
                "job_id": job["id"],
                "case_id": job["case_id"],
                "files_removed": removed,
                "rows_removed": rows,
                "reason": "fine ingaggio",
            })
            # NB: leggere events DENTRO il with — fuori, il tempdir e' rimosso
            # e SQLite non riesce piu' ad aprire il file.
            events = [e for e in store.all_audit_events() if e["action"] == "job_deleted"]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["details"]["job_id"], job["id"])
        self.assertEqual(events[0]["details"]["reason"], "fine ingaggio")

    def test_non_owner_cannot_read_then_delete(self):
        # Sicurezza: read_job e' la guardia. Verifico che bob NON veda alice.
        from osint_bot.web import WebError, create_job, read_job

        with _isolated_storage():
            job = create_job(_profile(), {}, actor="alice")
            with self.assertRaises(WebError) as ctx:
                read_job(job["id"], requester="bob")
        # 404 (non 403) per non leakare l'esistenza.
        self.assertEqual(ctx.exception.status, HTTPStatus.NOT_FOUND)

    def test_owner_can_read_own_job(self):
        from osint_bot.web import create_job, read_job

        with _isolated_storage():
            job = create_job(_profile(), {}, actor="alice")
            j = read_job(job["id"], requester="alice")
        self.assertEqual(j["id"], job["id"])

    def test_execute_job_on_deleted_queued_job_does_not_raise_regression(self):
        # Regression: handle_job_delete lets a job in ANY status (including
        # "queued") be deleted. If the worker then dequeues that job_id,
        # execute_job's read_job() raises. Before the fix, that exception
        # propagated straight out of execute_job — job_queue.py's own fix
        # (a try/except around the handler call) stops it from killing the
        # worker thread, but this test verifies the deeper fix: the
        # specific failure is now recorded (job_error audit event) instead
        # of vanishing into a server log line with zero trace for this
        # job_id, and execute_job itself never raises.
        from osint_bot.web import create_job, execute_job, get_storage

        with _isolated_storage() as (_, store):
            job = create_job(_profile(), {}, actor="alice")
            job_id = job["id"]
            store.delete_job(job_id)  # same effect as handle_job_delete
            try:
                execute_job(job_id, _profile(), {}, actor="alice")
            except Exception as exc:  # pragma: no cover - defect, not expected
                self.fail(f"execute_job raised instead of handling the missing job: {exc}")
            events = [e for e in get_storage().all_audit_events()
                      if e["action"] == "job_error" and e["details"].get("job_id") == job_id]
        self.assertEqual(len(events), 1)


if __name__ == "__main__":
    unittest.main()
