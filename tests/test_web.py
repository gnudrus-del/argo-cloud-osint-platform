import contextlib
import json
import tempfile
import threading
import unittest
from http import HTTPStatus
from pathlib import Path

from osint_bot.orchestrator import RunProfile
from osint_bot.storage import Storage
from osint_bot.web import (
    WebError,
    _content_disposition,
    _safe_str_equals,
    create_job,
    hash_password,
    list_jobs,
    parse_multipart_file,
    read_job,
    redact_report_json,
    verify_password,
)


@contextlib.contextmanager
def _isolated_storage():
    """Point web.STORAGE at a fresh on-disk SQLite DB under a temp dir.

    The web module's get_storage() lazy-caches Storage; the existing tests
    used to monkey-patch JOB_ROOT, but now state lives in SQLite, so we
    must reset web.STORAGE for each test.
    """
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
        depth=1,
        max_pages=1,
        notes=[],
    )


class WebTests(unittest.TestCase):
    def test_parse_multipart_file(self):
        boundary = "----test"
        body = (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="file"; filename="sample.txt"\r\n'
            "Content-Type: text/plain\r\n\r\n"
            "hello\r\n"
            f"--{boundary}--\r\n"
        ).encode()
        filename, data = parse_multipart_file(body, f"multipart/form-data; boundary={boundary}")

        self.assertEqual(filename, "sample.txt")
        self.assertEqual(data, b"hello")

    def test_password_hash_roundtrip(self):
        stored = hash_password("long-enough-password")
        self.assertTrue(verify_password("long-enough-password", stored))
        self.assertFalse(verify_password("wrong-password", stored))

    def test_create_job_exposes_pdf_link(self):
        with _isolated_storage():
            job = create_job(_profile(), {"modules": ["company_domain"]}, actor="test")
        self.assertIn("pdf", job["links"])
        self.assertTrue(job["links"]["pdf"].endswith("/report.pdf"))

    def test_list_jobs_filters_by_owner(self):
        with _isolated_storage():
            create_job(_profile(), {}, actor="alice")
            create_job(_profile(), {}, actor="bob")
            alice_jobs = list_jobs(owner="alice")
            bob_jobs = list_jobs(owner="bob")
            all_jobs = list_jobs()
        self.assertEqual({job["owner"] for job in alice_jobs}, {"alice"})
        self.assertEqual({job["owner"] for job in bob_jobs}, {"bob"})
        self.assertEqual(len(all_jobs), 2)

    def test_redact_report_json_redacts_emails_phones_and_target(self):
        payload = {
            "target": "+39 333 123 4567",
            "target_type": "phone",
            "entities": [
                {"type": "email", "value": "alice@example.com", "display_value": "alice@example.com"},
                {"type": "phone", "value": "+39 333 123 4567", "display_value": "+39 333 123 4567"},
                {"type": "domain", "value": "example.com", "display_value": "example.com"},
            ],
            "findings": [
                {"kind": "contact_email", "value": "alice@example.com"},
                {"kind": "phone_format", "value": "+39 333 123 4567"},
                {"kind": "related_domain", "value": "example.com"},
            ],
            "agent_results": [
                {
                    "name": "web",
                    "findings": [
                        {"kind": "contact_email", "value": "bob@example.com"},
                    ],
                }
            ],
            "pages": [{"emails": ["info@example.com"]}],
        }
        redacted = redact_report_json(payload)

        json_str = json.dumps(redacted)
        self.assertNotIn("alice@example.com", json_str)
        self.assertNotIn("bob@example.com", json_str)
        self.assertNotIn("info@example.com", json_str)
        self.assertNotIn("3331234567", json_str)
        self.assertNotIn("+39 333 123 4567", json_str)
        self.assertIn("example.com", json_str)

    def test_write_job_concurrent_reads_see_consistent_jobs(self):
        """Under contention, get_job() always returns a fully-formed dict.

        The old file-backed implementation had a tmpfile dance; SQLite gives
        us atomic writes via COMMIT, so a reader either sees the previous
        full payload or the new full payload — never something half-formed.
        """
        with _isolated_storage() as (_, store):
            job = create_job(_profile(), {}, actor="alice")
            job_id = job["id"]
            job["progress"] = [{"at": "x" * 200, "stage": "x", "message": "y" * 5000}] * 50

            stop = threading.Event()
            errors: list[Exception] = []

            def writer():
                for i in range(50):
                    if stop.is_set():
                        return
                    job["status"] = "running" if i % 2 == 0 else "complete"
                    from osint_bot.web import write_job
                    write_job(job_id, job)

            def reader():
                for _ in range(200):
                    if stop.is_set():
                        return
                    try:
                        record = store.get_job(job_id)
                    except Exception as exc:
                        errors.append(exc)
                        return
                    if record is None:
                        errors.append(RuntimeError("get_job returned None for an existing id"))
                        return
                    if "status" not in record:
                        errors.append(RuntimeError("record missing status"))
                        return

            writers = [threading.Thread(target=writer) for _ in range(2)]
            readers = [threading.Thread(target=reader) for _ in range(4)]
            for t in writers + readers:
                t.start()
            for t in writers:
                t.join()
            stop.set()
            for t in readers:
                t.join()

        self.assertEqual(errors, [], f"reader saw inconsistent state: {errors[:1]}")

    def test_safe_str_equals_matches_only_identical_strings(self):
        self.assertTrue(_safe_str_equals("token-abc", "token-abc"))
        self.assertFalse(_safe_str_equals("token-abc", "token-abd"))
        self.assertFalse(_safe_str_equals("token-abc", ""))
        self.assertFalse(_safe_str_equals("", "token-abc"))

    def test_recover_queued_jobs_re_enqueues_pending_work(self):
        """Server restart: queued + running jobs are re-submitted to the queue."""
        import osint_bot.web as web

        with _isolated_storage() as (_, store):
            # Simulate a job that was queued before the previous process died.
            queued_id = "c" * 32
            running_id = "d" * 32
            complete_id = "e" * 32
            for jid, status in ((queued_id, "queued"), (running_id, "running"), (complete_id, "complete")):
                store.put_job(jid, {
                    "id": jid,
                    "owner": "alice",
                    "status": status,
                    "created_at": web.now_iso(),
                    "updated_at": web.now_iso(),
                    "profile": {"target": "example.com", "target_type": "domain"},
                    "settings": {},
                })

            seen_specs: list[dict] = []
            original_dispatcher = web.JOB_QUEUE._dispatcher
            web.JOB_QUEUE.register_dispatcher(lambda spec: seen_specs.append(spec))
            try:
                count = web.recover_queued_jobs()
                # Give the worker a brief moment to drain the recovered specs.
                import time
                for _ in range(20):
                    if len(seen_specs) >= 2:
                        break
                    time.sleep(0.05)
            finally:
                web.JOB_QUEUE.register_dispatcher(original_dispatcher)

            self.assertEqual(count, 2)
            recovered_ids = {spec["job_id"] for spec in seen_specs}
            self.assertEqual(recovered_ids, {queued_id, running_id})
            # 'running' must have been demoted back to 'queued' so the UI is honest.
            self.assertEqual(store.get_job(running_id)["status"], "queued")
            # 'complete' must not have been touched.
            self.assertEqual(store.get_job(complete_id)["status"], "complete")

    def test_read_job_owner_mismatch_returns_404(self):
        with _isolated_storage():
            alice_job = create_job(_profile(), {}, actor="alice")
            read_job(alice_job["id"], requester="alice")
            with self.assertRaises(WebError) as ctx:
                read_job(alice_job["id"], requester="bob")
        self.assertEqual(ctx.exception.status, HTTPStatus.NOT_FOUND)


class ContentDispositionTests(unittest.TestCase):
    """Report/export downloads (report.pdf, report.json, ..., stix.json,
    misp.json) must force a real browser download rather than an inline
    view — without Content-Disposition: attachment, browsers with a built-in
    PDF/JSON/text viewer open the file in a new tab instead of downloading
    it, which is exactly the bug this header fixes."""

    def test_basic_filename_produces_attachment_header(self):
        self.assertEqual(_content_disposition("report.pdf"), 'attachment; filename="report.pdf"')

    def test_dangerous_characters_are_stripped(self):
        # CR/LF/quotes could otherwise break out of the filename value and
        # inject a second header; safe_filename() collapses them all to "_",
        # so the whole attempt stays inert text inside one filename="..."
        # value instead of splitting into a second header line. The literal
        # words survive (e.g. "Set-Cookie" as plain characters) -- that's
        # fine and expected; what matters is there is no CR/LF left to make
        # it a real header.
        header = _content_disposition('evil"\r\nSet-Cookie: pwn=1.pdf')
        self.assertNotIn("\r", header)
        self.assertNotIn("\n", header)
        self.assertEqual(header.count('"'), 2)  # exactly the wrapping quotes, none injected

    def test_stix_and_misp_kind_names_work_as_filenames(self):
        self.assertEqual(_content_disposition("stix.json"), 'attachment; filename="stix.json"')
        self.assertEqual(_content_disposition("misp.json"), 'attachment; filename="misp.json"')


class Pillar04GateTests(unittest.TestCase):
    """Phase 0.4: verify both gates are live on the web job path."""

    def test_execute_job_writes_darkweb_authorized_audit_event(self):
        """When a job runs with allow_darkweb=True and 'darkweb' in agents,
        execute_job must write a darkweb_authorized audit event BEFORE handing
        off to run_investigation, so the record exists even if the pipeline
        errors out later.
        """
        from unittest.mock import patch

        from osint_bot.web import execute_job

        profile = RunProfile(
            command="dark web monitoring example.com",
            target="example.com",
            target_type="domain",
            agents=["darkweb"],
            external_tools=[],
            seed_urls=[],
            depth=1,
            max_pages=1,
            notes=[],
        )
        with _isolated_storage() as (_, store):
            import osint_bot.web as web
            web.JOB_ROOT.mkdir(parents=True, exist_ok=True)
            job = create_job(profile, {"allow_darkweb": True}, actor="analyst")
            job_id = job["id"]

            with patch("osint_bot.web.run_investigation", return_value=(None, None)):
                execute_job(job_id, profile, {"allow_darkweb": True}, actor="analyst")

            actions = [e["action"] for e in store.all_audit_events()]
            self.assertIn(
                "darkweb_authorized",
                actions,
                "darkweb_authorized audit event not found; gate may not be wired",
            )

    def test_execute_job_ssn_target_marks_job_error_without_subprocess(self):
        """A web job whose target looks like an SSN must be rejected by
        assess_request before any subprocess or network call is made, and
        the job status must end up as 'error'.
        """
        from osint_bot.web import execute_job, read_job

        profile = RunProfile(
            command="cerca 123-45-6789",
            target="123-45-6789",
            target_type="person",
            agents=["planner"],
            external_tools=[],
            seed_urls=[],
            depth=1,
            max_pages=1,
            notes=[],
        )
        with _isolated_storage():
            import osint_bot.web as web
            web.JOB_ROOT.mkdir(parents=True, exist_ok=True)
            job = create_job(profile, {"confirm_authorization": True}, actor="analyst")
            job_id = job["id"]

            execute_job(job_id, profile, {"confirm_authorization": True}, actor="analyst")

            final = read_job(job_id)
            self.assertEqual(
                final["status"],
                "error",
                "Job with SSN-like target should have status 'error' after assess_request rejects it",
            )


if __name__ == "__main__":
    unittest.main()
