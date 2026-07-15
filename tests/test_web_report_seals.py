"""End-to-end (via le funzioni handle_seal_job/handle_get_seal/
handle_request_tsa_timestamp di web.py, non HTTP grezzo — stesso pattern di
tests/test_web_ai_endpoints.py) del sigillo automatico, del gate leggero sul
timestamp RFC3161 e degli eventi audit. Nessuna chiamata di rete reale:
osint_bot.tsa_client.request_timestamp e' sempre mockato."""
from __future__ import annotations

import base64
import contextlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from osint_bot import tsa_client

_FIXTURES_DIR = Path(__file__).parent / "fixtures"
CASE_ID = "c" * 32
JOB_ID = "1" * 32


@contextlib.contextmanager
def _isolated_storage():
    import osint_bot.web as web
    from osint_bot.storage import Storage

    with tempfile.TemporaryDirectory() as tmp:
        original_root = web.JOB_ROOT
        original_storage = web.STORAGE
        original_tsa = os.environ.get("TSA_URL")
        web.JOB_ROOT = Path(tmp)
        web.STORAGE = Storage(Path(tmp) / "gufo.sqlite3")
        os.environ.pop("TSA_URL", None)
        try:
            yield Path(tmp), web.STORAGE
        finally:
            try:
                web.STORAGE.close()
            except Exception:
                pass
            web.JOB_ROOT = original_root
            web.STORAGE = original_storage
            if original_tsa is None:
                os.environ.pop("TSA_URL", None)
            else:
                os.environ["TSA_URL"] = original_tsa


def _write_completed_job(tmp, store, *, job_id=JOB_ID, case_id=CASE_ID, owner="alice"):
    reports_dir = tmp / job_id / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    md_path = reports_dir / "report.md"
    md_path.write_text("# Report finale", encoding="utf-8")
    job = {
        "id": job_id, "owner": owner, "case_id": case_id, "status": "complete",
        "markdown_path": str(md_path), "json_path": "", "pdf_path": "",
        "forensic_markdown_path": "", "forensic_json_path": "",
        "redteam_markdown_path": "", "redteam_json_path": "",
        "created_at": "now", "updated_at": "now",
    }
    store.put_job(job_id, job)
    return job


def _fake_tsa_result(**overrides):
    defaults = dict(
        ok=True, status="granted", status_string="", token_der_b64="ZGVhZGJlZWY=",
        gen_time="2026-07-15T05:25:04+00:00", http_status=200, error="", error_class="",
    )
    defaults.update(overrides)
    return tsa_client.TSAResult(**defaults)


class SealOnJobCompletionTests(unittest.TestCase):
    def test_seal_is_created_without_manual_action(self):
        import osint_bot.web as web
        with _isolated_storage() as (tmp, store):
            store.put_case({"id": CASE_ID, "owner": "alice", "title": "T"})
            job = _write_completed_job(tmp, store)
            web.handle_seal_job(JOB_ID, job, "alice")
            seal = store.get_report_seal(JOB_ID)
            self.assertIsNotNone(seal)
            self.assertEqual(seal["case_id"], CASE_ID)
            self.assertEqual(len(seal["signing_pubkey_fingerprint"]), 64)
            self.assertEqual(seal["tsa_status"], "")  # nessun timestamp richiesto ancora

    def test_seal_writes_report_sealed_audit_event_without_secrets(self):
        import osint_bot.web as web
        with _isolated_storage() as (tmp, store):
            store.put_case({"id": CASE_ID, "owner": "alice", "title": "T"})
            job = _write_completed_job(tmp, store)
            web.handle_seal_job(JOB_ID, job, "alice")
            events = [e for e in store.all_audit_events() if e["action"] == "report_sealed"]
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["details"]["job_id"], JOB_ID)
            self.assertIn("manifest_hash", events[0]["details"])
            self.assertIn("signing_pubkey_fingerprint", events[0]["details"])
            # mai la firma o la chiave privata negli audit details
            self.assertNotIn("signature_b64", events[0]["details"])
            self.assertNotIn("private", str(events[0]["details"]).lower())

    def test_seal_covers_prior_case_evidence_too(self):
        """Il manifest e' case-scoped e cumulativo (vedi custody.py): un
        artifact raccolto prima del sigillo entra nel manifest_hash."""
        import osint_bot.web as web
        from osint_bot import custody
        with _isolated_storage() as (tmp, store):
            store.put_case({"id": CASE_ID, "owner": "alice", "title": "T"})
            custody.save_artifact(artifact_type="tool_output", content="raw evidence",
                                   case_id=CASE_ID, tool_name="sherlock", storage=store)
            job = _write_completed_job(tmp, store)
            web.handle_seal_job(JOB_ID, job, "alice")
            seal = store.get_report_seal(JOB_ID)
            self.assertEqual(seal["artifact_count"], 2)  # 1 evidenza + 1 report_output

    def test_resealing_same_job_keeps_seal_id_stable(self):
        import osint_bot.web as web
        with _isolated_storage() as (tmp, store):
            store.put_case({"id": CASE_ID, "owner": "alice", "title": "T"})
            job = _write_completed_job(tmp, store)
            first = web.handle_seal_job(JOB_ID, job, "alice")
            second = web.handle_seal_job(JOB_ID, job, "alice")
            self.assertEqual(first["id"], second["id"])


class GetSealTests(unittest.TestCase):
    def test_get_seal_includes_verify_hint(self):
        import osint_bot.web as web
        with _isolated_storage() as (tmp, store):
            store.put_case({"id": CASE_ID, "owner": "alice", "title": "T"})
            job = _write_completed_job(tmp, store)
            web.handle_seal_job(JOB_ID, job, "alice")
            result = web.handle_get_seal(JOB_ID, "alice")
            self.assertIn("verify_hint", result)
            self.assertEqual(result["job_id"], JOB_ID)

    def test_get_seal_404_when_not_sealed(self):
        import osint_bot.web as web
        with _isolated_storage() as (tmp, store):
            store.put_case({"id": CASE_ID, "owner": "alice", "title": "T"})
            _write_completed_job(tmp, store)  # mai sigillato: nessuna chiamata a handle_seal_job
            with self.assertRaises(web.WebError) as ctx:
                web.handle_get_seal(JOB_ID, "alice")
            self.assertEqual(ctx.exception.status, 404)

    def test_get_seal_404_for_non_owner(self):
        """Stesso pattern anti-existence-leak di read_job: un estraneo vede
        404, non 403."""
        import osint_bot.web as web
        with _isolated_storage() as (tmp, store):
            store.put_case({"id": CASE_ID, "owner": "alice", "title": "T"})
            job = _write_completed_job(tmp, store)
            web.handle_seal_job(JOB_ID, job, "alice")
            with self.assertRaises(web.WebError) as ctx:
                web.handle_get_seal(JOB_ID, "mallory")
            self.assertEqual(ctx.exception.status, 404)


class TsaGateTests(unittest.TestCase):
    def test_404_when_tsa_url_not_configured(self):
        import osint_bot.web as web
        with _isolated_storage() as (tmp, store):
            store.put_case({"id": CASE_ID, "owner": "alice", "title": "T"})
            job = _write_completed_job(tmp, store)
            web.handle_seal_job(JOB_ID, job, "alice")
            with self.assertRaises(web.WebError) as ctx:
                web.handle_request_tsa_timestamp(JOB_ID, "alice")
            self.assertEqual(ctx.exception.status, 404)

    def test_404_when_job_not_yet_sealed(self):
        import osint_bot.web as web
        with _isolated_storage() as (tmp, store):
            store.put_case({"id": CASE_ID, "owner": "alice", "title": "T"})
            _write_completed_job(tmp, store)
            with patch.dict(os.environ, {"TSA_URL": "https://tsa.example/"}):
                with self.assertRaises(web.WebError) as ctx:
                    web.handle_request_tsa_timestamp(JOB_ID, "alice")
            self.assertEqual(ctx.exception.status, 404)

    def test_capabilities_reports_tsa_configured_state(self):
        import osint_bot.web as web
        with _isolated_storage():
            self.assertFalse(web.capabilities()["report_sealing"]["tsa_configured"])
            with patch.dict(os.environ, {"TSA_URL": "https://timestamp.example.org/tsr"}):
                caps = web.capabilities()
            self.assertTrue(caps["report_sealing"]["tsa_configured"])
            self.assertEqual(caps["report_sealing"]["tsa_host"], "timestamp.example.org")
            self.assertTrue(caps["report_sealing"]["always_on"])


class TsaSuccessAndFailureTests(unittest.TestCase):
    def test_success_attaches_token_and_audits(self):
        import osint_bot.web as web
        with _isolated_storage() as (tmp, store):
            store.put_case({"id": CASE_ID, "owner": "alice", "title": "T"})
            job = _write_completed_job(tmp, store)
            web.handle_seal_job(JOB_ID, job, "alice")
            with patch.dict(os.environ, {"TSA_URL": "https://tsa.example/"}), \
                 patch("osint_bot.tsa_client.request_timestamp", return_value=_fake_tsa_result()):
                updated = web.handle_request_tsa_timestamp(JOB_ID, "alice")
            self.assertEqual(updated["tsa_status"], "granted")
            self.assertEqual(updated["tsa_gen_time"], "2026-07-15T05:25:04+00:00")
            events = [e["action"] for e in store.all_audit_events()]
            self.assertIn("report_timestamp_requested", events)
            self.assertIn("report_timestamp_received", events)
            # l'host va nell'audit, mai l'URL completo con eventuale query string
            requested = next(e for e in store.all_audit_events() if e["action"] == "report_timestamp_requested")
            self.assertEqual(requested["details"]["tsa_host"], "tsa.example")

    def test_failure_is_audited_and_raises_502(self):
        import osint_bot.web as web
        with _isolated_storage() as (tmp, store):
            store.put_case({"id": CASE_ID, "owner": "alice", "title": "T"})
            job = _write_completed_job(tmp, store)
            web.handle_seal_job(JOB_ID, job, "alice")
            failed = _fake_tsa_result(ok=False, status="rejection", token_der_b64="",
                                       gen_time="", error="TSA rifiuta la richiesta",
                                       error_class="rejected")
            with patch.dict(os.environ, {"TSA_URL": "https://tsa.example/"}), \
                 patch("osint_bot.tsa_client.request_timestamp", return_value=failed):
                with self.assertRaises(web.WebError) as ctx:
                    web.handle_request_tsa_timestamp(JOB_ID, "alice")
            self.assertEqual(ctx.exception.status, 502)
            events = [e["action"] for e in store.all_audit_events()]
            self.assertIn("report_timestamp_failed", events)
            # anche il fallimento aggiorna la riga (stato visibile, non silenzioso).
            # tsa_status riporta lo status PKI riportato dalla TSA quando c'e'
            # (qui "rejection", il valore vero riportato dal protocollo RFC3161),
            # non error_class — quest'ultimo e' solo un fallback per gli errori
            # di rete/HTTP dove nessuna risposta TSA e' mai stata parsata.
            seal = store.get_report_seal(JOB_ID)
            self.assertEqual(seal["tsa_status"], "rejection")

    def test_real_captured_response_end_to_end(self):
        """La stessa fixture reale usata in test_tsa_client.py, ma attraverso
        l'intero handler web (non solo il parsing)."""
        import osint_bot.web as web
        body_b64 = (_FIXTURES_DIR / "tsa_response_digicert_granted.b64").read_text().strip()

        def _fake_open_url(*args, **kwargs):
            return (200, base64.b64decode(body_b64), {})

        with _isolated_storage() as (tmp, store):
            store.put_case({"id": CASE_ID, "owner": "alice", "title": "T"})
            job = _write_completed_job(tmp, store)
            web.handle_seal_job(JOB_ID, job, "alice")
            with patch.dict(os.environ, {"TSA_URL": "https://tsa.example/"}), \
                 patch("osint_bot._safe_http.open_url", side_effect=_fake_open_url):
                updated = web.handle_request_tsa_timestamp(JOB_ID, "alice")
            self.assertEqual(updated["tsa_status"], "granted")
            self.assertTrue(updated["tsa_gen_time"].startswith("2026-07-15"))


class PublicKeyEndpointTests(unittest.TestCase):
    def test_public_key_stable_across_calls(self):
        from osint_bot import report_signing
        with _isolated_storage() as (tmp, _store):
            first = report_signing.export_public_key(tmp)
            second = report_signing.export_public_key(tmp)
            self.assertEqual(first["fingerprint_sha256"], second["fingerprint_sha256"])
            self.assertEqual(set(first), {"algorithm", "public_key_b64", "fingerprint_sha256"})


if __name__ == "__main__":
    unittest.main()
