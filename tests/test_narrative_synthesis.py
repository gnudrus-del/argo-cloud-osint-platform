"""osint_bot.narrative_synthesis — capability IA opt-in #1. Ogni test mocka
osint_bot.llm_client.complete: nessuna chiamata di rete reale."""
from __future__ import annotations

import contextlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from osint_bot import llm_client


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


def _write_job(tmp, store, job_id, case_id, findings):
    report_dir = tmp / job_id / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    json_path = report_dir / "report.json"
    json_path.write_text(json.dumps({"findings": findings}), encoding="utf-8")
    store.put_job(job_id, {
        "id": job_id, "owner": "alice", "case_id": case_id, "status": "complete",
        "json_path": str(json_path), "created_at": "now", "updated_at": "now",
    })


def _llm_response(parsed, ok=True, error="", error_class=""):
    return llm_client.LLMResponse(
        provider="anthropic", model="claude-sonnet-5", parsed=parsed if ok else None,
        raw_text=json.dumps(parsed) if parsed else "", latency_ms=1, http_status=200,
        error=error, error_class=error_class,
    )


class ValidateTests(unittest.TestCase):
    def test_valid_citations_pass(self):
        from osint_bot.narrative_synthesis import validate
        parsed = {"summary_paragraph": "x [F#job1#0]", "sections": [],
                  "citations_used": ["job1#0"], "caveats": []}
        result = validate(parsed, {"job1#0", "job1#1"})
        self.assertTrue(result.ok)

    def test_hallucinated_citation_hard_fails(self):
        from osint_bot.narrative_synthesis import validate
        parsed = {"summary_paragraph": "x", "sections": [],
                  "citations_used": ["job1#99"], "caveats": []}
        result = validate(parsed, {"job1#0"})
        self.assertFalse(result.ok)
        self.assertIn("job1#99", result.dropped_hallucinated)

    def test_citation_in_section_body_also_checked(self):
        from osint_bot.narrative_synthesis import validate
        parsed = {"summary_paragraph": "", "sections": [
            {"heading": "h", "body": "b", "citations": ["job1#99"]}
        ], "citations_used": [], "caveats": []}
        result = validate(parsed, {"job1#0"})
        self.assertFalse(result.ok)

    def test_no_citations_at_all_fails(self):
        from osint_bot.narrative_synthesis import validate
        parsed = {"summary_paragraph": "no evidence cited", "sections": [],
                  "citations_used": [], "caveats": []}
        result = validate(parsed, {"job1#0"})
        self.assertFalse(result.ok)

    def test_non_dict_response_fails(self):
        from osint_bot.narrative_synthesis import validate
        result = validate(None, {"job1#0"})
        self.assertFalse(result.ok)


class GenerateTests(unittest.TestCase):
    def test_success_path(self):
        from osint_bot.narrative_synthesis import generate
        with _isolated_storage() as (tmp, store):
            store.put_case({"id": "c" * 32, "owner": "alice", "title": "Caso"})
            _write_job(tmp, store, "job1", "c" * 32, [
                {"kind": "domain", "value": "a.com", "confidence": 0.9, "severity": "high", "evidence": []},
            ])
            fake = {"summary_paragraph": "Il dominio a.com [F#job1#0] è rilevante.",
                   "sections": [], "citations_used": ["job1#0"], "caveats": []}
            with patch("osint_bot.llm_client.complete", return_value=_llm_response(fake)):
                response, validation, collected = generate(
                    case_id="c" * 32, case_title="Caso", provider="anthropic",
                    model="claude-sonnet-5", api_key="sk-ant-x",
                )
            self.assertTrue(validation.ok)
            self.assertEqual(len(collected.refs), 1)

    def test_hallucination_triggers_one_repair_retry(self):
        from osint_bot.narrative_synthesis import generate
        with _isolated_storage() as (tmp, store):
            store.put_case({"id": "c" * 32, "owner": "alice", "title": "Caso"})
            _write_job(tmp, store, "job1", "c" * 32, [
                {"kind": "domain", "value": "a.com", "confidence": 0.9, "severity": "high", "evidence": []},
            ])
            bad = {"summary_paragraph": "x [F#job1#99]", "sections": [],
                  "citations_used": ["job1#99"], "caveats": []}
            good = {"summary_paragraph": "x [F#job1#0]", "sections": [],
                   "citations_used": ["job1#0"], "caveats": []}
            with patch("osint_bot.llm_client.complete", side_effect=[
                _llm_response(bad), _llm_response(good),
            ]) as mocked:
                response, validation, collected = generate(
                    case_id="c" * 32, case_title="Caso", provider="anthropic",
                    model="claude-sonnet-5", api_key="sk-ant-x",
                )
            self.assertTrue(validation.ok)
            self.assertEqual(mocked.call_count, 2)

    def test_persistent_hallucination_fails_after_retry(self):
        from osint_bot.narrative_synthesis import generate
        with _isolated_storage() as (tmp, store):
            store.put_case({"id": "c" * 32, "owner": "alice", "title": "Caso"})
            _write_job(tmp, store, "job1", "c" * 32, [
                {"kind": "domain", "value": "a.com", "confidence": 0.9, "severity": "high", "evidence": []},
            ])
            bad = {"summary_paragraph": "x [F#job1#99]", "sections": [],
                  "citations_used": ["job1#99"], "caveats": []}
            with patch("osint_bot.llm_client.complete", return_value=_llm_response(bad)) as mocked:
                response, validation, collected = generate(
                    case_id="c" * 32, case_title="Caso", provider="anthropic",
                    model="claude-sonnet-5", api_key="sk-ant-x",
                )
            self.assertFalse(validation.ok)
            self.assertEqual(mocked.call_count, 2)

    def test_llm_error_short_circuits_without_retry(self):
        from osint_bot.narrative_synthesis import generate
        with _isolated_storage() as (tmp, store):
            store.put_case({"id": "c" * 32, "owner": "alice", "title": "Caso"})
            _write_job(tmp, store, "job1", "c" * 32, [
                {"kind": "domain", "value": "a.com", "confidence": 0.9, "severity": "high", "evidence": []},
            ])
            err = _llm_response(None, ok=False, error="timeout", error_class="timeout")
            with patch("osint_bot.llm_client.complete", return_value=err) as mocked:
                response, validation, collected = generate(
                    case_id="c" * 32, case_title="Caso", provider="anthropic",
                    model="claude-sonnet-5", api_key="sk-ant-x",
                )
            self.assertFalse(validation.ok)
            mocked.assert_called_once()


if __name__ == "__main__":
    unittest.main()
