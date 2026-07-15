"""osint_bot.triage_ai — capability IA opt-in #3. generate() mocka
osint_bot.llm_client.complete; nessuna chiamata di rete reale."""
from __future__ import annotations

import contextlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from osint_bot import ai_context, llm_client


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


def _llm_response(parsed, ok=True, error=""):
    return llm_client.LLMResponse(
        provider="anthropic", model="claude-sonnet-5", parsed=parsed if ok else None,
        raw_text=json.dumps(parsed) if parsed else "", latency_ms=1, http_status=200,
        error=error, error_class="" if ok else "network_error",
    )


class BatchingTests(unittest.TestCase):
    def test_splits_into_batches_of_120(self):
        from osint_bot import triage_ai
        refs = [ai_context.CaseFindingRef(job_id="j", index=i, finding_id=f"j#{i}", finding=None) for i in range(250)]
        batches = triage_ai.split_into_batches(refs)
        self.assertEqual([len(b) for b in batches], [120, 120, 10])

    def test_caps_at_max_batches(self):
        from osint_bot import triage_ai
        refs = [ai_context.CaseFindingRef(job_id="j", index=i, finding_id=f"j#{i}", finding=None) for i in range(1000)]
        batches = triage_ai.split_into_batches(refs)
        self.assertEqual(len(batches), 6)
        self.assertEqual(sum(len(b) for b in batches), 720)


class ValidateTests(unittest.TestCase):
    def test_valid_ranking_kept(self):
        from osint_bot.triage_ai import validate
        parsed = {"rankings": [{"finding_id": "j#0", "priority_bucket": "high", "rationale": "x"}]}
        result = validate(parsed, {"j#0"})
        self.assertTrue(result.ok)
        self.assertEqual(result.rankings[0]["priority_bucket"], "high")
        self.assertFalse(result.rankings[0]["fallback"])

    def test_unknown_id_dropped_and_counted(self):
        from osint_bot.triage_ai import validate
        parsed = {"rankings": [{"finding_id": "j#99", "priority_bucket": "high", "rationale": "invented"}]}
        result = validate(parsed, {"j#0"})
        self.assertTrue(result.ok)
        self.assertEqual(result.rankings, [])
        self.assertEqual(result.dropped_hallucinated, 1)

    def test_invalid_bucket_normalized_to_noise(self):
        from osint_bot.triage_ai import validate
        parsed = {"rankings": [{"finding_id": "j#0", "priority_bucket": "urgentissimo", "rationale": "x"}]}
        result = validate(parsed, {"j#0"})
        self.assertEqual(result.rankings[0]["priority_bucket"], "noise")


class FallbackBucketTests(unittest.TestCase):
    def test_severity_maps_to_expected_bucket(self):
        from osint_bot.triage_ai import _fallback_bucket_for
        self.assertEqual(_fallback_bucket_for("critical"), "critical_now")
        self.assertEqual(_fallback_bucket_for("high"), "high")
        self.assertEqual(_fallback_bucket_for("medium"), "medium")
        self.assertEqual(_fallback_bucket_for("low"), "low")
        self.assertEqual(_fallback_bucket_for("info"), "noise")
        self.assertEqual(_fallback_bucket_for(""), "noise")
        self.assertEqual(_fallback_bucket_for("unknown-severity"), "noise")


class GenerateTests(unittest.TestCase):
    def test_every_finding_gets_a_ranking_even_with_partial_ai_coverage(self):
        from osint_bot.triage_ai import generate
        with _isolated_storage() as (tmp, store):
            store.put_case({"id": "c" * 32, "owner": "alice", "title": "T"})
            findings = [
                {"kind": "domain", "value": f"d{i}.com", "confidence": 0.5, "severity": sev, "evidence": []}
                for i, sev in enumerate(["critical", "high", "medium", "low", "info"])
            ]
            _write_job(tmp, store, "job1", "c" * 32, findings)
            collected = ai_context.collect_case_findings("c" * 32)
            fake = {"rankings": [
                {"finding_id": collected.refs[0].finding_id, "priority_bucket": "critical_now", "rationale": "x"},
                {"finding_id": collected.refs[1].finding_id, "priority_bucket": "high", "rationale": "y"},
                {"finding_id": "j#999", "priority_bucket": "high", "rationale": "invented"},
            ]}
            with patch("osint_bot.llm_client.complete", return_value=_llm_response(fake)):
                result = generate(case_id="c" * 32, provider="anthropic", model="claude-sonnet-5", api_key="sk-ant-x")

            self.assertEqual(len(result.rankings), 5)  # mai un finding senza ranking
            self.assertEqual(result.coverage["ai_ranked"], 2)
            self.assertEqual(result.coverage["fallback_ranked"], 3)
            self.assertEqual(result.coverage["dropped_hallucinated"], 1)
            self.assertEqual(result.coverage["total"], 5)
            fallback_rows = [r for r in result.rankings if r["fallback"]]
            self.assertEqual(len(fallback_rows), 3)
            # il finding 'info' deve ricadere deterministicamente su 'noise'
            info_ref = collected.refs[4]
            info_ranking = next(r for r in result.rankings if r["finding_id"] == info_ref.finding_id)
            self.assertEqual(info_ranking["priority_bucket"], "noise")

    def test_batch_failure_falls_back_for_that_batch_entirely(self):
        from osint_bot.triage_ai import generate
        with _isolated_storage() as (tmp, store):
            store.put_case({"id": "c" * 32, "owner": "alice", "title": "T"})
            findings = [{"kind": "domain", "value": "d.com", "confidence": 0.5, "severity": "critical", "evidence": []}]
            _write_job(tmp, store, "job1", "c" * 32, findings)
            err = _llm_response(None, ok=False, error="network down")
            with patch("osint_bot.llm_client.complete", return_value=err):
                result = generate(case_id="c" * 32, provider="anthropic", model="claude-sonnet-5", api_key="sk-ant-x")
            self.assertEqual(len(result.rankings), 1)
            self.assertTrue(result.rankings[0]["fallback"])
            self.assertEqual(result.coverage["ai_ranked"], 0)
            self.assertEqual(result.coverage["fallback_ranked"], 1)

    def test_findings_beyond_batch_cap_still_get_deterministic_ranking(self):
        from osint_bot.triage_ai import generate
        with _isolated_storage() as (tmp, store):
            store.put_case({"id": "c" * 32, "owner": "alice", "title": "T"})
            # 130 finding -> 2 batch (120 + 10), entrambi entro il cap di 6 batch,
            # ma nessuno viene "coperto" dal mock (risponde sempre rankings vuoti)
            # cosi' tutti i 130 finiscono in fallback per verificare la copertura totale.
            findings = [{"kind": "domain", "value": f"d{i}.com", "confidence": 0.5, "severity": "low", "evidence": []}
                       for i in range(130)]
            _write_job(tmp, store, "job1", "c" * 32, findings)
            with patch("osint_bot.llm_client.complete", return_value=_llm_response({"rankings": []})):
                result = generate(case_id="c" * 32, provider="anthropic", model="claude-sonnet-5", api_key="sk-ant-x",
                                  max_findings=200)
            self.assertEqual(len(result.rankings), 130)
            self.assertEqual(result.coverage["fallback_ranked"], 130)
            self.assertEqual(result.coverage["batches_sent"], 2)


if __name__ == "__main__":
    unittest.main()
