"""osint_bot.ai_context — unica fonte di verità per finding_id e per la
raccolta dei dati di caso usati dalle 3 capability IA opt-in."""
from __future__ import annotations

import contextlib
import json
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


def _write_job(tmp: Path, store, job_id: str, case_id: str, findings: list[dict], status: str = "complete"):
    report_dir = tmp / job_id / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    json_path = report_dir / "report.json"
    json_path.write_text(json.dumps({"findings": findings}), encoding="utf-8")
    store.put_job(job_id, {
        "id": job_id, "owner": "alice", "case_id": case_id, "status": status,
        "json_path": str(json_path), "created_at": "now", "updated_at": "now",
    })


class FindingIdTests(unittest.TestCase):
    def test_round_trip(self):
        from osint_bot.ai_context import finding_id_for, parse_finding_id
        fid = finding_id_for("job123", 7)
        self.assertEqual(fid, "job123#7")
        self.assertEqual(parse_finding_id(fid), ("job123", 7))

    def test_invalid_ids_return_none(self):
        from osint_bot.ai_context import parse_finding_id
        self.assertIsNone(parse_finding_id("no-separator"))
        self.assertIsNone(parse_finding_id("job#notanumber"))
        self.assertIsNone(parse_finding_id("#5"))


class CollectCaseFindingsTests(unittest.TestCase):
    def test_sorted_by_severity_then_confidence(self):
        from osint_bot.ai_context import collect_case_findings
        with _isolated_storage() as (tmp, store):
            store.put_case({"id": "c" * 32, "owner": "alice", "title": "T"})
            _write_job(tmp, store, "job1", "c" * 32, [
                {"kind": "domain", "value": "a.com", "confidence": 0.5, "severity": "low", "evidence": []},
                {"kind": "domain", "value": "b.com", "confidence": 0.9, "severity": "critical", "evidence": []},
                {"kind": "domain", "value": "c.com", "confidence": 0.6, "severity": "critical", "evidence": []},
            ])
            result = collect_case_findings("c" * 32)
            self.assertEqual(len(result.refs), 3)
            self.assertFalse(result.truncated)
            severities_confidences = [(r.finding.severity, r.finding.confidence) for r in result.refs]
            # entrambi critical prima di low; tra i due critical, confidence più alta prima
            self.assertEqual(severities_confidences, [("critical", 0.9), ("critical", 0.6), ("low", 0.5)])

    def test_truncation_is_always_reported(self):
        from osint_bot.ai_context import collect_case_findings
        with _isolated_storage() as (tmp, store):
            store.put_case({"id": "c" * 32, "owner": "alice", "title": "T"})
            findings = [{"kind": "domain", "value": f"d{i}.com", "confidence": 0.5, "evidence": []} for i in range(10)]
            _write_job(tmp, store, "job1", "c" * 32, findings)
            result = collect_case_findings("c" * 32, max_findings=3)
            self.assertEqual(len(result.refs), 3)
            self.assertEqual(result.total_available, 10)
            self.assertTrue(result.truncated)

    def test_incomplete_jobs_are_excluded(self):
        from osint_bot.ai_context import collect_case_findings
        with _isolated_storage() as (tmp, store):
            store.put_case({"id": "c" * 32, "owner": "alice", "title": "T"})
            _write_job(tmp, store, "job1", "c" * 32,
                      [{"kind": "domain", "value": "a.com", "confidence": 0.5, "evidence": []}],
                      status="running")
            result = collect_case_findings("c" * 32)
            self.assertEqual(len(result.refs), 0)

    def test_job_id_scopes_to_single_job(self):
        from osint_bot.ai_context import collect_case_findings
        with _isolated_storage() as (tmp, store):
            store.put_case({"id": "c" * 32, "owner": "alice", "title": "T"})
            _write_job(tmp, store, "job1", "c" * 32, [{"kind": "domain", "value": "a.com", "confidence": 0.5, "evidence": []}])
            _write_job(tmp, store, "job2", "c" * 32, [{"kind": "domain", "value": "b.com", "confidence": 0.5, "evidence": []}])
            result = collect_case_findings("c" * 32, job_id="job1")
            self.assertEqual(len(result.refs), 1)
            self.assertEqual(result.refs[0].job_id, "job1")

    def test_finding_ids_match_position_in_json(self):
        from osint_bot.ai_context import collect_case_findings, finding_id_for
        with _isolated_storage() as (tmp, store):
            store.put_case({"id": "c" * 32, "owner": "alice", "title": "T"})
            _write_job(tmp, store, "job1", "c" * 32, [
                {"kind": "domain", "value": "a.com", "confidence": 0.9, "severity": "critical", "evidence": []},
                {"kind": "domain", "value": "b.com", "confidence": 0.1, "severity": "info", "evidence": []},
            ])
            result = collect_case_findings("c" * 32)
            ids = {r.finding.value: r.finding_id for r in result.refs}
            self.assertEqual(ids["a.com"], finding_id_for("job1", 0))
            self.assertEqual(ids["b.com"], finding_id_for("job1", 1))

    def test_malformed_finding_is_skipped_not_fatal(self):
        from osint_bot.ai_context import collect_case_findings
        with _isolated_storage() as (tmp, store):
            store.put_case({"id": "c" * 32, "owner": "alice", "title": "T"})
            report_dir = tmp / "job1" / "reports"
            report_dir.mkdir(parents=True)
            (report_dir / "report.json").write_text(
                json.dumps({"findings": [
                    {"kind": "domain", "value": "ok.com", "confidence": 0.5, "evidence": []},
                    {"kind": "domain", "value": "bad.com", "confidence": "not-a-number", "evidence": []},
                ]}), encoding="utf-8")
            store.put_job("job1", {"id": "job1", "owner": "alice", "case_id": "c" * 32, "status": "complete",
                                   "json_path": str(report_dir / "report.json"), "created_at": "now", "updated_at": "now"})
            result = collect_case_findings("c" * 32)
            self.assertEqual(len(result.refs), 1)
            self.assertEqual(result.refs[0].finding.value, "ok.com")


class CollectCaseEntitiesTests(unittest.TestCase):
    def test_merges_entities_across_jobs(self):
        from osint_bot.ai_context import collect_case_entities
        with _isolated_storage() as (tmp, store):
            store.put_case({"id": "c" * 32, "owner": "alice", "title": "T"})
            _write_job(tmp, store, "job1", "c" * 32, [{"kind": "domain", "value": "shared.com", "confidence": 0.5, "evidence": []}])
            _write_job(tmp, store, "job2", "c" * 32, [{"kind": "domain", "value": "shared.com", "confidence": 0.9, "evidence": []}])
            graph = collect_case_entities("c" * 32)
            nodes = [n for n in graph.nodes() if n.value == "shared.com"]
            self.assertEqual(len(nodes), 1)  # stesso _stable_id -> un solo nodo, confidence assorbita col massimo
            self.assertEqual(nodes[0].confidence, 0.9)


class EstimatePromptBytesTests(unittest.TestCase):
    def test_counts_utf8_bytes_of_both_strings(self):
        from osint_bot.ai_context import estimate_prompt_bytes
        n = estimate_prompt_bytes("abc", "dé")  # 'é' è 2 byte in utf-8
        self.assertEqual(n, 3 + 3)


if __name__ == "__main__":
    unittest.main()
