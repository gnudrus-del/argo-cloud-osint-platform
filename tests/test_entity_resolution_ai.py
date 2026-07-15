"""osint_bot.entity_resolution_ai — capability IA opt-in #2. candidate_pairs
è puro/deterministico (nessun LLM); generate() mocka
osint_bot.llm_client.complete."""
from __future__ import annotations

import contextlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from osint_bot import llm_client
from osint_bot.link_analysis import EntityGraph, GraphNode


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


def _llm_response(parsed):
    return llm_client.LLMResponse(
        provider="anthropic", model="claude-sonnet-5", parsed=parsed,
        raw_text=json.dumps(parsed), latency_ms=1, http_status=200,
    )


class CandidatePairsTests(unittest.TestCase):
    def test_similar_values_form_a_pair(self):
        from osint_bot.entity_resolution_ai import candidate_pairs
        graph = EntityGraph()
        graph.add_node(GraphNode(id="e1", kind="handle", value="mario.rossi", label="mario.rossi"))
        graph.add_node(GraphNode(id="e2", kind="handle", value="mario_rossi", label="mario_rossi"))
        result = candidate_pairs(graph)
        self.assertEqual(len(result.pairs), 1)
        self.assertEqual(result.pairs[0].reason, "similar_value")

    def test_different_kind_never_pairs(self):
        from osint_bot.entity_resolution_ai import candidate_pairs
        graph = EntityGraph()
        graph.add_node(GraphNode(id="e1", kind="handle", value="test", label="test"))
        graph.add_node(GraphNode(id="e2", kind="domain", value="test", label="test"))
        result = candidate_pairs(graph)
        self.assertEqual(len(result.pairs), 0)

    def test_shared_email_domain_is_a_weak_signal(self):
        # Local part deliberatamente lungo e diverso, così il rapporto di
        # similarità testuale complessivo resta sotto soglia (0.55) e il
        # segnale che emerge è davvero l'attributo condiviso (dominio email),
        # non la somiglianza superficiale della stringa intera.
        from osint_bot.entity_resolution_ai import candidate_pairs
        graph = EntityGraph()
        graph.add_node(GraphNode(id="e1", kind="email", value="aaaaaaaaaaaaaaaaaaaa@corp-example.com"))
        graph.add_node(GraphNode(id="e2", kind="email", value="zzzzzzzzzzzzzzzzzzzz@corp-example.com"))
        result = candidate_pairs(graph)
        self.assertEqual(len(result.pairs), 1)
        self.assertEqual(result.pairs[0].reason, "same_email_domain")

    def test_similar_email_local_part_wins_over_domain_reason(self):
        # Precedenza attesa: se la somiglianza testuale complessiva supera
        # già la soglia (qui perché dominio E local part sono simili), il
        # motivo riportato è 'similar_value', non 'same_email_domain' — la
        # coppia resta comunque candidata in entrambi i casi.
        from osint_bot.entity_resolution_ai import candidate_pairs
        graph = EntityGraph()
        graph.add_node(GraphNode(id="e1", kind="email", value="alice@corp-example.com"))
        graph.add_node(GraphNode(id="e2", kind="email", value="bob@corp-example.com"))
        result = candidate_pairs(graph)
        self.assertEqual(len(result.pairs), 1)
        self.assertEqual(result.pairs[0].reason, "similar_value")

    def test_unrelated_entities_produce_no_pairs(self):
        from osint_bot.entity_resolution_ai import candidate_pairs
        graph = EntityGraph()
        graph.add_node(GraphNode(id="e1", kind="domain", value="totally-unrelated-one.net"))
        graph.add_node(GraphNode(id="e2", kind="domain", value="something-else-entirely.org"))
        result = candidate_pairs(graph)
        self.assertEqual(len(result.pairs), 0)

    def test_truncation_reported(self):
        from osint_bot.entity_resolution_ai import candidate_pairs
        graph = EntityGraph()
        # 6 handle quasi-identici -> C(6,2)=15 coppie candidate, tutte sopra soglia
        for i in range(6):
            graph.add_node(GraphNode(id=f"e{i}", kind="handle", value="mario.rossi" + "x" * i))
        result = candidate_pairs(graph, max_pairs=3)
        self.assertEqual(len(result.pairs), 3)
        self.assertTrue(result.truncated)
        self.assertGreater(result.total_available, 3)


class ValidateTests(unittest.TestCase):
    def test_valid_verdict_kept_and_confidence_clamped(self):
        from osint_bot.entity_resolution_ai import validate
        known = {frozenset(("e1", "e2"))}
        parsed = {"verdicts": [{"entity_id_a": "e1", "entity_id_b": "e2",
                                "same_entity": True, "confidence": 1.7, "rationale": "x"}]}
        result = validate(parsed, known)
        self.assertTrue(result.ok)
        self.assertEqual(len(result.verdicts), 1)
        self.assertEqual(result.verdicts[0]["confidence"], 1.0)

    def test_verdict_on_unknown_pair_is_dropped_not_hard_fail(self):
        from osint_bot.entity_resolution_ai import validate
        known = {frozenset(("e1", "e2"))}
        parsed = {"verdicts": [{"entity_id_a": "e99", "entity_id_b": "e100",
                                "same_entity": True, "confidence": 0.9, "rationale": "invented"}]}
        result = validate(parsed, known)
        self.assertTrue(result.ok)  # scarto, non hard-fail
        self.assertEqual(len(result.verdicts), 0)
        self.assertEqual(result.dropped_hallucinated, 1)

    def test_pair_order_independent(self):
        from osint_bot.entity_resolution_ai import validate
        known = {frozenset(("e1", "e2"))}
        parsed = {"verdicts": [{"entity_id_a": "e2", "entity_id_b": "e1",
                                "same_entity": False, "confidence": 0.3, "rationale": "x"}]}
        result = validate(parsed, known)
        self.assertEqual(len(result.verdicts), 1)


class GenerateTests(unittest.TestCase):
    def test_no_candidates_skips_llm_entirely(self):
        from osint_bot.entity_resolution_ai import generate
        with _isolated_storage() as (tmp, store):
            store.put_case({"id": "c" * 32, "owner": "alice", "title": "T"})
            _write_job(tmp, store, "job1", "c" * 32, [
                {"kind": "domain", "value": "unrelated-one.net", "confidence": 0.5, "evidence": []},
            ])
            with patch("osint_bot.llm_client.complete") as mocked:
                response, validation, collected = generate(
                    case_id="c" * 32, provider="anthropic", model="claude-sonnet-5", api_key="sk-ant-x",
                )
            mocked.assert_not_called()
            self.assertIsNone(response)
            self.assertTrue(validation.ok)
            self.assertEqual(validation.verdicts, [])

    def test_success_path(self):
        from osint_bot.entity_resolution_ai import generate
        with _isolated_storage() as (tmp, store):
            store.put_case({"id": "c" * 32, "owner": "alice", "title": "T"})
            _write_job(tmp, store, "job1", "c" * 32, [
                {"kind": "handle", "value": "mario.rossi", "confidence": 0.8, "evidence": []},
                {"kind": "handle", "value": "mario_rossi", "confidence": 0.7, "evidence": []},
            ])
            from osint_bot import ai_context
            from osint_bot.entity_resolution_ai import candidate_pairs
            graph = ai_context.collect_case_entities("c" * 32)
            pair = candidate_pairs(graph).pairs[0]
            fake = {"verdicts": [{"entity_id_a": pair.entity_a.id, "entity_id_b": pair.entity_b.id,
                                  "same_entity": True, "confidence": 0.8, "rationale": "stesso handle"}]}
            with patch("osint_bot.llm_client.complete", return_value=_llm_response(fake)):
                response, validation, collected = generate(
                    case_id="c" * 32, provider="anthropic", model="claude-sonnet-5", api_key="sk-ant-x",
                )
            self.assertTrue(validation.ok)
            self.assertEqual(len(validation.verdicts), 1)


if __name__ == "__main__":
    unittest.main()
