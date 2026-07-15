"""End-to-end (via le funzioni handle_ai_* di web.py, non HTTP grezzo — stesso
pattern di tests/test_dsar_erasure.py) dei 3 gate indipendenti (kill-switch,
consenso per-caso, chiave BYOK), degli eventi audit e del default di lang.
Nessuna chiamata LLM reale: osint_bot.llm_client.complete è sempre mockato."""
from __future__ import annotations

import contextlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from osint_bot import llm_client


@contextlib.contextmanager
def _isolated_storage(*, ai_enabled: bool = True):
    import osint_bot.web as web
    from osint_bot.storage import Storage

    with tempfile.TemporaryDirectory() as tmp:
        original_root = web.JOB_ROOT
        original_storage = web.STORAGE
        original_env = os.environ.get("OSINT_AI_AGENTS_ENABLED")
        web.JOB_ROOT = Path(tmp)
        web.STORAGE = Storage(Path(tmp) / "gufo.sqlite3")
        os.environ["OSINT_AI_AGENTS_ENABLED"] = "1" if ai_enabled else "0"
        try:
            yield Path(tmp), web.STORAGE
        finally:
            try:
                web.STORAGE.close()
            except Exception:
                pass
            web.JOB_ROOT = original_root
            web.STORAGE = original_storage
            if original_env is None:
                os.environ.pop("OSINT_AI_AGENTS_ENABLED", None)
            else:
                os.environ["OSINT_AI_AGENTS_ENABLED"] = original_env


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


class KillSwitchGateTests(unittest.TestCase):
    def test_narrative_404_when_kill_switch_off(self):
        import osint_bot.web as web
        with _isolated_storage(ai_enabled=False) as (tmp, store):
            store.put_case({"id": "c" * 32, "owner": "alice", "title": "T", "ai_enrichment_enabled": True})
            with self.assertRaises(web.WebError) as ctx:
                web.handle_ai_narrative({"case_id": "c" * 32, "provider": "anthropic"}, "alice")
            self.assertEqual(ctx.exception.status, 404)

    def test_ai_settings_toggle_404_when_kill_switch_off(self):
        import osint_bot.web as web
        with _isolated_storage(ai_enabled=False) as (tmp, store):
            store.put_case({"id": "c" * 32, "owner": "alice", "title": "T"})
            with self.assertRaises(web.WebError) as ctx:
                web.set_case_ai_settings("c" * 32, {"ai_enrichment_enabled": True}, "alice")
            self.assertEqual(ctx.exception.status, 404)

    def test_ai_key_catalog_excluded_from_catalog_when_off(self):
        import osint_bot.web as web
        with _isolated_storage(ai_enabled=False):
            self.assertEqual(web.api_key_catalog_for("alice"), web.API_KEY_CATALOG)

    def test_ai_key_catalog_included_when_on(self):
        import osint_bot.web as web
        with _isolated_storage(ai_enabled=True):
            services = {e["service"] for e in web.api_key_catalog_for("alice")}
            self.assertIn("llm_anthropic", services)


class CaseConsentGateTests(unittest.TestCase):
    def test_403_when_case_not_opted_in(self):
        import osint_bot.web as web
        with _isolated_storage() as (tmp, store):
            store.put_case({"id": "c" * 32, "owner": "alice", "title": "T"})  # ai_enrichment_enabled default False
            with self.assertRaises(web.WebError) as ctx:
                web.handle_ai_narrative({"case_id": "c" * 32, "provider": "anthropic"}, "alice")
            self.assertEqual(ctx.exception.status, 403)

    def test_owner_only_can_toggle_settings(self):
        import osint_bot.web as web
        with _isolated_storage() as (tmp, store):
            store.put_user({"username": "bob", "password": "x", "created_at": "now"})
            # bob è collaboratore (quindi read_case lo lascia passare) ma non
            # owner: è l'unico modo per esercitare davvero il ramo 403 di
            # set_case_ai_settings invece del 404 anti-existence-leak di
            # read_case, che scatterebbe per un estraneo qualsiasi.
            store.put_case({"id": "c" * 32, "owner": "alice", "title": "T", "collaborators": ["bob"]})
            with self.assertRaises(web.WebError) as ctx:
                web.set_case_ai_settings("c" * 32, {"ai_enrichment_enabled": True}, "bob")
            self.assertEqual(ctx.exception.status, 403)


class NoKeyGateTests(unittest.TestCase):
    def test_400_when_no_key_configured(self):
        import osint_bot.web as web
        with _isolated_storage() as (tmp, store):
            store.put_case({"id": "c" * 32, "owner": "alice", "title": "T", "ai_enrichment_enabled": True})
            with self.assertRaises(web.WebError) as ctx:
                web.handle_ai_narrative({"case_id": "c" * 32, "provider": "anthropic"}, "alice")
            self.assertEqual(ctx.exception.status, 400)

    def test_400_on_invalid_provider(self):
        import osint_bot.web as web
        with _isolated_storage() as (tmp, store):
            store.put_case({"id": "c" * 32, "owner": "alice", "title": "T", "ai_enrichment_enabled": True})
            with self.assertRaises(web.WebError) as ctx:
                web.handle_ai_narrative({"case_id": "c" * 32, "provider": "not-a-real-provider"}, "alice")
            self.assertEqual(ctx.exception.status, 400)


class AuditAndLangTests(unittest.TestCase):
    def test_success_writes_audit_event_without_secrets(self):
        import osint_bot.web as web
        with _isolated_storage() as (tmp, store):
            store.put_user({"username": "alice", "password": "x", "created_at": "now"})
            store.put_case({"id": "c" * 32, "owner": "alice", "title": "Caso", "ai_enrichment_enabled": True})
            store.put_api_key("alice", "llm_anthropic", "sk-ant-supersecret")
            _write_job(tmp, store, "job1", "c" * 32, [
                {"kind": "domain", "value": "a.com", "confidence": 0.9, "severity": "high", "evidence": []},
            ])
            fake = {"summary_paragraph": "x [F#job1#0]", "sections": [], "citations_used": ["job1#0"], "caveats": []}
            with patch("osint_bot.llm_client.complete", return_value=_llm_response(fake)):
                web.handle_ai_narrative({"case_id": "c" * 32, "provider": "anthropic"}, "alice")

            events = store.all_audit_events()
            narrative_events = [e for e in events if e["action"] == "ai_narrative_generated"]
            self.assertEqual(len(narrative_events), 1)
            details_str = json.dumps(narrative_events[0]["details"])
            self.assertNotIn("sk-ant-supersecret", details_str)
            self.assertIn("finding_count_sent", narrative_events[0]["details"])
            self.assertEqual(narrative_events[0]["details"]["status"], "ok")

    def test_failed_call_is_still_audited(self):
        import osint_bot.web as web
        with _isolated_storage() as (tmp, store):
            store.put_user({"username": "alice", "password": "x", "created_at": "now"})
            store.put_case({"id": "c" * 32, "owner": "alice", "title": "Caso", "ai_enrichment_enabled": True})
            store.put_api_key("alice", "llm_anthropic", "sk-ant-x")
            _write_job(tmp, store, "job1", "c" * 32, [
                {"kind": "domain", "value": "a.com", "confidence": 0.9, "severity": "high", "evidence": []},
            ])
            bad = {"summary_paragraph": "x [F#job1#99]", "sections": [], "citations_used": ["job1#99"], "caveats": []}
            with patch("osint_bot.llm_client.complete", return_value=_llm_response(bad)):
                with self.assertRaises(web.WebError) as ctx:
                    web.handle_ai_narrative({"case_id": "c" * 32, "provider": "anthropic"}, "alice")
            self.assertEqual(ctx.exception.status, 502)
            events = [e for e in store.all_audit_events() if e["action"] == "ai_narrative_generated"]
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["details"]["status"], "error")

    def test_case_ai_settings_toggle_is_audited(self):
        import osint_bot.web as web
        with _isolated_storage() as (tmp, store):
            store.put_case({"id": "c" * 32, "owner": "alice", "title": "T"})
            web.set_case_ai_settings("c" * 32, {"ai_enrichment_enabled": True}, "alice")
            actions = [e["action"] for e in store.all_audit_events()]
            self.assertIn("case_ai_enrichment_enabled", actions)

    def test_invalid_lang_defaults_to_it(self):
        import osint_bot.web as web
        with _isolated_storage() as (tmp, store):
            store.put_user({"username": "alice", "password": "x", "created_at": "now"})
            store.put_case({"id": "c" * 32, "owner": "alice", "title": "Caso", "ai_enrichment_enabled": True})
            store.put_api_key("alice", "llm_anthropic", "sk-ant-x")
            _write_job(tmp, store, "job1", "c" * 32, [
                {"kind": "domain", "value": "a.com", "confidence": 0.9, "severity": "high", "evidence": []},
            ])
            fake = {"summary_paragraph": "x [F#job1#0]", "sections": [], "citations_used": ["job1#0"], "caveats": []}
            captured = {}

            def _capture(*, provider, model, api_key, base_url, system_prompt, user_prompt, json_schema, **kw):
                captured["system_prompt"] = system_prompt
                return _llm_response(fake)

            with patch("osint_bot.llm_client.complete", side_effect=_capture):
                web.handle_ai_narrative({"case_id": "c" * 32, "provider": "anthropic", "lang": "zz-invalid"}, "alice")
            self.assertIn("italiano", captured["system_prompt"])


class EntitySuggestionsAndDecideTests(unittest.TestCase):
    def test_decide_does_not_require_ai_enabled(self):
        """Revocare/confermare una decisione già presa deve restare
        possibile anche a feature IA disattivata nel frattempo (vedi
        commento in handle_ai_entity_decide)."""
        import osint_bot.web as web
        with _isolated_storage(ai_enabled=False) as (tmp, store):
            store.put_case({"id": "c" * 32, "owner": "alice", "title": "T"})
            record = web.handle_ai_entity_decide({
                "case_id": "c" * 32, "entity_id_a": "e1", "entity_id_b": "e2", "decision": "confirmed",
            }, "alice")
            self.assertEqual(record["decision"], "confirmed")

    def test_decide_rejects_invalid_decision_value(self):
        import osint_bot.web as web
        with _isolated_storage() as (tmp, store):
            store.put_case({"id": "c" * 32, "owner": "alice", "title": "T"})
            with self.assertRaises(web.WebError) as ctx:
                web.handle_ai_entity_decide({
                    "case_id": "c" * 32, "entity_id_a": "e1", "entity_id_b": "e2", "decision": "maybe",
                }, "alice")
            self.assertEqual(ctx.exception.status, 400)


if __name__ == "__main__":
    unittest.main()
