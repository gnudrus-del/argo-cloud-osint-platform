"""osint_bot.llm_client — trasporto multi-provider per le capability IA
opt-in. Nessun test qui tocca una vera API LLM: ogni chiamata di rete passa
da _safe_http.open_url, mockato — stesso pattern di tests/test_connectors.py
(_mock_open_url) e tests/test_safe_http.py."""
from __future__ import annotations

import json
import unittest
import urllib.error
from unittest.mock import patch

from osint_bot import _safe_http, llm_client

_SCHEMA = {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]}


def _mock_open_url(status=200, body=b"", headers=None):
    return (status, body, headers or {})


class ParseLocalValueTests(unittest.TestCase):
    def test_with_token(self):
        base_url, token = llm_client.parse_local_value("http://localhost:11434/v1|secrettoken")
        self.assertEqual(base_url, "http://localhost:11434/v1")
        self.assertEqual(token, "secrettoken")

    def test_without_token(self):
        base_url, token = llm_client.parse_local_value("http://localhost:11434/v1")
        self.assertEqual(base_url, "http://localhost:11434/v1")
        self.assertEqual(token, "")

    def test_strips_trailing_slash(self):
        base_url, _ = llm_client.parse_local_value("http://localhost:11434/v1/|tok")
        self.assertEqual(base_url, "http://localhost:11434/v1")


class CompleteValidationTests(unittest.TestCase):
    """Errori di programmazione (provider ignoto, credenziali mancanti) non
    devono mai arrivare a una chiamata di rete."""

    def test_unknown_provider(self):
        resp = llm_client.complete(
            provider="bogus", model="x", api_key="", system_prompt="s",
            user_prompt="u", json_schema=_SCHEMA,
        )
        self.assertFalse(resp.ok)
        self.assertEqual(resp.error_class, "invalid_request")

    def test_missing_api_key_anthropic(self):
        resp = llm_client.complete(
            provider="anthropic", model="claude-sonnet-5", api_key="",
            system_prompt="s", user_prompt="u", json_schema=_SCHEMA,
        )
        self.assertFalse(resp.ok)
        self.assertEqual(resp.error_class, "auth_error")

    def test_missing_base_url_local(self):
        resp = llm_client.complete(
            provider="local", model="llama3", api_key="", base_url="",
            system_prompt="s", user_prompt="u", json_schema=_SCHEMA,
        )
        self.assertFalse(resp.ok)
        self.assertEqual(resp.error_class, "auth_error")

    def test_ssrf_blocked_target_never_calls_network(self):
        with patch("osint_bot._safe_http.open_url", side_effect=_safe_http.SSRFBlocked("blocked")) as mocked:
            resp = llm_client.complete(
                provider="anthropic", model="claude-sonnet-5", api_key="sk-ant-x",
                system_prompt="s", user_prompt="u", json_schema=_SCHEMA,
            )
        self.assertFalse(resp.ok)
        self.assertEqual(resp.error_class, "network_error")
        mocked.assert_called_once()


class AnthropicCallTests(unittest.TestCase):
    def test_success_parses_tool_use_block(self):
        fake_response = {
            "content": [{"type": "tool_use", "name": "emit_result", "input": {"ok": True}}],
            "usage": {"input_tokens": 10, "output_tokens": 5},
        }
        with patch("osint_bot._safe_http.open_url",
                  return_value=_mock_open_url(200, json.dumps(fake_response).encode())) as mocked:
            resp = llm_client.complete(
                provider="anthropic", model="claude-sonnet-5", api_key="sk-ant-x",
                system_prompt="s", user_prompt="u", json_schema=_SCHEMA,
            )
        self.assertTrue(resp.ok)
        self.assertEqual(resp.parsed, {"ok": True})
        self.assertEqual(resp.input_tokens, 10)
        self.assertEqual(resp.output_tokens, 5)
        # Verifica che il tool_choice forzi esattamente il tool 'emit_result'.
        _, kwargs = mocked.call_args
        body = json.loads(kwargs["data"])
        self.assertEqual(body["tool_choice"], {"type": "tool", "name": "emit_result"})
        self.assertEqual(body["tools"][0]["input_schema"], _SCHEMA)
        self.assertEqual(kwargs["headers"]["x-api-key"], "sk-ant-x")

    def test_no_matching_tool_use_block_yields_invalid_json(self):
        fake_response = {"content": [{"type": "text", "text": "no tool used"}]}
        with patch("osint_bot._safe_http.open_url",
                  return_value=_mock_open_url(200, json.dumps(fake_response).encode())):
            resp = llm_client.complete(
                provider="anthropic", model="claude-sonnet-5", api_key="sk-ant-x",
                system_prompt="s", user_prompt="u", json_schema=_SCHEMA,
            )
        self.assertFalse(resp.ok)
        self.assertEqual(resp.error_class, "invalid_json")


class OpenAICallTests(unittest.TestCase):
    def test_success_parses_json_content(self):
        fake_response = {
            "choices": [{"message": {"content": json.dumps({"ok": True})}}],
            "usage": {"prompt_tokens": 20, "completion_tokens": 8},
        }
        with patch("osint_bot._safe_http.open_url",
                  return_value=_mock_open_url(200, json.dumps(fake_response).encode())) as mocked:
            resp = llm_client.complete(
                provider="openai", model="gpt-4.1-mini", api_key="sk-oai-x",
                system_prompt="s", user_prompt="u", json_schema=_SCHEMA,
            )
        self.assertTrue(resp.ok)
        self.assertEqual(resp.parsed, {"ok": True})
        self.assertEqual(resp.input_tokens, 20)
        _, kwargs = mocked.call_args
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer sk-oai-x")
        body = json.loads(kwargs["data"])
        self.assertEqual(body["response_format"]["json_schema"]["schema"], _SCHEMA)


class LocalCallTests(unittest.TestCase):
    def test_success_no_response_format_required(self):
        fake_response = {"choices": [{"message": {"content": json.dumps({"ok": True})}}]}
        with patch("osint_bot._safe_http.open_url",
                  return_value=_mock_open_url(200, json.dumps(fake_response).encode())) as mocked:
            resp = llm_client.complete(
                provider="local", model="llama3", api_key="tok", base_url="http://localhost:11434/v1",
                system_prompt="s", user_prompt="u", json_schema=_SCHEMA,
            )
        self.assertTrue(resp.ok)
        self.assertEqual(resp.parsed, {"ok": True})
        # allow_private=True SOLO per provider='local' — endpoint operatore.
        _, kwargs = mocked.call_args
        self.assertTrue(kwargs["allow_private"])
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer tok")

    def test_malformed_json_triggers_exactly_one_repair_retry(self):
        good = {"choices": [{"message": {"content": json.dumps({"ok": True})}}]}
        bad = {"choices": [{"message": {"content": "not json at all"}}]}
        with patch("osint_bot._safe_http.open_url", side_effect=[
            _mock_open_url(200, json.dumps(bad).encode()),
            _mock_open_url(200, json.dumps(good).encode()),
        ]) as mocked:
            resp = llm_client.complete(
                provider="local", model="llama3", api_key="", base_url="http://localhost:11434/v1",
                system_prompt="s", user_prompt="u", json_schema=_SCHEMA,
            )
        self.assertTrue(resp.ok)
        self.assertEqual(resp.parsed, {"ok": True})
        self.assertEqual(mocked.call_count, 2)

    def test_still_malformed_after_repair_is_invalid_json(self):
        bad = {"choices": [{"message": {"content": "still not json"}}]}
        with patch("osint_bot._safe_http.open_url",
                  return_value=_mock_open_url(200, json.dumps(bad).encode())) as mocked:
            resp = llm_client.complete(
                provider="local", model="llama3", api_key="", base_url="http://localhost:11434/v1",
                system_prompt="s", user_prompt="u", json_schema=_SCHEMA,
            )
        self.assertFalse(resp.ok)
        self.assertEqual(resp.error_class, "invalid_json")
        self.assertEqual(mocked.call_count, 2)  # tentativo iniziale + una riparazione, mai di più


class RetryPolicyTests(unittest.TestCase):
    def _http_error(self, code):
        return urllib.error.HTTPError("https://api.anthropic.com/v1/messages", code, "err", {}, None)

    def test_429_is_retried_then_succeeds(self):
        fake_ok = {"content": [{"type": "tool_use", "name": "emit_result", "input": {"ok": True}}]}
        with patch("osint_bot._safe_http.open_url", side_effect=[
            self._http_error(429), _mock_open_url(200, json.dumps(fake_ok).encode()),
        ]) as mocked, patch("time.sleep"):
            resp = llm_client.complete(
                provider="anthropic", model="claude-sonnet-5", api_key="sk-ant-x",
                system_prompt="s", user_prompt="u", json_schema=_SCHEMA, max_retries=2,
            )
        self.assertTrue(resp.ok)
        self.assertEqual(mocked.call_count, 2)

    def test_401_is_never_retried(self):
        with patch("osint_bot._safe_http.open_url", side_effect=self._http_error(401)) as mocked:
            resp = llm_client.complete(
                provider="anthropic", model="claude-sonnet-5", api_key="sk-ant-bad",
                system_prompt="s", user_prompt="u", json_schema=_SCHEMA, max_retries=2,
            )
        self.assertFalse(resp.ok)
        self.assertEqual(resp.error_class, "auth_error")
        mocked.assert_called_once()

    def test_5xx_retried_up_to_max_then_fails(self):
        with patch("osint_bot._safe_http.open_url", side_effect=self._http_error(503)) as mocked, \
             patch("time.sleep"):
            resp = llm_client.complete(
                provider="anthropic", model="claude-sonnet-5", api_key="sk-ant-x",
                system_prompt="s", user_prompt="u", json_schema=_SCHEMA, max_retries=2,
            )
        self.assertFalse(resp.ok)
        self.assertEqual(resp.error_class, "http_error")
        self.assertEqual(mocked.call_count, 3)  # tentativo iniziale + 2 retry


class HealthCheckTests(unittest.TestCase):
    def test_not_configured_states(self):
        state, _, _ = llm_client.health_check("anthropic", "")
        self.assertEqual(state, "not_configured")
        state, _, _ = llm_client.health_check("local", "tok", base_url="")
        self.assertEqual(state, "not_configured")

    def test_ok_state_on_200(self):
        with patch("osint_bot._safe_http.open_url", return_value=_mock_open_url(200, b"{}")):
            state, _, status = llm_client.health_check("anthropic", "sk-ant-x")
        self.assertEqual(state, "ok")
        self.assertEqual(status, 200)

    def test_auth_error_state_on_401(self):
        err = urllib.error.HTTPError("https://api.anthropic.com/v1/models", 401, "err", {}, None)
        with patch("osint_bot._safe_http.open_url", side_effect=err):
            state, _, status = llm_client.health_check("anthropic", "sk-ant-bad")
        self.assertEqual(state, "auth_error")
        self.assertEqual(status, 401)


if __name__ == "__main__":
    unittest.main()
