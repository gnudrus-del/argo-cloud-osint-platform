"""Trasporto LLM multi-provider (Anthropic / OpenAI / endpoint locale).

Modulo di trasporto puro: nessuna logica di dominio (prompt, schema, scelta
dei finding da inviare vive nei moduli per-capability: narrative_synthesis,
entity_resolution_ai, triage_ai). Stesso principio di connector.py rispetto
a connectors/*.py.

Le feature IA sono opt-in e disattivate di default (vedi OSINT_AI_AGENTS_ENABLED
in web.py): nessuna chiamata parte senza che un caso l'abbia esplicitamente
abilitata e un analista l'abbia innescata a mano. Ogni chiamata esce da qui e
solo da qui, tramite ``_safe_http`` — stesso gateway SSRF di ogni connettore.

Non logghiamo mai qui: api_key, system_prompt, user_prompt, raw_text della
risposta. Solo metadati (provider, model, http_status, latency, byte).
"""
from __future__ import annotations

import json
import time
import urllib.error
from dataclasses import dataclass

from . import _safe_http

LLM_PROVIDERS = ("anthropic", "openai", "local")

_RETRYABLE_STATUS = {429, 500, 502, 503, 504}
_RETRY_DELAYS_S = (1.0, 3.0)

_ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
_ANTHROPIC_VERSION = "2023-06-01"
_OPENAI_URL = "https://api.openai.com/v1/chat/completions"

DEFAULT_ANTHROPIC_MODEL = "claude-sonnet-5"
DEFAULT_OPENAI_MODEL = "gpt-4.1-mini"


@dataclass
class LLMResponse:
    provider: str
    model: str
    parsed: dict | None = None
    raw_text: str = ""
    input_tokens: int | None = None
    output_tokens: int | None = None
    latency_ms: int = 0
    http_status: int | None = None
    error: str = ""
    # "" | "auth_error" | "rate_limited" | "invalid_json" | "network_error" |
    # "http_error" | "invalid_request"
    error_class: str = ""

    @property
    def ok(self) -> bool:
        return self.error == "" and self.parsed is not None


def parse_local_value(value: str) -> tuple[str, str]:
    """'base_url' oppure 'base_url|bearer_token' -> (base_url, token).

    Stessa convenzione pipe-separated già usata da google_pse per 'apikey|cx'.
    """
    value = (value or "").strip()
    if "|" in value:
        base, _, token = value.partition("|")
        return base.strip().rstrip("/"), token.strip()
    return value.rstrip("/"), ""


def _classify_http_status(status: int) -> str:
    if status in (401, 403):
        return "auth_error"
    if status == 429:
        return "rate_limited"
    return "http_error"


def _short(text: str, limit: int = 200) -> str:
    text = text or ""
    return text if len(text) <= limit else text[:limit] + "…"


def _read_error_body(exc: urllib.error.HTTPError) -> str:
    try:
        return exc.read().decode("utf-8", errors="replace")
    except Exception:
        return ""


def _call_anthropic(
    *, model: str, api_key: str, system_prompt: str, user_prompt: str,
    json_schema: dict, max_tokens: int, timeout: int,
) -> dict:
    """Una singola richiesta Anthropic. Output forzato via tool-use: niente
    parsing fragile di prosa, il blocco tool_use.input E' già il dict validato
    contro lo schema fornito."""
    body = {
        "model": model,
        "max_tokens": max_tokens,
        "system": system_prompt,
        "messages": [{"role": "user", "content": user_prompt}],
        "tools": [{
            "name": "emit_result",
            "description": "Emit the structured result matching the required schema.",
            "input_schema": json_schema,
        }],
        "tool_choice": {"type": "tool", "name": "emit_result"},
    }
    status, raw, _headers = _safe_http.open_url(
        _ANTHROPIC_URL,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "x-api-key": api_key,
            "anthropic-version": _ANTHROPIC_VERSION,
            "content-type": "application/json",
        },
        method="POST",
        timeout=timeout,
    )
    data = json.loads(raw.decode("utf-8", errors="replace"))
    parsed = None
    for block in data.get("content", []) or []:
        if block.get("type") == "tool_use" and block.get("name") == "emit_result":
            parsed = block.get("input")
            break
    usage = data.get("usage") or {}
    return {
        "parsed": parsed,
        "raw_text": json.dumps(data)[:2000],
        "input_tokens": usage.get("input_tokens"),
        "output_tokens": usage.get("output_tokens"),
        "http_status": status,
    }


def _call_openai(
    *, model: str, api_key: str, system_prompt: str, user_prompt: str,
    json_schema: dict, max_tokens: int, timeout: int,
) -> dict:
    body = {
        "model": model,
        "max_tokens": max_tokens,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "response_format": {
            "type": "json_schema",
            "json_schema": {"name": "emit_result", "schema": json_schema, "strict": True},
        },
    }
    status, raw, _headers = _safe_http.open_url(
        _OPENAI_URL,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "content-type": "application/json",
        },
        method="POST",
        timeout=timeout,
    )
    data = json.loads(raw.decode("utf-8", errors="replace"))
    content = ""
    try:
        content = data["choices"][0]["message"]["content"] or ""
    except (KeyError, IndexError, TypeError):
        content = ""
    try:
        parsed = json.loads(content) if content else None
    except json.JSONDecodeError:
        parsed = None
    usage = data.get("usage") or {}
    return {
        "parsed": parsed,
        "raw_text": content[:2000],
        "input_tokens": usage.get("prompt_tokens"),
        "output_tokens": usage.get("completion_tokens"),
        "http_status": status,
    }


def _call_local(
    *, model: str, base_url: str, token: str, system_prompt: str, user_prompt: str,
    json_schema: dict, max_tokens: int, timeout: int,
) -> dict:
    """Endpoint locale OpenAI-compatible (Ollama/llama.cpp). Molti server locali
    ignorano response_format: chiediamo JSON esplicitamente nel prompt e
    facciamo ESATTAMENTE un tentativo di 'riparazione' se il primo parse fallisce."""
    schema_hint = json.dumps(json_schema)
    system_with_hint = (
        f"{system_prompt}\n\nRispondi SOLO con un oggetto JSON valido, senza testo "
        f"aggiuntivo, senza markdown fence, conforme a questo schema: {schema_hint}"
    )

    def _one_call(sys_prompt: str, usr_prompt: str) -> tuple[int, str]:
        body = {
            "model": model,
            "max_tokens": max_tokens,
            "messages": [
                {"role": "system", "content": sys_prompt},
                {"role": "user", "content": usr_prompt},
            ],
        }
        headers = {"content-type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        status, raw, _headers = _safe_http.open_url(
            f"{base_url}/chat/completions",
            data=json.dumps(body).encode("utf-8"),
            headers=headers,
            method="POST",
            timeout=timeout,
            allow_private=True,  # endpoint locale configurato dall'operatore
        )
        data = json.loads(raw.decode("utf-8", errors="replace"))
        try:
            content = data["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError):
            content = ""
        return status, content

    status, content = _one_call(system_with_hint, user_prompt)
    try:
        parsed = json.loads(content) if content else None
    except json.JSONDecodeError as exc:
        # Un solo retry "di riparazione": rimando l'output precedente + l'errore.
        repair_prompt = (
            f"{user_prompt}\n\n--- La tua risposta precedente non era JSON valido ---\n"
            f"Risposta precedente: {_short(content, 500)}\n"
            f"Errore di parsing: {exc}\n"
            f"Rispondi di nuovo, SOLO con JSON valido conforme allo schema."
        )
        status, content = _one_call(system_with_hint, repair_prompt)
        try:
            parsed = json.loads(content) if content else None
        except json.JSONDecodeError:
            parsed = None

    return {
        "parsed": parsed,
        "raw_text": content[:2000],
        "input_tokens": None,
        "output_tokens": None,
        "http_status": status,
    }


def complete(
    *,
    provider: str,
    model: str,
    api_key: str,
    base_url: str = "",
    system_prompt: str,
    user_prompt: str,
    json_schema: dict,
    max_tokens: int = 4096,
    timeout: int = 60,
    max_retries: int = 2,
) -> LLMResponse:
    """Chiamata LLM sanzionata, con retry su errori transitori.

    Per ``provider="local"``: ``base_url`` è l'endpoint OpenAI-compatible,
    ``api_key`` è usato come bearer token opzionale (può essere vuoto se il
    server locale non richiede auth) — stesso valore restituito da
    ``parse_local_value()``.

    Ritorna sempre un LLMResponse — non solleva mai per errori di rete/HTTP
    (il chiamante controlla ``.ok``/``.error_class``). Solleva solo su errori
    di programmazione (provider sconosciuto -> risposta d'errore, non eccezione).
    """
    if provider not in LLM_PROVIDERS:
        return LLMResponse(provider=provider, model=model,
                           error=f"Provider sconosciuto: {provider!r}.",
                           error_class="invalid_request")
    if provider in ("anthropic", "openai") and not api_key:
        return LLMResponse(provider=provider, model=model,
                           error="Chiave API mancante.", error_class="auth_error")
    if provider == "local" and not base_url:
        return LLMResponse(provider=provider, model=model,
                           error="Endpoint locale non configurato.", error_class="auth_error")

    token = api_key  # per 'local', api_key è il bearer token opzionale

    attempt = 0
    last: LLMResponse | None = None
    while attempt <= max_retries:
        started = time.monotonic()
        try:
            if provider == "anthropic":
                raw = _call_anthropic(model=model, api_key=api_key, system_prompt=system_prompt,
                                      user_prompt=user_prompt, json_schema=json_schema,
                                      max_tokens=max_tokens, timeout=timeout)
            elif provider == "openai":
                raw = _call_openai(model=model, api_key=api_key, system_prompt=system_prompt,
                                   user_prompt=user_prompt, json_schema=json_schema,
                                   max_tokens=max_tokens, timeout=timeout)
            else:
                raw = _call_local(model=model, base_url=base_url, token=token,
                                  system_prompt=system_prompt, user_prompt=user_prompt,
                                  json_schema=json_schema, max_tokens=max_tokens, timeout=timeout)
        except _safe_http.SSRFBlocked as exc:
            return LLMResponse(provider=provider, model=model, error=str(exc),
                               error_class="network_error",
                               latency_ms=int((time.monotonic() - started) * 1000))
        except urllib.error.HTTPError as exc:
            body = _read_error_body(exc)
            err_class = _classify_http_status(exc.code)
            last = LLMResponse(provider=provider, model=model, http_status=exc.code,
                               error=f"HTTP {exc.code}: {_short(body)}", error_class=err_class,
                               latency_ms=int((time.monotonic() - started) * 1000))
            if exc.code in _RETRYABLE_STATUS and attempt < max_retries:
                time.sleep(_RETRY_DELAYS_S[min(attempt, len(_RETRY_DELAYS_S) - 1)])
                attempt += 1
                continue
            return last
        except urllib.error.URLError as exc:
            reason = str(getattr(exc, "reason", exc))
            err_class = "timeout" if "timed out" in reason.lower() else "network_error"
            last = LLMResponse(provider=provider, model=model, error=f"Errore rete: {reason}",
                               error_class=err_class,
                               latency_ms=int((time.monotonic() - started) * 1000))
            if attempt < max_retries:
                time.sleep(_RETRY_DELAYS_S[min(attempt, len(_RETRY_DELAYS_S) - 1)])
                attempt += 1
                continue
            return last
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            return LLMResponse(provider=provider, model=model,
                               error=f"Risposta provider non decodificabile: {exc}",
                               error_class="invalid_json",
                               latency_ms=int((time.monotonic() - started) * 1000))

        latency_ms = int((time.monotonic() - started) * 1000)
        parsed = raw["parsed"]
        return LLMResponse(
            provider=provider, model=model, parsed=parsed, raw_text=raw["raw_text"],
            input_tokens=raw.get("input_tokens"), output_tokens=raw.get("output_tokens"),
            latency_ms=latency_ms, http_status=raw.get("http_status"),
            error="" if parsed is not None else "Il provider non ha restituito JSON valido.",
            error_class="" if parsed is not None else "invalid_json",
        )
    return last or LLMResponse(provider=provider, model=model, error="Retry esauriti.",
                               error_class="network_error")


def health_check(provider: str, api_key: str, base_url: str = "") -> tuple[str, str, int | None]:
    """Probe leggero, stesso contratto (state, message, http_status) di
    provider_health.py — usato da check_llm_anthropic/openai/local."""
    if provider not in LLM_PROVIDERS:
        return "unsupported", f"Provider sconosciuto: {provider!r}.", None
    if provider in ("anthropic", "openai") and not api_key:
        return "not_configured", "Chiave non configurata.", None
    if provider == "local" and not base_url:
        return "not_configured", "Endpoint locale non configurato.", None

    try:
        if provider == "anthropic":
            status, _raw, _headers = _safe_http.open_url(
                "https://api.anthropic.com/v1/models",
                headers={"x-api-key": api_key, "anthropic-version": _ANTHROPIC_VERSION},
                timeout=5,
            )
        elif provider == "openai":
            status, _raw, _headers = _safe_http.open_url(
                "https://api.openai.com/v1/models",
                headers={"Authorization": f"Bearer {api_key}"},
                timeout=5,
            )
        else:
            status, _raw, _headers = _safe_http.open_url(
                f"{base_url}/models", headers={"Authorization": f"Bearer {api_key}"} if api_key else {},
                timeout=5, allow_private=True,
            )
        return "ok", f"HTTP {status}", status
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            return "auth_error", f"Chiave rifiutata (HTTP {exc.code}).", exc.code
        if exc.code == 429:
            return "quota_exceeded", "Rate limit superato.", 429
        return "network_error", f"HTTP {exc.code}.", exc.code
    except (urllib.error.URLError, _safe_http.SSRFBlocked) as exc:
        return "network_error", f"Errore di rete: {exc}", None


__all__ = [
    "LLM_PROVIDERS", "LLMResponse", "complete", "health_check", "parse_local_value",
    "DEFAULT_ANTHROPIC_MODEL", "DEFAULT_OPENAI_MODEL",
]
