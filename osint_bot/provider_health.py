"""Provider health-check — real HTTP probes to OSINT API endpoints.

Each provider gets a `check_<provider>(api_key)` function that performs the
lightest possible authenticated call (HEAD/short GET) and returns a
`ProviderStatus` with a semantic state:

    not_configured   — empty key
    ok               — provider accepted the key, quota available
    auth_error       — key rejected (401/403)
    quota_exceeded   — over rate limit (429) or daily quota
    network_error    — DNS/timeout/TLS issue
    unsupported      — no check implemented for this provider

The functions never raise; they wrap errors into the status. Designed to be
fast (≤5s timeout) and idempotent. Callers cache results to avoid hitting
provider rate limits on every UI refresh.
"""
from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import asdict, dataclass

LOG = logging.getLogger("osint_bot.provider_health")

# Semantic states
STATE_NOT_CONFIGURED = "not_configured"
STATE_OK = "ok"
STATE_AUTH_ERROR = "auth_error"
STATE_QUOTA_EXCEEDED = "quota_exceeded"
STATE_NETWORK_ERROR = "network_error"
STATE_UNSUPPORTED = "unsupported"
STATE_UNTESTED = "untested"  # key present but never tested

VALID_STATES = {
    STATE_NOT_CONFIGURED, STATE_OK, STATE_AUTH_ERROR, STATE_QUOTA_EXCEEDED,
    STATE_NETWORK_ERROR, STATE_UNSUPPORTED, STATE_UNTESTED,
}


@dataclass
class ProviderStatus:
    """Result of a provider health probe."""
    service: str
    state: str
    message: str
    checked_at: str
    last4: str = ""           # last 4 chars of the key, never the whole thing
    http_status: int | None = None
    latency_ms: int | None = None

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _last4(key: str) -> str:
    if not key:
        return ""
    return key[-4:] if len(key) >= 4 else key


def _probe(
    url: str,
    *,
    api_key: str,
    headers: dict | None = None,
    method: str = "GET",
    timeout: int = 5,
    auth_codes: tuple[int, ...] = (401, 403),
    quota_codes: tuple[int, ...] = (429,),
    success_codes: tuple[int, ...] = (200, 204),
) -> tuple[str, str, int | None]:
    """Generic HTTP probe. Returns (state, message, http_status).

    Maps HTTP responses to ProviderStatus states:
      success_codes → ok
      auth_codes    → auth_error
      quota_codes   → quota_exceeded
      anything else → returns "ok" if 2xx, else network_error-ish.
    """
    req = urllib.request.Request(url, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            if status in success_codes or 200 <= status < 300:
                return STATE_OK, f"HTTP {status}", status
            if status in auth_codes:
                return STATE_AUTH_ERROR, f"Chiave rifiutata dal provider (HTTP {status}).", status
            if status in quota_codes:
                return STATE_QUOTA_EXCEEDED, f"Quota esaurita o rate limit (HTTP {status}).", status
            return STATE_NETWORK_ERROR, f"Risposta inattesa HTTP {status}.", status
    except urllib.error.HTTPError as exc:
        if exc.code in auth_codes:
            return STATE_AUTH_ERROR, f"Chiave rifiutata (HTTP {exc.code}).", exc.code
        if exc.code in quota_codes:
            return STATE_QUOTA_EXCEEDED, f"Quota o rate limit superato (HTTP {exc.code}).", exc.code
        return STATE_NETWORK_ERROR, f"HTTP {exc.code}.", exc.code
    except urllib.error.URLError as exc:
        return STATE_NETWORK_ERROR, f"Errore di rete: {exc.reason}.", None
    except TimeoutError:
        return STATE_NETWORK_ERROR, "Timeout di rete.", None
    except Exception as exc:  # pragma: no cover — defensive
        return STATE_NETWORK_ERROR, f"Errore imprevisto: {exc.__class__.__name__}.", None


# ---------------------------------------------------------------------------
# Per-provider check functions
# ---------------------------------------------------------------------------

def check_brave(api_key: str) -> tuple[str, str, int | None]:
    if not api_key:
        return STATE_NOT_CONFIGURED, "Chiave non configurata.", None
    return _probe(
        "https://api.search.brave.com/res/v1/web/search?q=health&count=1",
        api_key=api_key,
        headers={
            "Accept": "application/json",
            "X-Subscription-Token": api_key,
            "User-Agent": "Argo-OSINT/1.0",
        },
    )


def check_bing(api_key: str) -> tuple[str, str, int | None]:
    if not api_key:
        return STATE_NOT_CONFIGURED, "Chiave non configurata.", None
    return _probe(
        "https://api.bing.microsoft.com/v7.0/search?q=health&count=1",
        api_key=api_key,
        headers={
            "Accept": "application/json",
            "Ocp-Apim-Subscription-Key": api_key,
            "User-Agent": "Argo-OSINT/1.0",
        },
    )


def check_serper(api_key: str) -> tuple[str, str, int | None]:
    if not api_key:
        return STATE_NOT_CONFIGURED, "Chiave non configurata.", None
    body = json.dumps({"q": "health", "num": 1}).encode("utf-8")
    req = urllib.request.Request(
        "https://google.serper.dev/search",
        data=body,
        headers={
            "X-API-KEY": api_key,
            "Content-Type": "application/json",
            "User-Agent": "Argo-OSINT/1.0",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status == 200:
                return STATE_OK, "HTTP 200", 200
            return STATE_NETWORK_ERROR, f"HTTP {resp.status}", resp.status
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            return STATE_AUTH_ERROR, f"Chiave rifiutata (HTTP {exc.code}).", exc.code
        if exc.code == 429:
            return STATE_QUOTA_EXCEEDED, "Rate limit superato.", 429
        return STATE_NETWORK_ERROR, f"HTTP {exc.code}.", exc.code
    except urllib.error.URLError as exc:
        return STATE_NETWORK_ERROR, f"Errore di rete: {exc.reason}.", None


def check_shodan(api_key: str) -> tuple[str, str, int | None]:
    if not api_key:
        return STATE_NOT_CONFIGURED, "Chiave non configurata.", None
    return _probe(
        f"https://api.shodan.io/api-info?key={urllib.parse.quote(api_key)}",
        api_key=api_key,
        headers={"User-Agent": "Argo-OSINT/1.0"},
    )


def check_virustotal(api_key: str) -> tuple[str, str, int | None]:
    if not api_key:
        return STATE_NOT_CONFIGURED, "Chiave non configurata.", None
    return _probe(
        "https://www.virustotal.com/api/v3/users/current",
        api_key=api_key,
        headers={"x-apikey": api_key, "User-Agent": "Argo-OSINT/1.0"},
    )


def check_hibp(api_key: str) -> tuple[str, str, int | None]:
    if not api_key:
        return STATE_NOT_CONFIGURED, "Chiave non configurata.", None
    # HIBP requires a real lookup. Probe with a synthetic account that returns 404 fast.
    return _probe(
        "https://haveibeenpwned.com/api/v3/breachedaccount/argo-healthcheck@example.com",
        api_key=api_key,
        headers={
            "hibp-api-key": api_key,
            "User-Agent": "Argo-OSINT/1.0",
        },
        success_codes=(200, 404),  # 404 = no breach, ma key OK
    )


def check_hunter(api_key: str) -> tuple[str, str, int | None]:
    if not api_key:
        return STATE_NOT_CONFIGURED, "Chiave non configurata.", None
    return _probe(
        f"https://api.hunter.io/v2/account?api_key={urllib.parse.quote(api_key)}",
        api_key=api_key,
        headers={"User-Agent": "Argo-OSINT/1.0"},
    )


def check_abuseipdb(api_key: str) -> tuple[str, str, int | None]:
    if not api_key:
        return STATE_NOT_CONFIGURED, "Chiave non configurata.", None
    return _probe(
        "https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=1",
        api_key=api_key,
        headers={
            "Key": api_key,
            "Accept": "application/json",
            "User-Agent": "Argo-OSINT/1.0",
        },
    )


def check_github(api_key: str) -> tuple[str, str, int | None]:
    if not api_key:
        return STATE_NOT_CONFIGURED, "Chiave non configurata.", None
    return _probe(
        "https://api.github.com/user",
        api_key=api_key,
        headers={
            "Authorization": f"token {api_key}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "Argo-OSINT/1.0",
        },
    )


def check_leakix(api_key: str) -> tuple[str, str, int | None]:
    if not api_key:
        return STATE_NOT_CONFIGURED, "Chiave non configurata.", None
    return _probe(
        "https://leakix.net/host/8.8.8.8",
        api_key=api_key,
        headers={
            "api-key": api_key,
            "Accept": "application/json",
            "User-Agent": "Argo-OSINT/1.0",
        },
    )


def check_intelx(api_key: str) -> tuple[str, str, int | None]:
    if not api_key:
        return STATE_NOT_CONFIGURED, "Chiave non configurata.", None
    return _probe(
        f"https://2.intelx.io/authenticate/info?k={urllib.parse.quote(api_key)}",
        api_key=api_key,
        headers={"x-key": api_key, "User-Agent": "Argo-OSINT/1.0"},
    )


def check_fullhunt(api_key: str) -> tuple[str, str, int | None]:
    if not api_key:
        return STATE_NOT_CONFIGURED, "Chiave non configurata.", None
    return _probe(
        "https://fullhunt.io/api/v1/auth/status",
        api_key=api_key,
        headers={"X-API-KEY": api_key, "User-Agent": "Argo-OSINT/1.0"},
    )


def _unsupported_check(api_key: str) -> tuple[str, str, int | None]:
    if not api_key:
        return STATE_NOT_CONFIGURED, "Chiave non configurata.", None
    return STATE_UNTESTED, "Health-check non implementato per questo provider; chiave salvata.", None


# -- AI agent (LLM, opt-in) --------------------------------------------------
# Questi 3 provider sono usati SOLO dalle capability IA opt-in
# (narrative_synthesis / entity_resolution_ai / triage_ai), mai da un
# connettore. Import locale di llm_client per evitare un import a livello
# modulo che non serve al resto di questo file.

def check_llm_anthropic(api_key: str) -> tuple[str, str, int | None]:
    if not api_key:
        return STATE_NOT_CONFIGURED, "Chiave non configurata.", None
    from .llm_client import health_check
    state, msg, http_status = health_check("anthropic", api_key)
    return _STATE_MAP.get(state, STATE_NETWORK_ERROR), msg, http_status


def check_llm_openai(api_key: str) -> tuple[str, str, int | None]:
    if not api_key:
        return STATE_NOT_CONFIGURED, "Chiave non configurata.", None
    from .llm_client import health_check
    state, msg, http_status = health_check("openai", api_key)
    return _STATE_MAP.get(state, STATE_NETWORK_ERROR), msg, http_status


def check_llm_local(value: str) -> tuple[str, str, int | None]:
    """`value` è 'base_url' o 'base_url|bearer_token' (stessa convenzione di
    google_pse per 'apikey|cx'), non una singola api_key — vedi
    llm_client.parse_local_value."""
    if not value:
        return STATE_NOT_CONFIGURED, "Endpoint locale non configurato.", None
    from .llm_client import health_check, parse_local_value
    base_url, token = parse_local_value(value)
    if not base_url:
        return STATE_NOT_CONFIGURED, "Endpoint locale non configurato.", None
    state, msg, http_status = health_check("local", token, base_url=base_url)
    return _STATE_MAP.get(state, STATE_NETWORK_ERROR), msg, http_status


# llm_client.health_check usa una nomenclatura di stato leggermente diversa
# (es. "unsupported" per provider ignoti) — mappata sugli stessi STATE_* di
# questo modulo così ProviderStatus resta uniforme in tutta la UI.
_STATE_MAP: dict[str, str] = {
    "ok": STATE_OK,
    "not_configured": STATE_NOT_CONFIGURED,
    "auth_error": STATE_AUTH_ERROR,
    "quota_exceeded": STATE_QUOTA_EXCEEDED,
    "network_error": STATE_NETWORK_ERROR,
    "unsupported": STATE_UNSUPPORTED,
}


# Registry of provider checks. Keys must match API_KEY_CATALOG service names.
PROVIDER_CHECKS: dict[str, Callable[[str], tuple[str, str, int | None]]] = {
    "brave": check_brave,
    "bing": check_bing,
    "serper": check_serper,
    "shodan": check_shodan,
    "virustotal": check_virustotal,
    "hibp": check_hibp,
    "hunter": check_hunter,
    "abuseipdb": check_abuseipdb,
    "github": check_github,
    "leakix": check_leakix,
    "intelx": check_intelx,
    "fullhunt": check_fullhunt,
    "llm_anthropic": check_llm_anthropic,
    "llm_openai": check_llm_openai,
    "llm_local": check_llm_local,
}


def check_provider(service: str, api_key: str) -> ProviderStatus:
    """Run a health probe for a provider. Returns a ProviderStatus.

    Never raises. Latency is measured in ms.
    """
    if service not in PROVIDER_CHECKS:
        if not api_key:
            return ProviderStatus(
                service=service, state=STATE_NOT_CONFIGURED,
                message="Chiave non configurata.", checked_at=_now_iso(),
            )
        # Key present but no probe implemented — be honest.
        return ProviderStatus(
            service=service, state=STATE_UNTESTED,
            message="Chiave salvata. Nessun health-check disponibile per questo provider.",
            checked_at=_now_iso(), last4=_last4(api_key),
        )
    fn = PROVIDER_CHECKS[service]
    t0 = time.monotonic()
    try:
        state, msg, http_status = fn(api_key)
    except Exception as exc:  # pragma: no cover — defensive
        state, msg, http_status = STATE_NETWORK_ERROR, f"Errore probe: {exc}", None
    latency = int((time.monotonic() - t0) * 1000)
    return ProviderStatus(
        service=service, state=state, message=msg, checked_at=_now_iso(),
        last4=_last4(api_key), http_status=http_status, latency_ms=latency,
    )


# ---------------------------------------------------------------------------
# In-memory result cache (TTL) — avoid hammering provider on every page load
# ---------------------------------------------------------------------------
_CACHE: dict[tuple[str, str], tuple[float, ProviderStatus]] = {}
_CACHE_TTL_SECONDS = 300  # 5 minuti


def cached_status(service: str, api_key: str) -> ProviderStatus:
    """Returns cached status if fresh, else runs check_provider and caches."""
    cache_key = (service, _last4(api_key))  # avoid storing full keys
    now = time.time()
    entry = _CACHE.get(cache_key)
    if entry and now - entry[0] < _CACHE_TTL_SECONDS:
        return entry[1]
    status = check_provider(service, api_key)
    _CACHE[cache_key] = (now, status)
    return status


def clear_cache() -> None:
    """Clear the in-memory provider status cache."""
    _CACHE.clear()


def invalidate_provider(service: str) -> None:
    """Forget cached status for a specific provider."""
    to_remove = [k for k in _CACHE if k[0] == service]
    for k in to_remove:
        _CACHE.pop(k, None)
