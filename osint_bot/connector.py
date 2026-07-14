"""Pillar 1.1 — Connector SDK: formal contract for typed, rate-limited, cached connectors.

A Connector is a typed data-collection unit that differs from an ExternalToolPlugin in
three fundamental ways:

1. **Transport**: pure Python HTTP (urllib / http.client), no subprocess.
2. **Typing**: declares input_types, output_categories, action_class, required_key, cache_ttl,
   rate_limit — all machine-readable so the registry and orchestrator can reason about them.
3. **Infrastructure**: rate limiting, caching, provenance stamping, and health-check are built
   into the SDK base class — a connector author writes only the `_fetch()` method.

Usage::

    from osint_bot.connectors import crt_sh
    from osint_bot.connector import ConnectorContext, ConnectorRegistry

    registry = ConnectorRegistry()
    registry.register(crt_sh.CrtShConnector())

    ctx = ConnectorContext(target="example.com", target_type="domain", actor="analyst")
    result = registry.run("crt_sh", ctx)
    for f in result.findings:
        print(f.kind, f.value)
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol

from .models import Finding, Provenance

# ---------------------------------------------------------------------------
# Security action classes (mirrors safety.py vocabulary)
# ---------------------------------------------------------------------------
ACTION_PASSIVE = "passive"
ACTION_ACTIVE_GATED = "active-gated"
ACTION_PII_GATED = "pii-gated"
ACTION_DARKWEB_GATED = "darkweb-gated"


# ---------------------------------------------------------------------------
# Rate-limit descriptor
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class RateLimit:
    per_minute: int = 60
    per_day: int = 10_000
    burst: int = 10  # max consecutive calls without back-off


# ---------------------------------------------------------------------------
# Connector specification (the contract)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ConnectorSpec:
    """Static metadata for one connector.  Validated at registration time."""
    name: str
    label: str                      # human-readable label shown in UI
    action_class: str               # one of ACTION_* constants above
    input_types: tuple[str, ...]    # e.g. ("domain", "ip")
    output_categories: tuple[str, ...]  # e.g. ("network_identifiers",)
    required_key: str               # service name in API_KEY_CATALOG, or "" if free
    cache_ttl: int                  # seconds; 0 = no cache
    rate_limit: RateLimit = field(default_factory=RateLimit)
    legal_note: str = ""
    health_check_url: str = ""


# ---------------------------------------------------------------------------
# Context passed to every connector call
# ---------------------------------------------------------------------------
@dataclass
class ConnectorContext:
    target: str
    target_type: str
    actor: str = "system"
    case_id: str = ""
    api_key: str = ""     # resolved by the caller (resolve_api_key)
    timeout: int = 20
    lang: str = "it"      # output language for findings/notes ("it" | "en")


# ---------------------------------------------------------------------------
# Connector result
# ---------------------------------------------------------------------------
@dataclass
class ConnectorResult:
    connector: str
    status: str            # ok | error | missing_key | rate_limited | cached | skipped
    findings: list[Finding] = field(default_factory=list)
    raw: dict = field(default_factory=dict)
    error: str = ""
    cached: bool = False
    duration_ms: int = 0
    provenance: Provenance | None = None

    def to_dict(self) -> dict[str, Any]:
        from dataclasses import asdict
        return asdict(self)


# ---------------------------------------------------------------------------
# Protocol for connector implementations
# ---------------------------------------------------------------------------
class Connector(Protocol):
    spec: ConnectorSpec

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        """Perform the actual HTTP call.  Called by BaseConnector.run()."""
        ...

    def health_check(self) -> bool:
        """Return True if the upstream API is reachable."""
        ...


# ---------------------------------------------------------------------------
# BaseConnector: provides rate-limiting + caching + provenance
# ---------------------------------------------------------------------------
class BaseConnector:
    """Mix-in that wraps _fetch() with rate-limiting, caching and provenance."""

    spec: ConnectorSpec

    def __init__(self) -> None:
        self._cache: dict[str, tuple[float, ConnectorResult]] = {}
        self._call_times: list[float] = []
        self._lock = threading.Lock()

    def run(self, context: ConnectorContext) -> ConnectorResult:
        started = time.monotonic()

        # ------------------------------------------------------------------
        # Policy gate (RoE + case scope + action-class enforcement).
        #
        # Runs BEFORE the api-key / cache / rate-limit checks so a denied
        # call never touches the connector's _fetch, never consumes a rate
        # budget, and never leaks cached output for an out-of-scope target.
        # ------------------------------------------------------------------
        from .policy import check_policy  # local import to avoid cycles
        allowed, reason = check_policy(context, self.spec)
        if not allowed:
            return ConnectorResult(
                connector=self.spec.name,
                status="policy_denied",
                error=reason,
                duration_ms=int((time.monotonic() - started) * 1000),
            )

        # Key check
        if self.spec.required_key and not context.api_key:
            return ConnectorResult(
                connector=self.spec.name,
                status="missing_key",
                error=f"Chiave API mancante per {self.spec.name} (servizio: {self.spec.required_key}). "
                      f"Configurala nel tab Chiavi API.",
            )

        # Cache check
        cache_key = self._cache_key(context)
        if self.spec.cache_ttl > 0:
            with self._lock:
                entry = self._cache.get(cache_key)
                if entry:
                    ts, cached_result = entry
                    if time.time() - ts < self.spec.cache_ttl:
                        result = ConnectorResult(
                            connector=cached_result.connector,
                            status="cached",
                            findings=cached_result.findings,
                            raw=cached_result.raw,
                            cached=True,
                            duration_ms=int((time.monotonic() - started) * 1000),
                            provenance=cached_result.provenance,
                        )
                        return result

        # Rate-limit check (per-minute window)
        with self._lock:
            now = time.time()
            window = 60.0
            self._call_times = [t for t in self._call_times if now - t < window]
            if len(self._call_times) >= self.spec.rate_limit.per_minute:
                return ConnectorResult(
                    connector=self.spec.name,
                    status="rate_limited",
                    error=f"Rate limit raggiunto per {self.spec.name} ({self.spec.rate_limit.per_minute}/min).",
                )
            self._call_times.append(now)

        # Actual fetch
        try:
            result = self._fetch(context)
        except Exception as exc:
            result = ConnectorResult(
                connector=self.spec.name,
                status="error",
                error=str(exc),
            )

        # Stamp provenance on every finding when we have a case
        prov = Provenance(
            tool=self.spec.name,
            collected_at=_now_iso(),
            actor=context.actor,
            case_id=context.case_id,
        ) if context.case_id else None
        result.provenance = prov
        if prov:
            result.findings = [_stamp(f, prov) for f in result.findings]

        result.duration_ms = int((time.monotonic() - started) * 1000)

        # Populate cache on success
        if result.status == "ok" and self.spec.cache_ttl > 0:
            with self._lock:
                self._cache[cache_key] = (time.time(), result)

        return result

    def health_check(self) -> bool:
        """Default: True (override in connectors that can probe cheaply)."""
        return True

    def _cache_key(self, context: ConnectorContext) -> str:
        raw = json.dumps(
            {"connector": self.spec.name, "target": context.target,
             "target_type": context.target_type},
            sort_keys=True,
        )
        return hashlib.sha256(raw.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Connector registry
# ---------------------------------------------------------------------------
class ConnectorRegistry:
    """Central registry of all registered connectors."""

    def __init__(self) -> None:
        self._connectors: dict[str, Connector] = {}

    def register(self, connector: Connector) -> None:
        name = connector.spec.name
        if name in self._connectors:
            raise ValueError(f"Connector '{name}' already registered.")
        self._connectors[name] = connector

    def get(self, name: str) -> Connector:
        if name not in self._connectors:
            raise KeyError(f"Connector '{name}' non registrato.")
        return self._connectors[name]

    def run(self, name: str, context: ConnectorContext) -> ConnectorResult:
        try:
            connector = self.get(name)
        except KeyError as exc:
            return ConnectorResult(connector=name, status="missing", error=str(exc))
        return connector.run(context)

    def by_input_type(self, target_type: str) -> list[str]:
        """Return names of all connectors that accept *target_type*."""
        return [
            name
            for name, conn in self._connectors.items()
            if target_type in conn.spec.input_types
        ]

    def by_action_class(self, action_class: str) -> list[str]:
        return [
            name
            for name, conn in self._connectors.items()
            if conn.spec.action_class == action_class
        ]

    def names(self) -> list[str]:
        return sorted(self._connectors)

    def catalog(self, lang: str = "it") -> list[dict[str, Any]]:
        """Return a list of spec dicts suitable for the UI / API catalog endpoint.

        ``legal_note`` may hold either literal text (legacy) or an i18n catalog
        key; ``_i18n_t`` resolves keys and returns literal text unchanged, so
        this is safe during and after the connector migration.
        """
        from .i18n import t as _i18n_t
        return [
            {
                "name": conn.spec.name,
                "label": conn.spec.label,
                "action_class": conn.spec.action_class,
                "input_types": list(conn.spec.input_types),
                "output_categories": list(conn.spec.output_categories),
                "required_key": conn.spec.required_key,
                "cache_ttl": conn.spec.cache_ttl,
                "legal_note": _i18n_t(conn.spec.legal_note, lang),
            }
            for conn in self._connectors.values()
        ]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _stamp(finding: Finding, prov: Provenance) -> Finding:
    from dataclasses import replace
    return replace(finding, provenance=prov)
