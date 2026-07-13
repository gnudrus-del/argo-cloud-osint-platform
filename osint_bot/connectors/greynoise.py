"""Connector: GreyNoise Community — IP "internet noise" context.

Community endpoint is free (API key obtainable for free). Tells you if an IP
is a known scanner / benign actor.

Action class: passive. Input: ``ip``.
"""
from __future__ import annotations

from .. import _safe_http
from ..connector import (
    ACTION_PASSIVE,
    BaseConnector,
    ConnectorContext,
    ConnectorResult,
    ConnectorSpec,
    RateLimit,
)
from ..models import Evidence, Finding

_SPEC = ConnectorSpec(
    name="greynoise",
    label="GreyNoise",
    action_class=ACTION_PASSIVE,
    input_types=("ip",),
    output_categories=("threat_intel",),
    required_key="greynoise",
    cache_ttl=3600,
    rate_limit=RateLimit(per_minute=20, per_day=10_000, burst=3),
    legal_note="GreyNoise: contesto su scanner Internet. Solo IP, no PII.",
    health_check_url="https://api.greynoise.io/ping",
)


class GreyNoiseConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        if not context.api_key:
            return ConnectorResult(connector=self.spec.name, status="missing_key",
                                   error="GreyNoise richiede API key (BYOK).")
        url = f"https://api.greynoise.io/v3/community/{context.target}"
        try:
            data = _safe_http.get_json(url, headers={
            "key": context.api_key, "Accept": "application/json"}, timeout=context.timeout)
        except Exception as exc:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=f"GreyNoise: {exc}")
        if not data.get("noise"):
            return ConnectorResult(connector=self.spec.name, status="ok", findings=[],
                                   raw={"noise": False})
        ev = [Evidence(url=f"https://viz.greynoise.io/ip/{context.target}",
                       title="GreyNoise")]
        return ConnectorResult(
            connector=self.spec.name, status="ok",
            findings=[Finding(
                kind="ip_known_scanner", value=context.target,
                confidence=0.90, source_reliability="B", info_credibility=2,
                evidence=ev,
                notes=f"GreyNoise: classification={data.get('classification', '?')}, "
                      f"name={data.get('name', '?')}",
            )],
            raw=data,
        )

    def health_check(self) -> bool:
        return False
