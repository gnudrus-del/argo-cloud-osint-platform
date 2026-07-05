"""Connector: AlienVault OTX — community threat intel pulses.

Free with API key. Returns malicious-context evidence for IP/domain/URL/hash.

Action class: passive. Input: ``ip``, ``domain``, ``url``.
"""
from __future__ import annotations

import json
import urllib.request

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
    name="otx",
    label="AlienVault OTX",
    action_class=ACTION_PASSIVE,
    input_types=("ip", "domain", "url"),
    output_categories=("threat_intel",),
    required_key="otx",
    cache_ttl=3600,
    rate_limit=RateLimit(per_minute=20, per_day=10_000, burst=3),
    legal_note="OTX: pulse community open. Free per uso difensivo.",
    health_check_url="https://otx.alienvault.com/api/v1/indicators/domain/example.com/general",
)


def _section_for(target_type: str) -> str:
    return {"ip": "IPv4", "domain": "domain", "url": "url"}.get(target_type, "domain")


class OTXConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        if not context.api_key:
            return ConnectorResult(connector=self.spec.name, status="missing_key",
                                   error="OTX richiede API key.")
        sec = _section_for(context.target_type)
        url = f"https://otx.alienvault.com/api/v1/indicators/{sec}/{context.target}/general"
        req = urllib.request.Request(url, headers={
            "X-OTX-API-KEY": context.api_key, "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=context.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
        except Exception as exc:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=f"OTX: {exc}")
        pulse_info = (data or {}).get("pulse_info") or {}
        pulses = pulse_info.get("pulses") or []
        count = pulse_info.get("count", 0)
        findings: list[Finding] = []
        for p in pulses[:5]:
            ev = [Evidence(url=f"https://otx.alienvault.com/pulse/{p.get('id', '')}",
                           title=p.get("name") or "OTX pulse")]
            findings.append(Finding(
                kind="otx_pulse_match", value=p.get("name", ""),
                confidence=0.80, source_reliability="B", info_credibility=2,
                severity="medium" if count > 0 else "info",
                evidence=ev,
                notes=f"Indicatore presente in pulse OTX (autore: {p.get('author_name', '?')}).",
            ))
        return ConnectorResult(connector=self.spec.name, status="ok",
                               findings=findings,
                               raw={"pulse_count": count})

    def health_check(self) -> bool:
        return False
