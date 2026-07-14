"""Connector: AlienVault OTX — community threat intel pulses.

Free with API key. Returns malicious-context evidence for IP/domain/URL/hash.

Action class: passive. Input: ``ip``, ``domain``, ``url``.
"""
from __future__ import annotations

from .. import _safe_http
from ..i18n import t as _t
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
    legal_note="otx.legal_note",
    health_check_url="https://otx.alienvault.com/api/v1/indicators/domain/example.com/general",
)


def _section_for(target_type: str) -> str:
    return {"ip": "IPv4", "domain": "domain", "url": "url"}.get(target_type, "domain")


class OTXConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        if not context.api_key:
            return ConnectorResult(connector=self.spec.name, status="missing_key",
                                   error=_t("generic.no_key", context.lang, service="OTX"))
        sec = _section_for(context.target_type)
        url = f"https://otx.alienvault.com/api/v1/indicators/{sec}/{context.target}/general"
        try:
            data = _safe_http.get_json(url, headers={
            "X-OTX-API-KEY": context.api_key, "Accept": "application/json"}, timeout=context.timeout)
        except Exception as exc:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=_t("generic.error", context.lang, service="OTX", error=exc))
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
                notes=_t("otx.pulse_match", context.lang, author=p.get('author_name', '?')),
            ))
        return ConnectorResult(connector=self.spec.name, status="ok",
                               findings=findings,
                               raw={"pulse_count": count})

    def health_check(self) -> bool:
        return False
