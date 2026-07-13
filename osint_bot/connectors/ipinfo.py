"""Connector: IPinfo.io — IP geolocation + ASN.

Free tier 50k/mo (or 1k/day without key). BYOK opzionale.

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
    name="ipinfo",
    label="IPinfo.io",
    action_class=ACTION_PASSIVE,
    input_types=("ip",),
    output_categories=("geo", "network_identifiers"),
    required_key="",
    cache_ttl=86400,
    rate_limit=RateLimit(per_minute=30, per_day=1000, burst=5),
    legal_note="IPinfo: geolocation IP pubblica. Niente PII di utenti.",
    health_check_url="https://ipinfo.io/8.8.8.8/json",
)


class IPinfoConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        url = f"https://ipinfo.io/{context.target}/json"
        if context.api_key:
            url += f"?token={context.api_key}"
        try:
            data = _safe_http.get_json(url, headers={
            "Accept": "application/json", "User-Agent": "Argo-OSINT/1.0"}, timeout=context.timeout)
        except Exception as exc:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=f"IPinfo: {exc}")
        ev = [Evidence(url=f"https://ipinfo.io/{context.target}", title="IPinfo")]
        findings: list[Finding] = []
        for key, kind in (("city", "geo_city"), ("country", "geo_country"),
                          ("org", "ip_owner"), ("loc", "geo_coord")):
            if data.get(key):
                findings.append(Finding(
                    kind=kind, value=str(data[key]),
                    confidence=0.80, source_reliability="B", info_credibility=2,
                    evidence=ev,
                    notes=f"IPinfo: {key}={data[key]}",
                ))
        return ConnectorResult(connector=self.spec.name, status="ok",
                               findings=findings, raw=data)

    def health_check(self) -> bool:
        try:
            _safe_http.get_bytes(self.spec.health_check_url, timeout=5)
            return True
        except Exception:
            return False
