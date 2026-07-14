"""Connector: SecurityTrails — historical DNS + subdomain enumeration.

Requires API key (free tier 50 q/mo). Set in BYOK panel as ``securitytrails``.

Action class: passive. Input: ``domain``.
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
from ..i18n import t as _t
from ..models import Evidence, Finding

_SPEC = ConnectorSpec(
    name="securitytrails",
    label="SecurityTrails",
    action_class=ACTION_PASSIVE,
    input_types=("domain",),
    output_categories=("dns_history", "subdomains"),
    required_key="securitytrails",
    cache_ttl=86400,
    rate_limit=RateLimit(per_minute=2, per_day=50, burst=1),
    legal_note="securitytrails.legal_note",
    health_check_url="https://api.securitytrails.com/v1/ping",
)


class SecurityTrailsConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        if not context.api_key:
            return ConnectorResult(connector=self.spec.name, status="missing_key",
                                   error=_t("securitytrails.missing_key", context.lang))
        url = f"https://api.securitytrails.com/v1/domain/{context.target}/subdomains?children_only=false"
        try:
            data = _safe_http.get_json(url, headers={
            "APIKEY": context.api_key, "Accept": "application/json"}, timeout=context.timeout)
        except Exception as exc:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=_t("generic.error", context.lang, service="SecurityTrails", error=exc))
        subs = (data or {}).get("subdomains") or []
        findings: list[Finding] = []
        for sub in subs[:30]:
            fqdn = f"{sub}.{context.target}"
            ev = [Evidence(
                url=f"https://securitytrails.com/list/apex_domain/{context.target}",
                title="SecurityTrails")]
            findings.append(Finding(
                kind="related_domain", value=fqdn,
                confidence=0.85, source_reliability="B", info_credibility=2,
                evidence=ev,
                notes=_t("securitytrails.subdomain", context.lang),
            ))
        return ConnectorResult(connector=self.spec.name, status="ok",
                               findings=findings,
                               raw={"count": len(subs)})

    def health_check(self) -> bool:
        return False
