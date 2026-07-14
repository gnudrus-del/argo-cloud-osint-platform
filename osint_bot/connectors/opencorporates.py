"""Connector: OpenCorporates — global company registry.

Free tier without key (limited). BYOK opzionale per piu' query.

Action class: passive. Input: ``company``, ``person`` (officer search).
"""
from __future__ import annotations

import urllib.parse

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
    name="opencorporates",
    label="OpenCorporates",
    action_class=ACTION_PASSIVE,
    input_types=("company",),
    output_categories=("corporate_registry",),
    required_key="",
    cache_ttl=86400,
    rate_limit=RateLimit(per_minute=10, per_day=200, burst=2),
    legal_note="opencorporates.legal_note",
    health_check_url="https://api.opencorporates.com/v0.4/companies/search?q=test&limit=1",
)


class OpenCorporatesConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        params = {"q": context.target.strip(), "limit": 5, "format": "json"}
        if context.api_key:
            params["api_token"] = context.api_key
        url = "https://api.opencorporates.com/v0.4/companies/search?" + urllib.parse.urlencode(params)
        try:
            data = _safe_http.get_json(url, headers={
            "Accept": "application/json", "User-Agent": "Argo-OSINT/1.0"}, timeout=context.timeout)
        except Exception as exc:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=_t("generic.error", context.lang, service="OpenCorporates", error=exc))
        results = ((data or {}).get("results") or {}).get("companies") or []
        findings: list[Finding] = []
        for r in results[:5]:
            c = r.get("company") or {}
            name = c.get("name", "")
            jur = c.get("jurisdiction_code", "")
            ev = [Evidence(url=c.get("opencorporates_url", ""), title="OpenCorporates")]
            findings.append(Finding(
                kind="company_record", value=f"{name} ({jur})",
                confidence=0.85, source_reliability="B", info_credibility=2,
                evidence=ev,
                notes=_t("opencorporates.company_record", context.lang,
                         number=c.get('company_number', '?'),
                         status=c.get('current_status', '?'),
                         created=c.get('incorporation_date', '?')),
            ))
        return ConnectorResult(connector=self.spec.name, status="ok",
                               findings=findings,
                               raw={"total": len(results)})

    def health_check(self) -> bool:
        try:
            _safe_http.get_bytes(self.spec.health_check_url, timeout=5)
            return True
        except Exception:
            return False
