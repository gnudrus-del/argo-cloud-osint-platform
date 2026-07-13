"""Connector: Google Programmable Search Engine (PSE).

Requires Google API key + Custom Search Engine ID (cx). BYOK both.
Configurazione attesa nell'API key: ``apikey|cx`` (separato da pipe).
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
from ..models import Evidence, Finding

_SPEC = ConnectorSpec(
    name="google_pse",
    label="Google PSE",
    action_class=ACTION_PASSIVE,
    input_types=("domain", "company", "person"),
    output_categories=("web_search",),
    required_key="google_pse",
    cache_ttl=600,
    rate_limit=RateLimit(per_minute=10, per_day=100, burst=2),
    legal_note="Google PSE: API ufficiale. ToS Google.",
    health_check_url="https://customsearch.googleapis.com/customsearch/v1",
)


class GooglePSEConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        if not context.api_key or "|" not in context.api_key:
            return ConnectorResult(connector=self.spec.name, status="missing_key",
                                   error="Google PSE richiede 'API_KEY|CX_ID'.")
        api_key, cx = context.api_key.split("|", 1)
        url = ("https://customsearch.googleapis.com/customsearch/v1?"
               + urllib.parse.urlencode({"key": api_key, "cx": cx,
                                         "q": context.target, "num": 10}))
        try:
            data = _safe_http.get_json(url, timeout=context.timeout)
        except Exception as exc:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=f"Google PSE: {exc}")
        items = (data or {}).get("items") or []
        findings: list[Finding] = []
        for it in items[:10]:
            ev = [Evidence(url=it.get("link", ""), title=it.get("title", ""))]
            findings.append(Finding(
                kind="web_presence", value=it.get("link", ""),
                confidence=0.65, source_reliability="C", info_credibility=3,
                evidence=ev,
                notes=f"Google PSE: {it.get('snippet', '')[:140]}",
            ))
        return ConnectorResult(connector=self.spec.name, status="ok",
                               findings=findings, raw={"results": len(items)})

    def health_check(self) -> bool:
        return False
