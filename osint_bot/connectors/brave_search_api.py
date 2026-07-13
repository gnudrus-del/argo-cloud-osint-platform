"""Connector: Brave Search API — web search results.

BYOK required. Returns title/url/snippet per result.

Action class: passive. Input: any text query.
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
    name="brave_search_api",
    label="Brave Search API",
    action_class=ACTION_PASSIVE,
    input_types=("domain", "company", "person"),
    output_categories=("web_search",),
    required_key="brave",
    cache_ttl=600,
    rate_limit=RateLimit(per_minute=20, per_day=2000, burst=3),
    legal_note="Brave Search API: BYOK richiesto. ToS Brave applicabile.",
    health_check_url="https://api.search.brave.com/res/v1/web/search?q=test",
)


class BraveSearchAPIConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        if not context.api_key:
            return ConnectorResult(connector=self.spec.name, status="missing_key",
                                   error="Brave Search richiede API key (BYOK).")
        url = ("https://api.search.brave.com/res/v1/web/search?"
               + urllib.parse.urlencode({"q": context.target, "count": 10}))
        try:
            data = _safe_http.get_json(url, headers={
            "X-Subscription-Token": context.api_key,
            "Accept": "application/json",
        }, timeout=context.timeout)
        except Exception as exc:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=f"Brave Search: {exc}")
        results = (((data or {}).get("web") or {}).get("results") or [])[:10]
        findings: list[Finding] = []
        for r in results:
            ev = [Evidence(url=r.get("url", ""), title=r.get("title", ""))]
            findings.append(Finding(
                kind="web_presence", value=r.get("url", ""),
                confidence=0.60, source_reliability="C", info_credibility=3,
                evidence=ev,
                notes=f"Brave Search: {r.get('description', '')[:140]}",
            ))
        return ConnectorResult(connector=self.spec.name, status="ok",
                               findings=findings, raw={"results": len(results)})

    def health_check(self) -> bool:
        return False
