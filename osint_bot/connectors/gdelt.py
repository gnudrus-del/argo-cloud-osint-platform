"""Connector: GDELT 2.0 — public news/events database.

Free GDELT DOC API: searches articles + tone + actors. No key required.

Action class: passive. Input: ``company``, ``person`` (text query).
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
    name="gdelt",
    label="GDELT 2.0",
    action_class=ACTION_PASSIVE,
    input_types=("company", "person", "domain"),
    output_categories=("news_media",),
    required_key="",
    cache_ttl=3600,
    rate_limit=RateLimit(per_minute=20, per_day=2000, burst=3),
    legal_note="GDELT e' un dataset open su news/eventi. Uso libero per ricerca.",
    health_check_url="https://api.gdeltproject.org/api/v2/doc/doc?query=test&mode=ArtList&format=json&maxrecords=1",
)


class GDELTConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        q = context.target.strip()
        if not q:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error="GDELT: query vuota.")
        url = (
            "https://api.gdeltproject.org/api/v2/doc/doc?"
            + urllib.parse.urlencode({
                "query": q, "mode": "ArtList", "format": "json",
                "maxrecords": 10, "sort": "datedesc",
            })
        )
        try:
            data = _safe_http.get_json(url, headers={
            "User-Agent": "Argo-OSINT/1.0", "Accept": "application/json"}, timeout=context.timeout)
        except Exception as exc:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=f"GDELT: {exc}")
        articles = (data or {}).get("articles") or []
        findings: list[Finding] = []
        for a in articles[:5]:
            link = a.get("url") or ""; title = a.get("title") or ""
            domain = a.get("domain") or ""
            ev = [Evidence(url=link, title=title)]
            findings.append(Finding(
                kind="news_mention", value=title,
                confidence=0.70, source_reliability="C", info_credibility=3,
                evidence=ev,
                notes=f"GDELT — fonte: {domain}, lingua: {a.get('language', '?')}",
            ))
        return ConnectorResult(connector=self.spec.name, status="ok",
                               findings=findings,
                               raw={"total": len(articles)})

    def health_check(self) -> bool:
        try:
            _safe_http.get_bytes(self.spec.health_check_url, timeout=5)
            return True
        except Exception:
            return False
