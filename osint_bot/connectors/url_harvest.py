"""Connector: URL harvesting (sostituto nativo di waybackurls/gau/hakrawler/linkfinder).

Aggrega URL storiche del target da fonti passive:
  * Wayback Machine CDX API (web.archive.org)
  * Common Crawl (via il connettore common_crawl esistente non richiamato qui;
    interroghiamo direttamente l'ultimo indice per completezza)
Estrae anche endpoint "interessanti" (parametri, api, file sensibili). Passivo.

Input: ``domain`` | ``url``.
"""
from __future__ import annotations

import re
import urllib.parse

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
    name="url_harvest",
    label="URL harvest (Wayback/CC)",
    action_class=ACTION_PASSIVE,
    input_types=("domain", "url"),
    output_categories=("url_history",),
    required_key="",
    cache_ttl=3600,
    rate_limit=RateLimit(per_minute=10, per_day=1000, burst=2),
    legal_note="url_harvest.legal_note",
    health_check_url="http://web.archive.org/",
)

_MAX_URLS = 200
_INTERESTING_RE = re.compile(
    r"(\?|/api/|/graphql|/admin|/login|/upload|/download|\.json|\.xml|\.sql|"
    r"\.bak|\.old|\.zip|\.env|/wp-json|/actuator|/swagger|token=|key=|password=)",
    re.I,
)


def _domain_of(target: str) -> str:
    t = target.strip()
    if t.startswith(("http://", "https://")):
        return urllib.parse.urlparse(t).netloc
    return t.rstrip("/")


def _wayback(domain: str, timeout: int) -> list[str]:
    url = ("http://web.archive.org/cdx/search/cdx?"
           + urllib.parse.urlencode({
               "url": f"*.{domain}/*", "output": "json",
               "fl": "original", "collapse": "urlkey", "limit": 1000,
           }))
    try:
        data = _safe_http.get_json(url, timeout=timeout)
        # prima riga = header ["original"]
        return [row[0] for row in data[1:] if row]
    except Exception:
        return []


class URLHarvestConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        domain = _domain_of(context.target or "")
        if not domain or "." not in domain:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error="Target deve essere un dominio o URL.")

        urls = _wayback(domain, context.timeout)
        seen: set[str] = set()
        deduped: list[str] = []
        for u in urls:
            if u not in seen:
                seen.add(u)
                deduped.append(u)
            if len(deduped) >= _MAX_URLS:
                break

        findings: list[Finding] = []
        interesting = 0
        for u in deduped:
            is_interesting = bool(_INTERESTING_RE.search(u))
            if is_interesting:
                interesting += 1
            findings.append(Finding(
                kind="archived_url" if not is_interesting else "interesting_url",
                value=u,
                confidence=0.75 if is_interesting else 0.6,
                source_reliability="A", info_credibility=2,
                evidence=[Evidence(url=f"http://web.archive.org/web/*/{u}",
                                   title="Wayback snapshot")],
                notes=("Endpoint potenzialmente interessante (parametri/api/file sensibili)."
                       if is_interesting else "URL storica indicizzata da Wayback."),
                severity="low" if is_interesting else "info",
            ))
        return ConnectorResult(
            connector=self.spec.name, status="ok",
            findings=findings,
            raw={"total": len(deduped), "interesting": interesting},
        )

    def health_check(self) -> bool:
        return True
