"""Connector: Common Crawl CDX index — trova URL storiche di un dominio.

Interroga l'ultimo indice pubblicato di Common Crawl per elencare URL
crawlate del target (utile per file dimenticati, endpoint deprecati, ecc.).

Zero API key. Un GET all'endpoint CDX pubblico.
Input: ``domain`` (usa ``*.domain/*`` per includere sottodomini).
"""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
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
    name="common_crawl",
    label="Common Crawl (CDX)",
    action_class=ACTION_PASSIVE,
    input_types=("domain",),
    output_categories=("archive", "url_history"),
    required_key="",
    cache_ttl=21_600,
    rate_limit=RateLimit(per_minute=6, per_day=200, burst=1),
    legal_note="Indice pubblico Common Crawl (Apache 2.0). No dati personali inviati.",
    health_check_url="http://index.commoncrawl.org/collinfo.json",
)

_MAX_URLS = 25
_CDX_LIMIT = 100  # cap richiesta all'API


def _list_indexes(timeout: int) -> list[str]:
    """Elenca gli ID degli indici Common Crawl in ordine di recenza."""
    try:
        req = urllib.request.Request("http://index.commoncrawl.org/collinfo.json",
                                     headers={"User-Agent": "argo-osint/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        return [c["id"] for c in data if isinstance(c, dict) and "id" in c]
    except Exception:
        return []


def _query_cdx(index_id: str, target: str, timeout: int) -> list[dict]:
    """Interroga /CC-MAIN-.../-index per il target (con wildcard sottodominio)."""
    url_query = f"*.{target}/*"
    qs = urllib.parse.urlencode({
        "url": url_query,
        "output": "json",
        "limit": _CDX_LIMIT,
    })
    url = f"http://index.commoncrawl.org/{index_id}-index?{qs}"
    req = urllib.request.Request(url, headers={"User-Agent": "argo-osint/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
    except Exception:
        return []
    rows: list[dict] = []
    for line in body.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


class CommonCrawlConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        target = (context.target or "").strip().lower().rstrip(".")
        if not target or "/" in target:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error="Target deve essere un dominio (no schema, no path).")

        indexes = _list_indexes(context.timeout)
        if not indexes:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error="Impossibile leggere collinfo.json da Common Crawl.")

        # Provo i due indici piu' recenti (se il primo e' vuoto)
        rows: list[dict] = []
        used_index = ""
        for idx in indexes[:2]:
            rows = _query_cdx(idx, target, context.timeout)
            if rows:
                used_index = idx
                break

        findings: list[Finding] = []
        ev = [Evidence(url=f"http://index.commoncrawl.org/{used_index or indexes[0]}-index?url=*.{target}/*",
                       title=f"Common Crawl {used_index or indexes[0]}")]
        seen: set[str] = set()
        for row in rows[:_MAX_URLS]:
            url = row.get("url") or ""
            if not url or url in seen:
                continue
            seen.add(url)
            status = row.get("status") or ""
            mime = row.get("mime") or ""
            findings.append(Finding(
                kind="archived_url", value=url,
                confidence=0.9, source_reliability="A", info_credibility=1,
                evidence=ev,
                notes=(f"URL indicizzata da Common Crawl {used_index}. "
                       f"HTTP {status}, MIME {mime}."),
            ))
        return ConnectorResult(
            connector=self.spec.name, status="ok",
            findings=findings,
            raw={"index": used_index or indexes[0], "rows": len(rows),
                 "returned": len(findings)},
        )

    def health_check(self) -> bool:
        try:
            urllib.request.urlopen("http://index.commoncrawl.org/collinfo.json",
                                   timeout=3).close()
            return True
        except Exception:
            return False
