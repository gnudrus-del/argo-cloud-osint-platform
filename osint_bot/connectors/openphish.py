"""Connector: OpenPhish — community phishing feed.

The free public feed (https://openphish.com/feed.txt) is a flat list of phishing
URLs updated hourly. We download it (cached), check membership for the target
URL/domain, and report a finding when present.

Action class: passive. Input: ``url``, ``domain``.
"""
from __future__ import annotations

import time
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
    name="openphish",
    label="OpenPhish",
    action_class=ACTION_PASSIVE,
    input_types=("url", "domain"),
    output_categories=("threat_intel",),
    required_key="",
    cache_ttl=3600,
    rate_limit=RateLimit(per_minute=6, per_day=240, burst=2),
    legal_note="Feed pubblico OpenPhish. Solo verifiche difensive.",
    health_check_url="https://openphish.com/feed.txt",
)

# Cache leggera in-memory: la feed e' aggiornata orariamente.
_CACHE: dict = {"at": 0.0, "set": frozenset()}


def _load_feed(timeout: int) -> frozenset[str]:
    if time.time() - _CACHE["at"] < 3600 and _CACHE["set"]:
        return _CACHE["set"]
    try:
        text = _safe_http.get_text("https://openphish.com/feed.txt", timeout=timeout)
        urls = frozenset(line.strip().lower() for line in text.splitlines() if line.strip())
        _CACHE["at"] = time.time()
        _CACHE["set"] = urls
        return urls
    except Exception:
        return frozenset()


class OpenPhishConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        feed = _load_feed(context.timeout)
        if not feed:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error="OpenPhish: feed non scaricabile.")
        target = context.target.strip().lower()
        # Check exact URL match + host match (since feed is URL-based).
        matches: list[str] = []
        if target in feed:
            matches.append(target)
        host = target
        if "://" in host:
            host = urllib.parse.urlparse(host).netloc
        for url in feed:
            if "://" in url and urllib.parse.urlparse(url).netloc == host:
                matches.append(url)
                if len(matches) >= 5:
                    break
        if not matches:
            return ConnectorResult(connector=self.spec.name, status="ok", findings=[])
        ev = [Evidence(url="https://openphish.com/", title="OpenPhish")]
        findings = [Finding(
            kind="openphish_match", value=m,
            confidence=0.92, source_reliability="C", info_credibility=2,
            severity="high", evidence=ev,
            notes="URL presente nella feed pubblica OpenPhish.",
        ) for m in matches[:5]]
        return ConnectorResult(connector=self.spec.name, status="ok",
                               findings=findings, raw={"matches": matches})

    def health_check(self) -> bool:
        return bool(_load_feed(5))
