"""Connector: PhishTank — known-phishing URL database.

Free API (no key required for HEAD lookups). Returns whether a URL/domain
appears in the PhishTank verified phishing feed.

Action class: passive. Input: ``url``, ``domain``.
"""
from __future__ import annotations

import json
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
    name="phishtank",
    label="PhishTank",
    action_class=ACTION_PASSIVE,
    input_types=("url", "domain"),
    output_categories=("threat_intel",),
    required_key="",  # free, no key
    cache_ttl=3600,
    rate_limit=RateLimit(per_minute=30, per_day=10_000, burst=5),
    legal_note=(
        "PhishTank: lookup pubblico su URL phishing verificati. Nessuna chiave "
        "richiesta. Usare per verifiche difensive, non per offuscare URL."
    ),
    health_check_url="https://data.phishtank.com/data/online-valid.json.gz",
)


class PhishTankConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        target = context.target.strip()
        if not target.startswith(("http://", "https://")):
            target = "http://" + target  # PhishTank store URL only
        url = "https://checkurl.phishtank.com/checkurl/"
        data = urllib.parse.urlencode({
            "url": target, "format": "json", "app_key": "argo-osint"
        }).encode("ascii")
        req = urllib.request.Request(url, data=data,
                                     headers={"User-Agent": "Argo-OSINT/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=context.timeout) as resp:
                body = json.loads(resp.read().decode("utf-8", errors="replace"))
        except Exception as exc:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=f"PhishTank: {exc}")
        result = (body or {}).get("results") or {}
        if not result.get("in_database"):
            return ConnectorResult(connector=self.spec.name, status="ok",
                                   findings=[], raw={"in_database": False})
        ev = [Evidence(url=result.get("phish_detail_page") or target,
                       title="PhishTank")]
        return ConnectorResult(
            connector=self.spec.name, status="ok",
            findings=[Finding(
                kind="phishtank_match", value=target,
                confidence=0.95, source_reliability="B", info_credibility=2,
                severity="high", evidence=ev,
                notes="URL presente nel database PhishTank di phishing verificato.",
            )],
            raw=result,
        )

    def health_check(self) -> bool:
        try:
            urllib.request.urlopen("https://www.phishtank.com/", timeout=5).close()
            return True
        except Exception:
            return False
