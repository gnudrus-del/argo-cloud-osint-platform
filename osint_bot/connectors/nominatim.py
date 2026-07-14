"""Connector: OpenStreetMap Nominatim — free geocoding & reverse geocoding.

Public Nominatim instance allows ~1 req/s without key. We send a polite
User-Agent (required by ToS) and respect rate limit.

Action class: passive. Input: ``address`` (text query).
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
    name="nominatim",
    label="OSM Nominatim",
    action_class=ACTION_PASSIVE,
    input_types=("address", "company"),
    output_categories=("geo",),
    required_key="",
    cache_ttl=86400,
    rate_limit=RateLimit(per_minute=30, per_day=2000, burst=2),
    legal_note="nominatim.legal_note",
    health_check_url="https://nominatim.openstreetmap.org/status",
)


class NominatimConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        q = context.target.strip()
        if not q:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=_t("nominatim.empty_query", context.lang))
        url = (
            "https://nominatim.openstreetmap.org/search?"
            + urllib.parse.urlencode({"q": q, "format": "json", "limit": 5,
                                      "addressdetails": 1})
        )
        try:
            results = _safe_http.get_json(url, timeout=context.timeout)
        except Exception as exc:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=_t("generic.error", context.lang,
                                            service="Nominatim", error=exc))

        findings: list[Finding] = []
        for r in (results or [])[:3]:
            display = r.get("display_name", "")
            lat = r.get("lat"); lon = r.get("lon")
            if lat and lon:
                ev = [Evidence(
                    url=f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}",
                    title="OpenStreetMap")]
                findings.append(Finding(
                    kind="geo_address",
                    value=f"{lat},{lon}",
                    confidence=0.75, source_reliability="B", info_credibility=3,
                    evidence=ev,
                    notes=_t("nominatim.result", context.lang, display=display),
                ))
        return ConnectorResult(connector=self.spec.name, status="ok",
                               findings=findings, raw={"hits": len(results)})

    def health_check(self) -> bool:
        try:
            _safe_http.get_bytes(self.spec.health_check_url, timeout=5)
            return True
        except Exception:
            return False
