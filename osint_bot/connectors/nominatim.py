"""Connector: OpenStreetMap Nominatim — free geocoding & reverse geocoding.

Public Nominatim instance allows ~1 req/s without key. We send a polite
User-Agent (required by ToS) and respect rate limit.

Action class: passive. Input: ``address`` (text query).
"""
from __future__ import annotations

from .._ua import user_agent as _ua

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
    name="nominatim",
    label="OSM Nominatim",
    action_class=ACTION_PASSIVE,
    input_types=("address", "company"),
    output_categories=("geo",),
    required_key="",
    cache_ttl=86400,
    rate_limit=RateLimit(per_minute=30, per_day=2000, burst=2),
    legal_note=(
        "Nominatim free tier richiede User-Agent identificativo e ~1 req/s. "
        "Rispetta le linee guida OSM."
    ),
    health_check_url="https://nominatim.openstreetmap.org/status",
)


class NominatimConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        q = context.target.strip()
        if not q:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error="Nominatim: query vuota.")
        url = (
            "https://nominatim.openstreetmap.org/search?"
            + urllib.parse.urlencode({"q": q, "format": "json", "limit": 5,
                                      "addressdetails": 1})
        )
        req = urllib.request.Request(url, headers={
            "User-Agent": _ua(),
            "Accept": "application/json",
        })
        try:
            with urllib.request.urlopen(req, timeout=context.timeout) as resp:
                results = json.loads(resp.read().decode("utf-8", errors="replace"))
        except Exception as exc:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=f"Nominatim: {exc}")

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
                    notes=f"OSM Nominatim: {display}",
                ))
        return ConnectorResult(connector=self.spec.name, status="ok",
                               findings=findings, raw={"hits": len(results)})

    def health_check(self) -> bool:
        try:
            urllib.request.urlopen(self.spec.health_check_url, timeout=5).close()
            return True
        except Exception:
            return False
