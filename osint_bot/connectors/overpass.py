"""Connector: Overpass API (OpenStreetMap) — geo-OSINT no-key.

Interroga l'API Overpass pubblica per estrarre feature OSM attorno a una
coordinata (``lat,lon``) o per nome. Utile per contestualizzare un IP
geolocalizzato, un indirizzo o coordinate trovate in un'immagine (EXIF GPS).

Zero API key. Passivo. Rispetta il rate-limit generoso di Overpass.
Input: ``geo`` nel formato ``lat,lon`` (opzionale raggio in metri: ``lat,lon,r``).
"""
from __future__ import annotations

import json
import re

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
    name="overpass",
    label="Overpass / OSM",
    action_class=ACTION_PASSIVE,
    input_types=("geo", "coordinate"),
    output_categories=("geo_features",),
    required_key="",
    cache_ttl=86_400,
    rate_limit=RateLimit(per_minute=10, per_day=1000, burst=2),
    legal_note="overpass.legal_note",
    health_check_url="https://overpass-api.de/api/status",
)

_COORD_RE = re.compile(r"^\s*([-+]?\d{1,2}(?:\.\d+)?)\s*,\s*([-+]?\d{1,3}(?:\.\d+)?)(?:\s*,\s*(\d+))?\s*$")
_ENDPOINT = "https://overpass-api.de/api/interpreter"
_MAX_FEATURES = 30


def _parse_geo(target: str) -> tuple[float, float, int] | None:
    m = _COORD_RE.match(target or "")
    if not m:
        return None
    lat = float(m.group(1))
    lon = float(m.group(2))
    radius = int(m.group(3)) if m.group(3) else 250
    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
        return None
    return lat, lon, min(radius, 2000)  # cap 2km per non sovraccaricare Overpass


def _query(lat: float, lon: float, radius: int, timeout: int) -> dict | None:
    # Feature "interessanti" per OSINT: amenity, shop, office, tourism, building name.
    ql = (
        f"[out:json][timeout:{min(timeout, 25)}];"
        f"("
        f"node(around:{radius},{lat},{lon})[amenity];"
        f"node(around:{radius},{lat},{lon})[shop];"
        f"node(around:{radius},{lat},{lon})[office];"
        f"node(around:{radius},{lat},{lon})[tourism];"
        f"way(around:{radius},{lat},{lon})[building][name];"
        f");"
        f"out center {_MAX_FEATURES};"
    )
    try:
        _, raw = _safe_http.post_form(_ENDPOINT, {"data": ql}, timeout=timeout + 5)
        return json.loads(raw.decode("utf-8", errors="replace"))
    except Exception:
        return None


class OverpassConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        parsed = _parse_geo(context.target or "")
        if not parsed:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=_t("overpass.invalid_target", context.lang))
        lat, lon, radius = parsed
        data = _query(lat, lon, radius, context.timeout)
        if data is None:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=_t("overpass.unreachable", context.lang))

        ev_base = f"https://www.openstreetmap.org/#map=18/{lat}/{lon}"
        findings: list[Finding] = []
        for el in (data.get("elements") or [])[:_MAX_FEATURES]:
            tags = el.get("tags") or {}
            name = tags.get("name")
            if not name:
                continue
            kind_label = tags.get("amenity") or tags.get("shop") or tags.get("office") \
                or tags.get("tourism") or tags.get("building") or "feature"
            osm_url = f"https://www.openstreetmap.org/{el.get('type')}/{el.get('id')}"
            findings.append(Finding(
                kind="geo_osm_feature",
                value=f"{name} ({kind_label})",
                confidence=0.7, source_reliability="B", info_credibility=2,
                evidence=[Evidence(url=osm_url, title=f"OSM {el.get('type')}/{el.get('id')}")],
                notes=_t("overpass.feature", context.lang, radius=radius, lat=lat, lon=lon),
            ))

        return ConnectorResult(
            connector=self.spec.name, status="ok",
            findings=findings,
            raw={"center": [lat, lon], "radius_m": radius,
                 "features": len(findings), "map": ev_base},
        )

    def health_check(self) -> bool:
        try:
            _safe_http.get_bytes("https://overpass-api.de/api/status", timeout=4)
            return True
        except Exception:
            return False
