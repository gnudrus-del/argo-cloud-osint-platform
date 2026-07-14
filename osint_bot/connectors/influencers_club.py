"""Connector: Influencers Club — username Instagram/social → email verificata.

Servizio SaaS a pagamento con API. Dato uno username Instagram (o profilo
social), restituisce l'email associata e ~40 punti dati (follower, categoria,
engagement, ecc.). BYOK: la chiave si inserisce nel tab "Chiavi API" del sito.

Config:
    INFLUENCERS_CLUB_API_KEY   API key (dal proprio account influencers.club)

Se la chiave manca -> ``status="missing_key"``.
Input: ``handle`` / ``username``. Passivo (API HTTPS).
"""
from __future__ import annotations

import json
import urllib.error

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
    name="influencers_club",
    label="Influencers Club (username → email)",
    action_class=ACTION_PASSIVE,
    input_types=("handle", "username"),
    output_categories=("email_footprint", "creator_intel"),
    required_key="influencers_club",   # cablato al catalogo
    cache_ttl=86_400,
    rate_limit=RateLimit(per_minute=15, per_day=500, burst=2),
    legal_note="influencers_club.legal_note",
    health_check_url="https://influencers.club/",
)

_ENDPOINT = "https://api.influencers.club/v1/instagram/find-email"


def _post_json(url: str, payload: dict, api_key: str, timeout: int) -> tuple[int, dict | None]:
    body = json.dumps(payload).encode("utf-8")
    headers = {
        "Authorization": f"Bearer {api_key}",
        "X-API-Key": api_key,               # backup: alcune versioni accettano X-API-Key
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    try:
        status, raw, _ = _safe_http.open_url(
            url, data=body, headers=headers, method="POST", timeout=timeout
        )
        return status, json.loads(raw.decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as e:
        try:
            data = json.loads(e.read().decode("utf-8", errors="replace"))
        except Exception:
            data = None
        return e.code, data
    except Exception:
        return 0, None


class InfluencersClubConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        # BYOK: la chiave è già iniettata da run() (spec.required_key non vuoto).
        if not context.api_key:
            return ConnectorResult(connector=self.spec.name, status="missing_key",
                                   error=_t("influencers_club.missing_key", context.lang))
        username = (context.target or "").strip().lstrip("@")
        if not username or "/" in username or " " in username:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=_t("influencers_club.invalid_username", context.lang))

        status, data = _post_json(_ENDPOINT, {"username": username}, context.api_key, context.timeout)
        if status in (401, 403):
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=_t("influencers_club.auth_or_quota", context.lang))
        if status == 429:
            return ConnectorResult(connector=self.spec.name, status="rate_limited",
                                   error=_t("influencers_club.rate_limit", context.lang))
        if status == 0 or data is None:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=_t("influencers_club.unreachable", context.lang))
        if status == 404 or (isinstance(data, dict) and data.get("error") == "not_found"):
            return ConnectorResult(connector=self.spec.name, status="ok", findings=[],
                                   raw={"note": _t("influencers_club.no_match", context.lang, username=username),
                                        "http": status})

        ev = [Evidence(url=f"https://www.instagram.com/{username}/", title=f"IG @{username}")]
        findings: list[Finding] = []
        # La response effettiva della v1 può variare; estraggo i campi più
        # comuni con fallback difensivi.
        email = (data.get("email") if isinstance(data, dict) else None) or (
            (data.get("data") or {}).get("email") if isinstance(data, dict) else None)
        if email:
            findings.append(Finding(
                kind="email", value=str(email), confidence=0.9,
                source_reliability="B", info_credibility=2, evidence=ev,
                notes=_t("influencers_club.email_public", context.lang, username=username),
                why_linked=[_t("influencers_club.email_why", context.lang, username=username)],
            ))
        for k, kind in [("full_name", "display_name"), ("category", "creator_category"),
                        ("followers", "followers_count"), ("phone", "phone")]:
            src = data if k in data else data.get("data", {}) if isinstance(data, dict) else {}
            v = src.get(k)
            if v not in (None, ""):
                findings.append(Finding(
                    kind=kind, value=str(v)[:200], confidence=0.85,
                    source_reliability="B", info_credibility=2, evidence=ev,
                    notes=_t("influencers_club.field_note", context.lang, field=k, username=username)))
        return ConnectorResult(connector=self.spec.name, status="ok", findings=findings,
                               raw={"engine": "influencers_club", "http": status})

    def health_check(self) -> bool:
        return True  # la validità della chiave è verificata dalla probe live.
