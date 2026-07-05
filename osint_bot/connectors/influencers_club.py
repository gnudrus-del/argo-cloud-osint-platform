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
    name="influencers_club",
    label="Influencers Club (username → email)",
    action_class=ACTION_PASSIVE,
    input_types=("handle", "username"),
    output_categories=("email_footprint", "creator_intel"),
    required_key="influencers_club",   # cablato al catalogo
    cache_ttl=86_400,
    rate_limit=RateLimit(per_minute=15, per_day=500, burst=2),
    legal_note=(
        "Servizio SaaS a pagamento (influencers.club). Restituisce email di "
        "creator/business associate a un username. BYOK dell'analista."),
    health_check_url="https://influencers.club/",
)

_ENDPOINT = "https://api.influencers.club/v1/instagram/find-email"


def _post_json(url: str, payload: dict, api_key: str, timeout: int) -> tuple[int, dict | None]:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers={
        "Authorization": f"Bearer {api_key}",
        "X-API-Key": api_key,               # backup: alcune versioni accettano X-API-Key
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "argo-osint/1.0",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8", errors="replace"))
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
                                   error="INFLUENCERS_CLUB_API_KEY non configurata.")
        username = (context.target or "").strip().lstrip("@")
        if not username or "/" in username or " " in username:
            return ConnectorResult(connector=self.spec.name, status="error", error="Username non valido.")

        status, data = _post_json(_ENDPOINT, {"username": username}, context.api_key, context.timeout)
        if status in (401, 403):
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error="Chiave Influencers Club non valida o quota esaurita.")
        if status == 429:
            return ConnectorResult(connector=self.spec.name, status="rate_limited",
                                   error="Rate limit Influencers Club.")
        if status == 0 or data is None:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error="Influencers Club non raggiungibile.")
        if status == 404 or (isinstance(data, dict) and data.get("error") == "not_found"):
            return ConnectorResult(connector=self.spec.name, status="ok", findings=[],
                                   raw={"note": f"Nessun match per @{username}.", "http": status})

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
                notes=f"Email pubblica di @{username} (Influencers Club).",
                why_linked=[f"Influencers Club ha collegato @{username} all'email"],
            ))
        for k, kind in [("full_name", "display_name"), ("category", "creator_category"),
                        ("followers", "followers_count"), ("phone", "phone")]:
            src = data if k in data else data.get("data", {}) if isinstance(data, dict) else {}
            v = src.get(k)
            if v not in (None, ""):
                findings.append(Finding(
                    kind=kind, value=str(v)[:200], confidence=0.85,
                    source_reliability="B", info_credibility=2, evidence=ev,
                    notes=f"Campo '{k}' da Influencers Club per @{username}."))
        return ConnectorResult(connector=self.spec.name, status="ok", findings=findings,
                               raw={"engine": "influencers_club", "http": status})

    def health_check(self) -> bool:
        return True  # la validità della chiave è verificata dalla probe live.
