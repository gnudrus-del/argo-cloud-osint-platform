"""Connector: Gravatar — profilo pubblico associato a un'email.

L'email viene lowercase+trim, poi hashata MD5 (per spec Gravatar). Se
``https://www.gravatar.com/{hash}.json`` risponde 200 -> esiste un profilo
pubblico. Zero API key, un solo GET.

Input: ``email``. Action class: passive.
"""
from __future__ import annotations

import hashlib
import json
import urllib.error
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
    name="gravatar",
    label="Gravatar",
    action_class=ACTION_PASSIVE,
    input_types=("email",),
    output_categories=("profile", "avatar"),
    required_key="",
    cache_ttl=86_400,
    rate_limit=RateLimit(per_minute=30, per_day=2000, burst=3),
    legal_note="Endpoint pubblico Gravatar. Nessun invio di dati personali oltre l'hash MD5.",
    health_check_url="https://www.gravatar.com/",
)


def _md5_email(email: str) -> str:
    return hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()


def _fetch_profile(md5: str, timeout: int) -> dict | None:
    url = f"https://www.gravatar.com/{md5}.json"
    req = urllib.request.Request(url, headers={
        "Accept": "application/json",
        "User-Agent": "argo-osint/1.0",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
        data = json.loads(body)
        entries = data.get("entry") or []
        return entries[0] if entries else None
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        return None
    except Exception:
        return None


class GravatarConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        email = (context.target or "").strip()
        if not email or "@" not in email:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error="Email non valida.")
        md5 = _md5_email(email)
        avatar_url = f"https://www.gravatar.com/avatar/{md5}?d=404"
        profile = _fetch_profile(md5, context.timeout)

        findings: list[Finding] = []
        ev = [Evidence(url=f"https://www.gravatar.com/{md5}", title="Gravatar")]

        if not profile:
            return ConnectorResult(
                connector=self.spec.name, status="ok",
                findings=[], raw={"md5": md5, "profile": None,
                                  "note": "Nessun profilo Gravatar pubblico."},
            )

        findings.append(Finding(
            kind="gravatar_profile", value=profile.get("profileUrl") or f"https://www.gravatar.com/{md5}",
            confidence=0.95, source_reliability="A", info_credibility=1,
            evidence=ev,
            notes=f"Profilo Gravatar pubblico associato a {email}.",
        ))
        if profile.get("preferredUsername"):
            findings.append(Finding(
                kind="username", value=profile["preferredUsername"],
                confidence=0.9, source_reliability="A", info_credibility=2,
                evidence=ev,
                notes="Username preferito dichiarato dall'utente su Gravatar.",
            ))
        if profile.get("displayName"):
            findings.append(Finding(
                kind="display_name", value=profile["displayName"],
                confidence=0.85, source_reliability="A", info_credibility=2,
                evidence=ev,
            ))
        for acc in (profile.get("accounts") or [])[:20]:
            url = acc.get("url") or ""
            shortname = acc.get("shortname") or ""
            if url:
                findings.append(Finding(
                    kind="social_account", value=url,
                    confidence=0.85, source_reliability="A", info_credibility=2,
                    evidence=ev,
                    notes=f"Account {shortname} collegato al profilo Gravatar.",
                ))
        findings.append(Finding(
            kind="avatar_url", value=avatar_url,
            confidence=0.99, source_reliability="A", info_credibility=1,
            evidence=ev,
        ))
        return ConnectorResult(
            connector=self.spec.name, status="ok",
            findings=findings,
            raw={"md5": md5, "profile": profile},
        )

    def health_check(self) -> bool:
        try:
            req = urllib.request.Request("https://www.gravatar.com/",
                                         headers={"User-Agent": "argo-osint/1.0"})
            with urllib.request.urlopen(req, timeout=3) as resp:
                return resp.status < 500
        except Exception:
            return False
