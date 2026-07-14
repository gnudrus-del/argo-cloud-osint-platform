"""Connector: Gravatar — profilo pubblico associato a un'email.

L'email viene lowercase+trim, poi hashata MD5 (per spec Gravatar). Se
``https://www.gravatar.com/{hash}.json`` risponde 200 -> esiste un profilo
pubblico. Zero API key, un solo GET.

Input: ``email``. Action class: passive.
"""
from __future__ import annotations

import hashlib

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
    try:
        data = _safe_http.get_json(url, timeout=timeout)
        entries = data.get("entry") or []
        return entries[0] if entries else None
    except Exception:
        # 404 (no public profile) surfaces here too — treated as "no profile".
        return None


class GravatarConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        email = (context.target or "").strip()
        if not email or "@" not in email:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=_t("generic.invalid_email", context.lang))
        md5 = _md5_email(email)
        avatar_url = f"https://www.gravatar.com/avatar/{md5}?d=404"
        profile = _fetch_profile(md5, context.timeout)

        findings: list[Finding] = []
        ev = [Evidence(url=f"https://www.gravatar.com/{md5}", title="Gravatar")]

        if not profile:
            return ConnectorResult(
                connector=self.spec.name, status="ok",
                findings=[], raw={"md5": md5, "profile": None,
                                  "note": _t("gravatar.no_profile", context.lang)},
            )

        findings.append(Finding(
            kind="gravatar_profile", value=profile.get("profileUrl") or f"https://www.gravatar.com/{md5}",
            confidence=0.95, source_reliability="A", info_credibility=1,
            evidence=ev,
            notes=_t("gravatar.profile", context.lang, email=email),
        ))
        if profile.get("preferredUsername"):
            findings.append(Finding(
                kind="username", value=profile["preferredUsername"],
                confidence=0.9, source_reliability="A", info_credibility=2,
                evidence=ev,
                notes=_t("gravatar.username", context.lang),
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
                    notes=_t("gravatar.account", context.lang, shortname=shortname),
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
            status, _, _ = _safe_http.open_url("https://www.gravatar.com/", timeout=3)
            return status < 500
        except Exception:
            return False
