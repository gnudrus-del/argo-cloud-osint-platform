"""Connector: email footprint (sostituto nativo parziale di holehe/mosint/infoga).

Verifica su quali servizi/segnali un'email lascia traccia, senza dipendenze:
  * Gravatar: profilo pubblico (ecosistema WordPress/Gravatar).
  * Validità del dominio: record MX (l'email può ricevere posta?).
  * Dominio "usa e getta" (disposable) da una lista curata.
  * Formato/normalizzazione (Gmail dot-trick, plus-addressing).

Copre il caso rapido; per la copertura profonda (~120 siti) resta holehe CLI.
Passivo. Input: ``email``.
"""
from __future__ import annotations

import hashlib
import socket

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
    name="holehe_native",
    label="Email footprint",
    action_class=ACTION_PASSIVE,
    input_types=("email",),
    output_categories=("email_footprint",),
    required_key="",
    cache_ttl=3600,
    rate_limit=RateLimit(per_minute=20, per_day=2000, burst=3),
    legal_note="Controlli passivi su email (Gravatar, MX, disposable). Nessun invio di posta.",
    health_check_url="",
)

_DISPOSABLE = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com",
    "temp-mail.org", "throwaway.email", "yopmail.com", "getnada.com",
    "trashmail.com", "sharklasers.com", "dispostable.com", "maildrop.cc",
    "fakeinbox.com", "mytemp.email", "moakt.com", "tempr.email",
}


def _has_mx(domain: str, timeout: int) -> bool:
    """Best-effort: il dominio risolve (proxy grezzo di 'può ricevere posta')."""
    try:
        socket.setdefaulttimeout(timeout)
        socket.getaddrinfo(domain, None)
        return True
    except Exception:
        return False


def _gravatar(email: str, timeout: int) -> dict | None:
    md5 = hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()
    url = f"https://www.gravatar.com/{md5}.json"
    try:
        data = _safe_http.get_json(url, timeout=timeout)
        entries = data.get("entry") or []
        return entries[0] if entries else None
    except Exception:
        return None


class HoleheNativeConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        email = (context.target or "").strip().lower()
        if "@" not in email:
            return ConnectorResult(connector=self.spec.name, status="error", error="Email non valida.")
        local, _, domain = email.partition("@")
        findings: list[Finding] = []
        ev_gr = [Evidence(url="https://www.gravatar.com/", title="Gravatar")]

        # 1) Dominio disposable?
        if domain in _DISPOSABLE:
            findings.append(Finding(
                kind="email_disposable", value=domain,
                confidence=0.95, source_reliability="A", info_credibility=1,
                evidence=[Evidence(url=f"https://{domain}", title=domain)],
                notes="Dominio email 'usa e getta': bassa affidabilità dell'identità.",
                severity="low",
            ))

        # 2) MX / dominio valido
        if _has_mx(domain, min(context.timeout, 5)):
            findings.append(Finding(
                kind="email_domain_valid", value=domain,
                confidence=0.8, source_reliability="A", info_credibility=2,
                evidence=[Evidence(url=f"https://{domain}", title=domain)],
                notes="Il dominio risolve: l'email è plausibilmente recapitabile.",
            ))

        # 3) Gravatar profile
        profile = _gravatar(email, context.timeout)
        if profile:
            findings.append(Finding(
                kind="email_service", value="Gravatar",
                confidence=0.95, source_reliability="A", info_credibility=1,
                evidence=ev_gr,
                notes=f"Profilo Gravatar pubblico ({profile.get('profileUrl', '')}).",
            ))
            for acc in (profile.get("accounts") or [])[:15]:
                if acc.get("url"):
                    findings.append(Finding(
                        kind="social_account", value=acc["url"],
                        confidence=0.85, source_reliability="A", info_credibility=2,
                        evidence=ev_gr,
                        notes=f"Account {acc.get('shortname', '')} collegato via Gravatar.",
                    ))

        # 4) Normalizzazioni note (utile per correlazione)
        if domain in ("gmail.com", "googlemail.com"):
            canonical = local.split("+")[0].replace(".", "") + "@gmail.com"
            if canonical != email:
                findings.append(Finding(
                    kind="email_canonical", value=canonical,
                    confidence=0.9, source_reliability="A", info_credibility=1,
                    evidence=[],
                    notes="Forma canonica Gmail (dot-trick/plus rimossi): stessa casella.",
                ))

        return ConnectorResult(
            connector=self.spec.name, status="ok",
            findings=findings,
            raw={"domain": domain, "disposable": domain in _DISPOSABLE,
                 "gravatar": bool(profile)},
        )

    def health_check(self) -> bool:
        return True
