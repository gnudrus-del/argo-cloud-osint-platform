"""Connector: ContactOut — profilo LinkedIn (o email) → email/telefono personali.

Servizio SaaS a pagamento con API REST. Dato l'URL di un profilo LinkedIn
pubblico, restituisce le email e i numeri di telefono personali associati
(dati raccolti da ContactOut da fonti pubbliche/breach, non da LinkedIn
stesso). BYOK: la chiave si inserisce nel tab "Chiavi API" del sito.

Config:
    CONTACTOUT_API_KEY   API key (dal proprio account ContactOut)

Se la chiave manca -> ``status="missing_key"``.
Input: ``url`` (URL profilo LinkedIn, es. https://www.linkedin.com/in/nome/)
oppure ``email``. Passivo (una singola GET). PII-gated: trova dati di
contatto personali, non solo footprint aziendale.

Nota implementativa: la response effettiva dell'API ContactOut v1 non è
documentata in modo stabile pubblicamente ed è nota variare tra versioni/
piani; l'estrazione qui sotto prova più percorsi comuni (``contact_info``,
``profile``, campi top-level) con fallback difensivi, sullo stesso pattern
già usato in ``influencers_club.py``. Verificare contro la doc ufficiale
(https://api.contactout.com/) se il piano dell'operatore restituisce una
forma diversa.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.parse

from .. import _safe_http
from ..connector import (
    ACTION_PII_GATED,
    BaseConnector,
    ConnectorContext,
    ConnectorResult,
    ConnectorSpec,
    RateLimit,
)
from ..i18n import t as _t
from ..models import Evidence, Finding

_SPEC = ConnectorSpec(
    name="contactout",
    label="ContactOut (LinkedIn → email/telefono)",
    action_class=ACTION_PII_GATED,
    input_types=("url", "email"),
    output_categories=("identity_data",),
    required_key="contactout",
    cache_ttl=86_400,
    rate_limit=RateLimit(per_minute=10, per_day=100, burst=2),
    legal_note="contactout.legal_note",
    health_check_url="",
)

_LINKEDIN_ENDPOINT = "https://api.contactout.com/v1/people/linkedin"
_EMAIL_ENDPOINT = "https://api.contactout.com/v1/people/email"


def _get_json(url: str, api_key: str, timeout: int) -> tuple[int, dict | None]:
    headers = {
        "token": api_key,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    try:
        status, raw, _ = _safe_http.open_url(url, headers=headers, method="GET", timeout=timeout)
        return status, json.loads(raw.decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as e:
        try:
            data = json.loads(e.read().decode("utf-8", errors="replace"))
        except Exception:
            data = None
        return e.code, data
    except Exception:
        return 0, None


def _extract_contacts(data: dict) -> tuple[list[str], list[str], str]:
    """Estrae (emails, phones, full_name) provando più percorsi noti della response."""
    if not isinstance(data, dict):
        return [], [], ""
    contact = data.get("contact_info") or data.get("contactInfo") or {}
    profile = data.get("profile") or {}

    def _as_list(v) -> list[str]:
        if v is None:
            return []
        if isinstance(v, str):
            return [v]
        if isinstance(v, list):
            return [str(x) for x in v if x]
        return []

    emails = (_as_list(contact.get("emails")) or _as_list(data.get("emails"))
              or _as_list(data.get("email")))
    phones = (_as_list(contact.get("phones")) or _as_list(data.get("phones"))
              or _as_list(data.get("phone")))
    full_name = (profile.get("full_name") or profile.get("name")
                 or data.get("full_name") or data.get("name") or "")
    return emails, phones, str(full_name)


class ContactOutConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        if not context.api_key:
            return ConnectorResult(connector=self.spec.name, status="missing_key",
                                   error=_t("contactout.missing_key", context.lang))
        target = (context.target or "").strip()
        if not target:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=_t("contactout.empty_target", context.lang))

        is_linkedin_url = target.startswith(("http://", "https://")) and "linkedin.com" in target
        is_email = "@" in target and " " not in target

        if is_linkedin_url:
            params = urllib.parse.urlencode({"profile": target})
            url = f"{_LINKEDIN_ENDPOINT}?{params}"
            ev_url, ev_title = target, "LinkedIn profile"
        elif is_email:
            params = urllib.parse.urlencode({"email": target})
            url = f"{_EMAIL_ENDPOINT}?{params}"
            ev_url, ev_title = f"mailto:{target}", "ContactOut reverse email"
        else:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=_t("contactout.invalid_target", context.lang))

        status, data = _get_json(url, context.api_key, context.timeout)
        if status in (401, 403):
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=_t("contactout.auth_or_quota", context.lang))
        if status == 429:
            return ConnectorResult(connector=self.spec.name, status="rate_limited",
                                   error=_t("contactout.rate_limit", context.lang))
        if status == 0 or data is None:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=_t("contactout.unreachable", context.lang))
        if status == 404:
            return ConnectorResult(connector=self.spec.name, status="ok", findings=[],
                                   raw={"note": _t("contactout.no_match", context.lang, target=target),
                                        "http": status})

        emails, phones, full_name = _extract_contacts(data)
        ev = [Evidence(url=ev_url, title=ev_title)]
        findings: list[Finding] = []
        for email_val in emails:
            findings.append(Finding(
                kind="email_address", value=email_val, confidence=0.85,
                severity="medium", attck_ttps=["T1589.002"],
                remediation=_t("contactout.email_remediation", context.lang),
                source_reliability="B", info_credibility=2, evidence=ev,
                notes=_t("contactout.email_found", context.lang, target=target),
            ))
        for phone_val in phones:
            findings.append(Finding(
                kind="phone", value=phone_val, confidence=0.75,
                severity="medium", source_reliability="B", info_credibility=2,
                evidence=ev,
                notes=_t("contactout.phone_found", context.lang, target=target),
            ))
        if full_name:
            findings.append(Finding(
                kind="display_name", value=full_name, confidence=0.8,
                source_reliability="B", info_credibility=2, evidence=ev,
                notes=_t("contactout.name_found", context.lang),
            ))

        return ConnectorResult(connector=self.spec.name, status="ok", findings=findings,
                               raw={"engine": "contactout", "target": target,
                                    "emails": len(emails), "phones": len(phones)})

    def health_check(self) -> bool:
        return True
