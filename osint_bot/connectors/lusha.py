"""Connector: Lusha — profilo LinkedIn (o email) → email/telefono professionali.

Servizio SaaS a pagamento con API REST v2 (``GET /v2/person``). Dato l'URL
di un profilo LinkedIn pubblico o un indirizzo email, restituisce email e
telefoni di contatto professionali associati alla persona. BYOK: la chiave
si inserisce nel tab "Chiavi API" del sito.

Config:
    LUSHA_API_KEY   API key (dal proprio account Lusha)

Se la chiave manca -> ``status="missing_key"``.
Input: ``url`` (URL profilo LinkedIn) oppure ``email``. Passivo (una singola
GET). PII-gated: trova dati di contatto personali/professionali.

Nota implementativa: la Person API v2 di Lusha (https://docs.lusha.com/)
accetta ``linkedinUrl`` o ``email`` come parametro di query con header
``api_key``. La forma esatta della response (nesting di
``emailAddresses``/``phoneNumbers``) varia per piano/versione; l'estrazione
qui sotto prova più percorsi comuni con fallback difensivi, sullo stesso
pattern già usato in ``influencers_club.py``/``contactout.py``.
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
    name="lusha",
    label="Lusha (LinkedIn/email → contatti)",
    action_class=ACTION_PII_GATED,
    input_types=("url", "email"),
    output_categories=("identity_data",),
    required_key="lusha",
    cache_ttl=86_400,
    rate_limit=RateLimit(per_minute=10, per_day=100, burst=2),
    legal_note="lusha.legal_note",
    health_check_url="",
)

_ENDPOINT = "https://api.lusha.com/v2/person"


def _get_json(url: str, api_key: str, timeout: int) -> tuple[int, dict | None]:
    headers = {"api_key": api_key, "Accept": "application/json"}
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
    """Estrae (emails, phones, full_name) provando più percorsi noti della response v2."""
    if not isinstance(data, dict):
        return [], [], ""
    body = data.get("data") if isinstance(data.get("data"), dict) else data
    contact = body.get("contactData") if isinstance(body.get("contactData"), dict) else body

    def _emails(v) -> list[str]:
        out: list[str] = []
        for entry in (v or []):
            if isinstance(entry, dict):
                e = entry.get("email") or entry.get("address")
                if e:
                    out.append(str(e))
            elif isinstance(entry, str):
                out.append(entry)
        return out

    def _phones(v) -> list[str]:
        out: list[str] = []
        for entry in (v or []):
            if isinstance(entry, dict):
                p = entry.get("number") or entry.get("phone")
                if p:
                    out.append(str(p))
            elif isinstance(entry, str):
                out.append(entry)
        return out

    emails = _emails(contact.get("emailAddresses")) or _emails(body.get("emailAddresses"))
    phones = _phones(contact.get("phoneNumbers")) or _phones(body.get("phoneNumbers"))
    full_name = body.get("fullName") or body.get("name") or contact.get("fullName") or ""
    return emails, phones, str(full_name)


class LushaConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        if not context.api_key:
            return ConnectorResult(connector=self.spec.name, status="missing_key",
                                   error=_t("lusha.missing_key", context.lang))
        target = (context.target or "").strip()
        if not target:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=_t("lusha.empty_target", context.lang))

        is_linkedin_url = target.startswith(("http://", "https://")) and "linkedin.com" in target
        is_email = "@" in target and " " not in target

        if is_linkedin_url:
            params = urllib.parse.urlencode({"linkedinUrl": target})
            ev_url, ev_title = target, "LinkedIn profile"
        elif is_email:
            params = urllib.parse.urlencode({"email": target})
            ev_url, ev_title = f"mailto:{target}", "Lusha reverse email"
        else:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=_t("lusha.invalid_target", context.lang))

        url = f"{_ENDPOINT}?{params}"
        status, data = _get_json(url, context.api_key, context.timeout)
        if status in (401, 403):
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=_t("lusha.auth_or_quota", context.lang))
        if status == 429:
            return ConnectorResult(connector=self.spec.name, status="rate_limited",
                                   error=_t("lusha.rate_limit", context.lang))
        if status == 0 or data is None:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=_t("lusha.unreachable", context.lang))
        if status == 404:
            return ConnectorResult(connector=self.spec.name, status="ok", findings=[],
                                   raw={"note": _t("lusha.no_match", context.lang, target=target),
                                        "http": status})

        emails, phones, full_name = _extract_contacts(data)
        ev = [Evidence(url=ev_url, title=ev_title)]
        findings: list[Finding] = []
        for email_val in emails:
            findings.append(Finding(
                kind="email_address", value=email_val, confidence=0.85,
                severity="medium", attck_ttps=["T1589.002"],
                remediation=_t("lusha.email_remediation", context.lang),
                source_reliability="B", info_credibility=2, evidence=ev,
                notes=_t("lusha.email_found", context.lang, target=target),
            ))
        for phone_val in phones:
            findings.append(Finding(
                kind="phone", value=phone_val, confidence=0.75,
                severity="medium", source_reliability="B", info_credibility=2,
                evidence=ev,
                notes=_t("lusha.phone_found", context.lang, target=target),
            ))
        if full_name:
            findings.append(Finding(
                kind="display_name", value=full_name, confidence=0.8,
                source_reliability="B", info_credibility=2, evidence=ev,
                notes=_t("lusha.name_found", context.lang),
            ))

        return ConnectorResult(connector=self.spec.name, status="ok", findings=findings,
                               raw={"engine": "lusha", "target": target,
                                    "emails": len(emails), "phones": len(phones)})

    def health_check(self) -> bool:
        return True
