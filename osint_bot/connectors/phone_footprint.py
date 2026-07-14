"""Connector: phone_footprint — sostituto NATIVO di PhoneInfoga (pure Python).

PhoneInfoga fa due cose: (1) valida/normalizza il numero, (2) genera un
"footprint" di URL OSINT (dork motori, ricerche social, siti di reverse-lookup)
su cui l'analista pivota. La parte (1) la copre già libphonenumber; la parte (2)
è generazione di URL — perfettamente nativizzabile senza il binario Go.

Questo connettore quindi: valida via ``phonenumbers`` e produce un set curato di
URL di footprint (Google dork, social, reverse-lookup, messaggistica) come
finding cliccabili. Zero rete, zero dipendenze oltre ``phonenumbers``.

Input: ``phone`` (E.164 preferibile). Passivo.
"""
from __future__ import annotations

import urllib.parse

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
    name="phone_footprint",
    label="Phone footprint (nativo)",
    action_class=ACTION_PASSIVE,
    input_types=("phone",),
    output_categories=("phone_footprint", "pivot_urls"),
    required_key="",
    cache_ttl=86_400,
    rate_limit=RateLimit(per_minute=60, per_day=50_000, burst=10),
    legal_note="phone_footprint.legal_note",
    health_check_url="",
)


def _dork_urls(e164: str, national: str, cc: int) -> list[tuple[str, str]]:
    """Ritorna [(label, url)] di footprint OSINT per il numero, vari formati."""
    plus = e164                      # +39066982
    no_plus = e164.lstrip("+")       # 39066982
    nat = national.replace(" ", "")  # nazionale compatto
    q = lambda s: urllib.parse.quote(f'"{s}"')  # noqa: E731

    out: list[tuple[str, str]] = []
    # Motori: cerca il numero in più formati
    for fmt in {plus, no_plus, nat}:
        out.append((f"Google \"{fmt}\"", f"https://www.google.com/search?q={q(fmt)}"))
        out.append((f"Bing \"{fmt}\"", f"https://www.bing.com/search?q={q(fmt)}"))
        out.append((f"DuckDuckGo \"{fmt}\"", f"https://duckduckgo.com/?q={q(fmt)}"))
    # Dork su piattaforme che indicizzano numeri (annunci, leak, incolla)
    for site in ("pastebin.com", "facebook.com", "linkedin.com", "twitter.com",
                 "t.me", "wa.me"):
        out.append((f"Google site:{site}",
                    f"https://www.google.com/search?q={urllib.parse.quote(f'site:{site} ' + chr(34)+plus+chr(34))}"))
    # Siti di reverse-lookup / caller-id
    out.append(("Truecaller", f"https://www.truecaller.com/search/{_region_hint(cc)}/{urllib.parse.quote(no_plus)}"))
    out.append(("Sync.me", f"https://sync.me/search/?number={urllib.parse.quote(no_plus)}"))
    out.append(("WhoCalld", f"https://whocalld.com/{urllib.parse.quote(plus)}"))
    # Messaggistica (esistenza account)
    out.append(("WhatsApp (wa.me)", f"https://wa.me/{urllib.parse.quote(no_plus)}"))
    out.append(("Telegram", f"https://t.me/{urllib.parse.quote(no_plus)}"))
    return out


def _region_hint(cc: int) -> str:
    # mapping minimale prefisso->regione truecaller; fallback 'intl'
    return {39: "it", 1: "us", 44: "gb", 33: "fr", 49: "de", 34: "es"}.get(cc, "intl")


class PhoneFootprintConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        try:
            import phonenumbers
        except ImportError:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=_t("phone_footprint.module_missing", context.lang))
        raw = (context.target or "").strip()
        if not raw:
            return ConnectorResult(connector=self.spec.name, status="error", error=_t("phone_footprint.empty_number", context.lang))
        try:
            parsed = phonenumbers.parse(raw, "IT")
        except Exception as exc:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=_t("phone_footprint.parse_failed", context.lang, error=str(exc)))
        if not phonenumbers.is_valid_number(parsed):
            return ConnectorResult(connector=self.spec.name, status="ok", findings=[],
                                   raw={"valid": False, "note": _t("phone_footprint.invalid_no_footprint", context.lang)})

        e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
        national = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
        cc = parsed.country_code

        findings: list[Finding] = []
        for label, url in _dork_urls(e164, national, cc):
            findings.append(Finding(
                kind="footprint_url", value=url,
                confidence=0.5, source_reliability="C", info_credibility=3,
                evidence=[Evidence(url=url, title=label)],
                notes=_t("phone_footprint.pivot", context.lang, e164=e164, label=label),
            ))
        return ConnectorResult(
            connector=self.spec.name, status="ok",
            findings=findings,
            raw={"e164": e164, "country_code": cc, "footprint_urls": len(findings)},
        )

    def health_check(self) -> bool:
        try:
            import phonenumbers  # noqa: F401
            return True
        except ImportError:
            return False
