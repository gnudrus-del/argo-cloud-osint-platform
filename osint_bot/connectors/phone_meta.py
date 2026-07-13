"""Connector: phone number metadata — pure Python.

Usa ``phonenumbers`` (libreria pura Python, port di Google libphonenumber)
per validare il numero, estrarre country/region, carrier hint, timezone,
tipologia (mobile/fixed/voip). Zero API key, zero network.

Sostituisce chiamate CLI a phoneinfoga/PhoneRipper per il caso base.
Input: ``phone`` (E.164 preferibilmente, con prefisso).
"""
from __future__ import annotations

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
    name="phone_meta",
    label="Phone metadata (libphonenumber)",
    action_class=ACTION_PASSIVE,
    input_types=("phone",),
    output_categories=("phone_metadata",),
    required_key="",
    cache_ttl=86_400,
    rate_limit=RateLimit(per_minute=120, per_day=100_000, burst=20),
    legal_note="Elaborazione locale via libphonenumber. Nessun dato inviato in rete.",
    health_check_url="",
)


class PhoneMetaConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        try:
            import phonenumbers
            from phonenumbers import PhoneNumberType, carrier, geocoder, number_type
            from phonenumbers import timezone as tz
        except ImportError:
            return ConnectorResult(
                connector=self.spec.name, status="error",
                error=("Modulo 'phonenumbers' non installato. "
                       "Installa con: pip install phonenumbers"),
            )

        raw_target = (context.target or "").strip()
        if not raw_target:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error="Numero vuoto.")

        try:
            # Se non ha prefisso, prova con IT default
            parsed = phonenumbers.parse(raw_target, "IT")
        except Exception as e:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=f"Parsing fallito: {e}")

        if not phonenumbers.is_valid_number(parsed):
            return ConnectorResult(
                connector=self.spec.name, status="ok",
                findings=[Finding(
                    kind="phone_valid", value="false",
                    confidence=0.99, source_reliability="A", info_credibility=1,
                    evidence=[],
                    notes="Numero sintatticamente non valido secondo libphonenumber.",
                )],
                raw={"input": raw_target, "valid": False},
            )

        e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
        intl = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        national = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
        region = phonenumbers.region_code_for_number(parsed) or ""
        country_code = parsed.country_code
        carrier_name = carrier.name_for_number(parsed, "en") or ""
        location = geocoder.description_for_number(parsed, "en") or ""
        timezones = tz.time_zones_for_number(parsed)
        ntype_id = number_type(parsed)
        ntype_map = {
            PhoneNumberType.MOBILE: "mobile",
            PhoneNumberType.FIXED_LINE: "fixed_line",
            PhoneNumberType.FIXED_LINE_OR_MOBILE: "fixed_line_or_mobile",
            PhoneNumberType.TOLL_FREE: "toll_free",
            PhoneNumberType.PREMIUM_RATE: "premium_rate",
            PhoneNumberType.SHARED_COST: "shared_cost",
            PhoneNumberType.VOIP: "voip",
            PhoneNumberType.PERSONAL_NUMBER: "personal_number",
            PhoneNumberType.PAGER: "pager",
            PhoneNumberType.UAN: "uan",
            PhoneNumberType.VOICEMAIL: "voicemail",
        }
        ntype = ntype_map.get(ntype_id, "unknown")

        ev = [Evidence(url=f"https://libphonenumber.appspot.com/?number={e164}",
                       title="libphonenumber (playground)")]
        findings = [
            Finding(kind="phone_e164", value=e164,
                    confidence=1.0, source_reliability="A", info_credibility=1,
                    evidence=ev),
            Finding(kind="phone_international", value=intl,
                    confidence=1.0, source_reliability="A", info_credibility=1,
                    evidence=ev),
            Finding(kind="phone_country", value=f"{region} (+{country_code})",
                    confidence=0.99, source_reliability="A", info_credibility=1,
                    evidence=ev),
            Finding(kind="phone_type", value=ntype,
                    confidence=0.95, source_reliability="A", info_credibility=1,
                    evidence=ev,
                    notes="Tipologia inferita dal piano di numerazione."),
        ]
        if carrier_name:
            findings.append(Finding(
                kind="phone_carrier", value=carrier_name,
                confidence=0.85, source_reliability="B", info_credibility=2,
                evidence=ev,
                notes="Carrier storico assegnato al prefisso. Portabilita' non tracciata.",
            ))
        if location:
            findings.append(Finding(
                kind="phone_location", value=location,
                confidence=0.9, source_reliability="A", info_credibility=2,
                evidence=ev,
            ))
        for tzn in timezones or ():
            if tzn and tzn != "Etc/Unknown":
                findings.append(Finding(
                    kind="phone_timezone", value=tzn,
                    confidence=0.9, source_reliability="A", info_credibility=1,
                    evidence=ev,
                ))
        return ConnectorResult(
            connector=self.spec.name, status="ok",
            findings=findings,
            raw={
                "input": raw_target, "e164": e164, "national": national,
                "region": region, "country_code": country_code,
                "carrier": carrier_name, "location": location,
                "type": ntype, "timezones": list(timezones or ()),
            },
        )

    def health_check(self) -> bool:
        try:
            import phonenumbers  # noqa: F401
            return True
        except ImportError:
            return False
