"""Connector: RIPEstat Data API — rete/ASN/abuse-contact per IP, SENZA API key.

RIPEstat (https://stat.ripe.net/data/...) e' il servizio pubblico e gratuito
di RIPE NCC: nessuna chiave, nessun account, rate-limit generoso, dati di
routing/allocazione autorevoli (RIPE e' uno dei 5 Regional Internet
Registry). Due endpoint GET, entrambi passivi (nessuna scansione attiva
del target, solo interrogazione di dati gia' pubblicati):

- network-info: prefisso di rete (ASN) che annuncia l'IP.
- abuse-contact-finder: email di abuse ufficiale registrata per il netblock
  — punto di contatto legittimo per una segnalazione, non un'inferenza.

Input: ``ip``.
"""
from __future__ import annotations

import ipaddress

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
    name="ripe_stat",
    label="RIPEstat",
    action_class=ACTION_PASSIVE,
    input_types=("ip",),
    output_categories=("network_identifiers", "abuse_contact"),
    required_key="",
    cache_ttl=3600,
    rate_limit=RateLimit(per_minute=60, per_day=10_000, burst=5),
    legal_note="ripe_stat.legal_note",
    health_check_url="https://stat.ripe.net/data/network-info/data.json?resource=8.8.8.8",
)


def _fetch(url: str, timeout: int) -> dict | None:
    try:
        return _safe_http.get_json(url, timeout=timeout)
    except Exception:
        return None


class RipeStatConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        ip = (context.target or "").strip()
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=_t("ripe_stat.invalid_ip", context.lang))

        net_data = _fetch(
            f"https://stat.ripe.net/data/network-info/data.json?resource={ip}",
            context.timeout,
        )
        abuse_data = _fetch(
            f"https://stat.ripe.net/data/abuse-contact-finder/data.json?resource={ip}",
            context.timeout,
        )
        if net_data is None and abuse_data is None:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=_t("generic.no_response", context.lang, service="RIPEstat"))

        findings: list[Finding] = []
        ev = [Evidence(url=f"https://stat.ripe.net/{ip}", title=f"RIPEstat {ip}")]
        net = (net_data or {}).get("data") or {}
        prefix = net.get("prefix")
        asns = net.get("asns") or []
        if prefix:
            findings.append(Finding(
                kind="network_prefix", value=str(prefix),
                confidence=0.9, source_reliability="A", info_credibility=2,
                evidence=ev,
                notes=_t("ripe_stat.prefix_note", context.lang, ip=ip),
            ))
        for asn in asns[:5]:
            findings.append(Finding(
                kind="asn", value=f"AS{asn}",
                confidence=0.9, source_reliability="A", info_credibility=2,
                evidence=[Evidence(url=f"https://stat.ripe.net/AS{asn}", title=f"AS{asn}")],
                notes=_t("ripe_stat.asn_note", context.lang),
            ))

        abuse = (abuse_data or {}).get("data") or {}
        contacts = abuse.get("abuse_contacts") or []
        for contact in contacts[:5]:
            findings.append(Finding(
                kind="abuse_contact_email", value=str(contact),
                confidence=0.85, source_reliability="A", info_credibility=2,
                evidence=ev,
                notes=_t("ripe_stat.abuse_note", context.lang),
            ))

        return ConnectorResult(
            connector=self.spec.name, status="ok",
            findings=findings,
            raw={"prefix": prefix, "asns": asns, "abuse_contacts": contacts},
        )

    def health_check(self) -> bool:
        try:
            _safe_http.get_bytes(self.spec.health_check_url, timeout=4)
            return True
        except Exception:
            return False
