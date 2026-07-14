"""Connector: ASN lookup via Team Cymru DNS-based whois.

Team Cymru offre un servizio pubblico che consente di risolvere IP -> ASN
tramite query DNS TXT: ``<ip-reverso>.origin.asn.cymru.com`` restituisce
``ASN | prefix | country | registry | date``.

Zero API key, latenza bassissima (una query DNS TXT). Passivo.
Input: ``ip``.

Fallback: se ``dig`` non e' disponibile o la query fallisce, ritorna error.
"""
from __future__ import annotations

import ipaddress
import shutil
import subprocess

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
    name="asn_lookup",
    label="ASN (Team Cymru)",
    action_class=ACTION_PASSIVE,
    input_types=("ip",),
    output_categories=("asn", "network_identifiers"),
    required_key="",
    cache_ttl=86_400,
    rate_limit=RateLimit(per_minute=60, per_day=20_000, burst=5),
    legal_note="asn_lookup.legal_note",
    health_check_url="",
)


def _reverse_ip(ip: str) -> str | None:
    """172.253.63.68 -> 68.63.253.172. IPv6 non supportato dal servizio origin."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address):
        return None
    return ".".join(reversed(ip.split(".")))


def _dig_txt(host: str, timeout: int) -> str:
    dig = shutil.which("dig")
    if not dig:
        return ""
    try:
        p = subprocess.run(
            [dig, "+short", "+time=3", "+tries=1", "TXT", host],
            capture_output=True, text=True, timeout=timeout,
        )
    except (subprocess.TimeoutExpired, OSError):
        return ""
    # dig +short TXT wrappa con "..."
    line = (p.stdout or "").strip().strip('"').strip()
    return line


def _parse_origin(txt: str) -> dict:
    # "15169 | 172.253.0.0/16 | US | arin | 2012-04-16"
    parts = [x.strip() for x in txt.split("|")]
    if len(parts) < 5:
        return {}
    return {
        "asn": parts[0],
        "prefix": parts[1],
        "country": parts[2],
        "registry": parts[3],
        "allocated": parts[4],
    }


def _parse_asname(txt: str) -> dict:
    # "15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US"
    parts = [x.strip() for x in txt.split("|")]
    if len(parts) < 5:
        return {}
    return {"asn": parts[0], "as_name": parts[4]}


class ASNLookupConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        ip = (context.target or "").strip()
        rev = _reverse_ip(ip)
        if not rev:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=_t("asn_lookup.invalid_ip", context.lang))

        origin_host = f"{rev}.origin.asn.cymru.com"
        origin_txt = _dig_txt(origin_host, context.timeout)
        if not origin_txt:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=_t("asn_lookup.empty_txt", context.lang))
        origin = _parse_origin(origin_txt)
        if not origin.get("asn"):
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=_t("asn_lookup.unparsable", context.lang, origin_txt=origin_txt))

        # Secondo lookup per il nome AS
        asname_host = f"AS{origin['asn']}.asn.cymru.com"
        asname_txt = _dig_txt(asname_host, context.timeout)
        asname = _parse_asname(asname_txt) if asname_txt else {}

        ev = [Evidence(url=f"https://bgp.he.net/AS{origin['asn']}",
                       title=f"AS{origin['asn']} on Hurricane Electric BGP")]
        findings = [
            Finding(kind="asn", value=f"AS{origin['asn']}",
                    confidence=0.99, source_reliability="A", info_credibility=1,
                    evidence=ev,
                    notes=(f"ASN che origina il prefisso di {ip} "
                           f"({origin.get('prefix', '?')}). Fonte: Team Cymru.")),
            Finding(kind="asn_prefix", value=origin.get("prefix", ""),
                    confidence=0.95, source_reliability="A", info_credibility=1,
                    evidence=ev),
            Finding(kind="asn_country", value=origin.get("country", ""),
                    confidence=0.9, source_reliability="A", info_credibility=2,
                    evidence=ev),
        ]
        if asname.get("as_name"):
            findings.append(Finding(
                kind="asn_name", value=asname["as_name"],
                confidence=0.95, source_reliability="A", info_credibility=1,
                evidence=ev,
                notes=f"Nome AS{origin['asn']} dal registro Team Cymru.",
            ))
        return ConnectorResult(
            connector=self.spec.name, status="ok",
            findings=findings,
            raw={"origin": origin, "asname": asname},
        )

    def health_check(self) -> bool:
        return shutil.which("dig") is not None
