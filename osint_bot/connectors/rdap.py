"""Connector: RDAP — Registration Data Access Protocol.

Queries the IANA RDAP bootstrap registry to find the authoritative RDAP
endpoint for a domain's TLD, then fetches domain registration data (registrar,
status, nameservers, dates).  No API key required; free and passive.

Action class: passive.
Output: ``whois_registrar``, ``whois_nameserver``, ``whois_status``,
        ``whois_created``, ``whois_expiry`` findings.
"""
from __future__ import annotations

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
    name="rdap",
    label="RDAP / WHOIS storico",
    action_class=ACTION_PASSIVE,
    input_types=("domain",),
    output_categories=("network_identifiers", "organisational_data"),
    required_key="",
    cache_ttl=86400,  # 24 h — registration data is stable
    rate_limit=RateLimit(per_minute=20, per_day=500, burst=5),
    legal_note="RDAP is an IETF standard (RFC 7480). Freely accessible for passive lookup.",
    health_check_url="https://rdap.org/domain/example.com",
)

# IANA bootstrap: maps TLD → RDAP base URL
_IANA_BOOTSTRAP = "https://data.iana.org/rdap/dns.json"
_bootstrap_cache: dict[str, str] = {}
_bootstrap_loaded = False


def _get_rdap_base(tld: str) -> str | None:
    global _bootstrap_loaded
    if not _bootstrap_loaded:
        try:
            data = _safe_http.get_json(_IANA_BOOTSTRAP, timeout=10)
            for entry in data.get("services", []):
                tlds, urls = entry
                for t in tlds:
                    _bootstrap_cache[t.lower()] = urls[0]
            _bootstrap_loaded = True
        except Exception:
            pass
    return _bootstrap_cache.get(tld.lower())


def _safe_get(req_url: str, timeout: int) -> dict | None:
    try:
        return _safe_http.get_json(req_url, timeout=timeout)
    except Exception:
        return None


class RdapConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        target = context.target.lower().strip()
        parts = target.split(".")
        if len(parts) < 2:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error="Target non è un dominio valido.")
        tld = parts[-1]

        # Try rdap.org as a universal fallback first (avoids bootstrap round-trip)
        data = _safe_get(f"https://rdap.org/domain/{target}", context.timeout)
        if data is None:
            base = _get_rdap_base(tld)
            if base:
                data = _safe_get(f"{base.rstrip('/')}/domain/{target}", context.timeout)
        if data is None:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=f"RDAP non disponibile per '{target}'.")

        findings: list[Finding] = []
        ev = [Evidence(url=f"https://rdap.org/domain/{target}", title="RDAP")]

        # Registrar
        entities = data.get("entities") or []
        for ent in entities:
            roles = ent.get("roles") or []
            if "registrar" in roles:
                name = (ent.get("vcardArray") or [None, []])[1]
                for vcard_line in (name or []):
                    if isinstance(vcard_line, list) and vcard_line[0] == "fn":
                        registrar_name = vcard_line[3]
                        findings.append(Finding(
                            kind="whois_registrar",
                            value=registrar_name,
                            confidence=0.90,
                            source_reliability="B",
                            info_credibility=2,
                            evidence=ev,
                            notes="Registrar ufficiale dal registro RDAP.",
                        ))
                        break

        # Nameservers
        for ns in (data.get("nameservers") or []):
            ldhName = ns.get("ldhName", "")
            if ldhName:
                findings.append(Finding(
                    kind="whois_nameserver",
                    value=ldhName.lower(),
                    confidence=0.90,
                    source_reliability="B",
                    info_credibility=2,
                    evidence=ev,
                    notes="Nameserver dal registro RDAP.",
                ))

        # Status
        for s in (data.get("status") or []):
            findings.append(Finding(
                kind="whois_status",
                value=s,
                confidence=0.90,
                source_reliability="B",
                info_credibility=2,
                evidence=ev,
                notes=f"Stato del dominio: {s}.",
            ))

        # Dates
        for event in (data.get("events") or []):
            action = event.get("eventAction", "")
            date = event.get("eventDate", "")
            if action == "registration" and date:
                findings.append(Finding(
                    kind="whois_created",
                    value=date,
                    confidence=0.90,
                    source_reliability="B",
                    info_credibility=2,
                    evidence=ev,
                    notes="Data di registrazione del dominio.",
                ))
            elif action == "expiration" and date:
                findings.append(Finding(
                    kind="whois_expiry",
                    value=date,
                    confidence=0.90,
                    source_reliability="B",
                    info_credibility=2,
                    evidence=ev,
                    notes="Data di scadenza del dominio.",
                ))

        return ConnectorResult(
            connector=self.spec.name,
            status="ok",
            findings=findings,
            raw={
                "handle": data.get("handle"),
                "ldhName": data.get("ldhName"),
                "status": data.get("status"),
            },
        )

    def health_check(self) -> bool:
        return _safe_get("https://rdap.org/domain/example.com", 5) is not None
