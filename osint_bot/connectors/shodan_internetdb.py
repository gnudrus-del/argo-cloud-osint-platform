"""Connector: Shodan InternetDB — porte/CPE/vuln/hostname per IP, SENZA API key.

InternetDB (https://internetdb.shodan.io/<ip>) e' l'endpoint gratuito e no-key
di Shodan: ritorna un JSON compatto con ports, cpes, hostnames, tags, vulns.
Zero costo, zero chiave, rate-limit generoso. Passivo.

Input: ``ip``.
"""
from __future__ import annotations

import ipaddress
import json
import urllib.error
import urllib.request

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
    name="shodan_internetdb",
    label="Shodan InternetDB",
    action_class=ACTION_PASSIVE,
    input_types=("ip",),
    output_categories=("ports", "vulnerabilities", "tech_stack"),
    required_key="",
    cache_ttl=3600,
    rate_limit=RateLimit(per_minute=60, per_day=10_000, burst=5),
    legal_note="Endpoint pubblico gratuito Shodan InternetDB. Solo dati già indicizzati, nessuna scansione attiva.",
    health_check_url="https://internetdb.shodan.io/",
)


def _fetch_internetdb(ip: str, timeout: int) -> dict | None:
    url = f"https://internetdb.shodan.io/{ip}"
    req = urllib.request.Request(url, headers={
        "Accept": "application/json",
        "User-Agent": "argo-osint/1.0",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {}  # IP non in InternetDB: risultato valido vuoto
        return None
    except Exception:
        return None


class ShodanInternetDBConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        ip = (context.target or "").strip()
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error="Target non è un IP valido.")

        data = _fetch_internetdb(ip, context.timeout)
        if data is None:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error="InternetDB non raggiungibile.")
        if not data:
            return ConnectorResult(connector=self.spec.name, status="ok",
                                   findings=[], raw={"note": "IP non presente in InternetDB."})

        ev = [Evidence(url=f"https://www.shodan.io/host/{ip}", title=f"Shodan host {ip}")]
        findings: list[Finding] = []

        for port in (data.get("ports") or [])[:50]:
            findings.append(Finding(
                kind="open_port", value=str(port),
                confidence=0.9, source_reliability="B", info_credibility=2,
                evidence=ev,
                notes=f"Porta osservata da Shodan su {ip} (indicizzata, non scan live).",
            ))
        for hostname in (data.get("hostnames") or [])[:20]:
            findings.append(Finding(
                kind="hostname", value=hostname,
                confidence=0.85, source_reliability="B", info_credibility=2,
                evidence=ev,
            ))
        for cpe in (data.get("cpes") or [])[:30]:
            findings.append(Finding(
                kind="tech_cpe", value=cpe,
                confidence=0.8, source_reliability="B", info_credibility=2,
                evidence=ev,
                notes="CPE (software/versione) inferito da Shodan.",
            ))
        for vuln in (data.get("vulns") or [])[:50]:
            findings.append(Finding(
                kind="vulnerability", value=vuln,
                confidence=0.75, source_reliability="B", info_credibility=3,
                evidence=[Evidence(url=f"https://nvd.nist.gov/vuln/detail/{vuln}", title=vuln)],
                notes=f"CVE potenziale associato a {ip} da Shodan. Verificare versione reale.",
                severity="medium",
            ))
        for tag in (data.get("tags") or [])[:20]:
            findings.append(Finding(
                kind="host_tag", value=str(tag),
                confidence=0.7, source_reliability="B", info_credibility=3,
                evidence=ev,
            ))

        return ConnectorResult(
            connector=self.spec.name, status="ok",
            findings=findings,
            raw={"ports": data.get("ports"), "vulns": data.get("vulns"),
                 "cpes": data.get("cpes"), "hostnames": data.get("hostnames"),
                 "tags": data.get("tags")},
        )

    def health_check(self) -> bool:
        try:
            _safe_http.get_bytes("https://internetdb.shodan.io/8.8.8.8", timeout=4)
            return True
        except Exception:
            return False
