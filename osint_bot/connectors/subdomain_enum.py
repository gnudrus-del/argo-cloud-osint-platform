"""Connector: subdomain enumeration (sostituto nativo di subfinder/amass/fierce/dnsenum).

Aggrega sottodomini da fonti passive + un bruteforce DNS leggero:
  * Certificate Transparency (crt.sh) — la fonte passiva più ricca.
  * Bruteforce di una wordlist curata di prefissi comuni (risoluzione DNS).
Deduplica e risolve gli host trovati. Passivo verso il target (le query DNS
risolvono nomi, non toccano il web server).

Input: ``domain``.
"""
from __future__ import annotations

import concurrent.futures as _cf
import json
import socket
import urllib.error
import urllib.request

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
    name="subdomain_enum",
    label="Subdomain enumeration",
    action_class=ACTION_PASSIVE,
    input_types=("domain",),
    output_categories=("subdomains",),
    required_key="",
    cache_ttl=3600,
    rate_limit=RateLimit(per_minute=10, per_day=1000, burst=2),
    legal_note="Fonti passive (CT logs) + risoluzione DNS di prefissi comuni. Nessuno scan attivo del target.",
    health_check_url="https://crt.sh/",
)

_BRUTE_PREFIXES = [
    "www", "mail", "webmail", "smtp", "imap", "pop", "ns1", "ns2", "dns",
    "vpn", "remote", "portal", "api", "api-dev", "dev", "staging", "stage",
    "test", "uat", "qa", "admin", "cpanel", "webdisk", "autodiscover",
    "app", "apps", "mobile", "m", "shop", "store", "blog", "news", "cdn",
    "static", "assets", "img", "images", "media", "files", "ftp", "sftp",
    "git", "gitlab", "jenkins", "ci", "docker", "registry", "k8s", "grafana",
    "kibana", "prometheus", "status", "monitor", "dashboard", "internal",
    "intranet", "corp", "vpn2", "gw", "gateway", "proxy", "mx", "mx1", "mx2",
]


def _crtsh_subdomains(domain: str, timeout: int) -> set[str]:
    url = f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": "argo-osint/1.0",
                                               "Accept": "application/json"})
    out: set[str] = set()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        for row in data:
            name = (row.get("name_value") or "").strip().lower()
            for entry in name.split("\n"):
                entry = entry.strip().lstrip("*.")
                if entry.endswith(domain) and entry != domain:
                    out.add(entry)
    except Exception:
        pass
    return out


def _resolve(host: str) -> str | None:
    try:
        return socket.gethostbyname(host)
    except (socket.gaierror, OSError):
        return None


import urllib.parse  # noqa: E402


class SubdomainEnumConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        domain = (context.target or "").strip().lower().rstrip(".")
        if not domain or "." not in domain:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error="Target deve essere un dominio.")

        # 1) Passivo: Certificate Transparency
        subs = _crtsh_subdomains(domain, context.timeout)

        # 2) Bruteforce leggero: prova i prefissi comuni
        brute_candidates = {f"{p}.{domain}" for p in _BRUTE_PREFIXES}
        to_resolve = subs | brute_candidates

        # 3) Risolvi tutto in parallelo, tieni solo quelli che risolvono
        resolved: dict[str, str] = {}
        with _cf.ThreadPoolExecutor(max_workers=20) as ex:
            futures = {ex.submit(_resolve, h): h for h in to_resolve}
            for f in _cf.as_completed(futures):
                host = futures[f]
                ip = f.result()
                if ip:
                    resolved[host] = ip

        findings: list[Finding] = []
        for host in sorted(resolved):
            source = "CT log (crt.sh)" if host in subs else "DNS bruteforce"
            findings.append(Finding(
                kind="subdomain", value=host,
                confidence=0.9, source_reliability="A", info_credibility=1,
                evidence=[Evidence(url=f"https://crt.sh/?q=%25.{domain}", title="crt.sh")],
                notes=f"Sottodominio attivo → {resolved[host]}. Fonte: {source}.",
            ))
        # Anche i sub trovati in CT ma non risolti (storici) sono utili
        unresolved_ct = sorted(subs - set(resolved))
        for host in unresolved_ct[:50]:
            findings.append(Finding(
                kind="subdomain_historic", value=host,
                confidence=0.6, source_reliability="A", info_credibility=2,
                evidence=[Evidence(url=f"https://crt.sh/?q=%25.{domain}", title="crt.sh")],
                notes="Sottodominio in CT log ma non risolve ora (storico/dismesso).",
            ))
        return ConnectorResult(
            connector=self.spec.name, status="ok",
            findings=findings,
            raw={"ct_total": len(subs), "resolved": len(resolved),
                 "brute_tried": len(brute_candidates)},
        )

    def health_check(self) -> bool:
        return True
