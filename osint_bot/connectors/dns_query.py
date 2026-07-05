"""Connector: DNS resolver — A / AAAA / MX / NS / TXT / CNAME.

Zero API key. Usa ``dig`` se disponibile (installato sulla VM via v6 apt),
altrimenti fallback su ``socket.getaddrinfo`` per soli A/AAAA.

Action class: passive. Input: ``domain``.
"""
from __future__ import annotations

import shutil
import socket
import subprocess
from typing import Iterable

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
    name="dns_query",
    label="DNS lookup",
    action_class=ACTION_PASSIVE,
    input_types=("domain",),
    output_categories=("dns_records",),
    required_key="",
    cache_ttl=600,
    rate_limit=RateLimit(per_minute=60, per_day=20_000, burst=5),
    legal_note="Query DNS pubbliche: nessuna informazione personale.",
    health_check_url="",
)

_RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME")


def _dig(domain: str, rtype: str, timeout: int) -> list[str]:
    """Restituisce la lista di record ``rtype`` per ``domain`` via ``dig``.

    Il ``+short`` di dig stampa solo i valori (uno per riga). Se dig non c'e'
    o va in errore, restituisce lista vuota.
    """
    dig = shutil.which("dig")
    if not dig:
        return []
    try:
        p = subprocess.run(
            [dig, "+short", "+time=3", "+tries=1", rtype, domain],
            capture_output=True, text=True, timeout=timeout,
        )
    except (subprocess.TimeoutExpired, OSError):
        return []
    lines = [line.strip() for line in (p.stdout or "").splitlines() if line.strip()]
    return lines[:20]  # cap per non gonfiare i finding


def _socket_a_aaaa(domain: str) -> Iterable[str]:
    """Fallback: risolvi A/AAAA via ``socket.getaddrinfo`` (senza tipo record)."""
    try:
        seen: set[str] = set()
        for info in socket.getaddrinfo(domain, None,
                                       proto=socket.IPPROTO_TCP):
            addr = info[4][0]
            if addr not in seen:
                seen.add(addr)
                yield addr
    except (OSError, UnicodeError):
        return


class DNSQueryConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        target = (context.target or "").strip().rstrip(".")
        if not target:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error="Target vuoto.")
        findings: list[Finding] = []
        found_any = False
        raw: dict[str, list[str]] = {}

        # Preferisco dig (installato via install-tools-vm-v6 apt).
        if shutil.which("dig"):
            for rtype in _RECORD_TYPES:
                values = _dig(target, rtype, context.timeout)
                if values:
                    found_any = True
                    raw[rtype] = values
                    for v in values:
                        findings.append(Finding(
                            kind=f"dns_{rtype.lower()}",
                            value=v,
                            confidence=0.95,
                            source_reliability="A", info_credibility=1,
                            evidence=[Evidence(
                                url=f"https://dns.google/query?name={target}&rr_type={rtype}",
                                title="DNS")],
                            notes=f"Record {rtype} per {target} via resolver di sistema.",
                        ))
        else:
            # Fallback minimale
            for addr in _socket_a_aaaa(target):
                found_any = True
                kind = "dns_aaaa" if ":" in addr else "dns_a"
                raw.setdefault(kind.upper()[4:], []).append(addr)
                findings.append(Finding(
                    kind=kind, value=addr,
                    confidence=0.95, source_reliability="A", info_credibility=1,
                    evidence=[Evidence(url=f"https://dns.google/query?name={target}",
                                       title="DNS")],
                    notes=f"IP risolto per {target} (fallback socket).",
                ))

        if not found_any:
            return ConnectorResult(connector=self.spec.name, status="ok",
                                   findings=[], raw={"note": "no records"})
        return ConnectorResult(connector=self.spec.name, status="ok",
                               findings=findings, raw=raw)

    def health_check(self) -> bool:
        return shutil.which("dig") is not None or True  # socket è sempre presente
