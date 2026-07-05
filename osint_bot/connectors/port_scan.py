"""Connector: port scan TCP-connect (sostituto nativo di nmap/masscan/naabu).

Per il caso OSINT/attack-surface: scan TCP-connect concorrente su una lista di
porte ad alto interesse, con banner-grab leggero. NON fa SYN/stealth scan (serve
raw socket + root) — per l'inventario di superficie il connect-scan è sufficiente
e più portabile.

ATTIVO (action-gated): apre connessioni TCP al target → richiede scope autorizzato.
Input: ``ip`` | ``domain``.
"""
from __future__ import annotations

import concurrent.futures as _cf
import socket

from ..connector import (
    ACTION_ACTIVE_GATED,
    BaseConnector,
    ConnectorContext,
    ConnectorResult,
    ConnectorSpec,
    RateLimit,
)
from ..models import Evidence, Finding

_SPEC = ConnectorSpec(
    name="port_scan",
    label="Port scan (TCP connect)",
    action_class=ACTION_ACTIVE_GATED,
    input_types=("ip", "domain"),
    output_categories=("open_ports",),
    required_key="",
    cache_ttl=300,
    rate_limit=RateLimit(per_minute=6, per_day=200, burst=1),
    legal_note="Attivo: apre connessioni TCP al target. Solo con scope autorizzato.",
    health_check_url="",
)

# Porte ad alto interesse (servizi comuni + high-risk per attack-surface).
_PORTS: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios", 143: "imap",
    443: "https", 445: "smb", 465: "smtps", 587: "smtp-sub", 993: "imaps",
    995: "pop3s", 1433: "mssql", 1521: "oracle", 2049: "nfs", 2375: "docker",
    2376: "docker-tls", 3000: "dev-http", 3306: "mysql", 3389: "rdp",
    5000: "upnp/dev", 5432: "postgres", 5601: "kibana", 5900: "vnc",
    6379: "redis", 7474: "neo4j", 8000: "http-alt", 8080: "http-proxy",
    8443: "https-alt", 8888: "http-alt", 9000: "http-alt", 9200: "elasticsearch",
    9300: "es-transport", 11211: "memcached", 27017: "mongodb",
}

_RISKY = {2375, 2376, 6379, 9200, 11211, 27017, 3306, 5432, 1433, 3389, 5900, 445}


def _resolve(host: str) -> str | None:
    try:
        return socket.gethostbyname(host)
    except (socket.gaierror, OSError):
        return None


def _scan_port(ip: str, port: int, timeout: float) -> dict | None:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            banner = ""
            try:
                sock.settimeout(1.0)
                data = sock.recv(128)
                banner = data.decode("latin-1", errors="replace").strip()
            except Exception:
                pass
            return {"port": port, "banner": banner[:120]}
    except Exception:
        return None


class PortScanConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        target = (context.target or "").strip()
        if not target:
            return ConnectorResult(connector=self.spec.name, status="error", error="Target vuoto.")
        # risolvi hostname -> IP (accetta anche IP diretto)
        ip = target if target.replace(".", "").isdigit() else _resolve(target)
        if not ip:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=f"Impossibile risolvere {target}.")

        per_port_timeout = 1.5
        open_ports: list[dict] = []
        with _cf.ThreadPoolExecutor(max_workers=16) as ex:
            futures = {ex.submit(_scan_port, ip, p, per_port_timeout): p for p in _PORTS}
            for f in _cf.as_completed(futures):
                r = f.result()
                if r:
                    open_ports.append(r)

        findings: list[Finding] = []
        for op in sorted(open_ports, key=lambda x: x["port"]):
            port = op["port"]
            svc = _PORTS.get(port, "?")
            risky = port in _RISKY
            note = f"Porta {port}/{svc} aperta su {ip}."
            if op["banner"]:
                note += f" Banner: {op['banner']}"
            if risky:
                note += " ⚠ servizio potenzialmente sensibile esposto."
            findings.append(Finding(
                kind="open_port", value=f"{ip}:{port} ({svc})",
                confidence=0.95, source_reliability="A", info_credibility=1,
                evidence=[Evidence(url=f"https://www.speedguide.net/port.php?port={port}",
                                   title=f"port {port}")],
                notes=note,
                severity="high" if risky else "info",
            ))
        return ConnectorResult(
            connector=self.spec.name, status="ok",
            findings=findings,
            raw={"ip": ip, "scanned": len(_PORTS), "open": len(open_ports)},
        )

    def health_check(self) -> bool:
        return True
