"""Connector: Shodan — passive host intelligence.

Uses the Shodan REST API to look up IP addresses and domain hostnames.
Requires a Shodan API key configured via the "Chiavi API" tab (service: ``shodan``)
or the ``SHODAN_API_KEY`` environment variable.

Action class: passive.
Input types: ip, domain.
Output: ``shodan_open_port``, ``shodan_service``, ``shodan_cpe``, ``shodan_vuln`` findings.
"""
from __future__ import annotations

import ipaddress
import socket

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
    name="shodan",
    label="Shodan",
    action_class=ACTION_PASSIVE,
    input_types=("ip", "domain"),
    output_categories=("network_identifiers",),
    required_key="shodan",
    cache_ttl=3600,  # 1 h
    rate_limit=RateLimit(per_minute=18, per_day=10_000, burst=5),
    legal_note=(
        "Shodan indexes publicly reachable services. Lookup is passive — no packets "
        "are sent to the target. Complies with Shodan ToS for research use."
    ),
    health_check_url="https://api.shodan.io/api-info",
)

_API_BASE = "https://api.shodan.io"


def _api_get(path: str, api_key: str, timeout: int) -> dict | None:
    url = f"{_API_BASE}{path}?key={api_key}"
    try:
        return _safe_http.get_json(url, timeout=timeout)
    except Exception:
        return None


def _resolve_to_ip(domain: str, timeout: int) -> str | None:
    try:
        result = socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)
        if result:
            return result[0][4][0]
    except OSError:
        return None
    return None


class ShodanConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        target = context.target.strip()
        api_key = context.api_key

        # Resolve domain → IP for Shodan host lookup
        ip: str = target
        if context.target_type == "domain":
            resolved = _resolve_to_ip(target, context.timeout)
            if resolved is None:
                return ConnectorResult(
                    connector=self.spec.name,
                    status="error",
                    error=_t("shodan.resolve_failed", context.lang, target=target),
                )
            ip = resolved

        # Validate IP
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=_t("shodan.invalid_ip", context.lang, ip=ip))

        data = _api_get(f"/shodan/host/{ip}", api_key, context.timeout)
        if data is None:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=_t("shodan.no_data", context.lang, ip=ip))
        if "error" in data:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=data["error"])

        findings: list[Finding] = []
        ev = [Evidence(url=f"https://www.shodan.io/host/{ip}", title="Shodan")]

        # Open ports + services
        for service_entry in (data.get("data") or []):
            port = service_entry.get("port")
            transport = service_entry.get("transport", "tcp")
            product = service_entry.get("product", "")
            version = service_entry.get("version", "")

            if port:
                svc_label = f"{port}/{transport}"
                if product:
                    svc_label += f" ({product}"
                    if version:
                        svc_label += f" {version}"
                    svc_label += ")"
                findings.append(Finding(
                    kind="shodan_open_port",
                    value=f"{ip}:{port}/{transport}",
                    confidence=0.85,
                    source_reliability="B",
                    info_credibility=2,
                    evidence=ev,
                    notes=_t("shodan.open_port", context.lang, service=svc_label),
                ))

            # CPEs
            for cpe in (service_entry.get("cpe") or []):
                findings.append(Finding(
                    kind="shodan_cpe",
                    value=cpe,
                    confidence=0.75,
                    source_reliability="B",
                    info_credibility=3,
                    evidence=ev,
                    notes=_t("shodan.cpe", context.lang, ip=ip, port=port),
                ))

            # Vulns
            for vuln_id in (service_entry.get("vulns") or {}):
                findings.append(Finding(
                    kind="shodan_vuln",
                    value=vuln_id,
                    confidence=0.70,
                    source_reliability="B",
                    info_credibility=3,
                    evidence=ev,
                    notes=_t("shodan.vuln", context.lang, ip=ip, port=port),
                ))

        # Hostnames
        for hostname in (data.get("hostnames") or []):
            findings.append(Finding(
                kind="shodan_hostname",
                value=hostname,
                confidence=0.80,
                source_reliability="B",
                info_credibility=2,
                evidence=ev,
                notes=_t("shodan.hostname", context.lang, ip=ip),
            ))

        # OS
        os_name = data.get("os")
        if os_name:
            findings.append(Finding(
                kind="shodan_os",
                value=os_name,
                confidence=0.65,
                source_reliability="B",
                info_credibility=3,
                evidence=ev,
                notes=_t("shodan.os", context.lang, ip=ip),
            ))

        return ConnectorResult(
            connector=self.spec.name,
            status="ok",
            findings=findings,
            raw={
                "ip": ip,
                "ports": data.get("ports"),
                "country_code": data.get("country_code"),
                "org": data.get("org"),
                "isp": data.get("isp"),
                "asn": data.get("asn"),
                "last_update": data.get("last_update"),
            },
        )

    def health_check(self) -> bool:
        return False  # requires API key — cannot probe without one
