"""Connector: LeakIX — leaked service and vulnerability database."""
from __future__ import annotations

from .. import _safe_http
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
    name="leakix", label="LeakIX", action_class=ACTION_PASSIVE,
    input_types=("domain", "ip"),
    output_categories=("network_identifiers", "threat_intel"),
    required_key="leakix", cache_ttl=3600,
    rate_limit=RateLimit(per_minute=15, per_day=1000, burst=5),
    legal_note="LeakIX API — passive lookup of public vulnerability and misconfiguration data.",
    health_check_url="https://leakix.net/",
)
_BASE = "https://leakix.net"


def _lx_get(path: str, key: str, timeout: int) -> dict | None:
    try:
        return _safe_http.get_json(
            f"{_BASE}{path}",
            headers={"api-key": key},
            timeout=timeout,
        )
    except Exception:
        return None


class LeakIXConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, ctx: ConnectorContext) -> ConnectorResult:
        t = ctx.target.strip()
        key = ctx.api_key
        if ctx.target_type == "ip":
            path = f"/host/{t}"
        else:
            path = f"/domain/{t}"

        data = _lx_get(path, key, ctx.timeout)
        if data is None:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=_t("generic.no_response", ctx.lang, service="LeakIX"))

        findings: list[Finding] = []
        events = data if isinstance(data, list) else [data]

        for event in events[:20]:
            if not isinstance(event, dict):
                continue
            ip = event.get("ip", "")
            port = event.get("port", "")
            host = event.get("host", t)
            plugin = event.get("plugin", "")
            leak = event.get("leak") or {}
            severity_raw = event.get("severity", "low")
            sev = {"critical": "critical", "high": "high", "medium": "medium",
                   "low": "low", "info": "info"}.get(severity_raw, "low")
            ev_url = f"https://leakix.net/host/{ip}" if ip else f"https://leakix.net/domain/{t}"
            ev = [Evidence(url=ev_url, title="LeakIX")]

            # Service / plugin finding
            if plugin:
                findings.append(Finding(
                    kind="leakix_service",
                    value=f"{ip}:{port} — {plugin}" if ip else f"{host}:{port} — {plugin}",
                    confidence=0.80,
                    severity=sev,
                    attck_ttps=["T1190", "T1082"],
                    remediation=_t("leakix.remediation_service", ctx.lang),
                    source_reliability="B", info_credibility=2,
                    evidence=ev,
                    notes=_t("leakix.plugin", ctx.lang, plugin=plugin, host=host, port=port),
                ))

            # Leak-specific data
            leak_type = leak.get("type", "")
            if leak_type:
                findings.append(Finding(
                    kind="leakix_leak",
                    value=leak_type,
                    confidence=0.75,
                    severity=sev,
                    attck_ttps=["T1530", "T1190"],
                    remediation=_t("leakix.remediation_leak", ctx.lang),
                    source_reliability="B", info_credibility=2,
                    evidence=ev,
                    notes=_t("leakix.leak", ctx.lang, leak_type=leak_type, host=host, port=port),
                ))

        return ConnectorResult(connector=self.spec.name, status="ok", findings=findings,
                               raw={"target": t, "events": len(events)})
