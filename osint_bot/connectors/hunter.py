"""Connector: Hunter.io — email discovery per dominio (PII-gated)."""
from __future__ import annotations

import urllib.parse

from .. import _safe_http
from ..connector import (
    ACTION_PII_GATED,
    BaseConnector,
    ConnectorContext,
    ConnectorResult,
    ConnectorSpec,
    RateLimit,
)
from ..i18n import t as _t
from ..models import Evidence, Finding

_SPEC = ConnectorSpec(
    name="hunter", label="Hunter.io", action_class=ACTION_PII_GATED,
    input_types=("domain",),
    output_categories=("identity_data",),
    required_key="hunter", cache_ttl=86400,
    rate_limit=RateLimit(per_minute=6, per_day=25, burst=2),
    legal_note="hunter.legal_note",
    health_check_url="https://api.hunter.io/v2/account",
)
_BASE = "https://api.hunter.io/v2"


class HunterConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, ctx: ConnectorContext) -> ConnectorResult:
        t = ctx.target.strip()
        key = ctx.api_key
        params = urllib.parse.urlencode({"domain": t, "api_key": key, "limit": "20"})
        try:
            data = _safe_http.get_json(f"{_BASE}/domain-search?{params}", headers={"Accept": "application/json", "User-Agent": "Argo-OSINT/1.0"}, timeout=ctx.timeout)
        except Exception as e:
            return ConnectorResult(connector=self.spec.name, status="error", error=str(e))

        if "errors" in data:
            errs = data["errors"]
            msg = errs[0].get("details", str(errs)) if errs else "Hunter error"
            return ConnectorResult(connector=self.spec.name, status="error", error=msg)

        body = data.get("data") or {}
        emails = body.get("emails") or []
        pattern = body.get("pattern", "")
        org = body.get("organization", "")
        findings: list[Finding] = []
        ev = [Evidence(url=f"https://hunter.io/search/{t}", title="Hunter.io")]

        if pattern:
            findings.append(Finding(
                kind="email_pattern",
                value=pattern,
                confidence=0.85,
                source_reliability="B", info_credibility=2,
                evidence=ev,
                notes=_t("hunter.email_pattern", ctx.lang, domain=t, pattern=pattern),
            ))
        if org:
            findings.append(Finding(
                kind="org_name",
                value=org,
                confidence=0.80,
                source_reliability="B", info_credibility=2,
                evidence=ev,
                notes=_t("hunter.org_name", ctx.lang, org=org),
            ))
        for entry in emails:
            email_val = entry.get("value", "")
            first = entry.get("first_name", "")
            last = entry.get("last_name", "")
            position = entry.get("position", "")
            confidence = entry.get("confidence", 50) / 100
            if email_val:
                findings.append(Finding(
                    kind="email_address",
                    value=email_val,
                    confidence=confidence,
                    severity="medium",
                    attck_ttps=["T1589.002"],
                    remediation=_t("hunter.email_remediation", ctx.lang),
                    source_reliability="B", info_credibility=3,
                    evidence=ev,
                    notes=_t("hunter.email_found", ctx.lang, first=first, last=last, position=position),
                ))

        return ConnectorResult(connector=self.spec.name, status="ok", findings=findings,
                               raw={"domain": t, "total": body.get("total", 0), "pattern": pattern})
