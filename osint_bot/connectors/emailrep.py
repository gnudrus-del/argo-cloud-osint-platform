"""Connector: EmailRep.io — email reputation (passive).

Free 100 req/day without key, more with BYOK. Returns reputation score +
flags (suspicious, blacklisted, deliverable, presence on platforms).

Action class: passive (PII gated by caller). Input: ``email``.
"""
from __future__ import annotations

import json
import urllib.parse
import urllib.request

from ..connector import (
    ACTION_PII_GATED,
    BaseConnector,
    ConnectorContext,
    ConnectorResult,
    ConnectorSpec,
    RateLimit,
)
from ..models import Evidence, Finding

_SPEC = ConnectorSpec(
    name="emailrep",
    label="EmailRep.io",
    action_class=ACTION_PII_GATED,
    input_types=("email",),
    output_categories=("reputation",),
    required_key="",  # opzionale
    cache_ttl=3600,
    rate_limit=RateLimit(per_minute=10, per_day=100, burst=2),
    legal_note=(
        "EmailRep.io: aggrega reputazione email da fonti pubbliche. "
        "Usabile solo con base giuridica (caso + autorizzazione)."
    ),
    health_check_url="https://emailrep.io/",
)


class EmailRepConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        email = urllib.parse.quote(context.target.strip(), safe="@")
        url = f"https://emailrep.io/{email}"
        headers = {"Accept": "application/json", "User-Agent": "Argo-OSINT/1.0"}
        if context.api_key:
            headers["Key"] = context.api_key
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=context.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
        except Exception as exc:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=f"EmailRep: {exc}")
        rep = (data or {}).get("reputation", "unknown")
        suspicious = (data or {}).get("suspicious", False)
        details = (data or {}).get("details") or {}
        ev = [Evidence(url=f"https://emailrep.io/{context.target}", title="EmailRep")]
        findings: list[Finding] = [Finding(
            kind="email_reputation",
            value=f"{context.target} -> {rep}",
            confidence=0.75, source_reliability="C", info_credibility=2,
            severity="medium" if suspicious else "info",
            evidence=ev,
            notes=(
                f"EmailRep: reputation={rep}, suspicious={suspicious}, "
                f"deliverable={details.get('deliverable', '?')}, "
                f"profiles={details.get('profiles', [])[:5]}"
            ),
        )]
        return ConnectorResult(connector=self.spec.name, status="ok",
                               findings=findings,
                               raw={"reputation": rep, "suspicious": suspicious})

    def health_check(self) -> bool:
        try:
            urllib.request.urlopen("https://emailrep.io/", timeout=5).close()
            return True
        except Exception:
            return False
