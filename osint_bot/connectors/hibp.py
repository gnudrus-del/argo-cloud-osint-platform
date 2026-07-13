"""Connector: Have I Been Pwned — breach intelligence (PII-gated)."""
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
    name="hibp", label="Have I Been Pwned", action_class=ACTION_PII_GATED,
    input_types=("email", "domain"),
    output_categories=("breach_intel",),
    required_key="hibp", cache_ttl=3600,
    rate_limit=RateLimit(per_minute=10, per_day=1000, burst=3),
    legal_note="HIBP API v3 — per-user key required. Domain search requires paid subscription.",
    health_check_url="https://haveibeenpwned.com/api/v3/",
)
_BASE = "https://haveibeenpwned.com/api/v3"


def _hibp_get(path: str, key: str, timeout: int) -> list | dict | None:
    req = urllib.request.Request(
        f"{_BASE}{path}",
        headers={"hibp-api-key": key, "user-agent": "Argo-OSINT/1.0", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            if r.status == 404:
                return []
            return json.loads(r.read().decode("utf-8", errors="replace"))
    except Exception:
        return None


class HIBPConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, ctx: ConnectorContext) -> ConnectorResult:
        t = ctx.target.strip()
        key = ctx.api_key
        findings: list[Finding] = []

        if ctx.target_type == "email":
            data = _hibp_get(f"/breachedaccount/{urllib.parse.quote(t)}?truncateResponse=false", key, ctx.timeout)
            if data is None:
                return ConnectorResult(connector=self.spec.name, status="error", error="HIBP non risponde o chiave non valida.")
            breaches = data if isinstance(data, list) else []
            ev = [Evidence(url=f"https://haveibeenpwned.com/account/{urllib.parse.quote(t)}", title="HIBP")]
            for breach in breaches:
                name = breach.get("Name", "")
                title = breach.get("Title", name)
                date = breach.get("BreachDate", "")
                pw_exposed = breach.get("DataClasses", [])
                has_pw = any("Passwords" in dc for dc in pw_exposed)
                sev = "critical" if has_pw else "high"
                findings.append(Finding(
                    kind="hibp_breach",
                    value=name,
                    confidence=0.95,
                    severity=sev,
                    attck_ttps=["T1589.001"],
                    remediation=f"Cambiare la password usata su {title}. Se riutilizzata altrove, cambiarla ovunque. Abilitare MFA.",
                    source_reliability="A", info_credibility=1,
                    evidence=ev,
                    notes=f"Email '{t}' trovata nel breach '{title}' ({date}). Dati esposti: {', '.join(pw_exposed[:5])}.",
                ))
            return ConnectorResult(connector=self.spec.name, status="ok", findings=findings,
                                   raw={"email": t, "breach_count": len(breaches)})

        elif ctx.target_type == "domain":
            # Domain-level breach search (v3 domain endpoint)
            data = _hibp_get(f"/breacheddomain/{urllib.parse.quote(t)}", key, ctx.timeout)
            if data is None:
                return ConnectorResult(connector=self.spec.name, status="error", error="HIBP non risponde.")
            accounts = data if isinstance(data, dict) else {}
            ev = [Evidence(url="https://haveibeenpwned.com/", title="HIBP Domain Search")]
            count = len(accounts)
            sev = "critical" if count >= 10 else ("high" if count >= 1 else "info")
            findings.append(Finding(
                kind="hibp_domain_breach",
                value=str(count),
                confidence=0.90,
                severity=sev,
                attck_ttps=["T1589.001"],
                remediation=f"Forzare il reset password per i {count} account compromessi. Notificare gli utenti secondo GDPR.",
                source_reliability="A", info_credibility=1,
                evidence=ev,
                notes=f"HIBP: {count} account del dominio '{t}' presenti in breach. Severità basata su conteggio.",
            ))
            return ConnectorResult(connector=self.spec.name, status="ok", findings=findings,
                                   raw={"domain": t, "account_count": count})

        return ConnectorResult(connector=self.spec.name, status="error", error="Target type non supportato da HIBP.")
