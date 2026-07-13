"""Connector: AbuseIPDB — IP reputation database."""
from __future__ import annotations

import urllib.parse

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
    name="abuseipdb", label="AbuseIPDB", action_class=ACTION_PASSIVE,
    input_types=("ip",),
    output_categories=("threat_intel",),
    required_key="abuseipdb", cache_ttl=3600,
    rate_limit=RateLimit(per_minute=10, per_day=1000, burst=5),
    legal_note="AbuseIPDB API v2 — passive IP reputation lookup.",
    health_check_url="https://api.abuseipdb.com/api/v2/",
)
_API = "https://api.abuseipdb.com/api/v2/check"


class AbuseIPDBConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, ctx: ConnectorContext) -> ConnectorResult:
        ip = ctx.target.strip()
        key = ctx.api_key
        params = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": "90", "verbose": ""})
        try:
            data = _safe_http.get_json(
                f"{_API}?{params}",
                headers={"Key": key},
                timeout=ctx.timeout,
            )
        except Exception as e:
            return ConnectorResult(connector=self.spec.name, status="error", error=str(e))

        body = data.get("data") or {}
        if not body:
            return ConnectorResult(connector=self.spec.name, status="error", error="AbuseIPDB nessun dato.")

        score = body.get("abuseConfidenceScore", 0)
        reports = body.get("totalReports", 0)
        distinct = body.get("numDistinctUsers", 0)
        country = body.get("countryCode", "")
        isp = body.get("isp", "")
        usage = body.get("usageType", "")
        is_public = body.get("isPublic", True)
        is_tor = body.get("isTor", False)

        sev = "critical" if score >= 80 else ("high" if score >= 40 else ("medium" if score >= 10 else "info"))
        ev = [Evidence(url=f"https://www.abuseipdb.com/check/{ip}", title="AbuseIPDB")]
        findings: list[Finding] = []

        findings.append(Finding(
            kind="abuseipdb_score",
            value=str(score),
            confidence=min(0.95, 0.40 + score / 100),
            severity=sev,
            attck_ttps=["T1071"] if score >= 40 else [],
            remediation="Bloccare IP su firewall se score > 40. Investigare log per connessioni da/verso questo IP." if score >= 40 else "",
            source_reliability="B", info_credibility=2,
            evidence=ev,
            notes=(
                f"AbuseIPDB score: {score}/100 ({reports} report da {distinct} utenti). "
                f"ISP: {isp}. Paese: {country}. Tipo: {usage}."
                + (" [TOR EXIT NODE]" if is_tor else "")
            ),
        ))

        if is_tor:
            findings.append(Finding(
                kind="abuseipdb_tor",
                value=ip,
                confidence=0.90,
                severity="medium",
                attck_ttps=["T1090.003"],
                remediation="IP è un nodo TOR. Considerare blocco selettivo o monitoraggio aumentato.",
                source_reliability="B", info_credibility=2,
                evidence=ev,
                notes=f"L'IP {ip} è un exit node TOR noto secondo AbuseIPDB.",
            ))

        if reports > 0:
            # Fetch last few reports for context
            last_reports = body.get("reports") or []
            for rpt in last_reports[:3]:
                cats = rpt.get("categories") or []
                comment = (rpt.get("comment") or "")[:200]
                reported_at = rpt.get("reportedAt", "")
                if comment or cats:
                    findings.append(Finding(
                        kind="abuseipdb_report",
                        value=f"Cat {cats}: {comment[:100]}" if cats else comment[:100],
                        confidence=0.60,
                        source_reliability="C", info_credibility=3,
                        evidence=ev,
                        notes=f"Report AbuseIPDB del {reported_at}: categorie {cats}.",
                    ))

        return ConnectorResult(connector=self.spec.name, status="ok", findings=findings,
                               raw={"ip": ip, "score": score, "reports": reports, "country": country, "isp": isp})
