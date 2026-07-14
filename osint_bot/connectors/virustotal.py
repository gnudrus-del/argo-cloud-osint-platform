"""Connector: VirusTotal — threat intelligence."""
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
    name="virustotal", label="VirusTotal", action_class=ACTION_PASSIVE,
    input_types=("domain", "ip", "url", "file_hash"),
    output_categories=("threat_intel",),
    required_key="virustotal", cache_ttl=3600,
    rate_limit=RateLimit(per_minute=4, per_day=500, burst=2),
    legal_note="VirusTotal API v3 — passive lookup only. Free tier: 4 req/min.",
    health_check_url="https://www.virustotal.com/api/v3/",
)
_API = "https://www.virustotal.com/api/v3"


def _vt_get(path: str, key: str, timeout: int) -> dict | None:
    try:
        return _safe_http.get_json(f"{_API}{path}", headers={"x-apikey": key}, timeout=timeout)
    except Exception:
        return None


class VirusTotalConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, ctx: ConnectorContext) -> ConnectorResult:
        t = ctx.target.strip()
        key = ctx.api_key
        # Determine endpoint
        import re
        if ctx.target_type in ("file_hash", ) or re.fullmatch(r"[0-9a-fA-F]{32,64}", t):
            data = _vt_get(f"/files/{t}", key, ctx.timeout)
            ev_url = f"https://www.virustotal.com/gui/file/{t}"
            subject = "file"
        elif ctx.target_type == "ip":
            data = _vt_get(f"/ip_addresses/{t}", key, ctx.timeout)
            ev_url = f"https://www.virustotal.com/gui/ip-address/{t}"
            subject = "ip"
        elif ctx.target_type == "url":
            import base64
            url_id = base64.urlsafe_b64encode(t.encode()).rstrip(b"=").decode()
            data = _vt_get(f"/urls/{url_id}", key, ctx.timeout)
            ev_url = f"https://www.virustotal.com/gui/url/{url_id}"
            subject = "url"
        else:
            data = _vt_get(f"/domains/{t}", key, ctx.timeout)
            ev_url = f"https://www.virustotal.com/gui/domain/{t}"
            subject = "domain"

        if not data:
            return ConnectorResult(connector=self.spec.name, status="error", error=_t("virustotal.no_response_or_limit", ctx.lang))

        attrs = (data.get("data") or {}).get("attributes") or {}
        findings: list[Finding] = []
        ev = [Evidence(url=ev_url, title="VirusTotal")]

        # Malicious verdict
        stats = attrs.get("last_analysis_stats") or {}
        malicious = stats.get("malicious", 0)
        total = sum(stats.values()) if stats else 0
        if total > 0:
            ratio = malicious / total
            findings.append(Finding(
                kind="vt_detection",
                value=f"{malicious}/{total} rilevamenti",
                confidence=min(0.95, ratio + 0.1) if malicious else 0.85,
                severity="critical" if malicious >= 5 else ("high" if malicious >= 2 else ("medium" if malicious == 1 else "info")),
                attck_ttps=["T1588.001"] if malicious else [],
                remediation=_t("virustotal.detection_remediation", ctx.lang) if malicious else "",
                source_reliability="A", info_credibility=2,
                evidence=ev,
                notes=_t("virustotal.detection_notes", ctx.lang, malicious=malicious, total=total),
            ))

        # Categories
        cats = attrs.get("categories") or {}
        if cats:
            cat_str = ", ".join(set(cats.values()))[:200]
            findings.append(Finding(kind="vt_category", value=cat_str, confidence=0.80,
                                    source_reliability="B", info_credibility=2, evidence=ev,
                                    notes=_t("virustotal.category_notes", ctx.lang)))

        # Reputation score
        reputation = attrs.get("reputation")
        if reputation is not None:
            sev = "high" if reputation < -10 else ("medium" if reputation < 0 else "info")
            findings.append(Finding(kind="vt_reputation", value=str(reputation), confidence=0.80,
                                    severity=sev, source_reliability="B", info_credibility=2,
                                    evidence=ev, notes=_t("virustotal.reputation_notes", ctx.lang, reputation=reputation)))

        # WHOIS / creation date
        if "creation_date" in attrs:
            import datetime as dt
            try:
                ts = dt.datetime.utcfromtimestamp(attrs["creation_date"]).strftime("%Y-%m-%d")
                findings.append(Finding(kind="vt_creation_date", value=ts, confidence=0.85,
                                        source_reliability="B", info_credibility=2, evidence=ev))
            except Exception:
                pass

        return ConnectorResult(connector=self.spec.name, status="ok", findings=findings,
                               raw={"subject": subject, "malicious": malicious, "total": total})
