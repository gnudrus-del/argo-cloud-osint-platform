"""Connector: URLScan.io — passive URL/domain intelligence."""
from __future__ import annotations

import urllib.parse

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
    name="urlscan", label="URLScan.io", action_class=ACTION_PASSIVE,
    input_types=("domain", "url", "ip"),
    output_categories=("network_identifiers", "threat_intel"),
    required_key="", cache_ttl=3600,
    rate_limit=RateLimit(per_minute=20, per_day=5000, burst=5),
    legal_note="URLScan.io search API — free, passive, no scanning triggered.",
    health_check_url="https://urlscan.io/api/v1/search/?q=domain:example.com&size=1",
)
_SEARCH = "https://urlscan.io/api/v1/search/"


def _search(query: str, timeout: int, key: str = "") -> dict | None:
    url = f"{_SEARCH}?q={urllib.parse.quote(query)}&size=20"
    headers = {}
    if key:
        headers["API-Key"] = key
    try:
        return _safe_http.get_json(url, headers=headers, timeout=timeout)
    except Exception:
        return None


class URLScanConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, ctx: ConnectorContext) -> ConnectorResult:
        t = ctx.target.strip()
        if ctx.target_type == "ip":
            query = f"ip:{t}"
        elif ctx.target_type == "url":
            import re
            domain = re.sub(r"https?://", "", t).split("/")[0]
            query = f"domain:{domain}"
        else:
            query = f"domain:{t}"

        data = _search(query, ctx.timeout, ctx.api_key)
        if data is None:
            return ConnectorResult(connector=self.spec.name, status="error", error=_t("generic.no_response", ctx.lang, service="URLScan"))

        results = data.get("results") or []
        findings: list[Finding] = []
        seen_domains: set[str] = set()
        seen_ips: set[str] = set()
        malicious_count = 0

        for result in results[:20]:
            page = result.get("page") or {}
            task = result.get("task") or {}
            verdicts = result.get("verdicts") or {}
            scan_url = task.get("url", "")
            scan_domain = page.get("domain", "")
            scan_ip = page.get("ip", "")
            is_malicious = verdicts.get("overall", {}).get("malicious", False)
            uuid_scan = result.get("_id", "")
            ev = [Evidence(url=f"https://urlscan.io/result/{uuid_scan}/", title="URLScan")]

            if is_malicious:
                malicious_count += 1
                findings.append(Finding(
                    kind="urlscan_malicious",
                    value=scan_url[:200],
                    confidence=0.75,
                    severity="high",
                    attck_ttps=["T1189", "T1566.002"],
                    remediation=_t("urlscan.malicious_remediation", ctx.lang),
                    source_reliability="B", info_credibility=2,
                    evidence=ev,
                    notes=_t("urlscan.malicious_notes", ctx.lang, uuid_scan=uuid_scan),
                ))

            if scan_domain and scan_domain not in seen_domains:
                seen_domains.add(scan_domain)
                findings.append(Finding(
                    kind="urlscan_domain",
                    value=scan_domain,
                    confidence=0.70,
                    source_reliability="C", info_credibility=3,
                    evidence=ev,
                    notes=_t("urlscan.domain_observed", ctx.lang, target=t),
                ))

            if scan_ip and scan_ip not in seen_ips:
                seen_ips.add(scan_ip)
                findings.append(Finding(
                    kind="urlscan_ip",
                    value=scan_ip,
                    confidence=0.70,
                    source_reliability="C", info_credibility=3,
                    evidence=ev,
                    notes=_t("urlscan.ip_observed", ctx.lang, target=t),
                ))

        total = data.get("total", len(results))
        return ConnectorResult(connector=self.spec.name, status="ok", findings=findings[:40],
                               raw={"total": total, "malicious": malicious_count, "query": query})
