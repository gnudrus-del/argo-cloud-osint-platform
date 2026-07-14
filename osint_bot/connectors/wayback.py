"""Connector: Wayback Machine CDX API — historical URL discovery."""
from __future__ import annotations

import json
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
    name="wayback", label="Wayback Machine CDX", action_class=ACTION_PASSIVE,
    input_types=("domain", "url"),
    output_categories=("network_identifiers",),
    required_key="", cache_ttl=86400,
    rate_limit=RateLimit(per_minute=10, per_day=1000, burst=3),
    legal_note="Internet Archive CDX API — freely accessible, no authentication.",
    health_check_url="http://web.archive.org/cdx/search/cdx?url=example.com&limit=1&output=json",
)
_CDX = "http://web.archive.org/cdx/search/cdx"

# URL patterns that suggest interesting/sensitive endpoints.
# The 4th tuple element is a catalog key for the user-facing description.
_INTERESTING_PATTERNS = [
    (".env", "red_team_exposed_path", "high", "wayback.desc_env", ["T1552.001"]),
    (".git/config", "red_team_exposed_path", "high", "wayback.desc_git_config", ["T1552.001"]),
    ("/admin", "wayback_admin_path", "medium", "wayback.desc_admin", ["T1078"]),
    ("/backup", "wayback_backup_path", "medium", "wayback.desc_backup", ["T1530"]),
    ("/wp-admin", "wayback_admin_path", "medium", "wayback.desc_wp_admin", ["T1078"]),
    ("/phpinfo", "red_team_exposed_path", "medium", "wayback.desc_phpinfo", ["T1082"]),
    ("/api/", "wayback_api_endpoint", "low", "wayback.desc_api", ["T1590"]),
    ("/swagger", "wayback_api_endpoint", "medium", "wayback.desc_swagger", ["T1590"]),
    ("/actuator", "wayback_api_endpoint", "high", "wayback.desc_actuator", ["T1082"]),
    ("password", "wayback_credential_hint", "high", "wayback.desc_password", ["T1552"]),
    ("token=", "wayback_credential_hint", "high", "wayback.desc_token", ["T1528"]),
    ("apikey=", "wayback_credential_hint", "high", "wayback.desc_apikey", ["T1552.001"]),
]


class WaybackConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, ctx: ConnectorContext) -> ConnectorResult:
        t = ctx.target.strip()
        import re
        if ctx.target_type == "url":
            domain = re.sub(r"https?://", "", t).split("/")[0]
        else:
            domain = t

        params = urllib.parse.urlencode({
            "url": f"*.{domain}/*",
            "output": "json",
            "fl": "original,statuscode,timestamp",
            "collapse": "urlkey",
            "limit": "500",
            "filter": "statuscode:200",
        })
        url = f"{_CDX}?{params}"
        try:
            raw = _safe_http.get_text(url, timeout=ctx.timeout)
        except Exception as e:
            return ConnectorResult(connector=self.spec.name, status="error", error=str(e))

        try:
            rows = json.loads(raw)
        except Exception:
            return ConnectorResult(connector=self.spec.name, status="error", error=_t("wayback.invalid_response", ctx.lang))

        if not rows or not isinstance(rows, list):
            return ConnectorResult(connector=self.spec.name, status="ok", findings=[], raw={"urls": 0})

        # First row is header
        header = rows[0]
        data_rows = rows[1:] if header[0] == "original" else rows

        findings: list[Finding] = []
        seen: set[str] = set()
        interesting_found: dict[str, list[str]] = {}

        for row in data_rows:
            if len(row) < 1:
                continue
            orig_url = row[0]
            ts = row[2] if len(row) > 2 else ""
            orig_lower = orig_url.lower()

            for pattern, kind, severity, desc_key, ttps in _INTERESTING_PATTERNS:
                if pattern in orig_lower:
                    key = f"{kind}:{orig_url[:80]}"
                    if key not in seen:
                        seen.add(key)
                        desc = _t(desc_key, ctx.lang)
                        snap_url = f"https://web.archive.org/web/{ts}/{orig_url}" if ts else orig_url
                        findings.append(Finding(
                            kind=kind,
                            value=orig_url[:200],
                            confidence=0.60,
                            severity=severity,
                            attck_ttps=ttps,
                            remediation=_t("wayback.remediation", ctx.lang, desc=desc),
                            source_reliability="C", info_credibility=3,
                            evidence=[Evidence(url=snap_url, title="Wayback Machine CDX")],
                            notes=_t("wayback.notes_url", ctx.lang, desc=desc),
                        ))
                    if kind not in interesting_found:
                        interesting_found[kind] = []
                    interesting_found[kind].append(orig_url)
                    break

        # Unique old URLs count as network_identifier
        all_urls = [row[0] for row in data_rows if row]
        findings.append(Finding(
            kind="wayback_url_count",
            value=str(len(all_urls)),
            confidence=0.90,
            source_reliability="B", info_credibility=2,
            evidence=[Evidence(url=f"https://web.archive.org/web/*/{domain}", title="Wayback Machine")],
            notes=_t("wayback.snapshot_count", ctx.lang, count=len(all_urls), domain=domain),
        ))

        return ConnectorResult(connector=self.spec.name, status="ok", findings=findings[:60],
                               raw={"total_urls": len(all_urls), "interesting": len(findings) - 1,
                                    "domain": domain})
