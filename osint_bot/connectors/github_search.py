"""Connector: GitHub Code Search — secret/credential exposure in public repos."""
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
    name="github_search", label="GitHub Code Search", action_class=ACTION_PASSIVE,
    input_types=("domain", "company", "email"),
    output_categories=("code_exposure",),
    required_key="github", cache_ttl=3600,
    rate_limit=RateLimit(per_minute=10, per_day=1000, burst=3),
    legal_note="GitHub Search API — passive read-only on public repositories.",
    health_check_url="https://api.github.com/rate_limit",
)
_API = "https://api.github.com/search/code"

# High-value dork patterns that indicate secret exposure
_DORKS: list[tuple[str, str, str, list[str]]] = [
    ("password",      "github_secret_hint", "high",   ["T1552.001"]),
    ("api_key",       "github_secret_hint", "high",   ["T1552.001"]),
    ("secret_key",    "github_secret_hint", "high",   ["T1552.001"]),
    ("private_key",   "github_secret_hint", "critical",["T1552.004"]),
    ("aws_access_key","github_secret_hint", "critical",["T1552.001"]),
    ("database_url",  "github_secret_hint", "critical",["T1552.001"]),
    ("smtp_password", "github_secret_hint", "high",   ["T1552.001"]),
    ("connectionstring","github_secret_hint","critical",["T1552.001"]),
]


def _gh_search(query: str, key: str, timeout: int) -> dict | None:
    encoded = urllib.parse.quote(query)
    try:
        return _safe_http.get_json(
            f"{_API}?q={encoded}&per_page=10",
            headers={
                "Authorization": f"token {key}",
                "Accept": "application/vnd.github.v3+json",
            },
            timeout=timeout,
        )
    except Exception:
        return None


class GitHubSearchConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, ctx: ConnectorContext) -> ConnectorResult:
        t = ctx.target.strip()
        key = ctx.api_key
        findings: list[Finding] = []
        seen: set[str] = set()

        for keyword, kind, severity, ttps in _DORKS:
            query = f'"{t}" {keyword}'
            data = _gh_search(query, key, ctx.timeout)
            if not data:
                continue
            items = data.get("items") or []
            for item in items[:5]:
                repo = item.get("repository", {})
                repo_name = repo.get("full_name", "")
                html_url = item.get("html_url", "")
                file_path = item.get("path", "")
                dedup_key = f"{repo_name}:{file_path}:{keyword}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                findings.append(Finding(
                    kind=kind,
                    value=f"{repo_name}: {file_path}",
                    confidence=0.65,
                    severity=severity,
                    attck_ttps=ttps,
                    remediation=_t("github_search.remediation_secret", ctx.lang, file_path=file_path),
                    source_reliability="B", info_credibility=2,
                    evidence=[Evidence(url=html_url, title=f"GitHub: {repo_name}")],
                    notes=_t("github_search.pattern_found", ctx.lang, keyword=keyword, target=t),
                ))

        # Also search for any public repos mentioning the target domain
        org_data = _gh_search(f'"{t}" in:readme,description', key, ctx.timeout)
        if org_data:
            total_refs = org_data.get("total_count", 0)
            if total_refs:
                findings.append(Finding(
                    kind="github_repo_mention",
                    value=str(total_refs),
                    confidence=0.60,
                    source_reliability="C", info_credibility=4,
                    evidence=[Evidence(url=f"https://github.com/search?q={urllib.parse.quote(t)}", title="GitHub Search")],
                    notes=_t("github_search.repo_mentions", ctx.lang, count=total_refs, target=t),
                ))

        return ConnectorResult(connector=self.spec.name, status="ok", findings=findings,
                               raw={"target": t, "dork_hits": len(findings)})
