"""Connector: content discovery — fuzzing di path HTTP (sostituto nativo).

Rimpiazza ffuf / dirsearch / feroxbuster (per il caso OSINT/recon): richiede in
parallelo una wordlist curata di path ad alto interesse e riporta quelli che
esistono (status non-404, con filtro soft-404 by lunghezza baseline).

ATTIVO (action-gated): tocca il target con molte richieste → richiede scope
autorizzato. Il gating è applicato a monte (scope/safety); qui implementiamo solo
la logica, con rate-limit prudente.

Input: ``domain`` | ``url``.
"""
from __future__ import annotations

import concurrent.futures as _cf
import urllib.error
import urllib.parse

from .. import _safe_http
from ..connector import (
    ACTION_ACTIVE_GATED,
    BaseConnector,
    ConnectorContext,
    ConnectorResult,
    ConnectorSpec,
    RateLimit,
)
from ..i18n import t as _t
from ..models import Evidence, Finding

_SPEC = ConnectorSpec(
    name="content_discovery",
    label="Content discovery",
    action_class=ACTION_ACTIVE_GATED,
    input_types=("domain", "url"),
    output_categories=("web_paths",),
    required_key="",
    cache_ttl=600,
    rate_limit=RateLimit(per_minute=6, per_day=200, burst=1),
    legal_note="content_discovery.legal_note",
    health_check_url="",
)

# Wordlist curata di path ad alto valore OSINT/recon (piccola e mirata, non un
# dizionario da 50k voci: qui conta il segnale, non la forza bruta).
_PATHS = [
    "robots.txt", "sitemap.xml", ".well-known/security.txt", "humans.txt",
    ".git/HEAD", ".git/config", ".env", ".env.local", ".env.production",
    "config.json", "config.php", "wp-config.php.bak", "backup.zip", "backup.sql",
    "admin", "admin/login", "administrator", "login", "wp-admin", "wp-login.php",
    "phpmyadmin", "adminer.php", "server-status", "server-info",
    "api", "api/v1", "api/v2", "api/docs", "swagger.json", "swagger-ui.html",
    "openapi.json", "graphql", "graphiql", "actuator", "actuator/health",
    "actuator/env", "metrics", "debug", "test", "status", ".DS_Store",
    "readme.md", "CHANGELOG.md", "composer.json", "package.json",
    "storage/logs/laravel.log", "app.log", "error.log", "phpinfo.php",
    ".svn/entries", ".htaccess", "web.config", "crossdomain.xml",
    "s3.json", "gcp.json", "credentials", "id_rsa", "dump.sql",
]

_INTERESTING_HINT = {
    ".env": "content_discovery.hint_env",
    ".git/config": "content_discovery.hint_git",
    ".git/HEAD": "content_discovery.hint_git",
    "actuator/env": "content_discovery.hint_actuator_env",
    "phpinfo.php": "content_discovery.hint_phpinfo",
    "id_rsa": "content_discovery.hint_id_rsa",
    "dump.sql": "content_discovery.hint_dump_sql",
}


def _base_url(target: str) -> str:
    t = target.strip().rstrip("/")
    if t.startswith(("http://", "https://")):
        return t
    return f"https://{t}"


def _probe(base: str, path: str, timeout: int, baseline_len: int) -> dict | None:
    url = f"{base}/{path}"
    try:
        status, body, _ = _safe_http.open_url(url, timeout=timeout)
        body = body[:4096]
    except urllib.error.HTTPError as e:
        status = e.code
        body = b""
    except Exception:
        # Includes _safe_http.SSRFBlocked (internal target) → skip.
        return None
    if status in (404, 410):
        return None
    # Filtro soft-404: se la lunghezza combacia con la baseline della 404 finta.
    if baseline_len and status == 200 and abs(len(body) - baseline_len) < 32:
        return None
    return {"path": path, "url": url, "status": status}


def _baseline_404_len(base: str, timeout: int) -> int:
    """Lunghezza del body per un path sicuramente inesistente (soft-404 detection)."""
    url = f"{base}/argo-nonexistent-{'z' * 12}"
    try:
        status, body, _ = _safe_http.open_url(url, timeout=timeout)
        if status == 200:
            return len(body[:4096])
    except Exception:
        pass
    return 0


class ContentDiscoveryConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        target = (context.target or "").strip()
        if not target:
            return ConnectorResult(connector=self.spec.name, status="error", error=_t("content_discovery.target_empty", context.lang))
        base = _base_url(target)
        per_req_timeout = min(context.timeout, 6)
        baseline = _baseline_404_len(base, per_req_timeout)

        hits: list[dict] = []
        with _cf.ThreadPoolExecutor(max_workers=8) as ex:
            futures = [ex.submit(_probe, base, p, per_req_timeout, baseline) for p in _PATHS]
            for f in _cf.as_completed(futures):
                try:
                    r = f.result()
                    if r:
                        hits.append(r)
                except Exception:
                    pass

        findings: list[Finding] = []
        for h in sorted(hits, key=lambda x: x["path"]):
            hint_key = _INTERESTING_HINT.get(h["path"], "")
            sev = "high" if hint_key else ("low" if h["status"] == 200 else "info")
            notes = (
                _t(hint_key, context.lang) if hint_key
                else _t("content_discovery.path_reachable", context.lang, status=h["status"])
            )
            findings.append(Finding(
                kind="web_path", value=f"{h['url']} [{h['status']}]",
                confidence=0.8 if h["status"] == 200 else 0.6,
                source_reliability="A", info_credibility=2,
                evidence=[Evidence(url=h["url"], title=f"HTTP {h['status']}")],
                notes=notes,
                severity=sev,
            ))
        return ConnectorResult(
            connector=self.spec.name, status="ok",
            findings=findings,
            raw={"probed": len(_PATHS), "hits": len(hits), "baseline_404_len": baseline},
        )

    def health_check(self) -> bool:
        return True
