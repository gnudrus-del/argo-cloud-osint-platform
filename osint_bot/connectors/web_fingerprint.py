"""Connector: Web fingerprint — Server / X-Powered-By / title / generator / cookies.

Un solo GET HTTP al target (con HEAD fallback). Estrae:
  * Server header (nginx/x.y, cloudflare, ecc.)
  * X-Powered-By / X-Generator
  * <title>
  * <meta name="generator" content="...">
  * Cookie names (indicative del framework: sessionid = django, PHPSESSID = php...)
  * Content-Security-Policy hint

Zero API key. Passivo (una connessione HTTPS).
Input: ``domain`` o ``url``.
"""
from __future__ import annotations

import re
import urllib.error
import urllib.request

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
    name="web_fingerprint",
    label="Web fingerprint",
    action_class=ACTION_PASSIVE,
    input_types=("domain", "url"),
    output_categories=("tech_stack",),
    required_key="",
    cache_ttl=3600,
    rate_limit=RateLimit(per_minute=20, per_day=2000, burst=2),
    legal_note="Un GET HTTPS al target. Passivo. No brute force.",
    health_check_url="",
)

_MAX_BODY = 200_000  # 200 KB, sufficiente per <head>
_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)
_GENERATOR_RE = re.compile(
    rb"""<meta[^>]+name=["']?generator["']?[^>]+content=["']([^"']+)["']""",
    re.I,
)

# Marker cookie name -> tech
_COOKIE_MARKERS = {
    "PHPSESSID": "PHP",
    "sessionid": "Django",
    "django_language": "Django",
    "csrftoken": "Django",
    "laravel_session": "Laravel",
    "ci_session": "CodeIgniter",
    "JSESSIONID": "Java (Servlet)",
    "ASPXAUTH": "ASP.NET",
    "ASP.NET_SessionId": "ASP.NET",
    "_shopify_y": "Shopify",
    "_wc_session": "WooCommerce",
    "wp-settings": "WordPress",
}


def _to_url(target: str) -> str:
    t = target.strip()
    if t.startswith(("http://", "https://")):
        return t
    return f"https://{t}"


def _fetch(url: str, timeout: int) -> tuple[dict, bytes] | None:
    from .._safe_http import SSRFBlocked, guard_ssrf
    try:
        guard_ssrf(url)
    except SSRFBlocked:
        return None
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (compatible; ArgoOSINT/1.0)",
        "Accept": "text/html,application/xhtml+xml",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            headers = {k: v for k, v in resp.getheaders()}
            body = resp.read(_MAX_BODY)
        return headers, body
    except urllib.error.HTTPError as e:
        # Anche 4xx/5xx portano info utili (server header, cookie di errore).
        headers = {k: v for k, v in e.headers.items()} if e.headers else {}
        try:
            body = e.read(_MAX_BODY)
        except Exception:
            body = b""
        return headers, body
    except Exception:
        return None


def _extract_title(body: bytes) -> str:
    m = _TITLE_RE.search(body or b"")
    if not m:
        return ""
    try:
        return m.group(1).decode("utf-8", errors="replace").strip()[:200]
    except Exception:
        return ""


def _extract_generator(body: bytes) -> str:
    m = _GENERATOR_RE.search(body or b"")
    if not m:
        return ""
    try:
        return m.group(1).decode("utf-8", errors="replace").strip()[:200]
    except Exception:
        return ""


def _cookie_names(headers: dict) -> list[str]:
    """Best-effort estrazione dei nomi cookie da Set-Cookie (case-insensitive)."""
    raw = ""
    for k, v in headers.items():
        if k.lower() == "set-cookie":
            raw += ";" + v
    names = []
    for chunk in raw.split(";"):
        chunk = chunk.strip()
        if "=" in chunk:
            name = chunk.split("=", 1)[0].strip()
            if name and name.lower() not in {"path", "expires", "max-age",
                                             "domain", "secure", "httponly",
                                             "samesite"}:
                names.append(name)
    # dedup mantieni ordine
    seen: set[str] = set()
    out = []
    for n in names:
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out[:20]


class WebFingerprintConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        target = (context.target or "").strip()
        if not target:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error="Target vuoto.")
        url = _to_url(target)
        result = _fetch(url, context.timeout)
        if result is None:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=f"HTTP fetch fallita per {url}.")
        headers, body = result

        findings: list[Finding] = []
        ev = [Evidence(url=url, title="HTTP response headers")]

        # Header di interesse
        for hname in ("Server", "X-Powered-By", "X-Generator", "Via",
                      "X-AspNet-Version", "X-Backend-Server"):
            for k, v in headers.items():
                if k.lower() == hname.lower() and v:
                    findings.append(Finding(
                        kind="tech_header", value=f"{hname}: {v}",
                        confidence=0.9, source_reliability="A", info_credibility=2,
                        evidence=ev,
                        notes=f"Header di risposta HTTP di {url}.",
                    ))
                    break

        title = _extract_title(body)
        if title:
            findings.append(Finding(
                kind="page_title", value=title,
                confidence=0.99, source_reliability="A", info_credibility=1,
                evidence=ev,
            ))
        gen = _extract_generator(body)
        if gen:
            findings.append(Finding(
                kind="tech_generator", value=gen,
                confidence=0.95, source_reliability="A", info_credibility=1,
                evidence=ev,
                notes="Valore di <meta name='generator'>.",
            ))
        cookies = _cookie_names(headers)
        for cname in cookies:
            findings.append(Finding(
                kind="cookie_name", value=cname,
                confidence=0.85, source_reliability="A", info_credibility=2,
                evidence=ev,
            ))
            tech = _COOKIE_MARKERS.get(cname)
            if tech:
                findings.append(Finding(
                    kind="tech_stack", value=tech,
                    confidence=0.75, source_reliability="B", info_credibility=2,
                    evidence=ev,
                    notes=f"Inferito dal cookie {cname}.",
                ))

        # CSP indica frontend framework / CDN
        csp = ""
        for k, v in headers.items():
            if k.lower() == "content-security-policy":
                csp = v
                break
        if csp:
            findings.append(Finding(
                kind="csp", value=csp[:300],
                confidence=0.85, source_reliability="A", info_credibility=2,
                evidence=ev,
                notes="Content-Security-Policy (truncato a 300 char).",
            ))

        return ConnectorResult(
            connector=self.spec.name, status="ok",
            findings=findings,
            raw={"url": url, "headers_count": len(headers),
                 "body_bytes": len(body)},
        )

    def health_check(self) -> bool:
        return True
