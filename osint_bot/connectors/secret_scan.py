"""Connector: secret scanning su contenuto web (sostituto nativo di
gitleaks/trufflehog/secretfinder).

Scarica il target (URL, oppure la home + file JS referenziati per un dominio) e
applica un catalogo di regex per chiavi/segreti (AWS, GCP, GitHub, Slack, Stripe,
API key generiche, JWT, chiavi private, token AI moderni). Passivo: solo GET.

Input: ``url`` | ``domain``.
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
    name="secret_scan",
    label="Secret scanning (web)",
    action_class=ACTION_PASSIVE,
    input_types=("url", "domain"),
    output_categories=("secrets",),
    required_key="",
    cache_ttl=1800,
    rate_limit=RateLimit(per_minute=10, per_day=1000, burst=2),
    legal_note="Scarica contenuto pubblico e cerca pattern di segreti. Solo GET, nessuna modifica.",
    health_check_url="",
)

# Catalogo regex segreti (nome, pattern, severità). Ampio ma mirato ai leak reali.
_SECRET_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("AWS Access Key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "critical"),
    ("AWS Secret Key", re.compile(r"(?i)aws_secret_access_key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})"), "critical"),
    ("GCP API Key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "high"),
    ("GitHub Token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "critical"),
    ("Slack Token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), "high"),
    ("Stripe Secret Key", re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b"), "critical"),
    ("Stripe Restricted Key", re.compile(r"\brk_live_[0-9a-zA-Z]{24,}\b"), "high"),
    ("Google OAuth", re.compile(r"\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b"), "medium"),
    ("Private Key Block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), "critical"),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "medium"),
    ("Slack Webhook", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+"), "high"),
    ("Twilio SID", re.compile(r"\bAC[a-f0-9]{32}\b"), "medium"),
    ("SendGrid Key", re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"), "high"),
    ("Anthropic API Key", re.compile(r"\bsk-ant-[A-Za-z0-9-]{20,}\b"), "critical"),
    ("OpenAI API Key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}\b"), "critical"),
    ("HuggingFace Token", re.compile(r"\bhf_[A-Za-z0-9]{34,}\b"), "high"),
    ("npm Token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), "high"),
    ("Generic API Key", re.compile(r"(?i)(?:api[_-]?key|apikey|secret|token)['\"]?\s*[:=]\s*['\"]([A-Za-z0-9_\-]{24,})['\"]"), "low"),
]

_JS_SRC_RE = re.compile(r"""<script[^>]+src=["']([^"']+\.js[^"']*)["']""", re.I)
_MAX_BYTES = 500_000
_MAX_JS = 6


def _to_url(target: str) -> str:
    t = target.strip()
    return t if t.startswith(("http://", "https://")) else f"https://{t}"


def _fetch(url: str, timeout: int) -> tuple[str, bytes]:
    from .._safe_http import SSRFBlocked, guard_ssrf
    try:
        guard_ssrf(url)
    except SSRFBlocked:
        return url, b""  # bloccato: ritorna vuoto senza fetchare
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (compatible; ArgoOSINT/1.0)"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return url, resp.read(_MAX_BYTES)
    except urllib.error.HTTPError as e:
        try:
            return url, e.read(_MAX_BYTES)
        except Exception:
            return url, b""
    except Exception:
        return url, b""


def _abs_url(base: str, src: str) -> str:
    if src.startswith(("http://", "https://")):
        return src
    if src.startswith("//"):
        return "https:" + src
    import urllib.parse
    return urllib.parse.urljoin(base, src)


def _redact(match: str) -> str:
    """Non esporre il segreto intero nel report: mostra i primi/ultimi char."""
    if len(match) <= 12:
        return match[:3] + "…"
    return match[:6] + "…" + match[-4:]


class SecretScanConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        target = (context.target or "").strip()
        if not target:
            return ConnectorResult(connector=self.spec.name, status="error", error="Target vuoto.")
        base = _to_url(target)

        # Scarica la pagina + un po' di JS referenziato (dove finiscono i leak).
        docs: list[tuple[str, bytes]] = []
        page_url, page = _fetch(base, context.timeout)
        docs.append((page_url, page))
        try:
            html = page.decode("utf-8", errors="replace")
            for m in _JS_SRC_RE.finditer(html):
                if len([d for d in docs if d[0] != page_url]) >= _MAX_JS:
                    break
                docs.append(_fetch(_abs_url(base, m.group(1)), context.timeout))
        except Exception:
            pass

        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        for src_url, content in docs:
            if not content:
                continue
            text = content.decode("utf-8", errors="replace")
            for name, pattern, severity in _SECRET_PATTERNS:
                for m in pattern.finditer(text):
                    raw = m.group(0)
                    key = (name, raw)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(Finding(
                        kind="secret_exposed",
                        value=f"{name}: {_redact(raw)}",
                        confidence=0.85 if severity in ("critical", "high") else 0.6,
                        source_reliability="A", info_credibility=2,
                        evidence=[Evidence(url=src_url, title=f"{name} in {src_url}")],
                        notes=(f"Pattern '{name}' trovato in {src_url}. "
                               f"Valore redatto. Verificare validità e revocare se reale."),
                        severity=severity,
                    ))
        return ConnectorResult(
            connector=self.spec.name, status="ok",
            findings=findings,
            raw={"documents_scanned": len(docs), "secrets": len(findings)},
        )

    def health_check(self) -> bool:
        return True
