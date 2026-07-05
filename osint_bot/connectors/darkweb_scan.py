"""Connector: darkweb_scan — ricerca su indici clear-web di risorse .onion.

Sostituzione leggera e onesta di Prying Deep (archiviato, Go+Postgres, troppo
pesante per la nostra VM 1-vCPU). Interroga fonti pubbliche CLEAR-WEB che
indicizzano risorse dark-web (Ahmia), senza richiedere Tor. Restituisce link
.onion + snippet come findings **darkweb-gated**: il modulo si attiva solo se
il caso Argo ha lo scope autorizzato (HighRiskResearchMode).

Zero API key, zero Tor obbligatorio, zero DB extra. Passivo verso l'indice.
Input: ``keyword`` (o ``email``/``handle``/``domain`` usati come keyword).
"""
from __future__ import annotations

import re
import urllib.parse
import urllib.request

from ..connector import (
    ACTION_DARKWEB_GATED,
    BaseConnector,
    ConnectorContext,
    ConnectorResult,
    ConnectorSpec,
    RateLimit,
)
from ..models import Evidence, Finding

_SPEC = ConnectorSpec(
    name="darkweb_scan",
    label="Darkweb scan (Ahmia index)",
    action_class=ACTION_DARKWEB_GATED,
    input_types=("keyword", "email", "handle", "domain"),
    output_categories=("darkweb",),
    required_key="",
    cache_ttl=3600,
    rate_limit=RateLimit(per_minute=6, per_day=200, burst=1),
    legal_note="Interroga solo l'indice clear-web pubblico Ahmia. Nessun accesso diretto a Tor. Gated dal scope.",
    health_check_url="https://ahmia.fi/",
)

_TITLE_RE = re.compile(r'<h4>\s*<a[^>]+href="([^"]+)"[^>]*>([^<]+)</a>', re.I | re.S)
_ONION_RE = re.compile(r'([a-z2-7]{16,56}\.onion)', re.I)


def _search_ahmia(query: str, timeout: int) -> list[dict]:
    """Interroga l'indice clear-web Ahmia (search) per una keyword."""
    url = f"https://ahmia.fi/search/?q={urllib.parse.quote(query)}"
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (compatible; ArgoOSINT/1.0)",
        "Accept": "text/html",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            html = resp.read(500_000).decode("utf-8", errors="replace")
    except Exception:
        return []
    out: list[dict] = []
    seen: set[str] = set()
    for m in _TITLE_RE.finditer(html):
        href, title = m.group(1), m.group(2).strip()
        onion = _ONION_RE.search(href) or _ONION_RE.search(title)
        if not onion:
            continue
        addr = onion.group(1).lower()
        if addr in seen:
            continue
        seen.add(addr)
        out.append({"onion": addr, "title": title[:200], "index_url": href})
    return out[:30]


class DarkwebScanConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        # La gating dark-web è gestita a monte (RunProfile.allow_darkweb + RoE).
        # Qui NON tocchiamo Tor; interroghiamo l'indice pubblico clear-web.
        q = (context.target or "").strip()
        if not q or len(q) < 3:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error="Keyword troppo corta.")

        hits = _search_ahmia(q, context.timeout)
        findings: list[Finding] = []
        for h in hits:
            findings.append(Finding(
                kind="darkweb_reference",
                value=h["onion"],
                confidence=0.7, source_reliability="B", info_credibility=3,
                evidence=[Evidence(url=f"https://ahmia.fi/search/?q={urllib.parse.quote(q)}",
                                   title=h["title"] or "Ahmia hit")],
                notes=(f"Risorsa .onion indicizzata da Ahmia per '{q}'. "
                       f"Titolo: {h['title'] or '—'}. Verificare con OPSEC su Tor Browser."),
                severity="medium",
                why_linked=[f"Ahmia ha risposto con questo .onion per la query '{q}'"],
            ))
        return ConnectorResult(
            connector=self.spec.name, status="ok",
            findings=findings,
            raw={"query": q, "hits": len(findings), "index": "ahmia"},
        )

    def health_check(self) -> bool:
        try:
            urllib.request.urlopen("https://ahmia.fi/", timeout=4).close()
            return True
        except Exception:
            return False
