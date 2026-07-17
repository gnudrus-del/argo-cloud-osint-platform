"""Connector: Wikipedia search — contesto pubblico su aziende/persone,
SENZA API key.

Usa la REST API pubblica di Wikipedia (``/w/rest.php/v1/search/page``),
senza autenticazione, per trovare la voce enciclopedica piu' pertinente al
target e restituirne titolo, estratto ed URL. Utile come primo contesto
biografico/aziendale verificabile (Wikipedia stessa non e' una fonte
primaria, ma la voce e la sua cronologia edit sono un punto di partenza
citabile, spesso con riferimenti a fonti primarie in nota). Prova prima
Wikipedia in italiano, poi quella in inglese se la prima non trova nulla.

Input: ``company``, ``person``.
"""
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
from ..i18n import t as _t
from ..models import Evidence, Finding

_SPEC = ConnectorSpec(
    name="wikipedia_search",
    label="Wikipedia",
    action_class=ACTION_PASSIVE,
    input_types=("company", "person"),
    output_categories=("background_context",),
    required_key="",
    cache_ttl=86_400,
    rate_limit=RateLimit(per_minute=60, per_day=10_000, burst=5),
    legal_note="wikipedia_search.legal_note",
    health_check_url="https://it.wikipedia.org/w/rest.php/v1/search/page?q=test&limit=1",
)


def _search(lang: str, query: str, timeout: int) -> list[dict]:
    url = (
        f"https://{lang}.wikipedia.org/w/rest.php/v1/search/page"
        f"?q={urllib.parse.quote(query)}&limit=3"
    )
    try:
        data = _safe_http.get_json(url, timeout=timeout)
    except Exception:
        return []
    return list((data or {}).get("pages") or [])


class WikipediaSearchConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        query = (context.target or "").strip()
        if not query:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=_t("wikipedia_search.empty_target", context.lang))

        primary_lang = "it" if context.lang == "it" else "en"
        fallback_lang = "en" if primary_lang == "it" else "it"
        pages = _search(primary_lang, query, context.timeout)
        used_lang = primary_lang
        if not pages:
            pages = _search(fallback_lang, query, context.timeout)
            used_lang = fallback_lang
        if not pages:
            return ConnectorResult(
                connector=self.spec.name, status="ok", findings=[],
                raw={"note": _t("wikipedia_search.no_match", context.lang, query=query)},
            )

        findings: list[Finding] = []
        for page in pages[:3]:
            title = page.get("title") or ""
            key = page.get("key") or title.replace(" ", "_")
            excerpt = (page.get("excerpt") or "").replace("<span class=\"searchmatch\">", "").replace("</span>", "")
            url = f"https://{used_lang}.wikipedia.org/wiki/{key}"
            findings.append(Finding(
                kind="wikipedia_article", value=title,
                confidence=0.55, source_reliability="C", info_credibility=3,
                evidence=[Evidence(url=url, title=title, quote=excerpt[:280])],
                notes=_t("wikipedia_search.article_note", context.lang, lang=used_lang.upper()),
            ))

        return ConnectorResult(
            connector=self.spec.name, status="ok",
            findings=findings,
            raw={"lang": used_lang, "pages": [{"title": p.get("title"), "key": p.get("key")} for p in pages[:3]]},
        )

    def health_check(self) -> bool:
        try:
            _safe_http.get_bytes(self.spec.health_check_url, timeout=4)
            return True
        except Exception:
            return False
