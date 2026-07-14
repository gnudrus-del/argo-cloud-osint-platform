"""Connector: username-across-sites — motore nativo ad ALTA PRECISIONE.

Filosofia (dopo test reali che hanno mostrato falsi positivi su siti SPA):
  * un GET che torna 200 NON prova che il profilo esista: i siti SPA/JS
    (Instagram, Twitter/X, TikTok, Twitch, Pinterest, YouTube, ...) rispondono
    200 per qualsiasi username. Fidarsi del 200 = falsi positivi.
  * Qui teniamo SOLO i siti con detection deterministica:
      - status 404 reale sul profilo mancante, OPPURE
      - un marker testuale di assenza inequivocabile nel body.
  * I siti SPA/login sono DELEGATI al connettore ``maigret`` (programma completo,
    ~3166 siti con detection per-sito/API affidabile). Questo connettore è il
    motore *veloce e senza dipendenze* ad alta precisione (bassa copertura);
    ``maigret`` è il motore *ad alta copertura+precisione* (più lento).

Zero API key, in-process. Input: ``handle`` / ``username``. Passivo.
"""
from __future__ import annotations

import concurrent.futures as _cf
import urllib.error
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
    name="sherlock_lite",
    label="Username scan (fast/precise)",
    action_class=ACTION_PASSIVE,
    input_types=("handle", "username"),
    output_categories=("social_accounts",),
    required_key="",
    cache_ttl=3600,
    rate_limit=RateLimit(per_minute=15, per_day=800, burst=2),
    legal_note="sherlock_lite.legal_note",
    health_check_url="",
)

# Detection method:
#   "404"    -> profilo assente = HTTP 404/410 (200 = presente).  [deterministico]
#   "marker" -> risposta 200 sempre; ASSENTE se il body contiene il marker.
# Solo siti dove uno dei due è affidabile. I siti SPA/login sono esclusi apposta.
_SITES: list[tuple[str, str, str, str]] = [
    # name, url_template, method, marker(if method=="marker" else "")
    ("GitHub",     "https://github.com/{u}",                    "404",    ""),
    ("GitLab",     "https://gitlab.com/{u}",                    "404",    ""),
    ("Bitbucket",  "https://bitbucket.org/{u}/",                "404",    ""),
    ("DEV.to",     "https://dev.to/{u}",                        "404",    ""),
    ("Reddit",     "https://www.reddit.com/user/{u}/about.json","404",    ""),
    ("SoundCloud", "https://soundcloud.com/{u}",                "404",    ""),
    ("Kaggle",     "https://www.kaggle.com/{u}",                "404",    ""),
    ("Replit",     "https://replit.com/@{u}",                   "404",    ""),
    ("Keybase",    "https://keybase.io/{u}",                    "marker", "Sorry, we couldn't find"),
    ("HackerNews", "https://news.ycombinator.com/user?id={u}",  "marker", "No such user."),
    ("Steam",      "https://steamcommunity.com/id/{u}",         "marker", "The specified profile could not be found"),
    ("Blogger",    "https://{u}.blogspot.com/",                 "marker", "Blog has been removed"),
]

# Siti SPA/login noti, gestiti da maigret (documentati per trasparenza).
_DELEGATED_TO_MAIGRET = (
    "Instagram", "Twitter/X", "TikTok", "Facebook", "Twitch", "YouTube",
    "Pinterest", "Threads", "Snapchat", "Telegram", "Fiverr", "Medium",
)

_MAX_BODY = 200_000  # abbastanza per contenere il marker di assenza


def _probe(site: tuple[str, str, str, str], username: str, timeout: int) -> dict | None:
    name, tmpl, method, marker = site
    url = tmpl.replace("{u}", urllib.parse.quote(username, safe=""))
    try:
        status, raw, _ = _safe_http.open_url(
            url,
            headers={"Accept": "text/html,application/json"},
            timeout=timeout,
        )
        body = raw[:_MAX_BODY] if method == "marker" else b""
    except urllib.error.HTTPError as e:
        # 404/410 con method "404" = assente (esito affidabile).
        return {"site": name, "url": url, "status": e.code, "hit": False}
    except Exception:
        return {"site": name, "url": url, "status": 0, "hit": False, "error": True}

    if status not in (200, 201):
        return {"site": name, "url": url, "status": status, "hit": False}
    if method == "marker" and marker and marker.encode("utf-8") in body:
        return {"site": name, "url": url, "status": status, "hit": False, "note": "marker-assente"}
    # method "404" con 200 = presente; method "marker" con 200 e nessun marker = presente.
    return {"site": name, "url": url, "status": status, "hit": True, "method": method}


class SherlockLiteConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        username = (context.target or "").strip()
        if not username or "/" in username or " " in username:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=_t("sherlock_lite.invalid_username", context.lang))

        per_site_timeout = min(context.timeout, 6)
        results: list[dict] = []
        with _cf.ThreadPoolExecutor(max_workers=8) as ex:
            futures = [ex.submit(_probe, s, username, per_site_timeout) for s in _SITES]
            for f in _cf.as_completed(futures):
                try:
                    r = f.result()
                    if r:
                        results.append(r)
                except Exception:
                    pass

        hits = [r for r in results if r.get("hit")]
        findings: list[Finding] = []
        for r in hits:
            findings.append(Finding(
                kind="social_account", value=r["url"],
                confidence=0.9, source_reliability="A", info_credibility=1,
                evidence=[Evidence(url=r["url"], title=f"{r['site']} — {username}")],
                notes=_t("sherlock_lite.profile_found", context.lang, site=r["site"], method=r.get("method")),
                why_linked=[_t("sherlock_lite.why_linked", context.lang, username=username, site=r["site"])],
            ))
        return ConnectorResult(
            connector=self.spec.name, status="ok",
            findings=findings,
            raw={"probed": len(results), "hits": len(hits),
                 "reliable_sites": [s[0] for s in _SITES],
                 "spa_delegated_to_maigret": list(_DELEGATED_TO_MAIGRET)},
        )

    def health_check(self) -> bool:
        return True
