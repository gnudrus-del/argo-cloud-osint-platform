"""Connector: socid-extractor — estrae ID/metadata da un URL di profilo social.

Data una URL di profilo (40+ piattaforme), socid-extractor analizza la risposta
pubblica ed estrae identificatori interni (user id numerici), username, nome
visualizzato, data creazione account, ecc. Utile per pivotare tra piattaforme
tramite l'ID interno stabile.

Libreria pura-Python importata nativamente (nessun subprocess). Se non installata
-> status="error" con istruzione. Passivo (un GET).

Input: ``url`` (profilo social). Es: https://www.instagram.com/<user>/
"""
from __future__ import annotations

import urllib.error

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
    name="socid_extractor",
    label="socid-extractor (URL → ID social)",
    action_class=ACTION_PASSIVE,
    input_types=("url",),
    output_categories=("social_ids",),
    required_key="",
    cache_ttl=3600,
    rate_limit=RateLimit(per_minute=20, per_day=2000, burst=3),
    legal_note="socid_extractor.legal_note",
    health_check_url="",
)

_MAX_BODY = 500_000
# Etichette leggibili per le chiavi più comuni restituite da socid-extractor.
_LABELS = {
    "uid": "user_id", "id": "user_id", "username": "username",
    "name": "display_name", "fullname": "display_name",
    "created_at": "account_created", "reg_date": "account_created",
    "bio": "bio", "email": "email", "phone": "phone",
    "is_verified": "verified", "follower_count": "followers",
}


def _fetch_html(url: str, timeout: int) -> str:
    from .. import _safe_http
    try:
        _, body, _ = _safe_http.open_url(
            url,
            headers={
                # UA mobile: molti scheme socid-extractor si basano sul markup mobile.
                "User-Agent": ("Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) "
                               "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1"),
                "Accept": "text/html,application/json",
            },
            timeout=timeout,
        )
        return body[:_MAX_BODY].decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        try:
            return e.read(_MAX_BODY).decode("utf-8", errors="replace")
        except Exception:
            return ""
    except Exception:
        # Includes _safe_http.SSRFBlocked (internal target) → empty.
        return ""


class SocidExtractorConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        try:
            import socid_extractor
        except ImportError:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=_t("socid_extractor.not_installed", context.lang))
        url = (context.target or "").strip()
        if not url.startswith(("http://", "https://")):
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=_t("socid_extractor.bad_target", context.lang))

        info: dict = {}
        # 1) API nativa parse(): applica mutate_url per-piattaforma (endpoint giusto).
        try:
            res = socid_extractor.parse(url, timeout=min(context.timeout, 10))
            page = res[0] if isinstance(res, tuple) else res
            if isinstance(page, dict):
                info = page
            elif page:
                info = socid_extractor.extract(page) or {}
        except Exception:
            info = {}
        # 2) Fallback: fetch manuale + extract (se parse non ha reso nulla).
        if not info:
            html = _fetch_html(url, context.timeout)
            if html:
                try:
                    info = socid_extractor.extract(html) or {}
                except Exception as exc:
                    return ConnectorResult(connector=self.spec.name, status="error",
                                           error=_t("socid_extractor.parse_failed", context.lang, error=exc))
        if not info:
            return ConnectorResult(connector=self.spec.name, status="ok", findings=[],
                                   raw={"note": _t("socid_extractor.no_ids", context.lang)})

        ev = [Evidence(url=url, title="profilo social")]
        findings: list[Finding] = []
        for key, value in info.items():
            if value in (None, "", []):
                continue
            kind = "socid_" + _LABELS.get(key, key)
            findings.append(Finding(
                kind=kind, value=str(value)[:300],
                confidence=0.85, source_reliability="A", info_credibility=2,
                evidence=ev,
                notes=_t("socid_extractor.field_extracted", context.lang, url=url, key=key),
                why_linked=[f"socid-extractor ha letto '{key}' dalla pagina del profilo"],
            ))
        return ConnectorResult(connector=self.spec.name, status="ok", findings=findings,
                               raw={"fields": list(info.keys()), "engine": "socid-extractor"})

    def health_check(self) -> bool:
        try:
            import socid_extractor  # noqa: F401
            return True
        except ImportError:
            return False
