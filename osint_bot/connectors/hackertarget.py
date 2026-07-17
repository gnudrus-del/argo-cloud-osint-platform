"""Connector: HackerTarget reverse-IP lookup — altri domini sullo stesso IP,
SENZA API key.

L'endpoint gratuito ``reverseiplookup`` di hackertarget.com (rate-limitato
ma senza chiave per uso occasionale) risponde in testo semplice, una riga
per hostname: e' la tecnica classica di correlazione infrastrutturale
("cosa altro gira su questo indirizzo?") — spesso rivela sotto-domini,
ambienti di staging o altri progetti dello stesso operatore condivisi
sullo stesso host virtuale. Passivo: nessuna scansione del target, solo
un lookup contro un indice gia' costruito da HackerTarget.

Input: ``ip``.
"""
from __future__ import annotations

import ipaddress

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
    name="hackertarget",
    label="HackerTarget Reverse IP",
    action_class=ACTION_PASSIVE,
    input_types=("ip",),
    output_categories=("hosting_correlation",),
    required_key="",
    cache_ttl=3600,
    rate_limit=RateLimit(per_minute=20, per_day=500, burst=3),
    legal_note="hackertarget.legal_note",
    health_check_url="https://api.hackertarget.com/reverseiplookup/?q=8.8.8.8",
)

# Messaggi noti dell'API free-tier quando il rate limit giornaliero e'
# esaurito o l'IP e' invalido: non sono host validi, vanno riconosciuti e
# trattati come "nessun risultato", non come nomi a dominio.
_ERROR_MARKERS = ("error", "api count exceeded", "invalid ip")


class HackerTargetConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        ip = (context.target or "").strip()
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=_t("hackertarget.invalid_ip", context.lang))

        try:
            text = _safe_http.get_text(
                f"https://api.hackertarget.com/reverseiplookup/?q={ip}",
                timeout=context.timeout,
            )
        except Exception:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=_t("generic.no_response", context.lang, service="HackerTarget"))

        lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
        lowered_first = lines[0].lower() if lines else ""
        if not lines or any(marker in lowered_first for marker in _ERROR_MARKERS):
            return ConnectorResult(
                connector=self.spec.name, status="ok", findings=[],
                raw={"note": _t("hackertarget.no_hosts", context.lang, ip=ip)},
            )

        ev = [Evidence(url=f"https://api.hackertarget.com/reverseiplookup/?q={ip}",
                        title=f"Reverse IP {ip}")]
        findings = [
            Finding(
                kind="cohosted_domain", value=host,
                confidence=0.6, source_reliability="C", info_credibility=4,
                evidence=ev,
                notes=_t("hackertarget.cohosted_note", context.lang, ip=ip),
            )
            for host in lines[:100]
        ]
        return ConnectorResult(connector=self.spec.name, status="ok", findings=findings,
                               raw={"hosts": lines[:100]})

    def health_check(self) -> bool:
        try:
            _safe_http.get_bytes(self.spec.health_check_url, timeout=4)
            return True
        except Exception:
            return False
