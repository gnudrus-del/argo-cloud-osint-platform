"""Connector: Hudson Rock Cavalier — infostealer breach corpus (domain/email).

Hudson Rock (https://www.hudsonrock.com) aggrega log di malware infostealer
(RedLine, Lumma, StealC, Vidar, Raccoon, ...) sottratti a macchine infette e
espone un'API pubblica gratuita e non autenticata (Cavalier "osint-tools")
per interrogare quel corpus per dominio o email.

Nessuna credenziale in chiaro viene mai restituita dal tier gratuito: solo
conteggi aggregati (dipendenti/utenti/terze parti), famiglie di stealer
coinvolte e URL di esempio spesso parzialmente redatti con asterischi.

No API key richiesta. Passivo. Input: ``domain`` | ``email``.
"""
from __future__ import annotations

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
    name="hudsonrock",
    label="Hudson Rock Cavalier (infostealer breach corpus)",
    action_class=ACTION_PASSIVE,
    input_types=("domain", "email"),
    output_categories=("breach_intel",),
    required_key="",
    cache_ttl=3600,
    rate_limit=RateLimit(per_minute=10, per_day=500, burst=1),
    legal_note="hudsonrock.legal_note",
    health_check_url="https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain=example.com",
)

_DOMAIN_ENDPOINT = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain"
_EMAIL_ENDPOINT = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email"


def _is_email(target: str) -> bool:
    return "@" in target


def _stealer_families(data: dict) -> str:
    families = ((data.get("data") or {}).get("stealer_families") or [])
    names = [f.get("_key") for f in families if isinstance(f, dict) and f.get("_key")]
    return ", ".join(names) if names else "—"


def _sample_urls(data: dict, key: str, limit: int = 5) -> str:
    entries = ((data.get("data") or {}).get(key) or [])[:limit]
    urls = [e.get("url", "?") for e in entries if isinstance(e, dict)]
    return "; ".join(urls) if urls else "—"


class HudsonRockConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        target = (context.target or "").strip()
        if not target:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=_t("hudsonrock.empty_target", context.lang))

        is_email = context.target_type == "email" or (context.target_type != "domain" and _is_email(target))

        if is_email:
            return self._fetch_email(context, target)
        return self._fetch_domain(context, target)

    def _fetch_domain(self, context: ConnectorContext, domain: str) -> ConnectorResult:
        url = f"{_DOMAIN_ENDPOINT}?domain={domain}"
        try:
            data = _safe_http.get_json(url, timeout=context.timeout)
        except Exception as exc:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=_t("generic.error", context.lang,
                                            service="Hudson Rock", error=str(exc)))

        data = data or {}
        total = data.get("total") or 0
        employees = data.get("employees") or 0
        users = data.get("users") or 0
        third_parties = data.get("third_parties") or 0

        if not total:
            return ConnectorResult(
                connector=self.spec.name, status="ok",
                findings=[Finding(
                    kind="breach_corpus_domain_none",
                    value=domain,
                    confidence=0.5, source_reliability="B", info_credibility=3,
                    evidence=[Evidence(url="https://cavalier.hudsonrock.com/", title="Hudson Rock Cavalier")],
                    notes=_t("hudsonrock.no_corpus_hits", context.lang),
                    severity="info",
                )],
                raw={"total": total},
            )

        families = _stealer_families(data)
        sample_urls = _sample_urls(data, "employees_urls")
        notes = _t(
            "hudsonrock.domain_summary", context.lang,
            employees=employees, users=users, third_parties=third_parties,
            families=families, sample_urls=sample_urls,
        )
        evidence = [Evidence(url="https://cavalier.hudsonrock.com/", title="Hudson Rock Cavalier")]

        if employees >= 10:
            kind, severity, confidence = "breach_corpus_domain_critical", "critical", 0.9
        elif employees >= 1:
            kind, severity, confidence = "breach_corpus_domain_high", "high", 0.8
        elif users >= 1:
            kind, severity, confidence = "breach_corpus_domain_medium", "medium", 0.65
        else:
            # total > 0 ma employees == users == 0 (solo third_parties):
            # segnale debole, non nella tabella di severity esplicita.
            kind, severity, confidence = "breach_corpus_domain_low", "low", 0.5

        findings = [Finding(
            kind=kind, value=domain,
            confidence=confidence, source_reliability="B", info_credibility=2,
            evidence=evidence, notes=notes, severity=severity,
        )]
        return ConnectorResult(
            connector=self.spec.name, status="ok",
            findings=findings,
            raw={"total": total, "employees": employees, "users": users,
                 "third_parties": third_parties},
        )

    def _fetch_email(self, context: ConnectorContext, email: str) -> ConnectorResult:
        url = f"{_EMAIL_ENDPOINT}?email={email}"
        try:
            data = _safe_http.get_json(url, timeout=context.timeout)
        except Exception as exc:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=_t("generic.error", context.lang,
                                            service="Hudson Rock", error=str(exc)))

        data = data or {}
        stealers = data.get("stealers")
        # L'API by-email risponde con un messaggio esplicito ("this email
        # ... is not associated...") quando non trova nulla; consideriamo
        # "found" solo se c'e' un contenuto positivo in "stealers".
        found = bool(stealers)

        if not found:
            return ConnectorResult(
                connector=self.spec.name, status="ok",
                findings=[Finding(
                    kind="breach_corpus_email_none",
                    value=email,
                    confidence=0.5, source_reliability="B", info_credibility=3,
                    evidence=[Evidence(url="https://cavalier.hudsonrock.com/", title="Hudson Rock Cavalier")],
                    notes=_t("hudsonrock.no_corpus_hits", context.lang),
                    severity="info",
                )],
                raw={"found": False},
            )

        families = ", ".join(stealers) if isinstance(stealers, list) else str(stealers)
        findings = [Finding(
            kind="breach_corpus_email_found",
            value=email,
            confidence=0.85, source_reliability="B", info_credibility=2,
            evidence=[Evidence(url="https://cavalier.hudsonrock.com/", title="Hudson Rock Cavalier")],
            notes=_t("hudsonrock.email_summary", context.lang, families=families),
            severity="high",
        )]
        return ConnectorResult(
            connector=self.spec.name, status="ok",
            findings=findings,
            raw={"found": True, "stealers": stealers},
        )

    def health_check(self) -> bool:
        return True
