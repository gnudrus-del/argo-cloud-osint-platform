"""Connector: abuse.ch ThreatFox — reputation IOC (IP/domain/URL/hash).

ThreatFox (https://threatfox.abuse.ch) e' un feed community di IOC associati a
malware/botnet. L'API pubblica accetta POST JSON e cerca un IOC restituendo
malware family, confidence, tag, prima/ultima osservazione.

No API key richiesta per la ricerca base (search_ioc). Passivo.
Input: ``ip`` | ``domain`` | ``url`` | ``file_hash``.
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
from ..models import Evidence, Finding

_SPEC = ConnectorSpec(
    name="threatfox",
    label="ThreatFox (abuse.ch)",
    action_class=ACTION_PASSIVE,
    input_types=("ip", "domain", "url", "file_hash"),
    output_categories=("threat_intel", "reputation"),
    required_key="",
    cache_ttl=3600,
    rate_limit=RateLimit(per_minute=30, per_day=5000, burst=3),
    legal_note="Feed IOC community abuse.ch (CC0). Consultazione passiva di reputation nota.",
    health_check_url="https://threatfox-api.abuse.ch/api/v1/",
)

_ENDPOINT = "https://threatfox-api.abuse.ch/api/v1/"


def _search(ioc: str, timeout: int) -> dict | None:
    try:
        return _safe_http.post_json(
            _ENDPOINT,
            {"query": "search_ioc", "search_term": ioc},
            timeout=timeout,
        )
    except Exception:
        return None


class ThreatFoxConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        ioc = (context.target or "").strip()
        if not ioc:
            return ConnectorResult(connector=self.spec.name, status="error", error="Target vuoto.")

        data = _search(ioc, context.timeout)
        if data is None:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error="ThreatFox non raggiungibile.")

        status = data.get("query_status")
        if status == "no_result":
            return ConnectorResult(
                connector=self.spec.name, status="ok",
                findings=[Finding(
                    kind="reputation_clean", value=ioc,
                    confidence=0.6, source_reliability="B", info_credibility=2,
                    evidence=[Evidence(url="https://threatfox.abuse.ch/", title="ThreatFox")],
                    notes="Nessun IOC ThreatFox per questo target (non prova assenza di rischio).",
                )],
                raw={"query_status": status},
            )
        if status != "ok":
            return ConnectorResult(connector=self.spec.name, status="ok",
                                   findings=[], raw={"query_status": status})

        findings: list[Finding] = []
        for entry in (data.get("data") or [])[:20]:
            malware = entry.get("malware_printable") or entry.get("malware") or "unknown"
            conf = entry.get("confidence_level")
            conf_f = (float(conf) / 100.0) if isinstance(conf, (int, float)) else 0.7
            ioc_id = entry.get("id")
            findings.append(Finding(
                kind="threat_ioc",
                value=f"{malware}: {entry.get('ioc', ioc)}",
                confidence=max(0.5, conf_f),
                source_reliability="B", info_credibility=2,
                evidence=[Evidence(
                    url=f"https://threatfox.abuse.ch/ioc/{ioc_id}/" if ioc_id else "https://threatfox.abuse.ch/",
                    title=f"ThreatFox {malware}")],
                notes=(f"IOC malevolo associato a {malware}. "
                       f"Primo avvistamento: {entry.get('first_seen', '?')}. "
                       f"Tag: {', '.join(entry.get('tags') or []) or '—'}."),
                severity="high",
            ))
        return ConnectorResult(
            connector=self.spec.name, status="ok",
            findings=findings,
            raw={"query_status": status, "matches": len(findings)},
        )

    def health_check(self) -> bool:
        return True
