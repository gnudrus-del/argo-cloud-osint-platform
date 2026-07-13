"""Connector: MISP — interroga un'istanza MISP per IOC correlati al target.

Bridge verso un MISP (self-hosted o condiviso). Cerca gli attributi che
matchano il target e restituisce gli eventi/attributi correlati come findings.

Configurazione via env (nel .env sulla VM, non nel repo):
    MISP_URL        base URL dell'istanza (es. https://misp.local)
    MISP_KEY        Automation key (Authorization header)
    MISP_VERIFY     "0" per disabilitare la verifica TLS (self-signed); default on.

Se URL o KEY mancano -> status="missing_key", il job prosegue senza.
Input: ``ip`` | ``domain`` | ``url`` | ``email`` | ``file_hash``.
"""
from __future__ import annotations

import json
import os

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
    name="misp",
    label="MISP (threat intel)",
    action_class=ACTION_PASSIVE,
    input_types=("ip", "domain", "url", "email", "file_hash", "handle"),
    output_categories=("threat_intel",),
    required_key="",  # credenziali via env, non nel BYOK panel
    cache_ttl=600,
    rate_limit=RateLimit(per_minute=30, per_day=5000, burst=3),
    legal_note="Interroga un MISP privato configurato dall'operatore. Nessun dato lascia il perimetro.",
    health_check_url="",
)


def _config() -> dict:
    return {
        "url": os.getenv("MISP_URL", "").rstrip("/"),
        "key": os.getenv("MISP_KEY", ""),
        "verify": os.getenv("MISP_VERIFY", "1") != "0",
    }


def _search_attributes(cfg: dict, value: str, timeout: int) -> dict | None:
    endpoint = f"{cfg['url']}/attributes/restSearch"
    body = json.dumps({"value": value, "limit": 50, "includeEventTags": True}).encode("utf-8")
    try:
        # MISP is an operator-configured, trusted, often-internal endpoint:
        # allow_private lets it reach a LAN instance, insecure_tls honours the
        # MISP_VERIFY=0 self-signed-cert option. The SSRF redirect guard still
        # blocks cloud-metadata hops.
        _, raw, _ = _safe_http.open_url(
            endpoint,
            data=body,
            headers={
                "Authorization": cfg["key"],
                "Content-Type": "application/json",
            },
            method="POST",
            timeout=timeout,
            allow_private=True,
            insecure_tls=not cfg["verify"],
        )
        return json.loads(raw.decode("utf-8", errors="replace"))
    except Exception:
        return None


class MISPConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        cfg = _config()
        if not cfg["url"] or not cfg["key"]:
            return ConnectorResult(
                connector=self.spec.name, status="missing_key",
                error="MISP non configurato. Setta MISP_URL e MISP_KEY nel .env sulla VM.",
            )
        value = (context.target or "").strip()
        if not value:
            return ConnectorResult(connector=self.spec.name, status="error", error="Target vuoto.")

        data = _search_attributes(cfg, value, context.timeout)
        if data is None:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error="MISP non raggiungibile o autenticazione fallita.")

        attributes = (((data.get("response") or {}).get("Attribute")) or [])
        findings: list[Finding] = []
        for attr in attributes[:50]:
            event_id = attr.get("event_id")
            category = attr.get("category") or "?"
            atype = attr.get("type") or "?"
            comment = attr.get("comment") or ""
            to_ids = attr.get("to_ids")
            findings.append(Finding(
                kind="misp_ioc",
                value=f"{atype}: {attr.get('value', value)}",
                confidence=0.85 if to_ids else 0.7,
                source_reliability="B", info_credibility=2,
                evidence=[Evidence(
                    url=f"{cfg['url']}/events/view/{event_id}" if event_id else cfg["url"],
                    title=f"MISP event {event_id}")],
                notes=(f"Attributo MISP [{category}]. {comment} "
                       f"{'(to_ids)' if to_ids else ''}").strip(),
                severity="medium" if to_ids else "low",
            ))

        if not findings:
            return ConnectorResult(
                connector=self.spec.name, status="ok",
                findings=[], raw={"note": "Nessun attributo MISP per il target."},
            )
        return ConnectorResult(
            connector=self.spec.name, status="ok",
            findings=findings, raw={"matches": len(findings)},
        )

    def health_check(self) -> bool:
        cfg = _config()
        return bool(cfg["url"] and cfg["key"])
