"""Connector: FlowSINT — graph-based OSINT investigation platform (Apache 2.0).

Bridge tra Argo e una istanza locale di FlowSINT (github.com/reconurge/flowsint).
Approccio pragmatico:

  * FlowSINT e' graph-first: gli enricher operano su nodi di uno "sketch"
    (grafo). NON sono chiamabili "one-shot" con solo target string, servono
    ``investigation_id`` + ``sketch_id`` + ``node_ids``. Orchestrare tutto
    questo da un connector Argo produrrebbe fragilita' che moltiplicherebbe
    il debito tecnico.
  * Questo connector fa quindi il minimo di valore reale:
      - **Health check** sull'API FlowSINT via env ``FLOWSINT_URL``.
      - **Auto-create investigation** per il target Argo, con nome/descrizione
        contestuali al caso.
      - Restituisce come Finding un **link cliccabile alla UI FlowSINT**
        pre-settata sull'investigation appena creata: l'analista clicca,
        salta nel grafo FlowSINT gia' preparato per il suo target.
      - Elenca gli enricher disponibili come output ``raw`` (per report).

Configurazione via env (nel .env sulla VM, non nel repo):
    FLOWSINT_URL             http://127.0.0.1:5001
    FLOWSINT_PUBLIC_URL      URL della UI (default: derivato da URL sostituendo
                             porta 5001 -> 5173). Usato per il link cliccabile.
    FLOWSINT_USER            email del service account
    FLOWSINT_PASSWORD        password del service account

Se una qualsiasi env manca, ``status="missing_key"`` e il job Argo prosegue senza.
"""
from __future__ import annotations

import json
import os
import urllib.parse
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
    name="flowsint",
    label="FlowSINT",
    action_class=ACTION_PASSIVE,
    input_types=("domain", "ip", "email", "phone", "handle", "crypto",
                 "company", "person"),
    output_categories=("graph_link", "external_platform"),
    required_key="",  # credentials in env, not in BYOK panel
    cache_ttl=300,
    rate_limit=RateLimit(per_minute=10, per_day=500, burst=2),
    legal_note=(
        "FlowSINT gira in locale (Docker). Nessun dato lascia la VM. La "
        "'investigation' creata rispetta il caso Argo di origine."
    ),
    health_check_url=os.getenv("FLOWSINT_URL", "http://127.0.0.1:5001") + "/health",
)


def _config() -> dict:
    return {
        "base_url":   os.getenv("FLOWSINT_URL", "").rstrip("/"),
        "public_url": os.getenv("FLOWSINT_PUBLIC_URL", "").rstrip("/"),
        "username":   os.getenv("FLOWSINT_USER", ""),
        "password":   os.getenv("FLOWSINT_PASSWORD", ""),
    }


def _derive_public_url(base_url: str) -> str:
    """Deriva l'URL della UI FlowSINT dall'URL API.

    Il pattern default del docker-compose FlowSINT e': API su 5001, UI su 5173.
    Se ``FLOWSINT_PUBLIC_URL`` e' settata la usa; senno' sostituisce ``:5001``
    con ``:5173``. Se anche questo fallisce, ritorna base_url invariato.
    """
    if not base_url:
        return ""
    return base_url.replace(":5001", ":5173")


def _get_token(base_url: str, username: str, password: str,
               timeout: int) -> str | None:
    """FastAPI Users: OAuth2 password flow su ``/api/auth/token``."""
    data = urllib.parse.urlencode({
        "username": username, "password": password,
    }).encode("ascii")
    req = urllib.request.Request(
        f"{base_url}/api/auth/token", data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded",
                 "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read().decode("utf-8", errors="replace"))
        return body.get("access_token")
    except Exception:
        return None


def _create_investigation(base_url: str, token: str,
                          name: str, description: str,
                          timeout: int) -> dict | None:
    body = json.dumps({"name": name[:200], "description": description[:1000]}).encode("utf-8")
    req = urllib.request.Request(
        f"{base_url}/api/investigations/create",
        data=body,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception:
        return None


def _list_enrichers(base_url: str, token: str, timeout: int) -> list[str]:
    req = urllib.request.Request(
        f"{base_url}/api/enrichers",
        headers={"Authorization": f"Bearer {token}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        lst = data if isinstance(data, list) else (data.get("enrichers") or [])
        return [x["name"] if isinstance(x, dict) else str(x) for x in lst]
    except Exception:
        return []


# Enricher rilevanti per ogni target_type Argo (per hint all'utente).
_RELEVANT_ENRICHERS: dict[str, tuple[str, ...]] = {
    "domain":  ("domain_to_subdomains", "domain_to_whois", "domain_to_ip",
                "domain_to_tls", "domain_to_history"),
    "ip":      ("ip_to_asn", "ip_to_ports", "ip_to_intelligence",
                "ip_to_infos", "ip_to_domain"),
    "email":   ("email_to_breaches", "email_to_gravatar",
                "email_to_intelligence", "email_to_domain",
                "email_to_username"),
    "phone":   ("phone_to_carrier", "phone_to_infos"),
    "handle":  ("username_to_socials_maigret", "username_to_socials_sherlock",
                "username_to_dehashed"),
    "crypto":  ("cryptowallet_to_transactions", "cryptowallet_to_nfts"),
    "company": ("org_to_domains", "org_to_asn", "org_to_infos",
                "individual_to_organization"),
    "person":  ("individual_to_domains", "individual_to_organization"),
}


class FlowSINTConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        cfg = _config()
        if not cfg["base_url"] or not cfg["username"] or not cfg["password"]:
            return ConnectorResult(
                connector=self.spec.name, status="missing_key",
                error=("FlowSINT non configurato. Setta FLOWSINT_URL, "
                       "FLOWSINT_USER, FLOWSINT_PASSWORD nel .env sulla VM."),
            )

        token = _get_token(cfg["base_url"], cfg["username"], cfg["password"],
                           context.timeout)
        if not token:
            return ConnectorResult(
                connector=self.spec.name, status="error",
                error="Autenticazione FlowSINT fallita.",
            )

        target = (context.target or "").strip()
        ttype = context.target_type or "unknown"
        case_ref = context.case_id or "senza caso"
        inv_name = f"[Argo] {target} ({ttype})"
        inv_desc = (
            f"Auto-created from Argo OSINT.\n"
            f"Target: {target}\nType: {ttype}\nCase: {case_ref}\n"
        )
        inv = _create_investigation(cfg["base_url"], token, inv_name, inv_desc,
                                    context.timeout)
        if not inv or not inv.get("id"):
            return ConnectorResult(
                connector=self.spec.name, status="error",
                error="Impossibile creare investigation su FlowSINT.",
            )

        inv_id = inv["id"]
        # Preferisco FLOWSINT_PUBLIC_URL se settata; senno' derivo dal base_url.
        public = cfg["public_url"] or _derive_public_url(cfg["base_url"])
        ui_url = f"{public}/investigations/{inv_id}"

        available = _list_enrichers(cfg["base_url"], token, context.timeout)
        relevant = [e for e in _RELEVANT_ENRICHERS.get(ttype, ()) if e in available]

        return ConnectorResult(
            connector=self.spec.name, status="ok",
            findings=[Finding(
                kind="flowsint_investigation",
                value=ui_url,
                confidence=0.9,
                source_reliability="B", info_credibility=2,
                evidence=[Evidence(url=ui_url,
                                   title=f"FlowSINT — {target}")],
                notes=(
                    "Investigation FlowSINT preconfigurata. Apri il link per "
                    "esplorare il grafo con enricher graph-based. "
                    f"Rilevanti per {ttype}: "
                    + ", ".join(relevant[:6]) if relevant
                    else "Nessun enricher specifico per questo target_type."
                ),
            )],
            raw={
                "investigation_id": inv_id,
                "ui_url": ui_url,
                "available_enrichers_total": len(available),
                "relevant_for_target_type": list(relevant),
            },
        )

    def health_check(self) -> bool:
        cfg = _config()
        if not cfg["base_url"]:
            return False
        try:
            urllib.request.urlopen(f"{cfg['base_url']}/health",
                                   timeout=3).close()
            return True
        except Exception:
            return False
