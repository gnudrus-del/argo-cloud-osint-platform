from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import logging
import mimetypes
import os
import re
import secrets
import time
import uuid

LOG = logging.getLogger("osint_bot.web")
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

from . import provider_health
from .celery_queue import create_job_queue
from .cli import run_investigation
from .connector import ConnectorContext
from .connectors import build_default_registry
from .contact_discovery import discover_contacts
from .defensive import (
    TakedownCase,
    assess_brand_impersonation,
    enrich_ioc,
    monitor_surface,
    score_digital_footprint,
)
from .email_verification import (
    EmailSendError,
    generate_token,
    send_verification_email,
    verify_token,
)
from .external_recon import run_recon_pipeline
from .external_tools import TOOL_SPECS, all_tools_health, tool_health_status
from .forensic_report import (
    CaseContext as _ForensicCase,
)
from .forensic_report import (
    ProviderUsage,
    build_forensic_report,
)
from .forensic_report import (
    ReportContext as _ForensicContext,
)
from .forensic_report import (
    to_json as forensic_to_json,
)
from .forensic_report import (
    to_markdown as forensic_to_markdown,
)
from .google_auth import (
    GoogleTokenError,
    google_client_id,
    google_login_enabled,
    username_from_email,
    verify_google_id_token,
)
from .high_risk import audit_event_payload as high_risk_audit
from .high_risk import detect_high_risk
from .job_queue import JobSpec
from .link_analysis import export_d3_json, resolve_entities
from .media import analyze_media_file
from .orchestrator import ALWAYS_ON_AGENTS, RunProfile, plan_from_command
from .pdf_report import write_pdf_from_markdown
from .ranking import rank_results
from .redteam_report import (
    RedTeamContext as _RedTeamContext,
)
from .redteam_report import (
    build_redteam_report as _build_redteam_report,
)
from .safety import redact_email, redact_phone
from .scope import CaseScope
from .scope import parse_entry as parse_scope_entry
from .storage import Storage
from .stores import InMemoryRateLimiter, InMemorySessionStore, RateLimiter, SessionStore
from .target_classifier import classify_target

ROOT = Path(__file__).resolve().parent
STATIC_ROOT = ROOT / "web_static"
JOB_ROOT = Path(os.getenv("OSINT_JOB_DIR", "web_jobs"))
UPLOAD_ROOT = JOB_ROOT / "uploads"
USER_STORE = JOB_ROOT / "users.json"  # kept for one-shot migration only
TOKEN = os.getenv("OSINT_WEB_TOKEN", "")
SIGNUPS_ENABLED = os.getenv("OSINT_SIGNUPS_ENABLED", "1") == "1"
SESSION_TTL_SECONDS = int(os.getenv("OSINT_SESSION_TTL_SECONDS", "28800"))
MAX_JSON_BYTES = int(os.getenv("OSINT_MAX_JSON_BYTES", "65536"))
MAX_UPLOAD_BYTES = int(os.getenv("OSINT_MAX_UPLOAD_BYTES", "26214400"))
SECURE_COOKIE = os.getenv("OSINT_SECURE_COOKIE", "0") == "1"
SESSION_STORE: SessionStore = InMemorySessionStore()
RATE_LIMITER: RateLimiter = InMemoryRateLimiter()
# Backend di coda scelto dall'env QUEUE_BACKEND (celery -> Redis, altrimenti
# in-process). Duck-type compatibile: register_dispatcher/submit_spec/pending_count.
JOB_QUEUE = create_job_queue()
STORAGE: Storage | None = None
_STORAGE_LOCK = __import__("threading").Lock()
CONNECTOR_REGISTRY = build_default_registry()


# Services for which the UI surfaces a per-user API key field. The order here
# drives the layout of the "Chiavi API" tab. service.env_var is the fallback
# read from process env when the user has not configured a per-user key.
API_KEY_CATALOG: list[dict] = [
    {"service": "shodan",     "label": "Shodan",      "env_var": "SHODAN_API_KEY",      "doc": "https://account.shodan.io/", "category": "Network OSINT"},
    {"service": "censys_id",  "label": "Censys ID",   "env_var": "CENSYS_API_ID",       "doc": "https://search.censys.io/account/api", "category": "Network OSINT"},
    {"service": "censys_sec", "label": "Censys Secret","env_var": "CENSYS_API_SECRET",   "doc": "https://search.censys.io/account/api", "category": "Network OSINT"},
    {"service": "hibp",       "label": "HaveIBeenPwned","env_var": "HIBP_API_KEY",       "doc": "https://haveibeenpwned.com/API/Key", "category": "Breach intel"},
    {"service": "hunter",     "label": "Hunter.io",   "env_var": "HUNTER_API_KEY",      "doc": "https://hunter.io/api_keys", "category": "Email recon"},
    {"service": "intelx",     "label": "Intelligence X","env_var": "INTELX_API_KEY",     "doc": "https://intelx.io/account?tab=developer", "category": "Breach intel"},
    {"service": "epieos",     "label": "Epieos",      "env_var": "EPIEOS_API_KEY",      "doc": "https://epieos.com/", "category": "Reverse account"},
    {"service": "bing",       "label": "Bing Search", "env_var": "BING_SEARCH_API_KEY", "doc": "https://portal.azure.com/", "category": "Search providers"},
    {"service": "brave",      "label": "Brave Search","env_var": "BRAVE_SEARCH_API_KEY","doc": "https://api.search.brave.com/", "category": "Search providers"},
    {"service": "serper",     "label": "Serper",      "env_var": "SERPER_API_KEY",      "doc": "https://serper.dev/", "category": "Search providers"},
    {"service": "abuseipdb",  "label": "AbuseIPDB",   "env_var": "ABUSEIPDB_API_KEY",   "doc": "https://www.abuseipdb.com/api", "category": "Network OSINT"},
    {"service": "virustotal", "label": "VirusTotal",  "env_var": "VIRUSTOTAL_API_KEY",  "doc": "https://www.virustotal.com/", "category": "Threat intel"},
    {"service": "github",     "label": "GitHub Token","env_var": "GITHUB_TOKEN",        "doc": "https://github.com/settings/tokens", "category": "Code recon"},
    {"service": "leakix",     "label": "LeakIX",      "env_var": "LEAKIX_API_KEY",      "doc": "https://leakix.net/auth/api", "category": "Leak intel"},
    {"service": "fullhunt",   "label": "FullHunt",    "env_var": "FULLHUNT_API_KEY",    "doc": "https://fullhunt.io/", "category": "Network OSINT"},
    # Phase 8 connectors (BYOK)
    {"service": "securitytrails", "label": "SecurityTrails", "env_var": "SECURITYTRAILS_API_KEY", "doc": "https://securitytrails.com/corp/api", "category": "Network OSINT"},
    {"service": "greynoise",  "label": "GreyNoise",   "env_var": "GREYNOISE_API_KEY",   "doc": "https://viz.greynoise.io/account/api-key", "category": "Threat intel"},
    {"service": "otx",        "label": "AlienVault OTX","env_var": "OTX_API_KEY",        "doc": "https://otx.alienvault.com/api", "category": "Threat intel"},
    {"service": "etherscan",  "label": "Etherscan",   "env_var": "ETHERSCAN_API_KEY",   "doc": "https://etherscan.io/apis", "category": "Blockchain"},
    {"service": "companies_house","label": "Companies House (UK)","env_var": "COMPANIES_HOUSE_API_KEY","doc": "https://developer.company-information.service.gov.uk/", "category": "Corporate registry"},
    {"service": "google_pse", "label": "Google PSE (key|cx)","env_var": "GOOGLE_PSE_API_KEY", "doc": "https://programmablesearchengine.google.com/", "category": "Search providers"},
    {"service": "influencers_club","label": "Influencers Club","env_var": "INFLUENCERS_CLUB_API_KEY","doc": "https://influencers.club/", "category": "Reverse account"},
    # Phase 25
    {"service": "contactout",  "label": "ContactOut", "env_var": "CONTACTOUT_API_KEY", "doc": "https://api.contactout.com/", "category": "Reverse account"},
    {"service": "lusha",       "label": "Lusha",       "env_var": "LUSHA_API_KEY",      "doc": "https://docs.lusha.com/", "category": "Reverse account"},
]

# Agenti IA (LLM) opt-in — vedi osint_bot/llm_client.py. Esclusi da
# API_KEY_CATALOG (quindi invisibili in "Chiavi API" e ogni /api/ai/* risponde
# 404) finché OSINT_AI_AGENTS_ENABLED non è impostata a "1": è il kill-switch
# a livello di deployment, indipendente dal flag ai_enrichment_enabled per
# singolo caso. Nessun dato lascia il perimetro finché entrambi non sono attivi.
AI_KEY_CATALOG: list[dict] = [
    {"service": "llm_anthropic", "label": "Anthropic Claude (agente IA)", "env_var": "ANTHROPIC_API_KEY", "doc": "https://console.anthropic.com/settings/keys", "category": "Agente IA (LLM, opt-in)"},
    {"service": "llm_openai",    "label": "OpenAI (agente IA)",           "env_var": "OPENAI_API_KEY",    "doc": "https://platform.openai.com/api-keys", "category": "Agente IA (LLM, opt-in)"},
    {"service": "llm_local",     "label": "Endpoint locale (Ollama/llama.cpp)", "env_var": "LOCAL_LLM_BASE_URL", "doc": "https://github.com/ollama/ollama/blob/main/docs/openai.md", "category": "Agente IA (LLM, opt-in)"},
]


def ai_agents_enabled() -> bool:
    """Kill-switch di deployment. Default OFF: nessun dato esce verso un LLM
    a meno che l'operatore non lo abiliti esplicitamente sulla VM."""
    return os.getenv("OSINT_AI_AGENTS_ENABLED", "0").strip() == "1"


def tsa_configured() -> str:
    """URL della TSA RFC3161 configurata dall'operatore, o '' se il timestamp
    esterno è disattivato. Nessun default hardcoded nel codice — stessa
    filosofia BYO di ogni altra integrazione di terze parti (MISP_URL,
    FLOWSINT_URL, ...); solo suggerimenti in docs/CONFIGURATION.md. La firma
    Ed25519 locale (report_signing.py) non ha bisogno di questo gate: è
    calcolo puramente locale, zero rete in uscita."""
    return os.getenv("TSA_URL", "").strip()


def api_key_catalog_for(actor: str = "") -> list[dict]:
    """API_KEY_CATALOG + AI_KEY_CATALOG quando il kill-switch è ON.

    Punto singolo da cui /api/keys, /api/keys/test e la UI leggono il
    catalogo effettivo — così 'disattivato di default' è garantito in un
    solo posto invece che replicato in ogni handler."""
    if ai_agents_enabled():
        return API_KEY_CATALOG + AI_KEY_CATALOG
    return API_KEY_CATALOG


def _resolve_actor_keys(actor: str) -> dict[str, str]:
    """Snapshot the per-actor key set into a flat dict for SearchConfig/agents."""
    if not actor:
        return {}
    keys: dict[str, str] = {}
    for entry in API_KEY_CATALOG:
        value = resolve_api_key(entry["service"], actor)
        if value:
            keys[entry["service"]] = value
    return keys


def resolve_api_key(service: str, actor: str = "") -> str:
    """Look up an API key for a service. Order: user key → env var.

    Returns '' when neither source has a key. Caller is responsible for
    gracefully degrading (most plugins already skip when the key is empty).
    """
    if actor:
        key = get_storage().get_api_key(actor, service)
        if key:
            return key
    for entry in API_KEY_CATALOG + AI_KEY_CATALOG:
        if entry["service"] == service:
            return os.getenv(entry["env_var"], "") or ""
    return ""


def get_storage() -> Storage:
    """Lazy singleton dello storage.

    Backend scelto dal factory ``create_storage`` in base a ``DATABASE_URL``:
    Postgres se ``postgres://...`` e psycopg è installato, altrimenti SQLite in
    ``JOB_ROOT/gufo.sqlite3`` (default). La migrazione dei legacy file gira solo
    sul backend SQLite (ha ``migrate_from_files``). Tests can reset STORAGE to
    None or assign a backend pointing at a tmp directory.
    """
    global STORAGE
    with _STORAGE_LOCK:
        if STORAGE is None:
            JOB_ROOT.mkdir(parents=True, exist_ok=True)
            from .storage_base import create_storage
            STORAGE = create_storage(JOB_ROOT)
            if hasattr(STORAGE, "migrate_from_files"):
                try:
                    STORAGE.migrate_from_files(JOB_ROOT)
                except Exception:
                    # Migration is best-effort; failures here must not block boot.
                    pass
        return STORAGE


def sign_roe(case_id: str, payload: dict, actor: str) -> dict:
    """Sign or replace the RoE for *case_id*. Owner-only for now (RBAC later)."""
    case = read_case(case_id, requester=actor)
    if case["owner"] != actor:
        raise WebError(HTTPStatus.FORBIDDEN, "Solo l'owner del caso può firmare la RoE.")
    allowed_classes = list(payload.get("allowed_classes") or [])
    invalid = [c for c in allowed_classes if c not in {"passive", "active-gated", "pii-gated", "darkweb-gated"}]
    if invalid:
        raise WebError(HTTPStatus.BAD_REQUEST, f"Classe non valida: {', '.join(invalid)}")
    scope = payload.get("scope") or {}
    if not isinstance(scope, dict):
        raise WebError(HTTPStatus.BAD_REQUEST, "Lo scope deve essere un oggetto.")
    roe = {
        "id": uuid.uuid4().hex,
        "case_id": case_id,
        "signed_by": actor,
        "mandate_reference": str(payload.get("mandate_reference") or "").strip()[:200],
        "scope": scope,
        "valid_from": payload.get("valid_from") or None,
        "valid_to": payload.get("valid_to") or None,
        "allowed_classes": allowed_classes,
        "requires_second_signature": bool(payload.get("requires_second_signature")),
        "notes": str(payload.get("notes") or "").strip()[:2000],
    }
    store = get_storage()
    # Revoke any previous active RoE so we always have exactly one in force.
    prev = store.get_active_roe(case_id)
    if prev:
        store.revoke_roe(prev["id"])
        store.append_audit_event(actor, "roe_revoked", {"case_id": case_id, "roe_id": prev["id"]})
    store.put_roe(roe)
    store.append_audit_event(
        actor, "roe_signed",
        {"case_id": case_id, "roe_id": roe["id"],
         "mandate_reference": roe["mandate_reference"],
         "allowed_classes": allowed_classes,
         "requires_second_signature": roe["requires_second_signature"]},
    )
    return roe


def list_cases_for(actor: str) -> list[dict]:
    if not actor:
        return []
    return get_storage().list_cases(owner=actor)


def read_case(case_id: str, requester: str = "") -> dict:
    if not re.fullmatch(r"[a-f0-9]{32}", case_id):
        raise WebError(HTTPStatus.BAD_REQUEST, "Case id non valido.")
    case = get_storage().get_case(case_id)
    if case is None:
        raise WebError(HTTPStatus.NOT_FOUND, "Caso non trovato.")
    if requester:
        if case["owner"] != requester and requester not in (case.get("collaborators") or []):
            # 404 (not 403) to avoid existence leak — same policy as read_job.
            raise WebError(HTTPStatus.NOT_FOUND, "Caso non trovato.")
    return case


def create_case(payload: dict, actor: str = "system") -> dict:
    title = str(payload.get("title") or "").strip()
    if not title:
        raise WebError(HTTPStatus.BAD_REQUEST, "Il titolo del caso è obbligatorio.")
    legal_basis = payload.get("legal_basis") or {}
    if not isinstance(legal_basis, dict):
        raise WebError(HTTPStatus.BAD_REQUEST, "Base giuridica non valida.")
    # Validate scope entries (round 6: hardening — refuse invalid input).
    raw_targets = payload.get("allowed_targets") or []
    if not isinstance(raw_targets, list):
        raise WebError(HTTPStatus.BAD_REQUEST,
                       "Campo 'allowed_targets' deve essere una lista di stringhe.")
    sanitized_targets: list[str] = []
    invalid: list[str] = []
    for t in raw_targets:
        t = str(t).strip()
        if not t:
            continue
        if parse_scope_entry(t) is None:
            invalid.append(t)
            continue
        sanitized_targets.append(t)
    if invalid:
        raise WebError(HTTPStatus.BAD_REQUEST,
                       f"Voci scope non valide: {', '.join(invalid[:5])}. "
                       "Formati ammessi: dominio, *.dominio, IP, CIDR, URL, @handle.")

    case = {
        "id": uuid.uuid4().hex,
        "owner": actor or "anonymous",
        "tenant_id": payload.get("tenant_id") or actor or "anonymous",
        "title": title[:200],
        "status": "open",
        "legal_basis": legal_basis,
        "purpose": str(payload.get("purpose") or "").strip()[:500],
        "retention_until": payload.get("retention_until") or None,
        "collaborators": list(payload.get("collaborators") or []),
        "notes": str(payload.get("notes") or "").strip()[:2000],
        "allowed_targets": sanitized_targets,
    }
    store = get_storage()
    store.put_case(case)
    store.append_audit_event(
        actor,
        "case_created",
        {"case_id": case["id"], "title": case["title"],
         "has_legal_basis": bool(legal_basis),
         "scope_entries": len(sanitized_targets)},
    )
    return case


def update_case_scope(case_id: str, payload: dict, actor: str) -> dict:
    """Aggiorna l'allowlist (scope) di un caso esistente."""
    store = get_storage()
    case = store.get_case(case_id)
    if not case:
        raise WebError(HTTPStatus.NOT_FOUND, "Caso non trovato.")
    if case.get("owner") != actor and actor not in (case.get("collaborators") or []):
        raise WebError(HTTPStatus.FORBIDDEN, "Non autorizzato a modificare questo caso.")
    raw_targets = payload.get("allowed_targets") or []
    if not isinstance(raw_targets, list):
        raise WebError(HTTPStatus.BAD_REQUEST,
                       "Campo 'allowed_targets' deve essere una lista di stringhe.")
    sanitized: list[str] = []
    invalid: list[str] = []
    for t in raw_targets:
        t = str(t).strip()
        if not t:
            continue
        if parse_scope_entry(t) is None:
            invalid.append(t)
            continue
        sanitized.append(t)
    if invalid:
        raise WebError(HTTPStatus.BAD_REQUEST,
                       f"Voci scope non valide: {', '.join(invalid[:5])}.")
    previous_n = len(case.get("allowed_targets") or [])
    case["allowed_targets"] = sanitized
    store.put_case(case)
    store.append_audit_event(actor, "case_scope_updated", {
        "case_id": case_id,
        "previous_entries": previous_n,
        "new_entries": len(sanitized),
    })
    return case


def ensure_default_case(actor: str) -> str:
    """Return the case id of the actor's default case, lazily creating one.

    Also auto-signs a permissive RoE so existing flows (CLI smoke runs,
    onboarding) keep working until the user formalises a real case+RoE.
    """
    if not actor:
        actor = "anonymous"
    store = get_storage()
    for case in store.list_cases(owner=actor, limit=200):
        if case["title"] == "Caso default" and case["owner"] == actor:
            return case["id"]
    case = {
        "id": uuid.uuid4().hex,
        "owner": actor,
        "tenant_id": actor,
        "title": "Caso default",
        "status": "open",
        "legal_basis": {"type": "unspecified", "reference": "auto-created"},
        "purpose": "Caso creato automaticamente per i job senza case_id esplicito. Specifica un caso vero quando l'indagine è formalizzata.",
        "collaborators": [],
    }
    store.put_case(case)
    store.append_audit_event(actor, "case_default_created", {"case_id": case["id"]})
    _auto_sign_permissive_roe(case["id"], actor, store)
    return case["id"]


def _auto_sign_permissive_roe(case_id: str, actor: str, store) -> None:
    """Sign a permissive RoE for legacy / default cases (Pillar 0.2 back-compat).

    Permissive means: every action class is allowed, no time window, scope is
    "*" (wildcard) honoured by safety._is_in_scope via the special "any" flag.
    The audit log records this as 'roe_signed_auto' so the trail is honest.
    """
    roe = {
        "id": uuid.uuid4().hex,
        "case_id": case_id,
        "signed_by": actor,
        "mandate_reference": "auto-permissive",
        "scope": {"any": True},
        "valid_from": None,
        "valid_to": None,
        "allowed_classes": ["passive", "active-gated", "pii-gated", "darkweb-gated"],
        "requires_second_signature": False,
        "notes": "RoE permissiva creata automaticamente per back-compat. Sostituiscila con una RoE firmata su un caso reale.",
    }
    store.put_roe(roe)
    store.append_audit_event(actor, "roe_signed_auto", {"case_id": case_id, "roe_id": roe["id"]})


def recover_legacy_jobs_into_cases() -> int:
    """For each owner with jobs missing case_id, link them to a 'Caso legacy'.

    Called once at boot after Storage init. Idempotent: rerunning is a no-op
    because the second pass finds no orphan jobs.
    """
    store = get_storage()
    orphans = store.list_jobs_without_case()
    if not orphans:
        return 0
    by_owner: dict[str, list[dict]] = {}
    for job in orphans:
        by_owner.setdefault(job.get("owner", "anonymous"), []).append(job)

    migrated = 0
    for owner, jobs in by_owner.items():
        legacy_case = {
            "id": uuid.uuid4().hex,
            "owner": owner,
            "tenant_id": owner,
            "title": "Caso legacy",
            "status": "archived",
            "legal_basis": {"type": "unspecified", "reference": "pre-0.1 jobs"},
            "purpose": "Caso creato automaticamente durante la migrazione a Pillar 0.1 per i job che non avevano un caso.",
            "collaborators": [],
        }
        store.put_case(legacy_case)
        _auto_sign_permissive_roe(legacy_case["id"], owner, store)
        for job in jobs:
            store.set_job_case(job["id"], legacy_case["id"])
            migrated += 1
        store.append_audit_event(
            owner,
            "case_legacy_migration",
            {"case_id": legacy_case["id"], "job_count": len(jobs)},
        )
    return migrated


def recover_queued_jobs() -> int:
    """Re-enqueue any DB job left in 'queued' or 'running' after a crash.

    Called at server startup. A job in 'running' state when we boot means the
    previous process died mid-execution; the cleanest recovery is to retry
    it. Returns the count for logging.
    """
    store = get_storage()
    recovered = 0
    for status in ("queued", "running"):
        for job in store.list_jobs(limit=1000):
            if job.get("status") != status:
                continue
            spec = JobSpec(
                job_id=job["id"],
                profile=job.get("profile") or {},
                payload=job.get("settings") or {},
                actor=job.get("owner", "system"),
            )
            if status == "running":
                # Mark as queued again so the UI doesn't show stuck-running.
                job["status"] = "queued"
                job.setdefault("progress", []).append(
                    {"at": now_iso(), "stage": "recovered", "message": "Ripresa dopo riavvio server."}
                )
                store.put_job(job["id"], job)
                store.append_audit_event("system", "job_recovered", {"job_id": job["id"]})
            try:
                JOB_QUEUE.submit_spec(spec)
                recovered += 1
            except RuntimeError:
                # Dispatcher not registered yet; should not happen because
                # dispatch_job_spec is wired at module import.
                pass
    return recovered


class WebError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


class OsintHandler(BaseHTTPRequestHandler):
    server_version = "OSINTBot/0.2"

    def do_GET(self) -> None:
        try:
            path = urlparse(self.path).path
            if path == "/api/auth/status":
                return self.send_json(auth_status(self))
            if path == "/api/auth/verify":
                qs = urlparse(self.path).query
                params = dict(p.split("=", 1) for p in qs.split("&") if "=" in p)
                token = unquote(params.get("token", ""))
                return self.handle_verify_email(token)
            if path == "/api/health":
                self.require_auth()
                return self.send_json({"status": "ok", "time": now_iso()})
            if path == "/api/capabilities":
                self.require_auth()
                sess = current_session(self)
                unlocked = bool(sess and sess.get("admin_unlocked"))
                return self.send_json(capabilities(actor_from_request(self), admin_unlocked=unlocked))
            if path == "/api/tools/health":
                self.require_auth()
                sess = current_session(self)
                if not (sess and sess.get("admin_unlocked")):
                    # Non-admin: rispondiamo senza svelare la lista tool.
                    raise WebError(HTTPStatus.FORBIDDEN, "Elenco tool riservato agli amministratori.")
                return self.send_json({"tools": all_tools_health()})
            if path == "/api/keys":
                # La lista chiavi API è a sua volta segreto di piattaforma.
                self.require_auth()
                sess = current_session(self)
                if not (sess and sess.get("admin_unlocked")):
                    raise WebError(HTTPStatus.FORBIDDEN, "Sblocca con la password amministratore per gestire le chiavi API.")
                actor = actor_from_request(self)
                return self.send_json({"keys": get_storage().list_api_keys(actor), "catalog": api_key_catalog_for(actor)})
            if path == "/api/report-signing/public-key":
                # Pensata per essere condivisa liberamente: nessun permesso
                # speciale oltre l'essere autenticati.
                self.require_auth()
                from . import report_signing
                return self.send_json(report_signing.export_public_key(JOB_ROOT))
            if path == "/api/jobs":
                self.require_auth()
                return self.send_json({"jobs": list_jobs(actor_from_request(self))})
            if path.startswith("/api/jobs/"):
                self.require_auth()
                return self.handle_job_get(path, actor_from_request(self))
            if path == "/api/cases":
                self.require_auth()
                actor = actor_from_request(self)
                return self.send_json({"cases": list_cases_for(actor)})
            if path.startswith("/api/cases/"):
                self.require_auth()
                actor = actor_from_request(self)
                return self.handle_case_get(path, actor)
            if path.startswith("/api/roe/"):
                self.require_auth()
                actor = actor_from_request(self)
                return self.handle_roe_get(path, actor)
            if path == "/api/connectors":
                self.require_auth()
                sess = current_session(self)
                if not (sess and sess.get("admin_unlocked")):
                    raise WebError(HTTPStatus.FORBIDDEN,
                                   "Catalogo connettori riservato agli amministratori.")
                return self.send_json({"connectors": CONNECTOR_REGISTRY.catalog()})
            if path == "/api/dashboard":
                self.require_auth()
                return self.send_json(dashboard_overview(actor_from_request(self)))
            if path == "/api/admin/stats":
                self.require_auth()
                sess = current_session(self)
                if not (sess and sess.get("admin_unlocked")):
                    raise WebError(HTTPStatus.FORBIDDEN,
                                   "Statistiche di piattaforma riservate all'amministratore.")
                return self.send_json(admin_stats())
            if path.startswith("/api/graph/"):
                self.require_auth()
                actor = actor_from_request(self)
                return self.handle_graph_get(path, actor)
            if path.startswith("/api/footprint/"):
                self.require_auth()
                actor = actor_from_request(self)
                return self.handle_footprint_get(path, actor)
            if path == "/api/privacy/log":
                self.require_auth()
                actor = actor_from_request(self)
                return self.send_json(get_privacy_log(actor))
            return self.serve_static(path)
        except WebError as exc:
            self.send_json({"error": exc.message}, exc.status)
        except Exception as exc:
            # NON leakiamo str(exc) al client: potrebbe contenere path assoluti,
            # nomi utente OS, valori interni. Log server-side + messaggio generico.
            LOG.exception("Unhandled error on %s: %s", getattr(self, "path", "?"), exc)
            self.send_json({"error": "Errore interno."}, HTTPStatus.INTERNAL_SERVER_ERROR)

    def do_POST(self) -> None:
        try:
            path = urlparse(self.path).path
            self.enforce_rate_limit()
            if path == "/api/auth/signup":
                return self.handle_signup()
            if path == "/api/auth/login":
                return self.handle_login()
            if path == "/api/auth/google":
                return self.handle_google_login()
            if path == "/api/auth/logout":
                session = current_session(self)
                if session:
                    SESSION_STORE.delete(session["id"])
                self.send_cookie("osint_session", "", max_age=0)
                return self.send_json({"status": "logged_out"})
            self.require_auth()
            self.require_csrf()
            if path == "/api/admin/unlock":
                # Unlock delle funzioni admin (es. ricerca aggressiva).
                # Fail-close: nessun log della password, audit solo su success.
                payload = self.read_json()
                username = str((payload or {}).get("username", "")).strip()
                password = str((payload or {}).get("password", ""))
                if not verify_admin_credentials(username, password):
                    # Ritardo costante per non permettere timing enumeration.
                    time.sleep(0.15)
                    raise WebError(HTTPStatus.UNAUTHORIZED, "Credenziali admin non valide.")
                # Persist il flag admin_unlocked nella sessione utente: la UI/API
                # reveleranno tool e connettori sensibili solo per questa sessione.
                sess = current_session(self)
                if sess is not None:
                    sess["admin_unlocked"] = True
                    sess["admin_unlocked_at"] = time.time()
                    SESSION_STORE.put(sess["id"], sess)
                get_storage().append_audit_event(
                    actor_from_request(self),
                    "admin_unlock",
                    {"username": username, "feature": "aggressive_hunt+tool_reveal"},
                )
                return self.send_json({"unlocked": True})
            if path == "/api/plan":
                payload = self.read_json()
                profile = build_profile(payload)
                return self.send_json({"profile": profile_to_dict(profile)})
            if path == "/api/jobs":
                payload = self.read_json()
                profile = build_profile(payload)
                actor = actor_from_request(self)
                job = create_job(profile, payload, actor)
                JOB_QUEUE.submit_spec(
                    JobSpec(
                        job_id=job["id"],
                        profile=profile_to_dict(profile),
                        payload=dict(payload),
                        actor=actor,
                    )
                )
                return self.send_json(job, HTTPStatus.ACCEPTED)
            if path == "/api/media":
                return self.handle_media_upload()
            if path == "/api/enrich/text":
                payload = self.read_json()
                text = str(payload.get("text") or "")
                if not text.strip():
                    raise WebError(HTTPStatus.BAD_REQUEST, "Campo 'text' obbligatorio.")
                from .enrichment_ai import enrich_text
                translate_to = str(payload.get("translate_to") or "").strip()
                result = enrich_text(
                    text[:200_000],
                    summarize=bool(payload.get("summarize", True)),
                    translate_to=translate_to,
                )
                return self.send_json(result)
            if path == "/api/search/findings":
                # Ricerca full-text cross-caso sui findings indicizzati (OpenSearch).
                payload = self.read_json()
                query = str(payload.get("query") or "").strip()
                if not query:
                    raise WebError(HTTPStatus.BAD_REQUEST, "Campo 'query' obbligatorio.")
                from .opensearch_index import OpenSearchIndex
                client = OpenSearchIndex()
                if not client.available():
                    raise WebError(HTTPStatus.SERVICE_UNAVAILABLE,
                                   "OpenSearch non configurato (OPENSEARCH_URL).")
                case_id = str(payload.get("case_id") or "").strip()
                size = min(int(payload.get("size", 25) or 25), 100)
                return self.send_json(client.search(query, size=size, case_id=case_id))
            if path == "/api/keys":
                sess = current_session(self)
                if not (sess and sess.get("admin_unlocked")):
                    raise WebError(HTTPStatus.FORBIDDEN, "Sblocca con la password amministratore per gestire le chiavi API.")
                payload = self.read_json()
                actor = actor_from_request(self)
                service = str(payload.get("service") or "").strip()
                value = str(payload.get("value") or "").strip()
                if service not in {entry["service"] for entry in api_key_catalog_for(actor)}:
                    raise WebError(HTTPStatus.BAD_REQUEST, "Servizio non riconosciuto.")
                store = get_storage()
                store.put_api_key(actor, service, value)
                # Invalido la cache di health-check così il prossimo /api/capabilities
                # forza una vera probe (e i pallini si aggiornano).
                provider_health.invalidate_provider(service)
                store.append_audit_event(
                    actor,
                    "api_key_updated" if value else "api_key_removed",
                    {"service": service},
                )
                return self.send_json({"keys": store.list_api_keys(actor), "catalog": api_key_catalog_for(actor)})
            if path == "/api/keys/test":
                sess = current_session(self)
                if not (sess and sess.get("admin_unlocked")):
                    raise WebError(HTTPStatus.FORBIDDEN, "Sblocca con la password amministratore per testare le chiavi API.")
                # Test on-demand di una chiave (NON la salva, solo verifica).
                # Usa la chiave già salvata se non viene fornita "value" nel payload.
                payload = self.read_json()
                actor = actor_from_request(self)
                service = str(payload.get("service") or "").strip()
                if service not in {entry["service"] for entry in api_key_catalog_for(actor)}:
                    raise WebError(HTTPStatus.BAD_REQUEST, "Servizio non riconosciuto.")
                # Se l'utente passa "value" testiamo quella chiave (senza salvare),
                # altrimenti usiamo la chiave salvata.
                key = str(payload.get("value") or "").strip() or resolve_api_key(service, actor)
                # Forza ricontrollo (no cache).
                provider_health.invalidate_provider(service)
                status = provider_health.check_provider(service, key)
                # Cache il risultato.
                provider_health._CACHE[(service, status.last4)] = (time.time(), status)
                get_storage().append_audit_event(actor, "api_key_tested", {
                    "service": service, "state": status.state, "http_status": status.http_status,
                })
                return self.send_json(status.to_dict())
            if path == "/api/cases":
                payload = self.read_json()
                actor = actor_from_request(self)
                return self.send_json(create_case(payload, actor), HTTPStatus.CREATED)
            if path.startswith("/api/cases/") and path.endswith("/roe"):
                payload = self.read_json()
                actor = actor_from_request(self)
                parts = [p for p in path.split("/") if p]
                if len(parts) != 4:
                    raise WebError(HTTPStatus.NOT_FOUND, "Endpoint non trovato.")
                case_id = parts[2]
                return self.send_json(sign_roe(case_id, payload, actor), HTTPStatus.CREATED)
            if path == "/api/connectors/run":
                payload = self.read_json()
                actor = actor_from_request(self)
                return self.handle_connector_run(payload, actor)
            if path == "/api/ioc/enrich":
                payload = self.read_json()
                return self.handle_ioc_enrich(payload)
            if path == "/api/monitor/brand":
                payload = self.read_json()
                return self.handle_brand_monitor(payload)
            if path == "/api/monitor/diff":
                payload = self.read_json()
                actor = actor_from_request(self)
                return self.handle_monitor_diff(payload, actor)
            if path == "/api/takedown":
                payload = self.read_json()
                actor = actor_from_request(self)
                return self.handle_takedown_create(payload, actor)
            if path == "/api/recon/run":
                payload = self.read_json()
                actor = actor_from_request(self)
                return self.handle_recon_run(payload, actor)
            if path.startswith("/api/cases/") and path.endswith("/scope"):
                parts = [p for p in path.split("/") if p]
                if len(parts) != 4:
                    raise WebError(HTTPStatus.NOT_FOUND, "Endpoint non trovato.")
                case_id = parts[2]
                payload = self.read_json()
                actor = actor_from_request(self)
                updated = update_case_scope(case_id, payload, actor)
                return self.send_json(updated)
            if path == "/api/privacy/export":
                self.require_auth()
                actor = actor_from_request(self)
                return self.send_json(handle_privacy_export(actor))
            if path == "/api/privacy/erase":
                self.require_auth()
                actor = actor_from_request(self)
                payload = self.read_json()
                return self.send_json(handle_privacy_erase(actor, payload))
            if path == "/api/privacy/dsar":
                self.require_auth()
                actor = actor_from_request(self)
                return self.send_json(handle_privacy_dsar(actor))
            if path.startswith("/api/cases/") and path.endswith("/ai-settings"):
                parts = [p for p in path.split("/") if p]
                if len(parts) != 4:
                    raise WebError(HTTPStatus.NOT_FOUND, "Endpoint non trovato.")
                case_id = parts[2]
                payload = self.read_json()
                actor = actor_from_request(self)
                return self.send_json(set_case_ai_settings(case_id, payload, actor))
            if path == "/api/ai/narrative":
                payload = self.read_json()
                actor = actor_from_request(self)
                return self.send_json(handle_ai_narrative(payload, actor))
            if path == "/api/ai/entity-suggestions":
                payload = self.read_json()
                actor = actor_from_request(self)
                return self.send_json(handle_ai_entity_suggestions(payload, actor))
            if path == "/api/ai/entity-suggestions/decide":
                payload = self.read_json()
                actor = actor_from_request(self)
                return self.send_json(handle_ai_entity_decide(payload, actor))
            if path == "/api/ai/triage":
                payload = self.read_json()
                actor = actor_from_request(self)
                return self.send_json(handle_ai_triage(payload, actor))
            if path.startswith("/api/jobs/") and path.endswith("/seal/tsa-timestamp"):
                parts = [p for p in path.split("/") if p]
                if len(parts) != 5:
                    raise WebError(HTTPStatus.NOT_FOUND, "Endpoint non trovato.")
                job_id = parts[2]
                actor = actor_from_request(self)
                return self.send_json(handle_request_tsa_timestamp(job_id, actor))
            raise WebError(HTTPStatus.NOT_FOUND, "Endpoint non trovato.")
        except WebError as exc:
            self.send_json({"error": exc.message}, exc.status)
        except Exception as exc:
            # NON leakiamo str(exc) al client: potrebbe contenere path assoluti,
            # nomi utente OS, valori interni. Log server-side + messaggio generico.
            LOG.exception("Unhandled error on %s: %s", getattr(self, "path", "?"), exc)
            self.send_json({"error": "Errore interno."}, HTTPStatus.INTERNAL_SERVER_ERROR)

    def do_DELETE(self) -> None:
        try:
            path = urlparse(self.path).path
            self.enforce_rate_limit()
            self.require_auth()
            self.require_csrf()
            if path.startswith("/api/jobs/"):
                actor = actor_from_request(self)
                return self.handle_job_delete(path, actor)
            if path.startswith("/api/cases/"):
                actor = actor_from_request(self)
                return self.handle_case_delete(path, actor)
            raise WebError(HTTPStatus.NOT_FOUND, "Endpoint non trovato.")
        except WebError as exc:
            self.send_json({"error": exc.message}, exc.status)
        except Exception as exc:
            # NON leakiamo str(exc) al client: potrebbe contenere path assoluti,
            # nomi utente OS, valori interni. Log server-side + messaggio generico.
            LOG.exception("Unhandled error on %s: %s", getattr(self, "path", "?"), exc)
            self.send_json({"error": "Errore interno."}, HTTPStatus.INTERNAL_SERVER_ERROR)

    def handle_job_delete(self, path: str, actor: str) -> None:
        parts = [p for p in path.split("/") if p]
        if len(parts) != 3:
            raise WebError(HTTPStatus.NOT_FOUND, "Endpoint non trovato.")
        job_id = parts[2]
        # read_job applies ownership check (404 if not owner) -> nessun leak.
        job = read_job(job_id, requester=actor)
        # Motivazione opzionale (audit). Body JSON ammesso ma non obbligatorio.
        try:
            payload = self.read_json()
        except Exception:
            payload = {}
        reason = str((payload or {}).get("reason", "")).strip()[:500]
        removed_files = delete_job_artifacts(job)
        rows = get_storage().delete_job(job_id)
        get_storage().append_audit_event(
            actor,
            "job_deleted",
            {
                "job_id": job_id,
                "case_id": job.get("case_id", ""),
                "files_removed": removed_files,
                "rows_removed": rows,
                "reason": reason,
            },
        )
        return self.send_json({
            "status": "ok",
            "job_id": job_id,
            "files_removed": removed_files,
            "rows_removed": rows,
        })

    def handle_case_delete(self, path: str, actor: str) -> None:
        """DELETE /api/cases/<id> — rimuove il caso.

        - Solo l'owner. read_case restituisce 404 (non 403) su non-owner: preserva
          l'invariante "nessun leak di esistenza" gia' presente per i job.
        - Cascade OPT-IN via ``?cascade=1`` in query: elimina anche i job del
          caso (file + record + audit event per ognuno). Default OFF: i job
          restano come record orfani (case_id preservato per audit trail).
        - L'evento ``case_deleted`` viene sempre appeso all'audit log:
          cancelliamo i dati, MAI la responsabilita' dell'azione.
        """
        parts = [p for p in path.split("/") if p]
        if len(parts) != 3:
            raise WebError(HTTPStatus.NOT_FOUND, "Endpoint non trovato.")
        case_id = parts[2]
        case = read_case(case_id, requester=actor)  # 404 se non owner

        try:
            payload = self.read_json()
        except Exception:
            payload = {}
        reason = str((payload or {}).get("reason", "")).strip()[:500]

        qs = urlparse(self.path).query or ""
        cascade = "cascade=1" in qs or "cascade=true" in qs

        store = get_storage()
        jobs_removed: list[str] = []
        files_removed_total: list[str] = []
        if cascade:
            for job in store.list_jobs(owner=actor, limit=1000):
                if job.get("case_id") == case_id:
                    files_removed_total.extend(delete_job_artifacts(job))
                    store.delete_job(job["id"])
                    jobs_removed.append(job["id"])

        store.delete_case(case_id)
        store.append_audit_event(
            actor,
            "case_deleted",
            {
                "case_id": case_id,
                "title": case.get("title", ""),
                "cascade": cascade,
                "jobs_removed": jobs_removed,
                "files_removed": files_removed_total,
                "reason": reason,
            },
        )
        return self.send_json({
            "status": "ok",
            "case_id": case_id,
            "cascade": cascade,
            "jobs_removed": jobs_removed,
            "files_removed": files_removed_total,
        })

    def handle_signup(self) -> None:
        if not SIGNUPS_ENABLED:
            raise WebError(HTTPStatus.FORBIDDEN, "Iscrizioni disattivate.")
        payload = self.read_json()
        username = normalize_username(payload.get("username", ""))
        password = str(payload.get("password", ""))
        email = str(payload.get("email", "")).strip().lower()
        if not username or len(username) < 3:
            raise WebError(HTTPStatus.BAD_REQUEST, "Username troppo corto.")
        if not email or "@" not in email or "." not in email.split("@")[-1]:
            raise WebError(HTTPStatus.BAD_REQUEST, "Email obbligatoria e valida.")
        validate_password(password)
        users = load_users()
        if username in users:
            raise WebError(HTTPStatus.CONFLICT, "Username gia registrato.")
        # Check email uniqueness too
        for existing in users.values():
            existing_email = (existing.get("email") or "").lower()
            if existing_email and existing_email == email:
                raise WebError(HTTPStatus.CONFLICT, "Email gia registrata.")
        users[username] = {
            "username": username,
            "email": email,
            "password": hash_password(password),
            "plan": "free",
            "created_at": now_iso(),
            "disabled": False,
            "verified": False,
            "verified_at": None,
        }
        save_users(users)
        # Audit + send verification email
        store = get_storage()
        store.append_audit_event(username, "user_signup", {"email": email})
        try:
            token = generate_token(username, email)
            result = send_verification_email(email, token)
            store.append_audit_event(username, "verification_email_sent", {
                "email": email,
                "provider": result.get("provider"),
                "status": result.get("status"),
            })
        except EmailSendError as exc:
            # Rollback the user — we don't want orphan unverified accounts.
            # NON esponiamo dettagli tecnici (potrebbero includere SMTP host,
            # username relay, ecc.); log server-side per debug.
            users.pop(username, None)
            save_users(users)
            LOG.warning("Signup rollback for %s: email send failed: %s", username, exc)
            store.append_audit_event(username, "signup_rollback_email_error",
                                     {"reason": "email_send_failed"})
            raise WebError(HTTPStatus.SERVICE_UNAVAILABLE,
                           "Errore invio email di verifica. Riprova più tardi.") from exc
        # Don't start session — user must verify first
        return self.send_json({
            "status": "pending_verification",
            "message": f"Email di verifica inviata a {email}. Controlla la casella e clicca il link.",
            "email": email,
        }, HTTPStatus.CREATED)

    def handle_login(self) -> None:
        payload = self.read_json()
        username = normalize_username(payload.get("username", ""))
        password = str(payload.get("password", ""))
        user = load_users().get(username)
        if not user or user.get("disabled") or not verify_password(password, user.get("password", "")):
            raise WebError(HTTPStatus.UNAUTHORIZED, "Credenziali non valide.")
        if not user.get("verified", False):
            raise WebError(HTTPStatus.FORBIDDEN,
                           "Account non ancora verificato. Controlla la mail di conferma.")
        # Audit login from IP
        store = get_storage()
        store.append_audit_event(username, "login_success", {
            "remote_ip": self.client_address[0],
            "method": "password",
        })
        return self.start_session(username)

    def handle_google_login(self) -> None:
        """Sign-in with Google — additional login door onto the same user table.

        First-time Google sign-in auto-provisions a user (already
        email-verified by Google, no usable password: password login stays
        impossible for that account since ``verify_password`` fails closed
        on an empty/malformed stored hash).
        """
        if not google_login_enabled():
            raise WebError(HTTPStatus.NOT_FOUND, "Login Google non configurato.")
        payload = self.read_json()
        credential = str(payload.get("credential", ""))
        try:
            identity = verify_google_id_token(credential)
        except GoogleTokenError as exc:
            raise WebError(HTTPStatus.UNAUTHORIZED, str(exc)) from exc

        store = get_storage()
        users = load_users()
        username = next(
            (u.get("username", "") for u in users.values()
             if (u.get("email") or "").lower() == identity.email
             and not u.get("disabled")),
            "",
        )
        is_new = not username
        if is_new:
            username = username_from_email(identity.email, set(users.keys()))
            users[username] = {
                "username": username,
                "email": identity.email,
                "password": "",  # no password set — Google is the only login door
                "plan": "free",
                "created_at": now_iso(),
                "disabled": False,
                "verified": True,  # Google already verified the email
                "verified_at": now_iso(),
                "auth_provider": "google",
                "google_sub": identity.google_sub,
            }
            save_users(users)
            store.append_audit_event(username, "user_signup", {
                "email": identity.email, "method": "google",
            })

        store.append_audit_event(username, "login_success", {
            "remote_ip": self.client_address[0],
            "method": "google",
        })
        return self.start_session(username)

    def handle_verify_email(self, token: str) -> None:
        try:
            claims = verify_token(token)
        except ValueError as exc:
            return self._render_verify_page(False, str(exc))
        users = load_users()
        user = users.get(claims.username)
        if not user:
            return self._render_verify_page(False, "Utente non trovato.")
        if (user.get("email") or "").lower() != claims.email.lower():
            return self._render_verify_page(False, "Email non corrisponde all'utente.")
        if user.get("verified", False):
            return self._render_verify_page(True, "Account gia verificato — puoi accedere.")
        user["verified"] = True
        user["verified_at"] = now_iso()
        users[claims.username] = user
        save_users(users)
        get_storage().append_audit_event(claims.username, "email_verified", {
            "email": claims.email,
        })
        return self._render_verify_page(True, "Email confermata. Ora puoi accedere.")

    def _render_verify_page(self, ok: bool, message: str) -> None:
        color = "#21d07a" if ok else "#ff5577"
        title = "Verifica riuscita" if ok else "Verifica fallita"
        html = f"""<!doctype html><html lang="it"><head><meta charset="utf-8">
<title>{title} — Argo</title>
<style>body{{font-family:system-ui,sans-serif;background:#0b1a30;color:#e6edf6;
display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;}}
.box{{max-width:480px;padding:32px;background:#102542;border-radius:12px;text-align:center;
border:1px solid #1d3559;}}
h1{{color:{color};margin:0 0 16px;}}p{{color:#94a3b8;}}a{{color:#65a8ff;}}
</style></head><body><div class="box"><h1>{title}</h1><p>{message}</p>
<p><a href="/">← Torna al login</a></p></div></body></html>"""
        self.send_raw(html.encode("utf-8"), "text/html; charset=utf-8")

    def start_session(self, username: str) -> None:
        session_id = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(24)
        SESSION_STORE.put(
            session_id,
            {
                "id": session_id,
                "username": username,
                "csrf": csrf,
                "created": time.time(),
                "last_seen": time.time(),
            },
        )
        self.send_cookie("osint_session", session_id, max_age=SESSION_TTL_SECONDS)
        user = load_users()[username]
        return self.send_json({"user": public_user(user), "csrf": csrf})

    def handle_roe_get(self, path: str, requester: str = "") -> None:
        parts = [p for p in path.split("/") if p]
        if len(parts) < 3:
            raise WebError(HTTPStatus.NOT_FOUND, "Risorsa RoE non trovata.")
        case_id = parts[2]
        # Authorise read via case ownership.
        read_case(case_id, requester=requester)
        roe = get_storage().get_active_roe(case_id)
        return self.send_json({"roe": roe})

    def handle_case_get(self, path: str, requester: str = "") -> None:
        parts = [part for part in path.split("/") if part]
        if len(parts) < 3:
            raise WebError(HTTPStatus.NOT_FOUND, "Caso non trovato.")
        case_id = parts[2]
        case = read_case(case_id, requester=requester)
        if len(parts) == 3:
            return self.send_json(case)
        if len(parts) == 4 and parts[3] == "jobs":
            jobs = get_storage().list_jobs_by_case(case_id)
            return self.send_json({"jobs": jobs})
        raise WebError(HTTPStatus.NOT_FOUND, "Risorsa caso non trovata.")

    def handle_job_get(self, path: str, requester: str = "") -> None:
        parts = [part for part in path.split("/") if part]
        if len(parts) < 3:
            raise WebError(HTTPStatus.NOT_FOUND, "Job non trovato.")
        job_id = parts[2]
        job = read_job(job_id, requester=requester)
        if len(parts) == 3:
            return self.send_json(job)
        # Export threat-intel generati al volo dall'investigation JSON.
        if len(parts) == 4 and parts[3] in {"stix.json", "misp.json"}:
            return self.handle_threatintel_export(job, parts[3])
        if len(parts) == 4 and parts[3] == "seal":
            return self.send_json(handle_get_seal(job_id, requester))
        if len(parts) == 4 and parts[3] in {
            "report.md", "report.json", "report.pdf",
            "forensic.md", "forensic.json",
            "redteam.md", "redteam.json",
        }:
            key_by_name = {
                "report.md": "markdown_path",
                "report.json": "json_path",
                "report.pdf": "pdf_path",
                "forensic.md": "forensic_markdown_path",
                "forensic.json": "forensic_json_path",
                "redteam.md": "redteam_markdown_path",
                "redteam.json": "redteam_json_path",
            }
            key = key_by_name[parts[3]]
            report_path = job.get(key)
            if not report_path:
                raise WebError(HTTPStatus.NOT_FOUND, "Report non disponibile.")
            content_type_by_key = {
                "markdown_path": "text/markdown; charset=utf-8",
                "json_path": "application/json; charset=utf-8",
                "pdf_path": "application/pdf",
                "forensic_markdown_path": "text/markdown; charset=utf-8",
                "forensic_json_path": "application/json; charset=utf-8",
                "redteam_markdown_path": "text/markdown; charset=utf-8",
                "redteam_json_path": "application/json; charset=utf-8",
            }
            content_type = content_type_by_key[key]
            include_contact = bool(job.get("settings", {}).get("include_contact"))
            if key == "json_path" and not include_contact:
                data = json.loads(Path(report_path).read_text(encoding="utf-8"))
                redacted = redact_report_json(data)
                return self.send_raw(
                    json.dumps(redacted, ensure_ascii=False, indent=2).encode("utf-8"),
                    content_type,
                    download_name=parts[3],
                )
            return self.send_file(Path(report_path), content_type, download_name=parts[3])
        raise WebError(HTTPStatus.NOT_FOUND, "Risorsa job non trovata.")

    def handle_threatintel_export(self, job: dict, kind: str) -> None:
        """Genera STIX 2.1 bundle o MISP event dall'investigation JSON del job.

        Rispetta la redaction: se il caso non ha include_contact, esporta dalla
        versione redatta del JSON (nessun contatto personale nei bundle condivisi).
        """
        json_path = job.get("json_path")
        if not json_path or not Path(json_path).exists():
            raise WebError(HTTPStatus.NOT_FOUND, "Report JSON non disponibile per l'export.")
        inv = json.loads(Path(json_path).read_text(encoding="utf-8"))
        include_contact = bool(job.get("settings", {}).get("include_contact"))
        if not include_contact:
            inv = redact_report_json(inv)
        if kind == "stix.json":
            from .stix_export import investigation_to_stix_bundle
            payload = investigation_to_stix_bundle(inv)
        else:
            from .stix_export import investigation_to_misp_event
            payload = investigation_to_misp_event(inv)
        return self.send_raw(
            json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8"),
            "application/json; charset=utf-8",
            download_name=kind,
        )

    def handle_media_upload(self) -> None:
        content_type = self.headers.get("Content-Type", "")
        if not content_type.startswith("multipart/form-data"):
            raise WebError(HTTPStatus.BAD_REQUEST, "Usa multipart/form-data con campo file.")
        UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)
        length = int(self.headers.get("Content-Length", "0"))
        if length > MAX_UPLOAD_BYTES:
            raise WebError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "File troppo grande.")
        raw = self.rfile.read(length)
        filename, data = parse_multipart_file(raw, content_type)
        if not filename or not data:
            raise WebError(HTTPStatus.BAD_REQUEST, "File mancante.")
        filename = safe_filename(filename)
        upload_path = UPLOAD_ROOT / f"{uuid.uuid4().hex}_{filename}"
        upload_path.write_bytes(data)
        metadata = analyze_media_file(upload_path)
        response: dict = {"metadata": metadata.to_dict()}
        # OCR opzionale su immagini: estrae testo + entità se tesseract è presente.
        if (metadata.media_type or "").startswith("image"):
            try:
                from .enrichment_ai import ocr_image
                ocr = ocr_image(str(upload_path))
                if ocr.available and ocr.text:
                    response["ocr"] = {
                        "engine": ocr.engine,
                        "text": ocr.text[:5000],
                        "entities": [{"text": e.text, "label": e.label,
                                      "confidence": round(e.confidence, 2)}
                                     for e in ocr.entities],
                    }
                elif not ocr.available:
                    response["ocr"] = {"available": False, "note": ocr.note}
            except Exception as exc:
                response["ocr"] = {"available": False, "note": f"OCR error: {exc}"}
        self.send_json(response)

    # ------------------------------------------------------------------
    # Pillar 1 — Connector endpoints
    # ------------------------------------------------------------------

    def handle_connector_run(self, payload: dict, actor: str) -> None:
        connector_name = str(payload.get("connector") or "").strip()
        target = str(payload.get("target") or "").strip()
        target_type = str(payload.get("target_type") or "auto").strip()
        case_id = str(payload.get("case_id") or "").strip()
        lang = str(payload.get("lang") or "it").strip().lower()
        if lang not in ("it", "en"):
            lang = "it"
        if not connector_name or not target:
            raise WebError(HTTPStatus.BAD_REQUEST, "Parametri 'connector' e 'target' obbligatori.")
        api_key = resolve_api_key(connector_name, actor)
        ctx = ConnectorContext(
            target=target,
            target_type=target_type,
            actor=actor,
            case_id=case_id,
            api_key=api_key,
            timeout=20,
            lang=lang,
        )
        from dataclasses import asdict
        result = CONNECTOR_REGISTRY.run(connector_name, ctx)
        findings_dicts = [asdict(f) for f in result.findings]
        return self.send_json({
            "connector": result.connector,
            "status": result.status,
            "cached": result.cached,
            "duration_ms": result.duration_ms,
            "error": result.error,
            "findings": findings_dicts,
            "raw": result.raw,
        })

    # ------------------------------------------------------------------
    # Pillar 4 — Graph endpoints
    # ------------------------------------------------------------------

    def handle_graph_get(self, path: str, requester: str = "") -> None:
        parts = [p for p in path.split("/") if p]
        if len(parts) < 3:
            raise WebError(HTTPStatus.NOT_FOUND, "Job ID mancante.")
        job_id = parts[2]
        job = read_job(job_id, requester=requester)
        json_path = job.get("json_path")
        if not json_path or not Path(json_path).exists():
            raise WebError(HTTPStatus.NOT_FOUND, "Report JSON non disponibile per questo job.")
        report = json.loads(Path(json_path).read_text(encoding="utf-8"))
        findings_raw = report.get("findings") or []
        from .models import Evidence as _Ev
        from .models import Finding as _F
        findings = []
        for fd in findings_raw:
            try:
                ev_list = [_Ev(**e) for e in (fd.get("evidence") or [])]
                findings.append(_F(
                    kind=fd.get("kind", ""),
                    value=fd.get("value", ""),
                    confidence=float(fd.get("confidence", 0.5)),
                    evidence=ev_list,
                    notes=fd.get("notes", ""),
                    severity=fd.get("severity", ""),
                    attck_ttps=list(fd.get("attck_ttps") or []),
                ))
            except Exception:
                pass
        graph = resolve_entities(findings)
        return self.send_json(export_d3_json(graph))

    # ------------------------------------------------------------------
    # Pillar 3 — Defensive endpoints
    # ------------------------------------------------------------------

    def handle_footprint_get(self, path: str, requester: str = "") -> None:
        parts = [p for p in path.split("/") if p]
        if len(parts) < 3:
            raise WebError(HTTPStatus.NOT_FOUND, "Job ID mancante.")
        job_id = parts[2]
        job = read_job(job_id, requester=requester)
        json_path = job.get("json_path")
        if not json_path or not Path(json_path).exists():
            raise WebError(HTTPStatus.NOT_FOUND, "Report JSON non disponibile.")
        report = json.loads(Path(json_path).read_text(encoding="utf-8"))
        findings_raw = report.get("findings") or []
        from .models import Finding as _F
        findings = [_F(kind=fd.get("kind",""), value=fd.get("value",""),
                       confidence=float(fd.get("confidence",0.5)),
                       severity=fd.get("severity",""),
                       attck_ttps=list(fd.get("attck_ttps") or []))
                    for fd in findings_raw]
        return self.send_json(score_digital_footprint(findings))

    def handle_ioc_enrich(self, payload: dict) -> None:
        ioc_value = str(payload.get("ioc") or "").strip()
        ioc_type = str(payload.get("type") or "auto").strip()
        if not ioc_value:
            raise WebError(HTTPStatus.BAD_REQUEST, "Parametro 'ioc' obbligatorio.")
        result = enrich_ioc(ioc_value, ioc_type)
        from dataclasses import asdict
        return self.send_json(asdict(result))

    def handle_brand_monitor(self, payload: dict) -> None:
        brand = str(payload.get("brand") or "").strip()
        domains = list(payload.get("domains") or [])
        handles = list(payload.get("handles") or [])
        if not brand:
            raise WebError(HTTPStatus.BAD_REQUEST, "Parametro 'brand' obbligatorio.")
        signals = assess_brand_impersonation(brand, domains, handles)
        findings = [s.to_finding() for s in signals]
        from dataclasses import asdict
        return self.send_json({
            "brand": brand,
            "signals": [asdict(s) for s in signals],
            "findings": [asdict(f) for f in findings],
        })

    def handle_monitor_diff(self, payload: dict, actor: str) -> None:
        baseline_job_id = str(payload.get("baseline_job_id") or "").strip()
        current_job_id = str(payload.get("current_job_id") or "").strip()
        if not baseline_job_id or not current_job_id:
            raise WebError(HTTPStatus.BAD_REQUEST, "Parametri 'baseline_job_id' e 'current_job_id' obbligatori.")

        def _load_findings(job_id: str) -> list:
            job = read_job(job_id, requester=actor)
            json_path = job.get("json_path")
            if not json_path or not Path(json_path).exists():
                return []
            report = json.loads(Path(json_path).read_text(encoding="utf-8"))
            from .models import Finding as _F
            result = []
            for fd in (report.get("findings") or []):
                try:
                    result.append(_F(kind=fd.get("kind",""), value=fd.get("value",""),
                                     confidence=float(fd.get("confidence",0.5)),
                                     severity=fd.get("severity","")))
                except Exception:
                    pass
            return result

        baseline = _load_findings(baseline_job_id)
        current = _load_findings(current_job_id)
        domain = str(payload.get("domain") or "")
        report = monitor_surface(domain, baseline, current)
        from dataclasses import asdict
        return self.send_json({
            "domain": report.domain,
            "checked_at": report.checked_at,
            "risk_delta": report.risk_delta,
            "summary": report.summary(),
            "new_exposures": [asdict(f) for f in report.new_exposures],
            "resolved_exposures": [asdict(f) for f in report.resolved_exposures],
            "unchanged_count": len(report.unchanged),
        })

    def handle_takedown_create(self, payload: dict, actor: str) -> None:
        kind = str(payload.get("kind") or "phishing").strip()
        target_url = str(payload.get("target_url") or "").strip()
        brand = str(payload.get("brand") or "").strip()
        if not target_url or not brand:
            raise WebError(HTTPStatus.BAD_REQUEST, "Parametri 'target_url' e 'brand' obbligatori.")
        tc = TakedownCase(
            id=uuid.uuid4().hex,
            kind=kind,
            target_url=target_url,
            brand=brand,
            evidence_urls=list(payload.get("evidence_urls") or []),
        )
        store = get_storage()
        store.append_audit_event(actor, "takedown_created", {
            "takedown_id": tc.id, "kind": kind, "brand": brand, "target_url": target_url,
        })
        return self.send_json(tc.to_dict(), HTTPStatus.CREATED)

    def handle_recon_run(self, payload: dict, actor: str) -> None:
        target = str(payload.get("target") or "").strip()
        if not target:
            raise WebError(HTTPStatus.BAD_REQUEST, "Parametro 'target' obbligatorio.")
        target_type = str(payload.get("target_type") or "domain").strip()
        api_keys = dict(payload.get("api_keys") or {})
        allow_pii = bool(payload.get("allow_pii", False))
        brand_name = str(payload.get("brand_name") or "").strip()
        extra_domains = list(payload.get("extra_domains") or [])
        extra_handles = list(payload.get("extra_handles") or [])
        case_id = str(payload.get("case_id") or "").strip()
        store = get_storage()
        store.append_audit_event(actor, "recon_run_started", {
            "target": target, "target_type": target_type, "case_id": case_id,
        })
        report = run_recon_pipeline(
            CONNECTOR_REGISTRY,
            target=target,
            target_type=target_type,
            api_keys=api_keys,
            actor=actor,
            case_id=case_id,
            allow_pii=allow_pii,
            brand_name=brand_name,
            extra_domains=extra_domains,
            extra_handles=extra_handles,
        )
        store.append_audit_event(actor, "recon_run_finished", {
            "target": target, "findings": len(report.all_findings),
            "duration_s": round(report.duration_s, 2),
        })
        return self.send_json(report.to_dict())

    def serve_static(self, path: str) -> None:
        if path in {"", "/"}:
            path = "/index.html"
        static_path = (STATIC_ROOT / unquote(path.lstrip("/"))).resolve()
        if STATIC_ROOT not in static_path.parents and static_path != STATIC_ROOT:
            raise WebError(HTTPStatus.FORBIDDEN, "Path non consentito.")
        if not static_path.is_file():
            raise WebError(HTTPStatus.NOT_FOUND, "File non trovato.")
        content_type = mimetypes.guess_type(static_path.name)[0] or "application/octet-stream"
        self.send_file(static_path, content_type)

    def send_file(self, path: Path, content_type: str, *, download_name: str = "") -> None:
        # Difesa in profondità contro path-traversal: il file DEVE essere sotto
        # JOB_ROOT (dove si generano report/upload) oppure sotto STATIC_ROOT
        # (asset del frontend). Anche se un attaccante forzasse un path via DB,
        # qui si ferma con 404.
        try:
            real = path.resolve(strict=True)
            allowed_roots = (JOB_ROOT.resolve(), STATIC_ROOT.resolve())
            if not any(str(real).startswith(str(r) + os.sep) or str(real) == str(r) for r in allowed_roots):
                raise WebError(HTTPStatus.NOT_FOUND, "File non trovato.")
        except FileNotFoundError as exc:
            raise WebError(HTTPStatus.NOT_FOUND, "File non trovato.") from exc
        if not path.is_file():
            raise WebError(HTTPStatus.NOT_FOUND, "File non trovato.")
        data = path.read_bytes()
        # Cache-busting basato sul contenuto: ETag SHA-256 weak su (size, mtime).
        # Con `Cache-Control: no-cache` il browser RIVALIDA ad ogni richiesta:
        # 304 se l'ETag combacia (zero byte), 200 con la nuova versione appena
        # cambia. Niente piu' "Ctrl+F5" obbligatorio dopo un deploy.
        stat = path.stat()
        etag = 'W/"%d-%d"' % (stat.st_size, int(stat.st_mtime_ns))
        client_etag = self.headers.get("If-None-Match", "")
        if client_etag and client_etag == etag:
            self.send_response(HTTPStatus.NOT_MODIFIED)
            self.send_header("ETag", etag)
            self.send_header("Cache-Control", "no-cache, must-revalidate")
            self.end_headers()
            return
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache, must-revalidate")
        self.send_header("ETag", etag)
        if download_name:
            self.send_header("Content-Disposition", _content_disposition(download_name))
        self.end_headers()
        self.wfile.write(data)

    def send_raw(self, data: bytes, content_type: str, *, download_name: str = "") -> None:
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        if download_name:
            self.send_header("Content-Disposition", _content_disposition(download_name))
        self.end_headers()
        self.wfile.write(data)

    def read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            return {}
        if length > MAX_JSON_BYTES:
            raise WebError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "Richiesta troppo grande.")
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def send_json(self, payload: dict, status: int = HTTPStatus.OK) -> None:
        data = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def require_auth(self) -> None:
        if not TOKEN:
            if current_session(self):
                return
            raise WebError(HTTPStatus.UNAUTHORIZED, "Accesso richiesto.")
        auth = self.headers.get("Authorization", "")
        header_token = self.headers.get("X-OSINT-Token", "")
        if _safe_str_equals(auth, f"Bearer {TOKEN}") or _safe_str_equals(header_token, TOKEN):
            return
        if current_session(self):
            return
        raise WebError(HTTPStatus.UNAUTHORIZED, "Token API mancante o non valido.")

    def require_csrf(self) -> None:
        if TOKEN and _safe_str_equals(self.headers.get("Authorization", ""), f"Bearer {TOKEN}"):
            return
        session = current_session(self)
        if not session:
            raise WebError(HTTPStatus.UNAUTHORIZED, "Sessione richiesta.")
        if not _safe_str_equals(self.headers.get("X-CSRF-Token", ""), session["csrf"]):
            raise WebError(HTTPStatus.FORBIDDEN, "CSRF token non valido.")

    def enforce_rate_limit(self) -> None:
        key = self.client_address[0]
        if not RATE_LIMITER.hit(key, window_seconds=60, limit=60):
            raise WebError(HTTPStatus.TOO_MANY_REQUESTS, "Troppe richieste, attendi un minuto.")

    def send_cookie(self, name: str, value: str, max_age: int) -> None:
        secure = "; Secure" if SECURE_COOKIE else ""
        self._pending_cookie = (
            f"{name}={value}; Max-Age={max_age}; Path=/; HttpOnly; SameSite=Strict{secure}"
        )

    def end_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        # Difesa clickjacking (retrocompatibile con CSP frame-ancestors 'none').
        self.send_header("X-Frame-Options", "DENY")
        # Isolamento cross-origin: previene attacchi Spectre-like e leaks.
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        )
        if hasattr(self, "_pending_cookie"):
            self.send_header("Set-Cookie", self._pending_cookie)
            delattr(self, "_pending_cookie")
        if os.getenv("OSINT_HSTS", "0") == "1":
            self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        super().end_headers()

    def log_message(self, format: str, *args) -> None:
        print(f"{self.address_string()} - {format % args}")


def build_profile(payload: dict) -> RunProfile:
    command = str(payload.get("command") or payload.get("target") or "").strip()
    if not command:
        raise WebError(HTTPStatus.BAD_REQUEST, "Comando o target richiesto.")
    target_type = payload.get("target_type") or ""
    if target_type == "auto":
        target_type = ""
    return plan_from_command(
        command,
        target=str(payload.get("target") or "").strip(),
        target_type=str(target_type).strip(),
        selected_modules=list(payload.get("modules") or []),
        search_engine=str(payload.get("provider") or "all"),
        source_route=str(payload.get("source_route") or "standard"),
        intensity=str(payload.get("intensity") or "meticulous"),
        confirm_authorization=bool(payload.get("confirm_authorization")),
        allow_network_scan=bool(payload.get("allow_network_scan")),
        allow_darkweb=bool(payload.get("allow_darkweb")),
        include_external_tools=bool(payload.get("include_external_tools", True)),
    )


def create_job(profile: RunProfile, payload: dict, actor: str = "system") -> dict:
    JOB_ROOT.mkdir(parents=True, exist_ok=True)
    job_id = uuid.uuid4().hex
    # Resolve target case: explicit case_id in payload, or the actor's default case.
    case_id = str(payload.get("case_id") or "").strip()
    if not case_id:
        case_id = ensure_default_case(actor)
    else:
        # Verify the case exists and the actor can see it; raises WebError otherwise.
        read_case(case_id, requester=actor)
    # Fase 3 — detection automatica HighRiskResearchMode. Calcoliamo qui (non
    # nel worker) cosi' il contesto e' visibile gia' dalla creazione del job e
    # finisce nell'audit log nello stesso istante.
    high_risk = detect_high_risk(
        target=profile.target,
        target_type=profile.target_type,
        command=getattr(profile, "command", "") or "",
        modules=list(payload.get("modules") or []),
        allow_darkweb=bool(payload.get("allow_darkweb")),
        seed_urls=list(payload.get("seed_urls") or []),
    )
    job = {
        "id": job_id,
        "owner": actor or "anonymous",
        "case_id": case_id,
        "status": "queued",
        "progress": [{"at": now_iso(), "stage": "queued", "message": "Job in coda."}],
        "created_at": now_iso(),
        "updated_at": now_iso(),
        "profile": profile_to_dict(profile),
        "settings": public_settings(payload),
        "high_risk": high_risk.to_dict(),
        "links": {
            "self": f"/api/jobs/{job_id}",
            "markdown": f"/api/jobs/{job_id}/report.md",
            "json": f"/api/jobs/{job_id}/report.json",
            "pdf": f"/api/jobs/{job_id}/report.pdf",
        },
    }
    write_job(job_id, job)
    store = get_storage()
    store.append_audit_event(
        actor,
        "job_created",
        {
            "job_id": job_id,
            "target_type": profile.target_type,
            "target": audit_target(profile),
            "confirm_authorization": bool(payload.get("confirm_authorization")),
            "allow_network_scan": bool(payload.get("allow_network_scan")),
            "allow_darkweb": bool(payload.get("allow_darkweb")),
            "include_contact": bool(payload.get("include_contact")),
            "modules": list(payload.get("modules") or []),
        },
    )
    if high_risk.active:
        store.append_audit_event(
            actor,
            "high_risk_mode_activated",
            {"job_id": job_id, **high_risk_audit(high_risk)},
        )
    return job


def _profile_from_dict(data: dict) -> RunProfile:
    return RunProfile(
        command=str(data.get("command") or ""),
        target=str(data.get("target") or ""),
        target_type=str(data.get("target_type") or ""),
        agents=list(data.get("agents") or []),
        external_tools=list(data.get("external_tools") or []),
        seed_urls=list(data.get("seed_urls") or []),
        depth=int(data.get("depth") or 2),
        max_pages=int(data.get("max_pages") or 12),
        notes=list(data.get("notes") or []),
    )


def dispatch_job_spec(spec_dict: dict) -> None:
    """Worker entry point used by JobQueue when a JobSpec is dequeued.

    Reconstructs the RunProfile from the serialised dict and calls
    ``execute_job``. Centralising this here means we can later swap the
    transport (Redis/Celery) without touching ``execute_job``.
    """
    spec = JobSpec.from_dict(spec_dict)
    profile = _profile_from_dict(spec.profile)
    execute_job(spec.job_id, profile, spec.payload, spec.actor)


# Wire the queue at import time so endpoint code and recovery paths don't
# have to remember to call register_dispatcher.
JOB_QUEUE.register_dispatcher(dispatch_job_spec)


def _generate_forensic_report(
    *, job: dict, profile: RunProfile, payload: dict, actor: str,
    investigation_json_path: Path | None, report_dir: Path,
) -> tuple[Path | None, Path | None]:
    """Costruisce il report a 19 sezioni accanto al markdown esistente."""
    if not investigation_json_path or not investigation_json_path.exists():
        return None, None
    try:
        investigation_data = json.loads(investigation_json_path.read_text(encoding="utf-8"))
    except Exception as exc:
        LOG.warning("forensic: impossibile leggere investigation JSON: %s", exc)
        return None, None

    # Ricostruisce un Investigation "leggero" dai dati su disco.
    from .models import Evidence, Finding, Investigation, Page, SearchResult
    def _f(d):
        return Finding(
            kind=d.get("kind", ""), value=d.get("value", ""),
            confidence=float(d.get("confidence", 0.0)),
            evidence=[Evidence(**e) for e in d.get("evidence", [])],
            notes=d.get("notes", ""),
            source_reliability=d.get("source_reliability", "F"),
            info_credibility=int(d.get("info_credibility", 6)),
            severity=d.get("severity", ""),
            attck_ttps=list(d.get("attck_ttps", [])),
            remediation=d.get("remediation", ""),
        )
    def _sr(d):
        return SearchResult(title=d.get("title", ""), url=d.get("url", ""),
                            snippet=d.get("snippet", ""), provider=d.get("provider", ""))
    def _p(d):
        return Page(
            url=d.get("url", ""), status=int(d.get("status", 0)),
            title=d.get("title", ""), description=d.get("description", ""),
            text=d.get("text", ""), links=list(d.get("links", [])),
            emails=list(d.get("emails", [])), error=d.get("error", ""),
        )
    investigation = Investigation(
        target=investigation_data.get("target", profile.target),
        target_type=investigation_data.get("target_type", profile.target_type),
        generated_at=investigation_data.get("generated_at", ""),
        safety_note=investigation_data.get("safety_note", ""),
        queries=list(investigation_data.get("queries", [])),
        search_results=[_sr(x) for x in investigation_data.get("search_results", [])],
        pages=[_p(x) for x in investigation_data.get("pages", [])],
        findings=[_f(x) for x in investigation_data.get("findings", [])],
        skipped_urls=list(investigation_data.get("skipped_urls", [])),
    )

    # Target classification
    target = classify_target(
        profile.target or job.get("target") or investigation.target,
        hint=profile.target_type or None,
    )

    # Case context
    case_id = job.get("case_id", "")
    case_data = {}
    if case_id:
        try:
            case_data = get_storage().get_case(case_id) or {}
        except Exception:
            case_data = {}
    legal = case_data.get("legal_basis") or {}
    case_ctx = _ForensicCase(
        case_id=case_id or job.get("id", "unknown"),
        title=case_data.get("title", "") or f"Indagine OSINT su {target.value or target.raw}",
        purpose=case_data.get("purpose", ""),
        legal_basis_type=legal.get("type", "") if isinstance(legal, dict) else "",
        legal_basis_reference=legal.get("reference", "") if isinstance(legal, dict) else "",
        owner=actor,
        collaborators=list(case_data.get("collaborators", []) if isinstance(case_data, dict) else []),
        retention_until=case_data.get("retention_until", "") if isinstance(case_data, dict) else "",
    )

    # Scope (se il caso ha asset autorizzati)
    scope = None
    scope_entries_raw = case_data.get("allowed_targets") or [] if isinstance(case_data, dict) else []
    if scope_entries_raw:
        scope = CaseScope(case_id=case_ctx.case_id)
        for raw in scope_entries_raw:
            entry = parse_scope_entry(str(raw), added_by=actor)
            if entry:
                scope.add(entry)

    # Provider usage da capabilities
    providers: list[ProviderUsage] = []
    try:
        caps = capabilities(actor)
        for p in caps.get("search_providers", []):
            if p.get("service") in (None, "all"):
                continue
            providers.append(ProviderUsage(
                name=p.get("label", p.get("service", "?")),
                state=p.get("state", "unknown"),
                message=p.get("message", ""),
                items_returned=0,
            ))
    except Exception as exc:
        LOG.warning("forensic: capabilities() failed: %s", exc)

    # Ranking risultati
    try:
        ranked = rank_results(investigation.search_results, target)
    except Exception as exc:
        LOG.warning("forensic: ranking failed: %s", exc)
        ranked = []

    # Contact discovery
    contacts = None
    try:
        contacts = discover_contacts(target, investigation.pages)
    except Exception as exc:
        LOG.warning("forensic: contact_discovery failed: %s", exc)

    rctx = _ForensicContext(
        case=case_ctx, target=target, investigation=investigation,
        ranked_results=ranked, contacts=contacts, scope=scope,
        providers=providers, generated_at=now_iso(),
    )
    report = build_forensic_report(rctx)

    report_dir.mkdir(parents=True, exist_ok=True)
    md_path = report_dir / "report.forensic.md"
    json_path_out = report_dir / "report.forensic.json"
    md_path.write_text(forensic_to_markdown(report), encoding="utf-8")
    json_path_out.write_text(json.dumps(forensic_to_json(report), indent=2, ensure_ascii=False),
                             encoding="utf-8")
    return md_path, json_path_out


def _generate_redteam_report(
    *, job: dict, profile: RunProfile, payload: dict, actor: str,
    forensic_md_path: Path | None, report_dir: Path,
    investigation_json_path: Path | None = None,
) -> tuple[Path | None, Path | None]:
    """Genera il report Red Team a partire dal forensic context già costruito.

    Si attiva SOLO se:
      - "red_team" è tra i moduli selezionati;
      - lo scope autorizzato del caso non è vuoto (no scope ⇒ nessun output RT).
    """
    if "red_team" not in (profile.agents or []) and "red_team" not in (payload.get("modules") or []):
        return None, None
    # Segno esplicitamente perche' l'utente possa capire dal progress log del job.
    def _log_skip(reason: str) -> None:
        job.setdefault("progress", []).append({
            "at": now_iso(), "stage": "redteam_report_skipped", "message": reason,
        })

    # Preferisco il path esplicito (passato da execute_job), fallback su job.
    investigation_json = investigation_json_path
    if investigation_json is None or not investigation_json.exists():
        jp = job.get("json_path")
        if jp and Path(jp).exists():
            investigation_json = Path(jp)
        else:
            _log_skip("Report investigation JSON non trovato: impossibile costruire il Red Team.")
            return None, None

    try:
        inv_data = json.loads(investigation_json.read_text(encoding="utf-8"))
    except Exception as exc:
        LOG.warning("redteam: read investigation failed: %s", exc)
        return None, None

    from .models import Evidence, Finding, Investigation, Page, SearchResult
    def _f(d):
        return Finding(
            kind=d.get("kind", ""), value=d.get("value", ""),
            confidence=float(d.get("confidence", 0.0)),
            evidence=[Evidence(**e) for e in d.get("evidence", [])],
            notes=d.get("notes", ""),
            source_reliability=d.get("source_reliability", "F"),
            info_credibility=int(d.get("info_credibility", 6)),
            severity=d.get("severity", ""),
            attck_ttps=list(d.get("attck_ttps", [])),
            remediation=d.get("remediation", ""),
        )
    def _sr(d):
        return SearchResult(title=d.get("title", ""), url=d.get("url", ""),
                            snippet=d.get("snippet", ""), provider=d.get("provider", ""))
    def _p(d):
        return Page(
            url=d.get("url", ""), status=int(d.get("status", 0)),
            title=d.get("title", ""), description=d.get("description", ""),
            text=d.get("text", ""), links=list(d.get("links", [])),
            emails=list(d.get("emails", [])), error=d.get("error", ""),
        )
    investigation = Investigation(
        target=inv_data.get("target", profile.target),
        target_type=inv_data.get("target_type", profile.target_type),
        generated_at=inv_data.get("generated_at", ""),
        safety_note=inv_data.get("safety_note", ""),
        queries=list(inv_data.get("queries", [])),
        search_results=[_sr(x) for x in inv_data.get("search_results", [])],
        pages=[_p(x) for x in inv_data.get("pages", [])],
        findings=[_f(x) for x in inv_data.get("findings", [])],
        skipped_urls=list(inv_data.get("skipped_urls", [])),
    )

    target = classify_target(profile.target or job.get("target") or investigation.target,
                             hint=profile.target_type or None)

    case_id = job.get("case_id", "")
    case_data = {}
    if case_id:
        try:
            case_data = get_storage().get_case(case_id) or {}
        except Exception:
            case_data = {}

    # Scope obbligatorio
    scope_entries_raw = case_data.get("allowed_targets") or [] if isinstance(case_data, dict) else []
    if not scope_entries_raw:
        # Nessuno scope → niente report Red Team (Priorità 8 del brief).
        _log_skip(
            "Red Team NON generato: il caso non ha target autorizzati (allowed_targets vuoto). "
            "Apri il caso in Casi → Scope autorizzato e aggiungi almeno un target, poi rilancia il job."
        )
        return None, None
    scope = CaseScope(case_id=case_id or job.get("id", "unknown"))
    for raw in scope_entries_raw:
        e = parse_scope_entry(str(raw), added_by=actor)
        if e:
            scope.add(e)

    legal = case_data.get("legal_basis") or {}
    case_ctx = _ForensicCase(
        case_id=case_id or job.get("id", "unknown"),
        title=(case_data.get("title", "") + " — Red Team") if case_data.get("title") else f"Red Team report {target.value}",
        purpose=case_data.get("purpose", ""),
        legal_basis_type=legal.get("type", "") if isinstance(legal, dict) else "",
        legal_basis_reference=legal.get("reference", "") if isinstance(legal, dict) else "",
        owner=actor,
        collaborators=list(case_data.get("collaborators", []) if isinstance(case_data, dict) else []),
        retention_until=case_data.get("retention_until", "") if isinstance(case_data, dict) else "",
    )

    # Providers state
    providers: list[ProviderUsage] = []
    try:
        caps = capabilities(actor)
        for p in caps.get("search_providers", []):
            if p.get("service") in (None, "all"):
                continue
            providers.append(ProviderUsage(
                name=p.get("label", p.get("service", "?")),
                state=p.get("state", "unknown"),
                message=p.get("message", ""),
                items_returned=0,
            ))
    except Exception:
        pass

    # Red Team findings: prendo tutto ciò che ha severity (di solito dai connettori RT).
    rt_findings = [f for f in investigation.findings if f.severity]

    rctx = _RedTeamContext(
        case=case_ctx, target=target, investigation=investigation,
        ranked_results=[], scope=scope, providers=providers,
        redteam_findings=rt_findings, generated_at=now_iso(),
    )
    report = _build_redteam_report(rctx)

    report_dir.mkdir(parents=True, exist_ok=True)
    md_path = report_dir / "report.redteam.md"
    json_path_out = report_dir / "report.redteam.json"
    md_path.write_text(forensic_to_markdown(report), encoding="utf-8")
    json_path_out.write_text(json.dumps(forensic_to_json(report), indent=2, ensure_ascii=False),
                             encoding="utf-8")
    return md_path, json_path_out


def execute_job(job_id: str, profile: RunProfile, payload: dict, actor: str = "system") -> None:
    job = read_job(job_id)
    try:
        store = get_storage()
        store.append_audit_event(actor, "job_started", {"job_id": job_id, "target_type": profile.target_type})
        if bool(payload.get("allow_darkweb")) and "darkweb" in profile.agents:
            store.append_audit_event(
                actor,
                "darkweb_authorized",
                {"job_id": job_id, "target_type": profile.target_type},
            )
        job.setdefault("progress", []).append({"at": now_iso(), "stage": "running", "message": "Pipeline avviata."})
        job.update({"status": "running", "updated_at": now_iso()})
        write_job(job_id, job)
        report_dir = JOB_ROOT / job_id / "reports"
        args = argparse.Namespace(
            target=profile.target,
            type=profile.target_type,
            command=None,
            depth=profile.depth,
            provider=payload.get("provider", "all"),
            seed_url=profile.seed_urls + list(payload.get("seed_urls") or []),
            max_results=int(payload.get("max_results", 10)),
            max_pages=int(payload.get("max_pages", profile.max_pages)),
            timeout=int(payload.get("timeout", 12)),
            output_dir=str(report_dir),
            format="both",
            agent=profile.agents,
            external_tool=profile.external_tools,
            proxy_url=os.getenv("OSINT_HTTP_PROXY") or os.getenv("OSINT_HTTPS_PROXY") or "",
            allow_network_scan=bool(payload.get("allow_network_scan")),
            allow_darkweb=bool(payload.get("allow_darkweb")),
            include_contact=bool(payload.get("include_contact")),
            confirm_authorization=bool(payload.get("confirm_authorization")),
            api_keys=_resolve_actor_keys(actor),
            case_id=job.get("case_id"),
            actor=actor,
        )
        job.setdefault("progress", []).append({"at": now_iso(), "stage": "collecting", "message": "Raccolta, moduli e report in corso."})
        job.update({"updated_at": now_iso()})
        write_job(job_id, job)
        markdown_path, json_path = run_investigation(args)
        pdf_path = None
        if markdown_path:
            try:
                pdf_path = write_pdf_from_markdown(markdown_path)
                job.setdefault("progress", []).append({"at": now_iso(), "stage": "pdf", "message": "Export PDF generato."})
            except Exception as exc:
                job.setdefault("progress", []).append({"at": now_iso(), "stage": "pdf_error", "message": str(exc)})

        # --- Report forensico a 19 sezioni (parallelo al markdown classico).
        forensic_md_path: Path | None = None
        forensic_json_path: Path | None = None
        try:
            forensic_md_path, forensic_json_path = _generate_forensic_report(
                job=job, profile=profile, payload=payload, actor=actor,
                investigation_json_path=json_path,
                report_dir=report_dir,
            )
            job.setdefault("progress", []).append({
                "at": now_iso(), "stage": "forensic_report",
                "message": "Report forensico a 19 sezioni generato.",
            })
        except Exception as exc:
            LOG.exception("forensic report failed")
            job.setdefault("progress", []).append({
                "at": now_iso(), "stage": "forensic_report_error", "message": str(exc),
            })

        # --- Report Red Team (solo se modulo red_team + scope autorizzato).
        redteam_md_path: Path | None = None
        redteam_json_path: Path | None = None
        try:
            redteam_md_path, redteam_json_path = _generate_redteam_report(
                job=job, profile=profile, payload=payload, actor=actor,
                forensic_md_path=forensic_md_path,
                report_dir=report_dir,
                investigation_json_path=json_path,
            )
            if redteam_md_path:
                job.setdefault("progress", []).append({
                    "at": now_iso(), "stage": "redteam_report",
                    "message": "Report Red Team generato (scope autorizzato).",
                })
        except Exception as exc:
            LOG.exception("redteam report failed")
            job.setdefault("progress", []).append({
                "at": now_iso(), "stage": "redteam_report_error", "message": str(exc),
            })

        # --- Sync best-effort verso Neo4j (grafo) e OpenSearch (full-text).
        # Entrambi sono no-op se non configurati via env; non devono mai
        # interrompere il job (wrap difensivo + funzioni che non sollevano).
        try:
            _sync_external_stores(job_id=job_id, json_path=json_path,
                                  case_id=job.get("case_id") or "", job=job)
        except Exception as exc:
            LOG.warning("external store sync failed: %s", exc)

        job.setdefault("progress", []).append({"at": now_iso(), "stage": "complete", "message": "Report completato."})
        job.update(
            {
                "status": "complete",
                "updated_at": now_iso(),
                "markdown_path": str(markdown_path) if markdown_path else "",
                "json_path": str(json_path) if json_path else "",
                "pdf_path": str(pdf_path) if pdf_path else "",
                "forensic_markdown_path": str(forensic_md_path) if forensic_md_path else "",
                "forensic_json_path": str(forensic_json_path) if forensic_json_path else "",
                "redteam_markdown_path": str(redteam_md_path) if redteam_md_path else "",
                "redteam_json_path": str(redteam_json_path) if redteam_json_path else "",
            }
        )
        get_storage().append_audit_event(actor, "job_completed", {"job_id": job_id, "target_type": profile.target_type})

        # --- Sigillo automatico: firma Ed25519 locale del manifest (evidenze +
        # output). Zero gate, zero rete in uscita — non deve mai far fallire
        # il job (vedi commento su handle_seal_job).
        try:
            handle_seal_job(job_id, job, actor)
        except Exception as exc:
            LOG.warning("report sealing failed: %s", exc)
            get_storage().append_audit_event(
                actor, "report_seal_failed",
                {"job_id": job_id, "case_id": job.get("case_id") or "", "error": str(exc)},
            )
    except Exception as exc:
        job.setdefault("progress", []).append({"at": now_iso(), "stage": "error", "message": str(exc)})
        job.update({"status": "error", "updated_at": now_iso(), "error": str(exc)})
        get_storage().append_audit_event(actor, "job_error", {"job_id": job_id, "target_type": profile.target_type, "error": str(exc)})
    write_job(job_id, job)


def _sync_external_stores(*, job_id: str, json_path, case_id: str, job: dict) -> None:
    """Sincronizza grafo + findings verso Neo4j/OpenSearch se configurati.

    Ricostruisce il grafo dall'investigation JSON con lo stesso builder usato
    dall'endpoint /api/graph, poi delega ai due helper best-effort. Registra
    l'esito nel progress log del job (visibile all'utente) senza mai sollevare.
    """
    if not json_path or not Path(json_path).exists():
        return
    inv = json.loads(Path(json_path).read_text(encoding="utf-8"))

    # OpenSearch: indicizzazione full-text dei findings.
    try:
        from .opensearch_index import index_investigation
        os_res = index_investigation(job_id, inv, case_id=case_id, indexed_at=now_iso())
        if os_res.get("indexed"):
            job.setdefault("progress", []).append({
                "at": now_iso(), "stage": "opensearch",
                "message": f"Indicizzati {os_res.get('count', 0)} findings su OpenSearch.",
            })
    except Exception as exc:
        LOG.warning("opensearch index failed: %s", exc)

    # Neo4j: sync del grafo entità-relazioni.
    try:
        from .neo4j_sync import capabilities as _neo_caps
        from .neo4j_sync import sync_investigation_graph
        if _neo_caps().get("configured"):
            from .models import Evidence as _Ev
            from .models import Finding as _F
            findings = []
            for fd in (inv.get("findings") or []):
                try:
                    findings.append(_F(
                        kind=fd.get("kind", ""), value=str(fd.get("value", "")),
                        confidence=float(fd.get("confidence", 0.5) or 0.5),
                        evidence=[_Ev(**e) for e in (fd.get("evidence") or [])],
                        notes=fd.get("notes", ""), severity=fd.get("severity", ""),
                        attck_ttps=list(fd.get("attck_ttps") or []),
                    ))
                except Exception:
                    pass
            # Stesso builder dell'endpoint /api/graph: resolve_entities + export_d3_json.
            graph = export_d3_json(resolve_entities(findings))
            neo_res = sync_investigation_graph(graph, case_id=case_id)
            if neo_res.get("synced"):
                job.setdefault("progress", []).append({
                    "at": now_iso(), "stage": "neo4j",
                    "message": f"Grafo sincronizzato su Neo4j ({neo_res.get('nodes', 0)} nodi).",
                })
    except Exception as exc:
        LOG.warning("neo4j sync failed: %s", exc)


def profile_to_dict(profile: RunProfile) -> dict:
    return {
        "command": profile.command,
        "target": profile.target,
        "target_type": profile.target_type,
        "agents": profile.agents,
        "external_tools": profile.external_tools,
        "seed_urls": profile.seed_urls,
        "depth": profile.depth,
        "max_pages": profile.max_pages,
        "notes": profile.notes,
    }


def public_settings(payload: dict) -> dict:
    allowed = {
        "provider",
        "source_route",
        "intensity",
        "modules",
        "confirm_authorization",
        "allow_network_scan",
        "allow_darkweb",
        "include_contact",
        "max_results",
        "max_pages",
        "timeout",
    }
    return {key: payload.get(key) for key in allowed if key in payload}


# Connettori che dipendono da un tool locale configurato via env (health_check
# è un semplice controllo di config, senza rete → sicuro nel capabilities).
_LOCAL_TOOL_CONNECTORS = {
    "maigret", "holehe", "ignorant", "ghunt", "toutatis", "theharvester",
    "flowsint", "misp", "phone_meta", "socid_extractor",
    "telegram_checker", "linkedin2username",
}


def _obfuscate_tools(tools: list[dict]) -> list[dict]:
    """Nascondi nomi/env dei tool. Espone solo un placeholder + conteggio."""
    ok = sum(1 for t in tools if t.get("available"))
    total = len(tools)
    if not total:
        return []
    return [{
        "name": "🔒 Tool nascosti",
        "env_var": "",
        "configured": ok > 0,
        "available": True,
        "health_reason": f"{ok}/{total} disponibili. Sblocca con la password amministratore per elencarli.",
        "checked_at": "",
        "description": "Tool di ricerca oscurati a utenti non-admin.",
        "hidden": True,
    }]


def _obfuscate_connectors(conns: list[dict]) -> list[dict]:
    ok = sum(1 for c in conns if c.get("status") == "ok")
    total = len(conns)
    if not total:
        return []
    return [{
        "name": "hidden",
        "label": "🔒 Connettori nascosti",
        "action_class": "passive",
        "input_types": [],
        "output_categories": [],
        "required_key": "",
        "status": "locked",
        "needs": "admin_password",
        "count": total,
        "count_ok": ok,
        "hidden": True,
    }]


def _obfuscate_providers(providers: list[dict]) -> list[dict]:
    configured = sum(1 for p in providers if p.get("configured") and p.get("service") != "all")
    total = sum(1 for p in providers if p.get("service") != "all")
    return [{
        "name": "hidden", "service": "hidden",
        "label": "🔒 Provider nascosti",
        "env_var": "", "state": "locked",
        "configured": configured > 0,
        "message": f"{configured}/{total} configurati. Sblocca per gestirli.",
        "last4": "", "checked_at": "", "category": "Locked",
        "hidden": True,
    }]


def _connector_capabilities(actor: str = "") -> list[dict]:
    """Espone il registro connettori alla UI con uno stato calcolato SENZA rete.

    Stato: 'ok' (nativo o configurato) | 'needs_key' (manca API key BYOK) |
    'needs_config' (manca il tool/credenziale locale via env).
    """
    out: list[dict] = []
    for name in CONNECTOR_REGISTRY.names():
        try:
            conn = CONNECTOR_REGISTRY.get(name)
            spec = conn.spec
        except Exception:
            continue
        needs = ""
        if spec.required_key:
            key = resolve_api_key(spec.required_key, actor) if actor else os.getenv(
                next((e["env_var"] for e in API_KEY_CATALOG if e["service"] == spec.required_key), ""), "")
            status = "ok" if key else "needs_key"
            needs = spec.required_key
        elif name in _LOCAL_TOOL_CONNECTORS:
            try:
                status = "ok" if conn.health_check() else "needs_config"
            except Exception:
                status = "needs_config"
        else:
            status = "ok"  # nativo no-key
        out.append({
            "name": name,
            "label": spec.label,
            "action_class": spec.action_class,
            "input_types": list(spec.input_types),
            "output_categories": list(spec.output_categories),
            "required_key": spec.required_key,
            "status": status,
            "needs": needs,
        })
    return out


def capabilities(actor: str = "", admin_unlocked: bool = False) -> dict:
    """Snapshot delle capabilities runtime per l'utente corrente.

    Per ogni provider in API_KEY_CATALOG, restituisce uno stato semantico
    coerente col backend reale (DB delle chiavi + env var + cache health-check).

    Stati possibili (dal modulo provider_health):
        not_configured | untested | ok | auth_error | quota_exceeded |
        network_error | unsupported
    """
    tools = []
    for name, spec in sorted(TOOL_SPECS.items()):
        health = tool_health_status(name, spec)
        tools.append(
            {
                "name": name,
                "env_var": spec.env_var,
                "configured": health["available"],
                "available": health["available"],
                "health_reason": health["reason"],
                "checked_at": health["checked_at"],
                "description": spec.description,
            }
        )

    # Stato per-provider basato sulle chiavi salvate dall'utente + env var.
    providers: list[dict] = []
    # "all" è sempre disponibile (orchestratore usa quello che c'è + dork).
    providers.append({
        "name": "all", "service": "all", "state": provider_health.STATE_OK,
        "configured": True, "message": "Tutte le API disponibili + dork.",
        "env_var": "n/a", "last4": "", "checked_at": "", "category": "Meta",
    })

    for entry in api_key_catalog_for(actor):
        service = entry["service"]
        key = resolve_api_key(service, actor) if actor else os.getenv(entry["env_var"], "")
        # Cached probe se la chiave c'è, altrimenti not_configured immediato.
        status = provider_health.cached_status(service, key) if key else \
                 provider_health.ProviderStatus(
                     service=service, state=provider_health.STATE_NOT_CONFIGURED,
                     message="Chiave non configurata.",
                     checked_at=provider_health._now_iso(),
                 )
        providers.append({
            "name": service,
            "service": service,
            "label": entry.get("label", service),
            "env_var": entry["env_var"],
            "category": entry.get("category", ""),
            "doc": entry.get("doc", ""),
            "configured": bool(key),
            "state": status.state,
            "message": status.message,
            "last4": status.last4,
            "http_status": status.http_status,
            "latency_ms": status.latency_ms,
            "checked_at": status.checked_at,
        })

    # Tutti gli agenti sempre attivi + i due gated (darkweb, red_team) esposti
    # con marcatura, così la UI può indicare quali richiedono un flag esplicito.
    all_agents = [*ALWAYS_ON_AGENTS, "darkweb", "red_team"]
    try:
        from .enrichment_ai import capabilities as _ai_caps
        ai_caps = _ai_caps()
    except Exception:
        ai_caps = {}
    try:
        from .neo4j_sync import capabilities as _neo_caps
        from .opensearch_index import capabilities as _os_caps
        stores = {"neo4j": _neo_caps(), "opensearch": _os_caps()}
    except Exception:
        stores = {}
    try:
        from .celery_queue import capabilities as _q_caps
        queue_caps = _q_caps()
    except Exception:
        queue_caps = {}
    connectors = _connector_capabilities(actor)
    # Segreto di piattaforma (Fase 22): tool/connettori/provider di ricerca
    # sono OSCURATI a chi non ha sbloccato con la password admin. La UI mostra
    # solo un conteggio aggregato; l'API non svela i nomi.
    if not admin_unlocked:
        tools = _obfuscate_tools(tools)
        connectors = _obfuscate_connectors(connectors)
        providers = _obfuscate_providers(providers)
    tsa_url = tsa_configured()
    return {
        "agents": all_agents,
        "always_on_agents": list(ALWAYS_ON_AGENTS),
        "gated_agents": ["darkweb", "red_team"],
        "admin_unlocked": bool(admin_unlocked),
        "ai_enrichment": ai_caps,
        "external_stores": stores,
        "tools": tools,
        "connectors": connectors,
        "search_providers": providers,
        "auth_enabled": True,
        "signup_enabled": SIGNUPS_ENABLED,
        "plans": ["free", "pro"],
        "queue": {"pending": JOB_QUEUE.pending_count(), **queue_caps},
        "report_sealing": {
            "always_on": True,
            "tsa_configured": bool(tsa_url),
            "tsa_host": (urlparse(tsa_url).hostname or "") if tsa_url else "",
        },
    }


def _auth_capability_fields() -> dict:
    # google_client_id is not a secret — it's meant to be embedded in
    # frontend JS (Google Identity Services reads it from the page).
    enabled = google_login_enabled()
    return {
        "signup_enabled": SIGNUPS_ENABLED,
        "google_login_enabled": enabled,
        "google_client_id": google_client_id() if enabled else "",
    }


def auth_status(handler: OsintHandler) -> dict:
    session = current_session(handler)
    if not session:
        return {"authenticated": False, **_auth_capability_fields()}
    user = load_users().get(session["username"])
    if not user:
        SESSION_STORE.delete(session["id"])
        return {"authenticated": False, **_auth_capability_fields()}
    return {"authenticated": True, "user": public_user(user), "csrf": session["csrf"],
            **_auth_capability_fields()}


def current_session(handler: OsintHandler) -> dict | None:
    cookies = handler.headers.get("Cookie", "")
    session_id = ""
    for part in cookies.split(";"):
        name, sep, value = part.strip().partition("=")
        if sep and name == "osint_session":
            session_id = value
            break
    session = SESSION_STORE.get(session_id)
    if not session:
        return None
    if time.time() - session["last_seen"] > SESSION_TTL_SECONDS:
        SESSION_STORE.delete(session_id)
        return None
    SESSION_STORE.touch(session_id, time.time())
    return session


def load_users() -> dict:
    """Return the full users dict. Kept as a dict for backwards compat with
    existing call-sites that do ``load_users().get(username)``.
    """
    return get_storage().all_users()


def save_users(users: dict) -> None:
    """Upsert each user in the given dict into Storage.

    The old file-backed implementation rewrote the entire users.json on every
    call; Storage upserts the diff. Behaviour is equivalent for any caller
    that round-trips ``load_users()`` → mutate → ``save_users``.
    """
    store = get_storage()
    for username, user in (users or {}).items():
        user.setdefault("username", username)
        store.put_user(user)


def _atomic_write_text(path: Path, content: str) -> None:
    """Replace the file at *path* with *content* atomically.

    Avoids the race where a concurrent reader sees a half-written file (which
    in JSON-land would surface as a 500 from json.loads). Tmp filename is
    per-call-unique so two concurrent writers do not stomp each other's tmp.
    Retries os.replace briefly on Windows: a concurrent reader holding the
    destination open can cause a transient PermissionError there.
    """
    tmp_path = path.with_name(f"{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
    with tmp_path.open("w", encoding="utf-8") as handle:
        handle.write(content)
        handle.flush()
        try:
            os.fsync(handle.fileno())
        except OSError:
            pass
    last_exc: PermissionError | None = None
    for _ in range(10):
        try:
            os.replace(tmp_path, path)
            return
        except PermissionError as exc:
            last_exc = exc
            time.sleep(0.01)
    try:
        tmp_path.unlink(missing_ok=True)
    except OSError:
        pass
    if last_exc is not None:
        raise last_exc


def normalize_username(value: str) -> str:
    username = str(value).strip().lower()
    if not re.fullmatch(r"[a-z0-9_.-]{3,40}", username):
        return ""
    return username


def validate_password(password: str) -> None:
    if len(password) < 12:
        raise WebError(HTTPStatus.BAD_REQUEST, "Password minima: 12 caratteri.")


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 210_000)
    return "pbkdf2_sha256$210000$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(digest).decode()


def verify_password(password: str, stored: str) -> bool:
    try:
        algorithm, rounds, salt_b64, digest_b64 = stored.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(rounds))
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def public_user(user: dict) -> dict:
    return {
        "username": user.get("username", ""),
        "plan": user.get("plan", "free"),
        "created_at": user.get("created_at", ""),
    }


def actor_from_request(handler: OsintHandler) -> str:
    session = current_session(handler)
    if session:
        return session.get("username", "session")
    if handler.headers.get("Authorization") or handler.headers.get("X-OSINT-Token"):
        return "api_token"
    return "anonymous"


def _safe_str_equals(a: str, b: str) -> bool:
    """Constant-time string compare, to avoid leaking the token via timing."""
    return hmac.compare_digest((a or "").encode("utf-8"), (b or "").encode("utf-8"))


def redact_report_json(data: dict) -> dict:
    """Return a copy of the report.json payload with email/phone PII redacted.

    Applied when the served job has include_contact=False. The on-disk report
    keeps the unredacted view for the analyst; this function gates what the
    HTTP layer is allowed to hand back over the wire.
    """
    payload = json.loads(json.dumps(data, ensure_ascii=False))

    target_type = payload.get("target_type", "")
    if target_type == "email":
        payload["target"] = redact_email(payload.get("target", ""))
    elif target_type == "phone":
        payload["target"] = redact_phone(payload.get("target", ""))

    for entity in payload.get("entities", []) or []:
        if entity.get("type") == "email":
            entity["value"] = redact_email(entity.get("value", ""))
            entity["display_value"] = redact_email(entity.get("display_value", ""))
        elif entity.get("type") == "phone":
            entity["value"] = redact_phone(entity.get("value", ""))
            entity["display_value"] = redact_phone(entity.get("display_value", ""))

    for finding in payload.get("findings", []) or []:
        kind = finding.get("kind", "")
        if kind == "contact_email":
            finding["kind"] = "redacted_contact_email"
            finding["value"] = redact_email(finding.get("value", ""))
        elif kind in {"phone_format"}:
            finding["value"] = redact_phone(finding.get("value", ""))

    for agent in payload.get("agent_results", []) or []:
        for finding in agent.get("findings", []) or []:
            kind = finding.get("kind", "")
            if kind == "contact_email":
                finding["kind"] = "redacted_contact_email"
                finding["value"] = redact_email(finding.get("value", ""))
            elif kind == "phone_format":
                finding["value"] = redact_phone(finding.get("value", ""))

    for page in payload.get("pages", []) or []:
        page["emails"] = [redact_email(email) for email in page.get("emails", []) or []]

    return payload


def audit_target(profile: RunProfile) -> str:
    if profile.target_type == "email":
        return redact_email(profile.target)
    if profile.target_type == "phone":
        return redact_phone(profile.target)
    return profile.target


def list_jobs(owner: str = "") -> list[dict]:
    return get_storage().list_jobs(owner=owner, limit=50)


# ---------------------------------------------------------------------------
# Admin unlock — accesso alle funzioni "restricted" (es. ricerca aggressiva).
#
# Credenziali admin: mai in codice.
#   - ``ARGO_ADMIN_USER``           : username admin
#   - ``ARGO_ADMIN_PASSWORD_HASH``  : hash in formato "pbkdf2_sha256$<iter>$<salt_hex>$<hash_hex>"
#
# Il file .env sulla VM ha chmod 600 ed e' caricato via EnvironmentFile della
# unit systemd — NON e' nel repo git. Se le due env non sono impostate,
# l'endpoint fail-close: nessuno puo' sbloccare.
# ---------------------------------------------------------------------------
def verify_admin_credentials(username: str, password: str) -> bool:
    """Verifica user+password admin.

    Confronta ``username`` con ``ARGO_ADMIN_USER`` (case-sensitive) e verifica
    l'hash PBKDF2-SHA256 stored in ``ARGO_ADMIN_PASSWORD_HASH``. Costante-time:
    usa ``hmac.compare_digest`` sia sull'user sia sull'hash calcolato.

    Fail-closed: se una delle due env manca o l'hash e' mal-formato → False.
    """
    admin_user = os.getenv("ARGO_ADMIN_USER", "")
    stored = os.getenv("ARGO_ADMIN_PASSWORD_HASH", "")
    if not admin_user or not stored:
        return False
    if not username or not password:
        return False
    # constant-time username check
    user_ok = hmac.compare_digest(username.encode("utf-8"),
                                  admin_user.encode("utf-8"))
    # Parse "pbkdf2_sha256$<iter>$<salt_hex>$<hash_hex>"
    try:
        algo, iter_s, salt_hex, hash_hex = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        iterations = int(iter_s)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
    except (ValueError, AttributeError):
        return False
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                  salt, iterations, dklen=len(expected))
    hash_ok = hmac.compare_digest(derived, expected)
    # Restituisce True solo se ENTRAMBE le comparazioni sono OK; le eseguo
    # sempre e ANDo alla fine per evitare timing side-channel su user.
    return user_ok and hash_ok


def compliance_warnings(cases: list[dict], jobs: list[dict]) -> list[dict]:
    """Avvisi privacy/compliance derivati, mostrati nella dashboard.

    Solo segnali non bloccanti pensati per ricordare all'analista di mantenere
    la base giuridica documentata e di sorvegliare i job falliti. I messaggi non
    contengono mai dati personali (solo titolo del caso e conteggi aggregati).
    """
    out: list[dict] = []
    if not cases:
        out.append({
            "level": "warning",
            "case_id": "",
            "message": "Nessun caso aperto. Crea un caso con base giuridica prima di avviare ricerche.",
        })
    for case in cases:
        legal = (case.get("legal_basis") or {}).get("type") or ""
        if not legal or legal == "unspecified":
            out.append({
                "level": "warning",
                "case_id": case.get("id", ""),
                "message": f"Il caso «{case.get('title', '')}» non ha una base giuridica chiara.",
            })
    no_scope = sum(1 for case in cases if not (case.get("allowed_targets") or []))
    if cases and no_scope:
        out.append({
            "level": "info",
            "case_id": "",
            "message": f"{no_scope} caso/i senza scope: i moduli red team restano disabilitati.",
        })
    error_jobs = sum(1 for job in jobs if job.get("status") == "error")
    if error_jobs:
        out.append({
            "level": "info",
            "case_id": "",
            "message": f"{error_jobs} job in stato di errore: verifica fonti o autorizzazioni.",
        })
    return out


def admin_stats() -> dict:
    """Metriche di piattaforma (solo admin sbloccato).

    Riusa lo storage esistente: utenti totali/verificati/attivi, job (per stato),
    casi, audit chain (verificabile). Nessun dato personale del target
    dell'indagine viene esposto — solo aggregati.
    """
    store = get_storage()
    users = store.all_users()
    users_total = len(users)
    users_verified = sum(1 for u in users.values() if u.get("verified"))
    users_disabled = sum(1 for u in users.values() if u.get("disabled"))
    # "attivi negli ultimi 7gg" = user con login_success nell'audit chain recente
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    week_ago = (now - timedelta(days=7)).isoformat(timespec="seconds")
    day_ago = (now - timedelta(days=1)).isoformat(timespec="seconds")
    events = store.all_audit_events()
    logins_7d = {e.get("actor") for e in events
                 if e.get("action") == "login_success" and e.get("timestamp", "") >= week_ago}
    logins_24h = {e.get("actor") for e in events
                  if e.get("action") == "login_success" and e.get("timestamp", "") >= day_ago}
    signups_7d = sum(1 for e in events
                     if e.get("action") == "user_signup" and e.get("timestamp", "") >= week_ago)
    # Storico accessi per utente: chi, quando (ultimo), quante volte, con che
    # metodo (password/google) — costruito dagli stessi eventi login_success
    # gia' letti sopra, nessuna query aggiuntiva.
    # Two logins in the same second share an identical second-resolution
    # timestamp string, so sorting/picking "most recent" by that string alone
    # is ambiguous. ``events`` is already seq-ordered (Storage.all_audit_events:
    # ORDER BY seq ASC) — use each event's position in that list as a tie-free
    # recency rank instead.
    login_events_by_user: dict[str, list[tuple[int, dict]]] = {}
    for idx, e in enumerate(events):
        if e.get("action") == "login_success":
            login_events_by_user.setdefault(e.get("actor", ""), []).append((idx, e))
    logins_detail = []
    for uname, user in users.items():
        user_logins = login_events_by_user.get(uname, [])
        last_idx, last_event = user_logins[-1] if user_logins else (-1, None)
        logins_detail.append({
            "username": uname,
            "email": user.get("email", ""),
            "login_count": len(user_logins),
            "last_login": last_event.get("timestamp", "") if last_event else "",
            "last_method": (last_event.get("details") or {}).get("method", "") if last_event else "",
            "provider": user.get("auth_provider", "password"),
            "_recency_rank": last_idx,
        })
    logins_detail.sort(key=lambda d: d["_recency_rank"], reverse=True)
    for row in logins_detail:
        del row["_recency_rank"]
    # Job aggregati per stato
    jobs = store.list_jobs(limit=10_000)
    by_status: dict[str, int] = {}
    for j in jobs:
        by_status[j.get("status", "?")] = by_status.get(j.get("status", "?"), 0) + 1
    # Audit chain integrity
    chain_ok = store.verify_audit_chain()
    return {
        "users": {
            "total": users_total,
            "verified": users_verified,
            "disabled": users_disabled,
            "active_7d": len(logins_7d),
            "active_24h": len(logins_24h),
            "signups_7d": signups_7d,
        },
        "logins": logins_detail,
        "jobs": {
            "total": len(jobs),
            "by_status": by_status,
        },
        "cases": {
            "total": len(store.list_cases(limit=10_000)),
        },
        "audit": {
            "events_total": len(events),
            "chain_valid": bool(chain_ok),
        },
        "signup_enabled": SIGNUPS_ENABLED,
    }


def dashboard_overview(actor: str = "") -> dict:
    """Aggregato per la home/dashboard stile motore di ricerca OSINT.

    Riusa gli helper esistenti (``list_cases_for``, ``list_jobs``,
    ``capabilities``) così la dashboard non duplica logica di storage né di
    health-check. Restituisce solo dati già di proprietà dell'``actor``.
    """
    cases = list_cases_for(actor)
    jobs = list_jobs(actor)

    def _job_ts(job: dict) -> str:
        return str(job.get("updated_at") or job.get("created_at") or "")

    cases_sorted = sorted(cases, key=lambda c: str(c.get("created_at") or ""), reverse=True)
    jobs_sorted = sorted(jobs, key=_job_ts, reverse=True)

    stats = {"queued": 0, "running": 0, "complete": 0, "error": 0}
    for job in jobs:
        status = job.get("status")
        if status in stats:
            stats[status] += 1

    recent_cases = [
        {
            "id": case.get("id", ""),
            "title": case.get("title", ""),
            "status": case.get("status", ""),
            "legal_basis": (case.get("legal_basis") or {}).get("type") or "",
            "created_at": case.get("created_at", ""),
        }
        for case in cases_sorted[:6]
    ]

    recent_jobs = []
    for job in jobs_sorted[:6]:
        profile = job.get("profile") or {}
        recent_jobs.append({
            "id": job.get("id", ""),
            "target": profile.get("target", ""),
            "target_type": profile.get("target_type", ""),
            "status": job.get("status", ""),
            "case_id": job.get("case_id", ""),
            "updated_at": _job_ts(job),
        })

    caps = capabilities(actor)
    providers = caps.get("search_providers") or []
    tools = caps.get("tools") or []
    # Il provider meta "all" è sempre configurato: lo escludo dal rapporto così
    # la copertura riflette le fonti realmente configurate dall'utente.
    real_providers = [p for p in providers if p.get("service") != "all"]
    coverage = {
        "providers_configured": sum(1 for p in real_providers if p.get("configured")),
        "providers_total": len(real_providers),
        "tools_available": sum(1 for t in tools if t.get("available")),
        "tools_total": len(tools),
    }

    # Lista compatta di TUTTI i casi per il selettore della ricerca globale:
    # così il dropdown resta completo ed è alimentato dal backend (niente cache
    # client-side parziale).
    cases_select = [{"id": c.get("id", ""), "title": c.get("title", "")} for c in cases_sorted]

    return {
        "stats": stats,
        "recent_cases": recent_cases,
        "recent_jobs": recent_jobs,
        "cases_select": cases_select,
        "coverage": coverage,
        "warnings": compliance_warnings(cases, jobs),
        "totals": {"cases": len(cases), "jobs": len(jobs)},
    }


def is_job_record(value: dict) -> bool:
    return bool(
        isinstance(value, dict)
        and re.fullmatch(r"[a-f0-9]{32}", str(value.get("id", "")))
        and isinstance(value.get("profile"), dict)
        and value.get("status") in {"queued", "running", "complete", "error"}
    )


def read_job(job_id: str, requester: str = "") -> dict:
    if not re.fullmatch(r"[a-f0-9]{32}", job_id):
        raise WebError(HTTPStatus.BAD_REQUEST, "Job id non valido.")
    job = get_storage().get_job(job_id)
    if job is None:
        raise WebError(HTTPStatus.NOT_FOUND, "Job non trovato.")
    if requester:
        owner = job.get("owner", "")
        # Return 404 (not 403) on owner mismatch so we don't reveal job existence.
        if owner and owner != requester:
            raise WebError(HTTPStatus.NOT_FOUND, "Job non trovato.")
    return job


def write_job(job_id: str, job: dict) -> None:
    get_storage().put_job(job_id, job)


def delete_job_artifacts(job: dict) -> list[str]:
    """Rimuove dal disco TUTTI gli artefatti report associati a un job.

    Tipi coperti: markdown_path, json_path, pdf_path, forensic_markdown_path,
    forensic_json_path, redteam_markdown_path, redteam_json_path. Resilient:
    file gia' assenti vengono ignorati senza errore. Restituisce l'elenco dei
    path effettivamente rimossi (utile per audit trail).
    """
    removed: list[str] = []
    keys = (
        "markdown_path", "json_path", "pdf_path",
        "forensic_markdown_path", "forensic_json_path",
        "redteam_markdown_path", "redteam_json_path",
    )
    for key in keys:
        raw = job.get(key)
        if not raw:
            continue
        try:
            p = Path(str(raw))
            if p.is_file():
                p.unlink()
                removed.append(str(p))
        except OSError:
            # File system error: continue silently — un report che non si
            # cancella non e' una emergenza ed il record DB viene comunque
            # rimosso a valle.
            continue
    return removed


def safe_filename(value: str) -> str:
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", Path(value).name).strip("._-")
    return stem[:120] or "upload.bin"


def _content_disposition(filename: str) -> str:
    """``Content-Disposition: attachment`` header value, filename sanitized
    through the same allow-list as uploads (no CR/LF/quotes reach a header —
    header-injection defense, even though every call site here passes an
    internally-controlled name, not user input)."""
    return f'attachment; filename="{safe_filename(filename)}"'


def parse_multipart_file(raw: bytes, content_type: str) -> tuple[str, bytes]:
    match = re.search(r'boundary="?([^";]+)"?', content_type)
    if not match:
        raise WebError(HTTPStatus.BAD_REQUEST, "Boundary multipart mancante.")
    boundary = f"--{match.group(1)}".encode()
    for part in raw.split(boundary):
        if b' name="file"' not in part or b"filename=" not in part:
            continue
        part = part.strip(b"\r\n")
        if part.endswith(b"--"):
            part = part[:-2]
        if b"\r\n\r\n" not in part:
            continue
        header_blob, body = part.split(b"\r\n\r\n", 1)
        headers = header_blob.decode("utf-8", errors="replace")
        filename_match = re.search(r'filename="([^"]*)"', headers)
        filename = filename_match.group(1) if filename_match else "upload.bin"
        return filename, body.rstrip(b"\r\n")
    return "", b""


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ─────────────────────────────── Privacy Center ───────────────────────────────

def _log_privacy_request(owner: str, req_type: str, reason: str = "") -> dict:
    req_id = hashlib.sha256(f"{owner}:{req_type}:{now_iso()}".encode()).hexdigest()[:16]
    ts = now_iso()
    get_storage().log_privacy_request({
        "id": req_id, "owner": owner, "type": req_type,
        "status": "pending", "reason": reason, "created_at": ts,
    })
    return {"id": req_id, "type": req_type, "status": "pending", "created_at": ts, "reason": reason}


def get_privacy_log(actor: str) -> dict:
    return {"requests": get_storage().list_privacy_requests(actor)}


def _mark_privacy_request_processed(request_id: str) -> None:
    """Flip a privacy_requests row from 'pending' to 'processed'."""
    try:
        get_storage().mark_privacy_request_processed(request_id)
    except Exception:
        LOG.exception("privacy.mark_processed_failed request_id=%s", request_id)


def _collect_user_data(actor: str) -> dict:
    """Return every row of user-owned data that GDPR art. 15 requires
    to be disclosed to the data subject on request.

    Schema-tolerant: probes each table for its actual columns and only
    reads those that are present, so older databases do not break the
    DSAR flow. Backend-agnostic: goes through Storage.select_owned_columns
    (dialect-correct on both SQLite and Postgres), never touches _conn()
    directly — the previous version hand-wrote SQLite-only SQL here
    (?-placeholders, PRAGMA table_info) that broke silently on Postgres.
    """
    stor = get_storage()

    user_rows = stor.select_owned_columns("users", "username", actor,
                                          ["username", "email", "created_at", "verified"])
    user = user_rows[0] if user_rows else {"username": actor}

    try:
        cases = stor.list_cases(actor)
    except Exception:
        cases = []

    jobs = stor.select_owned_columns("jobs", "owner", actor,
                                     ["id", "status", "case_id", "created_at", "updated_at"])
    # api_keys e' keyed su (username, service), non "owner" — la versione
    # precedente interrogava "WHERE owner = ?" su una tabella senza colonna
    # owner: falliva silenziosamente e l'export non rivelava mai le chiavi
    # configurate. Bug verificato empiricamente prima di questo fix.
    api_keys = stor.select_owned_columns("api_keys", "username", actor,
                                         ["service", "created_at"])
    privacy_history = stor.list_privacy_requests(actor)

    return {
        "account": user,
        "cases": cases,
        "jobs": jobs,
        "api_keys_configured": api_keys,
        "privacy_history": privacy_history,
    }


def handle_privacy_export(actor: str) -> dict:
    """GDPR art. 20 — portability. Returns the actual export payload, not
    a promise. The response is the same shape as the DSAR access response
    but delivered as a downloadable bundle in the front-end."""
    rec = _log_privacy_request(actor, "export")
    try:
        data = _collect_user_data(actor)
        export = {
            "actor": actor,
            "exported_at": now_iso(),
            "request_id": rec["id"],
            "gdpr_basis": "Art. 20 GDPR — portability",
            "data": data,
        }
        _mark_privacy_request_processed(rec["id"])
        LOG.info("privacy.export actor=%s request_id=%s cases=%d jobs=%d",
                 actor, rec["id"], len(data["cases"]), len(data["jobs"]))
        return {
            "status": "ok",
            "message": f"Esportazione completata (ID {rec['id']}).",
            "export": export,
        }
    except Exception as exc:  # pragma: no cover - defensive
        LOG.exception("privacy.export_failed actor=%s request_id=%s", actor, rec["id"])
        return {
            "status": "error",
            "message": f"Esportazione fallita (ID {rec['id']}): {exc}",
        }


def handle_privacy_dsar(actor: str) -> dict:
    """GDPR art. 15 — right of access. Returns the same payload as export
    but framed as a subject access response."""
    rec = _log_privacy_request(actor, "dsar")
    try:
        data = _collect_user_data(actor)
        response = {
            "actor": actor,
            "responded_at": now_iso(),
            "request_id": rec["id"],
            "gdpr_basis": "Art. 15 GDPR — right of access",
            "categories_held": sorted(data.keys()),
            "retention_note": (
                "Case data lives in your local SQLite/Postgres. Argo does "
                "not phone home. Deletion is available via /api/privacy/erase."
            ),
            "data": data,
        }
        _mark_privacy_request_processed(rec["id"])
        LOG.info("privacy.dsar actor=%s request_id=%s", actor, rec["id"])
        return {"status": "ok", "response": response}
    except Exception as exc:  # pragma: no cover - defensive
        LOG.exception("privacy.dsar_failed actor=%s request_id=%s", actor, rec["id"])
        return {"status": "error", "message": str(exc)}


def handle_privacy_erase(actor: str, payload: dict) -> dict:
    """GDPR art. 17 — right to erasure.

    Executes a **real** atomic deletion instead of just logging a promise —
    the actual redaction/tombstone/deletion logic lives in
    ``Storage.erase_actor_data`` (SQLite) / ``PostgresStorage.erase_actor_data``
    (Postgres), one implementation per backend in its own dialect, mirroring
    how ``append_audit_event`` is already split per-backend. This function
    only logs the request and formats the response.

    The whole erasure is atomic; if any step fails inside
    ``erase_actor_data`` the deletion is rolled back and the actor's account
    is left intact.
    """
    reason = str(payload.get("reason", "")).strip()[:500]
    rec = _log_privacy_request(actor, "erase", reason)
    LOG.warning("privacy.erase_request actor=%s request_id=%s reason=%s",
                actor, rec["id"], reason[:80])

    redacted_placeholder = f"[REDACTED-DSAR-{now_iso()[:10]}]"
    try:
        result = get_storage().erase_actor_data(
            actor, request_id=rec["id"], redacted_placeholder=redacted_placeholder,
        )
        LOG.warning(
            "privacy.erase_completed actor_hash=%s request_id=%s tombstone=%s "
            "redacted_events=%d deleted=%s",
            result["selector_sha256"][:16], rec["id"], result["tombstone_id"],
            result["redacted_events_count"], result["deleted_counts"],
        )
        return {
            "status": "ok",
            "message": (
                f"Cancellazione eseguita (richiesta {rec['id']}). "
                f"Tombstone: {result['tombstone_id']}. L'account non è più recuperabile "
                f"dal filesystem attivo; eventuali backup restano soggetti "
                f"alla policy di rotazione del datastore."
            ),
            "request_id": rec["id"],
            "tombstone_id": result["tombstone_id"],
            "selector_sha256": result["selector_sha256"],
            "erased_at": result["erased_at"],
        }
    except Exception as exc:
        LOG.exception("privacy.erase_failed actor=%s request_id=%s", actor, rec["id"])
        return {
            "status": "error",
            "message": f"Cancellazione fallita (ID {rec['id']}): {exc}. Nessun dato è stato modificato.",
        }


# ------------------------------------------------------------------------
# Agenti IA (LLM, opt-in) — vedi llm_client.py / ai_context.py /
# narrative_synthesis.py / policy.py (nessun action_class dedicato: vedi
# _require_ai_enabled_case per i tre gate indipendenti usati al suo posto).
# ------------------------------------------------------------------------

def _require_ai_agents_enabled() -> None:
    """Kill-switch di deployment. 404 (non 403) per non rivelare l'esistenza
    della feature quando l'operatore l'ha disattivata del tutto."""
    if not ai_agents_enabled():
        raise WebError(HTTPStatus.NOT_FOUND, "Endpoint non trovato.")


def _require_ai_enabled_case(case_id: str, actor: str) -> dict:
    """I tre gate indipendenti, in ordine: kill-switch server -> consenso
    per-caso -> (a valle, nel chiamante) presenza della chiave BYOK. Ognuno
    fallisce chiuso: un caso non trovato o senza consenso non genera mai
    una chiamata LLM."""
    _require_ai_agents_enabled()
    case = read_case(case_id, requester=actor)
    if not case.get("ai_enrichment_enabled"):
        raise WebError(HTTPStatus.FORBIDDEN, "Arricchimento AI non abilitato per questo caso.")
    return case


def _resolve_llm_credentials(provider: str, actor: str) -> tuple[str, str]:
    """Ritorna (api_key, base_url). Per 'local' il valore salvato è
    'base_url|token' (llm_client.parse_local_value); per anthropic/openai
    api_key è il valore diretto e base_url resta vuoto. Nessuna chiave
    configurata -> entrambi vuoti (il chiamante decide come rispondere)."""
    from . import llm_client
    value = resolve_api_key(f"llm_{provider}", actor)
    if provider == "local":
        base_url, token = llm_client.parse_local_value(value)
        return token, base_url
    return value, ""


def _resolve_llm_model(provider: str, requested_model: str) -> str:
    from . import llm_client
    if requested_model:
        return requested_model
    if provider == "anthropic":
        return llm_client.DEFAULT_ANTHROPIC_MODEL
    if provider == "openai":
        return llm_client.DEFAULT_OPENAI_MODEL
    return os.getenv("LOCAL_LLM_MODEL", "")


def set_case_ai_settings(case_id: str, payload: dict, actor: str) -> dict:
    """Owner-only, stesso controllo di sign_roe. Consenso per-caso alle
    capability IA — indipendente dal kill-switch OSINT_AI_AGENTS_ENABLED."""
    _require_ai_agents_enabled()
    case = read_case(case_id, requester=actor)
    if case["owner"] != actor:
        raise WebError(HTTPStatus.FORBIDDEN, "Solo l'owner del caso può modificare le impostazioni IA.")
    enabled = bool(payload.get("ai_enrichment_enabled"))
    store = get_storage()
    store.set_case_ai_enrichment(case_id, enabled)
    store.append_audit_event(
        actor,
        "case_ai_enrichment_enabled" if enabled else "case_ai_enrichment_disabled",
        {"case_id": case_id},
    )
    return read_case(case_id, requester=actor)


# ------------------------------------------------------------ report sealing

_REPORT_PATH_FIELDS = (
    "markdown_path", "json_path", "pdf_path",
    "forensic_markdown_path", "forensic_json_path",
    "redteam_markdown_path", "redteam_json_path",
)


def _report_paths_from_job(job: dict) -> dict[str, str]:
    """Stessa tupla di campi di delete_job_artifacts — i path dei report
    finali di un job, così com'è, filtrati dai vuoti a valle da
    custody.register_report_artifacts."""
    return {key: job.get(key, "") for key in _REPORT_PATH_FIELDS}


def handle_seal_job(job_id: str, job: dict, actor: str) -> dict:
    """Sigilla i report di un job: registra i file di output come artifact
    (custody.register_report_artifacts), produce il manifest dell'intero
    caso (custody.export_case_manifest — vedi il commento in custody.py sul
    perché è case-scoped, non job-scoped) e lo firma con la chiave Ed25519
    locale dell'istanza (report_signing.py). Zero gate, zero rete in uscita:
    chiamata automaticamente al completamento di ogni job. Il chiamante
    (execute_job) la avvolge in try/except — un fallimento qui non deve mai
    far fallire il job."""
    from . import custody, report_signing

    case_id = job.get("case_id") or ""
    store = get_storage()
    custody.register_report_artifacts(
        job_id=job_id, case_id=case_id, report_paths=_report_paths_from_job(job),
        storage=store, job_root=JOB_ROOT, actor=actor,
    )
    manifest = custody.export_case_manifest(case_id, store, JOB_ROOT)
    signature = report_signing.sign_digest(manifest["manifest_hash"], JOB_ROOT)
    seal = store.put_report_seal({
        "case_id": case_id,
        "job_id": job_id,
        "manifest_hash": manifest["manifest_hash"],
        "artifact_count": manifest["artifact_count"],
        "signature_b64": signature["signature_b64"],
        "signing_pubkey_b64": signature["public_key_b64"],
        "signing_pubkey_fingerprint": signature["fingerprint_sha256"],
        "sealed_by": actor,
    })
    store.append_audit_event(actor, "report_sealed", {
        "job_id": job_id, "case_id": case_id,
        "manifest_hash": manifest["manifest_hash"],
        "artifact_count": manifest["artifact_count"],
        "signing_pubkey_fingerprint": signature["fingerprint_sha256"],
    })
    return seal


def handle_get_seal(job_id: str, actor: str) -> dict:
    """GET /api/jobs/<id>/seal — il sigillo di un job, con istruzioni di
    verifica indipendente. 404 se il job non è ancora stato sigillato (job
    non completo, o il sigillo automatico è fallito)."""
    read_job(job_id, requester=actor)  # visibility check, stesso pattern degli altri job endpoint
    seal = get_storage().get_report_seal(job_id)
    if seal is None:
        raise WebError(HTTPStatus.NOT_FOUND, "Nessun sigillo per questo job.")
    seal = dict(seal)
    seal["verify_hint"] = (
        "openssl ts -reply -in token.der -text  # decodifica il token RFC3161 (se presente)\n"
        "La firma Ed25519 si verifica con la chiave pubblica dell'istanza "
        "(GET /api/report-signing/public-key) sul digest SHA-256 del manifest."
    )
    return seal


def handle_request_tsa_timestamp(job_id: str, actor: str) -> dict:
    """POST /api/jobs/<id>/seal/tsa-timestamp — richiede un timestamp RFC3161
    esterno sul manifest_hash già sigillato. 404 se TSA_URL non è configurato
    (stesso pattern 'invisibile se non configurato' del resto del catalogo
    BYO). Verso la TSA esce solo il digest SHA-256 (32 byte) — mai contenuto
    del caso — motivo per cui questo endpoint non ha bisogno del consenso
    per-caso della feature IA: e' un solo gate leggero, non tre."""
    from . import tsa_client

    tsa_url = tsa_configured()
    if not tsa_url:
        raise WebError(HTTPStatus.NOT_FOUND, "Endpoint non trovato.")

    read_job(job_id, requester=actor)  # visibility check, stesso pattern degli altri job endpoint
    store = get_storage()
    seal = store.get_report_seal(job_id)
    if seal is None:
        raise WebError(HTTPStatus.NOT_FOUND, "Nessun sigillo per questo job: sigillalo prima di richiedere un timestamp.")

    tsa_host = urlparse(tsa_url).hostname or tsa_url
    requested_at = now_iso()
    store.append_audit_event(actor, "report_timestamp_requested", {
        "job_id": job_id, "case_id": seal["case_id"], "tsa_host": tsa_host,
    })
    result = tsa_client.request_timestamp(tsa_url, seal["manifest_hash"])
    updated = store.update_report_seal_tsa(
        job_id, tsa_url_host=tsa_host, tsa_status=result.status or result.error_class,
        tsa_token_der_b64=result.token_der_b64, tsa_gen_time=result.gen_time,
        tsa_requested_at=requested_at,
    )
    store.append_audit_event(
        actor,
        "report_timestamp_received" if result.ok else "report_timestamp_failed",
        {
            "job_id": job_id, "case_id": seal["case_id"], "tsa_host": tsa_host,
            "status": result.status, "error_class": result.error_class,
            "http_status": result.http_status,
        },
    )
    if not result.ok:
        raise WebError(HTTPStatus.BAD_GATEWAY, result.error or "Richiesta di timestamp fallita.")
    return updated


def handle_ai_narrative(payload: dict, actor: str) -> dict:
    """POST /api/ai/narrative — sintesi narrativa del caso con citazioni.
    Mai un merge/scrittura automatica: l'output è restituito al chiamante,
    che decide come mostrarlo (vedi ReportContext.ai_narrative per l'hook
    fase 2, non ancora attivo)."""
    from . import ai_context, llm_client, narrative_synthesis

    case_id = str(payload.get("case_id") or "").strip()
    if not case_id:
        raise WebError(HTTPStatus.BAD_REQUEST, "Parametro 'case_id' obbligatorio.")
    case = _require_ai_enabled_case(case_id, actor)

    job_id = str(payload.get("job_id") or "").strip()
    provider = str(payload.get("provider") or "").strip()
    if provider not in llm_client.LLM_PROVIDERS:
        raise WebError(HTTPStatus.BAD_REQUEST, "Parametro 'provider' non valido (anthropic|openai|local).")
    lang = str(payload.get("lang") or "it").strip().lower()
    if lang not in ("it", "en"):
        lang = "it"
    max_findings = min(int(payload.get("max_findings") or 150), 400)

    api_key, base_url = _resolve_llm_credentials(provider, actor)
    if not api_key and not base_url:
        raise WebError(HTTPStatus.BAD_REQUEST, "Nessuna chiave AI configurata per questo provider.")
    model = _resolve_llm_model(provider, str(payload.get("model") or "").strip())

    run_id = uuid.uuid4().hex
    started = time.monotonic()
    response, validation, collected = narrative_synthesis.generate(
        case_id=case_id, case_title=case.get("title", ""), job_id=job_id, lang=lang,
        provider=provider, model=model, api_key=api_key, base_url=base_url,
        max_findings=max_findings,
    )
    duration_ms = int((time.monotonic() - started) * 1000)

    # Ricostruito solo per il conteggio byte nell'audit — pure funzioni di
    # formattazione stringa, nessuna seconda chiamata di rete.
    sys_prompt, usr_prompt = narrative_synthesis.build_prompt(
        collected.refs, case_title=case.get("title", ""), lang=lang,
    )
    byte_count_sent = ai_context.estimate_prompt_bytes(sys_prompt, usr_prompt)
    byte_count_received = len(response.raw_text.encode("utf-8"))

    store = get_storage()
    status = "ok" if validation.ok else "error"
    store.put_ai_run({
        "id": run_id, "case_id": case_id, "kind": "narrative", "actor": actor,
        "provider": provider, "model": model, "status": status,
        "input_summary": {
            "finding_count_sent": len(collected.refs),
            "truncated": collected.truncated,
            "total_available": collected.total_available,
        },
        "output_json": validation.parsed if validation.ok else {},
        "error": "" if validation.ok else (validation.error or response.error),
    })
    store.append_audit_event(actor, "ai_narrative_generated", {
        "case_id": case_id, "run_id": run_id, "kind": "narrative",
        "provider": provider, "model": model, "status": status,
        "error_class": response.error_class,
        "finding_count_sent": len(collected.refs),
        "byte_count_sent": byte_count_sent, "byte_count_received": byte_count_received,
        "duration_ms": duration_ms, "job_ids": sorted({r.job_id for r in collected.refs}),
    })

    if not validation.ok:
        raise WebError(HTTPStatus.BAD_GATEWAY,
                       validation.error or response.error or "Generazione narrativa fallita.")
    return {
        "run_id": run_id,
        "case_id": case_id,
        "narrative": validation.parsed,
        "truncated": collected.truncated,
        "total_available": collected.total_available,
        "finding_count_sent": len(collected.refs),
    }


def handle_ai_entity_suggestions(payload: dict, actor: str) -> dict:
    """POST /api/ai/entity-suggestions — coppie di entità candidate a essere
    lo stesso soggetto. Le coppie sono generate deterministicamente (nessun
    LLM) da entity_resolution_ai.candidate_pairs prima di essere inviate."""
    from . import ai_context, entity_resolution_ai, llm_client

    case_id = str(payload.get("case_id") or "").strip()
    if not case_id:
        raise WebError(HTTPStatus.BAD_REQUEST, "Parametro 'case_id' obbligatorio.")
    _require_ai_enabled_case(case_id, actor)

    provider = str(payload.get("provider") or "").strip()
    if provider not in llm_client.LLM_PROVIDERS:
        raise WebError(HTTPStatus.BAD_REQUEST, "Parametro 'provider' non valido (anthropic|openai|local).")
    lang = str(payload.get("lang") or "it").strip().lower()
    if lang not in ("it", "en"):
        lang = "it"
    max_pairs = min(int(payload.get("max_pairs") or 40), 100)

    api_key, base_url = _resolve_llm_credentials(provider, actor)
    if not api_key and not base_url:
        raise WebError(HTTPStatus.BAD_REQUEST, "Nessuna chiave AI configurata per questo provider.")
    model = _resolve_llm_model(provider, str(payload.get("model") or "").strip())

    run_id = uuid.uuid4().hex
    started = time.monotonic()
    response, validation, collected = entity_resolution_ai.generate(
        case_id=case_id, lang=lang, provider=provider, model=model,
        api_key=api_key, base_url=base_url, max_pairs=max_pairs,
    )
    duration_ms = int((time.monotonic() - started) * 1000)

    store = get_storage()
    if response is None:
        # Nessuna coppia candidata: nessuna chiamata LLM è mai partita, nulla
        # da loggare come 'ai_entity_suggestions_generated' (non è successo
        # nulla che riguardi un provider esterno).
        return {"run_id": run_id, "case_id": case_id, "verdicts": [],
               "candidates_total": 0, "candidates_truncated": False, "dropped_hallucinated": 0}

    status = "ok" if validation.ok else "error"
    # collected.pairs esiste sempre a questo punto (siamo passati oltre il
    # return anticipato per "nessuna coppia") indipendentemente dal fatto
    # che la chiamata LLM sia andata a buon fine: il prompt è stato
    # comunque costruito e inviato.
    sys_prompt, usr_prompt = entity_resolution_ai.build_prompt(collected.pairs, lang=lang)
    byte_count_sent = ai_context.estimate_prompt_bytes(sys_prompt, usr_prompt)
    store.put_ai_run({
        "id": run_id, "case_id": case_id, "kind": "entity_suggestions", "actor": actor,
        "provider": provider, "model": model, "status": status,
        "input_summary": {"candidates_sent": len(collected.pairs), "candidates_truncated": collected.truncated,
                          "candidates_total": collected.total_available},
        "output_json": {"verdicts": validation.verdicts, "dropped_hallucinated": validation.dropped_hallucinated}
                       if validation.ok else {},
        "error": "" if validation.ok else (validation.error or response.error),
    })
    store.append_audit_event(actor, "ai_entity_suggestions_generated", {
        "case_id": case_id, "run_id": run_id, "kind": "entity_suggestions",
        "provider": provider, "model": model, "status": status,
        "error_class": response.error_class,
        "finding_count_sent": len(collected.pairs),
        "byte_count_sent": byte_count_sent,
        "byte_count_received": len(response.raw_text.encode("utf-8")),
        "duration_ms": duration_ms, "job_ids": [],
    })

    if not validation.ok:
        raise WebError(HTTPStatus.BAD_GATEWAY, validation.error or response.error or "Generazione suggerimenti fallita.")
    return {
        "run_id": run_id,
        "case_id": case_id,
        "verdicts": validation.verdicts,
        "candidates_total": collected.total_available,
        "candidates_truncated": collected.truncated,
        "dropped_hallucinated": validation.dropped_hallucinated,
    }


def handle_ai_entity_decide(payload: dict, actor: str) -> dict:
    """POST /api/ai/entity-suggestions/decide — decisione UMANA su una coppia
    suggerita. Nessuna chiamata LLM. Scrive solo in entity_merge_decisions:
    non tocca mai link_analysis.resolve_entities() né l'Investigation
    salvata — il 'mai auto-merged' è garantito a livello di modello dati."""
    case_id = str(payload.get("case_id") or "").strip()
    entity_id_a = str(payload.get("entity_id_a") or "").strip()
    entity_id_b = str(payload.get("entity_id_b") or "").strip()
    decision = str(payload.get("decision") or "").strip()
    if not case_id or not entity_id_a or not entity_id_b:
        raise WebError(HTTPStatus.BAD_REQUEST, "Parametri 'case_id', 'entity_id_a', 'entity_id_b' obbligatori.")
    if decision not in ("confirmed", "rejected"):
        raise WebError(HTTPStatus.BAD_REQUEST, "Parametro 'decision' deve essere 'confirmed' o 'rejected'.")
    # read_case applica il controllo di visibilità owner/collaboratore
    # (404 non 403, coerente col resto della piattaforma); non richiede il
    # kill-switch IA: revocare/confermare una decisione già presa deve
    # restare possibile anche a feature IA disattivata nel frattempo.
    read_case(case_id, requester=actor)

    ordered_a, ordered_b = sorted((entity_id_a, entity_id_b))
    store = get_storage()
    record = store.put_entity_merge_decision({
        "case_id": case_id, "entity_id_a": ordered_a, "entity_id_b": ordered_b,
        "decision": decision, "decided_by": actor,
        "ai_run_id": str(payload.get("ai_run_id") or "") or None,
        "ai_confidence": payload.get("ai_confidence"),
        "ai_rationale": str(payload.get("ai_rationale") or "")[:500],
    })
    store.append_audit_event(
        actor, "entity_merge_confirmed" if decision == "confirmed" else "entity_merge_rejected",
        {"case_id": case_id, "entity_id_a": ordered_a, "entity_id_b": ordered_b},
    )
    return record


def handle_ai_triage(payload: dict, actor: str) -> dict:
    """POST /api/ai/triage — priorità investigativa consultiva. Non filtra
    né nasconde mai un finding: solo ordinamento/badge, con fallback
    deterministico per tutto ciò che l'IA non ha coperto (vedi
    triage_ai.generate — coverage['fallback_ranked'])."""
    from . import ai_context, llm_client, triage_ai

    case_id = str(payload.get("case_id") or "").strip()
    if not case_id:
        raise WebError(HTTPStatus.BAD_REQUEST, "Parametro 'case_id' obbligatorio.")
    _require_ai_enabled_case(case_id, actor)

    job_id = str(payload.get("job_id") or "").strip()
    provider = str(payload.get("provider") or "").strip()
    if provider not in llm_client.LLM_PROVIDERS:
        raise WebError(HTTPStatus.BAD_REQUEST, "Parametro 'provider' non valido (anthropic|openai|local).")
    lang = str(payload.get("lang") or "it").strip().lower()
    if lang not in ("it", "en"):
        lang = "it"

    api_key, base_url = _resolve_llm_credentials(provider, actor)
    if not api_key and not base_url:
        raise WebError(HTTPStatus.BAD_REQUEST, "Nessuna chiave AI configurata per questo provider.")
    model = _resolve_llm_model(provider, str(payload.get("model") or "").strip())

    run_id = uuid.uuid4().hex
    started = time.monotonic()
    result = triage_ai.generate(
        case_id=case_id, job_id=job_id, lang=lang, provider=provider, model=model,
        api_key=api_key, base_url=base_url,
    )
    duration_ms = int((time.monotonic() - started) * 1000)

    byte_count_sent = 0
    byte_count_received = 0
    for batch, response in zip(triage_ai.split_into_batches(result.collected.refs), result.responses, strict=True):
        sys_prompt, usr_prompt = triage_ai.build_prompt(batch, lang=lang)
        byte_count_sent += ai_context.estimate_prompt_bytes(sys_prompt, usr_prompt)
        byte_count_received += len(response.raw_text.encode("utf-8"))

    # Un run è considerato riuscito se almeno un batch ha risposto — un
    # fallimento parziale resta visibile in coverage, non nasconde nulla,
    # e non deve mai risultare in un 502 quando il fallback ha comunque
    # coperto ogni finding con un bucket deterministico.
    any_batch_ok = any(r.ok for r in result.responses) if result.responses else True
    status = "ok" if any_batch_ok else "error"

    store = get_storage()
    store.put_ai_run({
        "id": run_id, "case_id": case_id, "kind": "triage", "actor": actor,
        "provider": provider, "model": model, "status": status,
        "input_summary": result.coverage,
        "output_json": {"rankings": result.rankings} if any_batch_ok else {},
        "error": "" if any_batch_ok else "; ".join(r.error for r in result.responses if r.error),
    })
    store.append_audit_event(actor, "ai_triage_generated", {
        "case_id": case_id, "run_id": run_id, "kind": "triage",
        "provider": provider, "model": model, "status": status,
        "finding_count_sent": result.coverage["ai_ranked"] + result.coverage.get("dropped_hallucinated", 0),
        "byte_count_sent": byte_count_sent, "byte_count_received": byte_count_received,
        "duration_ms": duration_ms,
        "job_ids": sorted({r.job_id for r in result.collected.refs}),
    })

    if not any_batch_ok:
        errors = "; ".join(r.error for r in result.responses if r.error) or "Generazione triage fallita."
        raise WebError(HTTPStatus.BAD_GATEWAY, errors)

    return {
        "run_id": run_id,
        "case_id": case_id,
        "rankings": result.rankings,
        "coverage": result.coverage,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="OSINT Bot web platform")
    parser.add_argument("--host", default=os.getenv("OSINT_WEB_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("OSINT_WEB_PORT", "8000")))
    args = parser.parse_args(argv)

    migrated_cases = recover_legacy_jobs_into_cases()
    if migrated_cases:
        print(f"Migrated {migrated_cases} legacy job(s) into per-owner legacy cases.")
    recovered = recover_queued_jobs()
    if recovered:
        print(f"Recovered {recovered} queued/running job(s) from a previous run.")
    server = ThreadingHTTPServer((args.host, args.port), OsintHandler)
    print(f"OSINT Bot web listening on http://{args.host}:{args.port}")
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
