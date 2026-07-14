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
import sqlite3
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
]


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
    for entry in API_KEY_CATALOG:
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
                return self.send_json({"keys": get_storage().list_api_keys(actor), "catalog": API_KEY_CATALOG})
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
                if service not in {entry["service"] for entry in API_KEY_CATALOG}:
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
                return self.send_json({"keys": store.list_api_keys(actor), "catalog": API_KEY_CATALOG})
            if path == "/api/keys/test":
                sess = current_session(self)
                if not (sess and sess.get("admin_unlocked")):
                    raise WebError(HTTPStatus.FORBIDDEN, "Sblocca con la password amministratore per testare le chiavi API.")
                # Test on-demand di una chiave (NON la salva, solo verifica).
                # Usa la chiave già salvata se non viene fornita "value" nel payload.
                payload = self.read_json()
                actor = actor_from_request(self)
                service = str(payload.get("service") or "").strip()
                if service not in {entry["service"] for entry in API_KEY_CATALOG}:
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
                )
            return self.send_file(Path(report_path), content_type)
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

    def send_file(self, path: Path, content_type: str) -> None:
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
        self.end_headers()
        self.wfile.write(data)

    def send_raw(self, data: bytes, content_type: str) -> None:
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
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

    for entry in API_KEY_CATALOG:
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
    }


def auth_status(handler: OsintHandler) -> dict:
    session = current_session(handler)
    if not session:
        return {"authenticated": False, "signup_enabled": SIGNUPS_ENABLED}
    user = load_users().get(session["username"])
    if not user:
        SESSION_STORE.delete(session["id"])
        return {"authenticated": False, "signup_enabled": SIGNUPS_ENABLED}
    return {"authenticated": True, "user": public_user(user), "csrf": session["csrf"], "signup_enabled": SIGNUPS_ENABLED}


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

def _privacy_table_exists() -> bool:
    stor = get_storage()
    try:
        stor._conn().execute("SELECT 1 FROM privacy_requests LIMIT 1")
        return True
    except Exception:
        return False


def _ensure_privacy_table() -> None:
    stor = get_storage()
    con = stor._conn()
    con.execute("""
        CREATE TABLE IF NOT EXISTS privacy_requests (
            id TEXT PRIMARY KEY,
            owner TEXT NOT NULL,
            type TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            reason TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            processed_at TEXT
        )
    """)
    con.commit()


def _log_privacy_request(owner: str, req_type: str, reason: str = "") -> dict:
    _ensure_privacy_table()
    import hashlib as _hl
    req_id = _hl.sha256(f"{owner}:{req_type}:{now_iso()}".encode()).hexdigest()[:16]
    ts = now_iso()
    get_storage()._conn().execute(
        "INSERT OR IGNORE INTO privacy_requests (id, owner, type, status, reason, created_at) VALUES (?,?,?,?,?,?)",
        (req_id, owner, req_type, "pending", reason, ts),
    )
    get_storage()._conn().commit()
    return {"id": req_id, "type": req_type, "status": "pending", "created_at": ts, "reason": reason}


def get_privacy_log(actor: str) -> dict:
    _ensure_privacy_table()
    rows = get_storage()._conn().execute(
        "SELECT id, type, status, reason, created_at, processed_at FROM privacy_requests WHERE owner=? ORDER BY created_at DESC LIMIT 50",
        (actor,),
    ).fetchall()
    requests = [
        {"id": r[0], "type": r[1], "status": r[2], "reason": r[3], "created_at": r[4], "processed_at": r[5]}
        for r in rows
    ]
    return {"requests": requests}


def _mark_privacy_request_processed(request_id: str) -> None:
    """Flip a privacy_requests row from 'pending' to 'processed'."""
    try:
        get_storage()._conn().execute(
            "UPDATE privacy_requests SET status = ?, processed_at = ? WHERE id = ?",
            ("processed", now_iso(), request_id),
        )
        get_storage()._conn().commit()
    except Exception:
        LOG.exception("privacy.mark_processed_failed request_id=%s", request_id)


def _table_columns(conn, table: str) -> list[str]:
    """Return the column names of ``table`` or [] if the table is absent.
    Used to make the DSAR collector schema-tolerant."""
    try:
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
        return [r[1] for r in rows]
    except Exception:
        return []


def _safe_select(conn, table: str, actor: str,
                 wanted: list[str], where_col: str = "owner") -> list[dict]:
    """SELECT only those wanted columns that actually exist in table.
    Returns a list of dicts keyed by column name, [] on any failure."""
    cols = [c for c in wanted if c in _table_columns(conn, table)]
    if not cols:
        return []
    q = f"SELECT {', '.join(cols)} FROM {table} WHERE {where_col} = ?"
    try:
        rows = conn.execute(q, (actor,)).fetchall()
    except Exception:
        return []
    return [dict(zip(cols, r, strict=False)) for r in rows]


def _collect_user_data(actor: str) -> dict:
    """Return every row of user-owned data that GDPR art. 15 requires
    to be disclosed to the data subject on request.

    Schema-tolerant: probes each table for its actual columns and only
    reads those that are present, so older databases do not break the
    DSAR flow.
    """
    stor = get_storage()
    conn = stor._conn()

    user_rows = _safe_select(conn, "users", actor,
                             ["username", "email", "created_at", "verified"],
                             where_col="username")
    user = user_rows[0] if user_rows else {"username": actor}

    try:
        cases = stor.list_cases(actor)
    except Exception:
        cases = []

    jobs = _safe_select(conn, "jobs", actor,
                        ["id", "status", "case_id", "created_at", "updated_at"])
    api_keys = _safe_select(conn, "api_keys", actor,
                            ["service", "created_at"])
    privacy_history = _safe_select(
        conn, "privacy_requests", actor,
        ["id", "type", "status", "reason", "created_at", "processed_at"],
    )

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

    Executes a **real** atomic deletion instead of just logging a promise:

    1. INSERT a ``privacy_requests`` row for the audit trail.
    2. Redact the actor's personal fields from every ``audit_events`` row
       that mentions them (case_id is hashed, target strings are replaced
       by a stable placeholder).
    3. Append a new ``audit_events`` row of kind ``account_erased_dsar``
       so the chain moves forward with the erasure recorded.
    4. INSERT a ``dsar_tombstones`` row with a SHA-256 selector of the
       erased subject and the last audit hash, so future proof-of-erasure
       requests can be answered without re-disclosing the subject.
    5. DELETE the actor's rows from ``cases``, ``jobs``, ``artifacts``,
       ``roes``, ``api_keys`` and finally ``users``.
    6. Flip the privacy_requests row to ``processed`` and return the
       tombstone_id and the request_id.

    The whole transaction is atomic; if any step fails the deletion is
    rolled back and the actor's account is left intact.
    """
    reason = str(payload.get("reason", "")).strip()[:500]
    rec = _log_privacy_request(actor, "erase", reason)
    LOG.warning("privacy.erase_request actor=%s request_id=%s reason=%s",
                actor, rec["id"], reason[:80])

    import hashlib as _hl
    import json as _json
    import uuid as _uuid

    ts = now_iso()
    selector_bytes = f"user:{actor.lower()}".encode()
    selector_hash = _hl.sha256(selector_bytes).hexdigest()
    tomb_id = "TOMB-" + _uuid.uuid4().hex[:12]
    redacted = f"[REDACTED-DSAR-{ts[:10]}]"

    stor = get_storage()
    db = stor._conn()

    try:
        db.execute("BEGIN")

        # 2. Redact the actor's identifiers in audit_events.
        rows = db.execute(
            "SELECT seq, actor, details FROM audit_events "
            "WHERE actor = ? OR details LIKE ?",
            (actor, f"%{actor}%"),
        ).fetchall()
        redacted_seqs: list[int] = []
        for seq, ev_actor, details in rows:
            new_actor = redacted if ev_actor == actor else ev_actor
            new_details = details or ""
            if actor in new_details:
                new_details = new_details.replace(actor, redacted)
            if new_actor != ev_actor or new_details != (details or ""):
                db.execute(
                    "UPDATE audit_events SET actor = ?, details = ? WHERE seq = ?",
                    (new_actor, new_details, seq),
                )
                redacted_seqs.append(seq)

        # 3. Append the account_erased_dsar event.
        last = db.execute(
            "SELECT hash FROM audit_events ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        prev_hash = last[0] if last else ""
        new_seq_row = db.execute(
            "SELECT COALESCE(MAX(seq), 0) + 1 FROM audit_events"
        ).fetchone()
        new_seq = new_seq_row[0] if new_seq_row else 1
        details_json = _json.dumps({
            "subject_hash": selector_hash,
            "tombstone_id": tomb_id,
            "privacy_request_id": rec["id"],
            "reason": "GDPR art. 17 erasure",
            "redacted_seqs_count": len(redacted_seqs),
        })
        canonical = f"{new_seq}|{ts}|system|account_erased_dsar|{details_json}|{prev_hash}"
        new_hash = _hl.sha256(canonical.encode()).hexdigest()
        db.execute(
            "INSERT INTO audit_events (seq, timestamp, actor, action, details, previous_hash, hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (new_seq, ts, "system", "account_erased_dsar",
             details_json, prev_hash, new_hash),
        )

        # 4. Tombstone.
        db.execute(
            "INSERT INTO dsar_tombstones (id, selector_sha256, erased_at, actor, scope, audit_hash) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (tomb_id, selector_hash, ts, "system",
             _json.dumps({
                 "subject_kind": "user_account",
                 "redacted_audit_events": len(redacted_seqs),
                 "privacy_request_id": rec["id"],
             }),
             new_hash),
        )

        # 5. Delete the user's business data. Order matters for FK safety.
        # Each table is deleted schema-tolerantly: we build a WHERE clause
        # from whichever ownership column(s) actually exist on the table.
        counts = {}
        ownership_columns = ("owner", "actor", "signed_by", "tenant_id", "username")
        for table in ("artifacts", "roes", "jobs", "cases", "api_keys"):
            cols_present = [c for c in ownership_columns
                            if c in _table_columns(db, table)]
            if not cols_present:
                counts[table] = 0
                continue
            where = " OR ".join(f"{c} = ?" for c in cols_present)
            try:
                cur = db.execute(
                    f"DELETE FROM {table} WHERE {where}",
                    tuple([actor] * len(cols_present)),
                )
                counts[table] = cur.rowcount
            except sqlite3.OperationalError:
                counts[table] = 0

        # Finally, the user row.
        cur = db.execute("DELETE FROM users WHERE username = ?", (actor,))
        counts["users"] = cur.rowcount

        # 6. Mark privacy request processed.
        db.execute(
            "UPDATE privacy_requests SET status = ?, processed_at = ? WHERE id = ?",
            ("processed", ts, rec["id"]),
        )

        db.commit()

        LOG.warning(
            "privacy.erase_completed actor_hash=%s request_id=%s tombstone=%s "
            "redacted_events=%d deleted=%s",
            selector_hash[:16], rec["id"], tomb_id, len(redacted_seqs), counts,
        )
        return {
            "status": "ok",
            "message": (
                f"Cancellazione eseguita (richiesta {rec['id']}). "
                f"Tombstone: {tomb_id}. L'account non è più recuperabile "
                f"dal filesystem attivo; eventuali backup restano soggetti "
                f"alla policy di rotazione del datastore."
            ),
            "request_id": rec["id"],
            "tombstone_id": tomb_id,
            "selector_sha256": selector_hash,
            "erased_at": ts,
        }
    except Exception as exc:
        db.rollback()
        LOG.exception("privacy.erase_failed actor=%s request_id=%s", actor, rec["id"])
        return {
            "status": "error",
            "message": f"Cancellazione fallita (ID {rec['id']}): {exc}. Nessun dato è stato modificato.",
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
