"""Backend di storage PostgreSQL — implementa la stessa interfaccia di Storage.

Mirror 1:1 dei metodi pubblici di ``storage.Storage`` (SQLite) su Postgres via
``psycopg`` (v3). Riusa i mapper di riga di storage.py: con ``dict_row`` le righe
sono dict, compatibili con gli helper ``_row_to_*`` che accedono a ``row["x"]``.

Differenze SQL gestite qui:
  * placeholder named ``%(name)s`` (psycopg) al posto di ``:name`` (sqlite)
  * ``BIGSERIAL`` per il seq audit al posto di ``AUTOINCREMENT``
  * niente ``PRAGMA``; le foreign key sono attive per default
  * catena audit in transazione esplicita + advisory lock, così due append
    concorrenti non condividono mai lo stesso previous_hash

psycopg viene importato in ``__init__``: il modulo si importa anche senza la
libreria (il factory lo istanzia solo quando serve).
"""
from __future__ import annotations

import hashlib
import json
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import secrets_crypto
from .audit import event_hash
from .storage import (
    _mask,
    _row_to_ai_run,
    _row_to_artifact,
    _row_to_case,
    _row_to_entity_merge_decision,
    _row_to_report_seal,
    _row_to_roe,
    _row_to_user,
)

# Schema Postgres — parità funzionale con storage._SCHEMA (SQLite).
_SCHEMA_STATEMENTS = [
    """
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password TEXT NOT NULL,
        plan TEXT NOT NULL DEFAULT 'free',
        created_at TEXT NOT NULL,
        disabled INTEGER NOT NULL DEFAULT 0,
        email TEXT,
        verified INTEGER NOT NULL DEFAULT 0,
        verified_at TEXT,
        auth_provider TEXT NOT NULL DEFAULT 'password',
        google_sub TEXT,
        role TEXT NOT NULL DEFAULT 'analyst'
    )""",
    # Google Sign-In (opt-in, additional login door) — same semantics as
    # storage._migrate_users_auth_provider (SQLite).
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS auth_provider TEXT NOT NULL DEFAULT 'password'",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS google_sub TEXT",
    # RBAC (opt-in, additional-privilege door) — same semantics as
    # storage._migrate_users_role (SQLite).
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'analyst'",
    """
    CREATE TABLE IF NOT EXISTS jobs (
        id TEXT PRIMARY KEY,
        owner TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        payload TEXT NOT NULL,
        case_id TEXT
    )""",
    "CREATE INDEX IF NOT EXISTS jobs_owner_updated ON jobs(owner, updated_at DESC)",
    "CREATE INDEX IF NOT EXISTS jobs_status ON jobs(status)",
    "CREATE INDEX IF NOT EXISTS jobs_by_case ON jobs(case_id)",
    """
    CREATE TABLE IF NOT EXISTS audit_events (
        seq BIGSERIAL PRIMARY KEY,
        timestamp TEXT NOT NULL,
        actor TEXT NOT NULL,
        action TEXT NOT NULL,
        details TEXT NOT NULL,
        previous_hash TEXT NOT NULL,
        hash TEXT NOT NULL
    )""",
    """
    CREATE TABLE IF NOT EXISTS api_keys (
        username TEXT NOT NULL,
        service TEXT NOT NULL,
        value TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        PRIMARY KEY (username, service)
    )""",
    "CREATE INDEX IF NOT EXISTS api_keys_by_user ON api_keys(username)",
    """
    CREATE TABLE IF NOT EXISTS cases (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        owner TEXT NOT NULL,
        title TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'open',
        legal_basis TEXT NOT NULL DEFAULT '{}',
        purpose TEXT NOT NULL DEFAULT '',
        retention_until TEXT,
        collaborators TEXT NOT NULL DEFAULT '[]',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        notes TEXT NOT NULL DEFAULT '',
        allowed_targets TEXT NOT NULL DEFAULT '[]'
    )""",
    "CREATE INDEX IF NOT EXISTS cases_by_owner_updated ON cases(owner, updated_at DESC)",
    "CREATE INDEX IF NOT EXISTS cases_by_tenant_updated ON cases(tenant_id, updated_at DESC)",
    "CREATE INDEX IF NOT EXISTS cases_by_status ON cases(status)",
    """
    CREATE TABLE IF NOT EXISTS roes (
        id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
        signed_by TEXT NOT NULL,
        signed_at TEXT NOT NULL,
        mandate_reference TEXT NOT NULL DEFAULT '',
        scope TEXT NOT NULL DEFAULT '{}',
        valid_from TEXT,
        valid_to TEXT,
        allowed_classes TEXT NOT NULL DEFAULT '[]',
        requires_second_signature INTEGER NOT NULL DEFAULT 0,
        second_signed_by TEXT,
        second_signed_at TEXT,
        revoked_at TEXT,
        notes TEXT NOT NULL DEFAULT ''
    )""",
    "CREATE INDEX IF NOT EXISTS roes_by_case ON roes(case_id, signed_at DESC)",
    """
    CREATE TABLE IF NOT EXISTS artifacts (
        id TEXT PRIMARY KEY,
        artifact_type TEXT NOT NULL,
        tool_name TEXT NOT NULL DEFAULT '',
        command_hash TEXT NOT NULL DEFAULT '',
        collected_at TEXT NOT NULL,
        actor TEXT NOT NULL DEFAULT 'system',
        content_sha256 TEXT NOT NULL,
        content_size INTEGER NOT NULL DEFAULT 0,
        storage_path TEXT NOT NULL DEFAULT '',
        job_id TEXT NOT NULL DEFAULT '',
        case_id TEXT,
        finding_id TEXT NOT NULL DEFAULT ''
    )""",
    "CREATE INDEX IF NOT EXISTS artifacts_by_job ON artifacts(job_id)",
    "CREATE INDEX IF NOT EXISTS artifacts_by_case ON artifacts(case_id)",
    """
    CREATE TABLE IF NOT EXISTS dsar_tombstones (
        id TEXT PRIMARY KEY,
        selector_sha256 TEXT NOT NULL,
        erased_at TEXT NOT NULL,
        actor TEXT NOT NULL,
        scope TEXT NOT NULL DEFAULT '',
        audit_hash TEXT NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS tombstones_by_selector ON dsar_tombstones(selector_sha256)",
    # Agenti IA (LLM, opt-in) — stessa semantica di storage._SCHEMA.
    "ALTER TABLE cases ADD COLUMN IF NOT EXISTS ai_enrichment_enabled INTEGER NOT NULL DEFAULT 0",
    """
    CREATE TABLE IF NOT EXISTS ai_runs (
        id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
        kind TEXT NOT NULL,
        actor TEXT NOT NULL,
        provider TEXT NOT NULL,
        model TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        status TEXT NOT NULL,
        input_summary TEXT NOT NULL DEFAULT '{}',
        output_json TEXT NOT NULL DEFAULT '{}',
        error TEXT NOT NULL DEFAULT ''
    )""",
    "CREATE INDEX IF NOT EXISTS ai_runs_by_case ON ai_runs(case_id, created_at DESC)",
    "CREATE INDEX IF NOT EXISTS ai_runs_by_case_kind ON ai_runs(case_id, kind, created_at DESC)",
    """
    CREATE TABLE IF NOT EXISTS entity_merge_decisions (
        id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
        entity_id_a TEXT NOT NULL,
        entity_id_b TEXT NOT NULL,
        decision TEXT NOT NULL,
        decided_by TEXT NOT NULL,
        decided_at TEXT NOT NULL,
        ai_run_id TEXT,
        ai_confidence REAL,
        ai_rationale TEXT NOT NULL DEFAULT ''
    )""",
    "CREATE UNIQUE INDEX IF NOT EXISTS entity_merge_decisions_pair "
    "ON entity_merge_decisions(case_id, entity_id_a, entity_id_b)",
    # Sigilli dei report — stessa semantica di storage._SCHEMA.
    """
    CREATE TABLE IF NOT EXISTS report_seals (
        id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
        job_id TEXT NOT NULL,
        manifest_hash TEXT NOT NULL,
        artifact_count INTEGER NOT NULL DEFAULT 0,
        signature_b64 TEXT NOT NULL,
        signing_pubkey_b64 TEXT NOT NULL,
        signing_pubkey_fingerprint TEXT NOT NULL,
        sealed_at TEXT NOT NULL,
        sealed_by TEXT NOT NULL,
        tsa_url_host TEXT NOT NULL DEFAULT '',
        tsa_status TEXT NOT NULL DEFAULT '',
        tsa_token_der_b64 TEXT NOT NULL DEFAULT '',
        tsa_gen_time TEXT NOT NULL DEFAULT '',
        tsa_requested_at TEXT NOT NULL DEFAULT ''
    )""",
    "CREATE UNIQUE INDEX IF NOT EXISTS report_seals_by_job ON report_seals(job_id)",
    "CREATE INDEX IF NOT EXISTS report_seals_by_case ON report_seals(case_id, sealed_at DESC)",
]

# Advisory lock key arbitraria ma stabile per serializzare la catena audit.
_AUDIT_LOCK_KEY = 918273645


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class PostgresStorage:
    """Backend Postgres con una connessione per thread (come il backend SQLite)."""

    def __init__(self, dsn: str, job_root: Any = None):
        import os as _os

        import psycopg  # import ritardato: opzionale
        from psycopg.rows import dict_row

        self._psycopg = psycopg
        self._dict_row = dict_row
        self._dsn = dsn
        # Master key per la cifratura delle API key BYOK vive qui — un file
        # locale sul filesystem dell'app, mai una riga nel DB Postgres remoto
        # (vedi secrets_crypto.py). Nessun "job_root" naturale per un backend
        # di rete: fallback su OSINT_JOB_DIR se il chiamante non lo passa.
        self._job_root = Path(job_root) if job_root else Path(_os.getenv("OSINT_JOB_DIR", "web_jobs"))
        self._local = threading.local()
        self._write_lock = threading.Lock()
        self._connections: list[Any] = []
        self._connections_lock = threading.Lock()

        boot = psycopg.connect(dsn, autocommit=True)
        try:
            with boot.cursor() as cur:
                for stmt in _SCHEMA_STATEMENTS:
                    cur.execute(stmt)
        finally:
            boot.close()

    # ---------------------------------------------------------------- plumbing
    def _open_connection(self):
        conn = self._psycopg.connect(self._dsn, autocommit=True, row_factory=self._dict_row)
        with self._connections_lock:
            self._connections.append(conn)
        return conn

    def _conn(self):
        conn = getattr(self._local, "conn", None)
        if conn is None or conn.closed:
            conn = self._open_connection()
            self._local.conn = conn
        return conn

    def _exec(self, sql: str, params: Any = None):
        conn = self._conn()
        with conn.cursor() as cur:
            cur.execute(sql, params or ())
            return None

    def _fetchone(self, sql: str, params: Any = None) -> dict | None:
        conn = self._conn()
        with conn.cursor() as cur:
            cur.execute(sql, params or ())
            return cur.fetchone()

    def _fetchall(self, sql: str, params: Any = None) -> list[dict]:
        conn = self._conn()
        with conn.cursor() as cur:
            cur.execute(sql, params or ())
            return cur.fetchall()

    def close(self) -> None:
        with self._connections_lock:
            for conn in self._connections:
                try:
                    conn.close()
                except Exception:
                    pass
            self._connections.clear()
        self._local = threading.local()

    # ------------------------------------------------------------------- users
    def get_user(self, username: str) -> dict | None:
        row = self._fetchone(
            "SELECT username, password, plan, created_at, disabled, email, verified, verified_at, "
            "auth_provider, google_sub, role FROM users WHERE username = %s", (username,))
        return _row_to_user(row) if row else None

    def all_users(self) -> dict[str, dict]:
        rows = self._fetchall(
            "SELECT username, password, plan, created_at, disabled, email, verified, verified_at, "
            "auth_provider, google_sub, role FROM users")
        return {row["username"]: _row_to_user(row) for row in rows}

    def put_user(self, user: dict) -> None:
        self._exec(
            """
            INSERT INTO users (username, password, plan, created_at, disabled, email, verified, verified_at, auth_provider, google_sub, role)
            VALUES (%(username)s, %(password)s, %(plan)s, %(created_at)s, %(disabled)s, %(email)s, %(verified)s, %(verified_at)s, %(auth_provider)s, %(google_sub)s, %(role)s)
            ON CONFLICT (username) DO UPDATE SET
                password = EXCLUDED.password, plan = EXCLUDED.plan,
                disabled = EXCLUDED.disabled, email = EXCLUDED.email,
                verified = EXCLUDED.verified, verified_at = EXCLUDED.verified_at,
                auth_provider = EXCLUDED.auth_provider, google_sub = EXCLUDED.google_sub,
                role = EXCLUDED.role
            """,
            {
                "username": user["username"], "password": user.get("password", ""),
                "plan": user.get("plan", "free"),
                "created_at": user.get("created_at", _now_iso()),
                "disabled": 1 if user.get("disabled") else 0,
                "email": user.get("email") or None,
                "verified": 1 if user.get("verified") else 0,
                "verified_at": user.get("verified_at") or None,
                "auth_provider": user.get("auth_provider", "password"),
                "google_sub": user.get("google_sub") or None,
                "role": user.get("role", "analyst"),
            })

    # -------------------------------------------------------------------- jobs
    def put_job(self, job_id: str, job: dict) -> None:
        self._exec(
            """
            INSERT INTO jobs (id, owner, status, created_at, updated_at, payload, case_id)
            VALUES (%(id)s, %(owner)s, %(status)s, %(created_at)s, %(updated_at)s, %(payload)s, %(case_id)s)
            ON CONFLICT (id) DO UPDATE SET
                owner = EXCLUDED.owner, status = EXCLUDED.status,
                updated_at = EXCLUDED.updated_at, payload = EXCLUDED.payload,
                case_id = COALESCE(EXCLUDED.case_id, jobs.case_id)
            """,
            {
                "id": job_id, "owner": job.get("owner", "anonymous"),
                "status": job.get("status", "queued"),
                "created_at": job.get("created_at", _now_iso()),
                "updated_at": job.get("updated_at", _now_iso()),
                "payload": json.dumps(job, ensure_ascii=False),
                "case_id": job.get("case_id"),
            })

    def get_job(self, job_id: str) -> dict | None:
        row = self._fetchone("SELECT payload FROM jobs WHERE id = %s", (job_id,))
        return json.loads(row["payload"]) if row else None

    def list_jobs(self, owner: str = "", limit: int = 50) -> list[dict]:
        if owner:
            rows = self._fetchall(
                "SELECT payload FROM jobs WHERE owner = %s ORDER BY updated_at DESC LIMIT %s",
                (owner, limit))
        else:
            rows = self._fetchall(
                "SELECT payload FROM jobs ORDER BY updated_at DESC LIMIT %s", (limit,))
        return [json.loads(r["payload"]) for r in rows]

    def list_jobs_by_case(self, case_id: str, limit: int = 200) -> list[dict]:
        rows = self._fetchall(
            "SELECT payload FROM jobs WHERE case_id = %s ORDER BY updated_at DESC LIMIT %s",
            (case_id, limit))
        return [json.loads(r["payload"]) for r in rows]

    def list_jobs_without_case(self) -> list[dict]:
        rows = self._fetchall(
            "SELECT payload FROM jobs WHERE case_id IS NULL ORDER BY updated_at ASC")
        return [json.loads(r["payload"]) for r in rows]

    def set_job_case(self, job_id: str, case_id: str) -> None:
        self._exec("UPDATE jobs SET case_id = %s WHERE id = %s", (case_id, job_id))

    def delete_job(self, job_id: str) -> int:
        conn = self._conn()
        with conn.cursor() as cur:
            cur.execute("DELETE FROM jobs WHERE id = %s", (job_id,))
            return cur.rowcount or 0

    # ------------------------------------------------------------------- cases
    def put_case(self, case: dict) -> None:
        record = {
            "id": case["id"], "tenant_id": case.get("tenant_id") or case["owner"],
            "owner": case["owner"], "title": case.get("title", "Caso senza titolo"),
            "status": case.get("status", "open"),
            "legal_basis": json.dumps(case.get("legal_basis") or {}, ensure_ascii=False),
            "purpose": case.get("purpose", ""),
            "retention_until": case.get("retention_until"),
            "collaborators": json.dumps(case.get("collaborators") or [], ensure_ascii=False),
            "created_at": case.get("created_at", _now_iso()), "updated_at": _now_iso(),
            "notes": case.get("notes", ""),
            "allowed_targets": json.dumps(case.get("allowed_targets") or [], ensure_ascii=False),
            "ai_enrichment_enabled": 1 if case.get("ai_enrichment_enabled") else 0,
        }
        self._exec(
            """
            INSERT INTO cases (id, tenant_id, owner, title, status, legal_basis, purpose,
                               retention_until, collaborators, created_at, updated_at, notes, allowed_targets,
                               ai_enrichment_enabled)
            VALUES (%(id)s, %(tenant_id)s, %(owner)s, %(title)s, %(status)s, %(legal_basis)s, %(purpose)s,
                    %(retention_until)s, %(collaborators)s, %(created_at)s, %(updated_at)s, %(notes)s, %(allowed_targets)s,
                    %(ai_enrichment_enabled)s)
            ON CONFLICT (id) DO UPDATE SET
                title = EXCLUDED.title, status = EXCLUDED.status,
                legal_basis = EXCLUDED.legal_basis, purpose = EXCLUDED.purpose,
                retention_until = EXCLUDED.retention_until, collaborators = EXCLUDED.collaborators,
                updated_at = EXCLUDED.updated_at, notes = EXCLUDED.notes,
                allowed_targets = EXCLUDED.allowed_targets,
                ai_enrichment_enabled = EXCLUDED.ai_enrichment_enabled
            """, record)

    def set_case_ai_enrichment(self, case_id: str, enabled: bool) -> None:
        self._exec(
            "UPDATE cases SET ai_enrichment_enabled = %s, updated_at = %s WHERE id = %s",
            (1 if enabled else 0, _now_iso(), case_id))

    def get_case(self, case_id: str) -> dict | None:
        row = self._fetchone("SELECT * FROM cases WHERE id = %s", (case_id,))
        return _row_to_case(row) if row else None

    def list_cases(self, owner: str = "", tenant_id: str = "", limit: int = 100) -> list[dict]:
        if owner:
            rows = self._fetchall(
                "SELECT * FROM cases WHERE owner = %s OR collaborators LIKE %s "
                "ORDER BY updated_at DESC LIMIT %s",
                (owner, f'%"{owner}"%', limit))
        elif tenant_id:
            rows = self._fetchall(
                "SELECT * FROM cases WHERE tenant_id = %s ORDER BY updated_at DESC LIMIT %s",
                (tenant_id, limit))
        else:
            rows = self._fetchall("SELECT * FROM cases ORDER BY updated_at DESC LIMIT %s", (limit,))
        return [_row_to_case(r) for r in rows]

    def delete_case(self, case_id: str) -> None:
        self._exec("DELETE FROM cases WHERE id = %s", (case_id,))

    # ------------------------------------------------------------- ai agents
    def put_ai_run(self, run: dict) -> None:
        self._exec(
            """
            INSERT INTO ai_runs (id, case_id, kind, actor, provider, model,
                                 created_at, status, input_summary, output_json, error)
            VALUES (%(id)s, %(case_id)s, %(kind)s, %(actor)s, %(provider)s, %(model)s,
                    %(created_at)s, %(status)s, %(input_summary)s, %(output_json)s, %(error)s)
            """,
            {
                "id": run["id"], "case_id": run["case_id"], "kind": run["kind"],
                "actor": run.get("actor", "system"), "provider": run.get("provider", ""),
                "model": run.get("model", ""), "created_at": run.get("created_at", _now_iso()),
                "status": run.get("status", "error"),
                "input_summary": json.dumps(run.get("input_summary") or {}, ensure_ascii=False),
                "output_json": json.dumps(run.get("output_json") or {}, ensure_ascii=False),
                "error": run.get("error", ""),
            })

    def get_ai_run(self, run_id: str) -> dict | None:
        row = self._fetchone("SELECT * FROM ai_runs WHERE id = %s", (run_id,))
        return _row_to_ai_run(row) if row else None

    def list_ai_runs(self, case_id: str, kind: str = "", limit: int = 50) -> list[dict]:
        if kind:
            rows = self._fetchall(
                "SELECT * FROM ai_runs WHERE case_id = %s AND kind = %s "
                "ORDER BY created_at DESC LIMIT %s", (case_id, kind, limit))
        else:
            rows = self._fetchall(
                "SELECT * FROM ai_runs WHERE case_id = %s ORDER BY created_at DESC LIMIT %s",
                (case_id, limit))
        return [_row_to_ai_run(r) for r in rows]

    def latest_ai_run(self, case_id: str, kind: str) -> dict | None:
        row = self._fetchone(
            "SELECT * FROM ai_runs WHERE case_id = %s AND kind = %s "
            "ORDER BY created_at DESC LIMIT 1", (case_id, kind))
        return _row_to_ai_run(row) if row else None

    def put_entity_merge_decision(self, decision: dict) -> dict:
        record = {
            "id": decision.get("id") or uuid.uuid4().hex,
            "case_id": decision["case_id"],
            "entity_id_a": decision["entity_id_a"],
            "entity_id_b": decision["entity_id_b"],
            "decision": decision["decision"],
            "decided_by": decision["decided_by"],
            "decided_at": decision.get("decided_at", _now_iso()),
            "ai_run_id": decision.get("ai_run_id"),
            "ai_confidence": decision.get("ai_confidence"),
            "ai_rationale": decision.get("ai_rationale", ""),
        }
        self._exec(
            """
            INSERT INTO entity_merge_decisions
                (id, case_id, entity_id_a, entity_id_b, decision, decided_by,
                 decided_at, ai_run_id, ai_confidence, ai_rationale)
            VALUES
                (%(id)s, %(case_id)s, %(entity_id_a)s, %(entity_id_b)s, %(decision)s, %(decided_by)s,
                 %(decided_at)s, %(ai_run_id)s, %(ai_confidence)s, %(ai_rationale)s)
            ON CONFLICT (case_id, entity_id_a, entity_id_b) DO UPDATE SET
                decision = EXCLUDED.decision,
                decided_by = EXCLUDED.decided_by,
                decided_at = EXCLUDED.decided_at,
                ai_run_id = EXCLUDED.ai_run_id,
                ai_confidence = EXCLUDED.ai_confidence,
                ai_rationale = EXCLUDED.ai_rationale
            """, record)
        # ON CONFLICT non tocca id: su un update la riga mantiene il suo id
        # originale, diverso dal uuid4 appena generato in `record`. Rileggiamo
        # la riga vera invece di restituire il dict fabbricato (stesso fix di
        # storage.py — vedi il commento lì per il dettaglio del bug).
        row = self._fetchone(
            "SELECT * FROM entity_merge_decisions WHERE case_id = %s AND entity_id_a = %s AND entity_id_b = %s",
            (record["case_id"], record["entity_id_a"], record["entity_id_b"]))
        return _row_to_entity_merge_decision(row)

    def list_entity_merge_decisions(self, case_id: str) -> list[dict]:
        rows = self._fetchall(
            "SELECT * FROM entity_merge_decisions WHERE case_id = %s ORDER BY decided_at DESC",
            (case_id,))
        return [_row_to_entity_merge_decision(r) for r in rows]

    # ----------------------------------------------------------- report seals
    def put_report_seal(self, seal: dict) -> dict:
        record = {
            "id": seal.get("id") or uuid.uuid4().hex,
            "case_id": seal["case_id"],
            "job_id": seal["job_id"],
            "manifest_hash": seal["manifest_hash"],
            "artifact_count": seal.get("artifact_count", 0),
            "signature_b64": seal["signature_b64"],
            "signing_pubkey_b64": seal["signing_pubkey_b64"],
            "signing_pubkey_fingerprint": seal["signing_pubkey_fingerprint"],
            "sealed_at": seal.get("sealed_at", _now_iso()),
            "sealed_by": seal.get("sealed_by", "system"),
        }
        self._exec(
            """
            INSERT INTO report_seals
                (id, case_id, job_id, manifest_hash, artifact_count, signature_b64,
                 signing_pubkey_b64, signing_pubkey_fingerprint, sealed_at, sealed_by)
            VALUES
                (%(id)s, %(case_id)s, %(job_id)s, %(manifest_hash)s, %(artifact_count)s, %(signature_b64)s,
                 %(signing_pubkey_b64)s, %(signing_pubkey_fingerprint)s, %(sealed_at)s, %(sealed_by)s)
            ON CONFLICT (job_id) DO UPDATE SET
                manifest_hash = EXCLUDED.manifest_hash,
                artifact_count = EXCLUDED.artifact_count,
                signature_b64 = EXCLUDED.signature_b64,
                signing_pubkey_b64 = EXCLUDED.signing_pubkey_b64,
                signing_pubkey_fingerprint = EXCLUDED.signing_pubkey_fingerprint,
                sealed_at = EXCLUDED.sealed_at,
                sealed_by = EXCLUDED.sealed_by
            """, record)
        # stesso motivo di put_entity_merge_decision: ON CONFLICT non tocca id,
        # rileggiamo la riga vera invece di restituire il dict fabbricato.
        return self.get_report_seal(record["job_id"])

    def get_report_seal(self, job_id: str) -> dict | None:
        row = self._fetchone("SELECT * FROM report_seals WHERE job_id = %s", (job_id,))
        return _row_to_report_seal(row) if row else None

    def list_report_seals(self, case_id: str) -> list[dict]:
        rows = self._fetchall(
            "SELECT * FROM report_seals WHERE case_id = %s ORDER BY sealed_at DESC", (case_id,))
        return [_row_to_report_seal(r) for r in rows]

    def update_report_seal_tsa(
        self, job_id: str, *, tsa_url_host: str, tsa_status: str,
        tsa_token_der_b64: str = "", tsa_gen_time: str = "", tsa_requested_at: str = "",
    ) -> dict | None:
        self._exec(
            """
            UPDATE report_seals SET
                tsa_url_host = %(tsa_url_host)s,
                tsa_status = %(tsa_status)s,
                tsa_token_der_b64 = %(tsa_token_der_b64)s,
                tsa_gen_time = %(tsa_gen_time)s,
                tsa_requested_at = %(tsa_requested_at)s
            WHERE job_id = %(job_id)s
            """,
            {
                "job_id": job_id, "tsa_url_host": tsa_url_host, "tsa_status": tsa_status,
                "tsa_token_der_b64": tsa_token_der_b64, "tsa_gen_time": tsa_gen_time,
                "tsa_requested_at": tsa_requested_at,
            })
        return self.get_report_seal(job_id)

    # -------------------------------------------------------------------- roes
    def put_roe(self, roe: dict) -> None:
        record = {
            "id": roe["id"], "case_id": roe["case_id"], "signed_by": roe["signed_by"],
            "signed_at": roe.get("signed_at", _now_iso()),
            "mandate_reference": roe.get("mandate_reference", ""),
            "scope": json.dumps(roe.get("scope") or {}, ensure_ascii=False),
            "valid_from": roe.get("valid_from"), "valid_to": roe.get("valid_to"),
            "allowed_classes": json.dumps(roe.get("allowed_classes") or [], ensure_ascii=False),
            "requires_second_signature": 1 if roe.get("requires_second_signature") else 0,
            "second_signed_by": roe.get("second_signed_by"),
            "second_signed_at": roe.get("second_signed_at"),
            "revoked_at": roe.get("revoked_at"), "notes": roe.get("notes", ""),
        }
        self._exec(
            """
            INSERT INTO roes (id, case_id, signed_by, signed_at, mandate_reference, scope,
                              valid_from, valid_to, allowed_classes, requires_second_signature,
                              second_signed_by, second_signed_at, revoked_at, notes)
            VALUES (%(id)s, %(case_id)s, %(signed_by)s, %(signed_at)s, %(mandate_reference)s, %(scope)s,
                    %(valid_from)s, %(valid_to)s, %(allowed_classes)s, %(requires_second_signature)s,
                    %(second_signed_by)s, %(second_signed_at)s, %(revoked_at)s, %(notes)s)
            ON CONFLICT (id) DO UPDATE SET
                signed_by = EXCLUDED.signed_by, signed_at = EXCLUDED.signed_at,
                mandate_reference = EXCLUDED.mandate_reference, scope = EXCLUDED.scope,
                valid_from = EXCLUDED.valid_from, valid_to = EXCLUDED.valid_to,
                allowed_classes = EXCLUDED.allowed_classes,
                requires_second_signature = EXCLUDED.requires_second_signature,
                second_signed_by = EXCLUDED.second_signed_by,
                second_signed_at = EXCLUDED.second_signed_at,
                revoked_at = EXCLUDED.revoked_at, notes = EXCLUDED.notes
            """, record)

    def get_active_roe(self, case_id: str) -> dict | None:
        row = self._fetchone(
            "SELECT * FROM roes WHERE case_id = %s AND revoked_at IS NULL "
            "ORDER BY signed_at DESC LIMIT 1", (case_id,))
        return _row_to_roe(row) if row else None

    def list_roes(self, case_id: str) -> list[dict]:
        rows = self._fetchall(
            "SELECT * FROM roes WHERE case_id = %s ORDER BY signed_at DESC", (case_id,))
        return [_row_to_roe(r) for r in rows]

    def revoke_roe(self, roe_id: str) -> None:
        self._exec("UPDATE roes SET revoked_at = %s WHERE id = %s AND revoked_at IS NULL",
                   (_now_iso(), roe_id))

    # --------------------------------------------------------------- artifacts
    def put_artifact(self, artifact: dict) -> None:
        self._exec(
            """
            INSERT INTO artifacts (id, artifact_type, tool_name, command_hash, collected_at,
                                   actor, content_sha256, content_size, storage_path, job_id, case_id, finding_id)
            VALUES (%(id)s, %(artifact_type)s, %(tool_name)s, %(command_hash)s, %(collected_at)s,
                    %(actor)s, %(content_sha256)s, %(content_size)s, %(storage_path)s, %(job_id)s, %(case_id)s, %(finding_id)s)
            ON CONFLICT (id) DO UPDATE SET
                storage_path = EXCLUDED.storage_path, finding_id = EXCLUDED.finding_id
            """,
            {
                "id": artifact["id"], "artifact_type": artifact.get("artifact_type", "tool_output"),
                "tool_name": artifact.get("tool_name", ""), "command_hash": artifact.get("command_hash", ""),
                "collected_at": artifact.get("collected_at", _now_iso()),
                "actor": artifact.get("actor", "system"), "content_sha256": artifact["content_sha256"],
                "content_size": artifact.get("content_size", 0),
                "storage_path": artifact.get("storage_path", ""),
                "job_id": artifact.get("job_id", ""), "case_id": artifact.get("case_id") or None,
                "finding_id": artifact.get("finding_id", ""),
            })

    def list_artifacts(self, case_id: str = "", job_id: str = "") -> list[dict]:
        if case_id:
            rows = self._fetchall(
                "SELECT * FROM artifacts WHERE case_id = %s ORDER BY collected_at ASC", (case_id,))
        elif job_id:
            rows = self._fetchall(
                "SELECT * FROM artifacts WHERE job_id = %s ORDER BY collected_at ASC", (job_id,))
        else:
            rows = self._fetchall("SELECT * FROM artifacts ORDER BY collected_at ASC")
        return [_row_to_artifact(r) for r in rows]

    def get_artifact(self, artifact_id: str) -> dict | None:
        row = self._fetchone("SELECT * FROM artifacts WHERE id = %s", (artifact_id,))
        return _row_to_artifact(row) if row else None

    # ----------------------------------------------------------------- api keys
    def put_api_key(self, username: str, service: str, value: str) -> None:
        if not value:
            self.delete_api_key(username, service)
            return
        encrypted = secrets_crypto.encrypt_secret(
            value, secrets_crypto.get_master_key(self._job_root),
            aad=secrets_crypto.api_key_aad(username, service),
        )
        self._exec(
            """
            INSERT INTO api_keys (username, service, value, updated_at)
            VALUES (%(username)s, %(service)s, %(value)s, %(updated_at)s)
            ON CONFLICT (username, service) DO UPDATE SET
                value = EXCLUDED.value, updated_at = EXCLUDED.updated_at
            """,
            {"username": username, "service": service, "value": encrypted, "updated_at": _now_iso()})
        self.append_audit_event(username, "api_key_stored", {"service": service})

    def get_api_key(self, username: str, service: str) -> str | None:
        row = self._fetchone(
            "SELECT value FROM api_keys WHERE username = %s AND service = %s", (username, service))
        if not row:
            return None
        plaintext = secrets_crypto.decrypt_secret(
            row["value"], secrets_crypto.get_master_key(self._job_root),
            aad=secrets_crypto.api_key_aad(username, service),
        )
        self.append_audit_event(username, "api_key_accessed", {"service": service})
        return plaintext

    def list_api_keys(self, username: str) -> list[dict]:
        rows = self._fetchall(
            "SELECT service, value, updated_at FROM api_keys WHERE username = %s ORDER BY service",
            (username,))
        master_key = secrets_crypto.get_master_key(self._job_root)
        return [{"service": r["service"],
                 "masked": _mask(secrets_crypto.decrypt_secret(
                     r["value"], master_key, aad=secrets_crypto.api_key_aad(username, r["service"]))),
                 "updated_at": r["updated_at"]}
                for r in rows]

    def delete_api_key(self, username: str, service: str) -> None:
        self._exec("DELETE FROM api_keys WHERE username = %s AND service = %s", (username, service))
        self.append_audit_event(username, "api_key_deleted", {"service": service})

    def all_api_keys(self) -> list[dict]:
        rows = self._fetchall("SELECT username, service, value FROM api_keys ORDER BY username, service")
        return [{"username": r["username"], "service": r["service"], "value": r["value"]} for r in rows]

    def set_api_key_encrypted(self, username: str, service: str, encrypted_value: str) -> None:
        self._exec(
            "UPDATE api_keys SET value = %(value)s, updated_at = %(updated_at)s "
            "WHERE username = %(username)s AND service = %(service)s",
            {"username": username, "service": service, "value": encrypted_value, "updated_at": _now_iso()})

    # ------------------------------------------------------------------- audit
    def append_audit_event(self, actor: str, action: str,
                           details: dict[str, Any] | None = None) -> dict[str, Any]:
        record = {"timestamp": _now_iso(), "actor": actor or "system",
                  "action": action, "details": details or {}}
        conn = self._conn()
        with self._write_lock:
            with conn.cursor() as cur:
                # advisory lock a livello di sessione, serializza la catena
                cur.execute("SELECT pg_advisory_lock(%s)", (_AUDIT_LOCK_KEY,))
                try:
                    cur.execute("SELECT hash FROM audit_events ORDER BY seq DESC LIMIT 1")
                    prev = cur.fetchone()
                    record["previous_hash"] = prev["hash"] if prev else ""
                    record["hash"] = event_hash(record)
                    cur.execute(
                        """
                        INSERT INTO audit_events (timestamp, actor, action, details, previous_hash, hash)
                        VALUES (%(timestamp)s, %(actor)s, %(action)s, %(details)s, %(previous_hash)s, %(hash)s)
                        """,
                        {
                            "timestamp": record["timestamp"], "actor": record["actor"],
                            "action": record["action"],
                            "details": json.dumps(record["details"], ensure_ascii=False, sort_keys=True),
                            "previous_hash": record["previous_hash"], "hash": record["hash"],
                        })
                finally:
                    cur.execute("SELECT pg_advisory_unlock(%s)", (_AUDIT_LOCK_KEY,))
        return record

    def all_audit_events(self) -> list[dict[str, Any]]:
        rows = self._fetchall(
            "SELECT timestamp, actor, action, details, previous_hash, hash "
            "FROM audit_events ORDER BY seq ASC")
        return [{
            "timestamp": r["timestamp"], "actor": r["actor"], "action": r["action"],
            "details": json.loads(r["details"]) if r["details"] else {},
            "previous_hash": r["previous_hash"], "hash": r["hash"],
        } for r in rows]

    def import_audit_verbatim(self, events: list[dict[str, Any]]) -> int:
        """Inserisce eventi audit preservando timestamp e hash originali.

        Usato dalla migrazione SQLite→Postgres per non spezzare la catena:
        ricalcolare gli hash con nuovi timestamp la invaliderebbe. Idempotente
        a livello di run: inserisce solo se la tabella è vuota.
        """
        existing = self._fetchone("SELECT COUNT(*) AS n FROM audit_events")
        if existing and existing["n"]:
            return 0
        n = 0
        for record in events:
            self._exec(
                """
                INSERT INTO audit_events (timestamp, actor, action, details, previous_hash, hash)
                VALUES (%(timestamp)s, %(actor)s, %(action)s, %(details)s, %(previous_hash)s, %(hash)s)
                """,
                {
                    "timestamp": record.get("timestamp", _now_iso()),
                    "actor": record.get("actor", "system"),
                    "action": record.get("action", ""),
                    "details": json.dumps(record.get("details", {}), ensure_ascii=False, sort_keys=True),
                    "previous_hash": record.get("previous_hash", ""),
                    "hash": record.get("hash", ""),
                })
            n += 1
        return n

    def _redacted_seqs_from_tombstones(self) -> set[int]:
        """Vedi storage.Storage._redacted_seqs_from_tombstones — stessa logica,
        dialetto Postgres."""
        redacted: set[int] = set()
        rows = self._fetchall("SELECT scope FROM dsar_tombstones")
        for row in rows:
            try:
                scope = json.loads(row["scope"] or "{}")
            except json.JSONDecodeError:
                continue
            redacted.update(scope.get("redacted_seqs") or [])
        return redacted

    def verify_audit_chain(self) -> bool:
        """Vedi storage.Storage.verify_audit_chain per la motivazione
        completa: le righe redatte da un tombstone GDPR documentato sono
        escluse dal controllo di auto-hash, il collegamento previous_hash è
        sempre verificato."""
        redacted_seqs = self._redacted_seqs_from_tombstones()
        previous = ""
        rows = self._fetchall(
            "SELECT seq, timestamp, actor, action, details, previous_hash, hash "
            "FROM audit_events ORDER BY seq ASC"
        )
        for row in rows:
            try:
                details = json.loads(row["details"]) if row["details"] else {}
            except json.JSONDecodeError:
                return False
            record = {
                "timestamp": row["timestamp"], "actor": row["actor"], "action": row["action"],
                "details": details, "previous_hash": row["previous_hash"],
            }
            stored_hash = row["hash"]
            if record["previous_hash"] != previous:
                return False
            if row["seq"] not in redacted_seqs and event_hash(record) != stored_hash:
                return False
            previous = stored_hash
        return True

    # ------------------------------------------------------------ privacy/dsar

    _PRIVACY_OWNERSHIP_COLUMNS = ("owner", "actor", "signed_by", "tenant_id", "username")
    _PRIVACY_ERASABLE_TABLES = ("artifacts", "roes", "jobs", "cases", "api_keys", "privacy_requests")

    def ensure_privacy_table(self) -> None:
        self._exec(
            """
            CREATE TABLE IF NOT EXISTS privacy_requests (
                id TEXT PRIMARY KEY,
                owner TEXT NOT NULL,
                type TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                reason TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                processed_at TEXT
            )
            """
        )

    def log_privacy_request(self, record: dict) -> None:
        self.ensure_privacy_table()
        self._exec(
            "INSERT INTO privacy_requests (id, owner, type, status, reason, created_at) "
            "VALUES (%(id)s, %(owner)s, %(type)s, %(status)s, %(reason)s, %(created_at)s) "
            "ON CONFLICT (id) DO NOTHING",
            record,
        )

    def list_privacy_requests(self, owner: str, limit: int = 50) -> list[dict]:
        self.ensure_privacy_table()
        rows = self._fetchall(
            "SELECT id, type, status, reason, created_at, processed_at FROM privacy_requests "
            "WHERE owner = %s ORDER BY created_at DESC LIMIT %s",
            (owner, limit),
        )
        return list(rows)

    def mark_privacy_request_processed(self, request_id: str) -> None:
        self._exec(
            "UPDATE privacy_requests SET status = %s, processed_at = %s WHERE id = %s",
            ("processed", _now_iso(), request_id),
        )

    def table_columns(self, table: str) -> list[str]:
        """Nomi colonna di *table* via information_schema (equivalente
        Postgres di PRAGMA table_info), o [] se assente."""
        try:
            rows = self._fetchall(
                "SELECT column_name FROM information_schema.columns WHERE table_name = %s",
                (table,),
            )
            return [r["column_name"] for r in rows]
        except Exception:
            return []

    def select_owned_columns(self, table: str, owner_col: str, owner: str, wanted: list[str]) -> list[dict]:
        cols = [c for c in wanted if c in self.table_columns(table)]
        if not cols:
            return []
        query = f"SELECT {', '.join(cols)} FROM {table} WHERE {owner_col} = %s"
        try:
            rows = self._fetchall(query, (owner,))
        except Exception:
            return []
        return [dict(r) for r in rows]

    def erase_actor_data(self, actor: str, *, request_id: str, redacted_placeholder: str) -> dict:
        """Vedi storage.Storage.erase_actor_data per la documentazione
        completa — stessa semantica, dialetto Postgres. Atomicità: l'intera
        redazione + append + tombstone + cancellazione gira dentro
        ``conn.transaction()`` (BEGIN/COMMIT/ROLLBACK espliciti anche su una
        connessione autocommit=True — API psycopg3 pensata esattamente per
        questo), avvolta dall'advisory lock che serializza anche contro un
        append_audit_event concorrente su un'altra connessione.
        """
        ts = _now_iso()
        selector_hash = hashlib.sha256(f"user:{actor.lower()}".encode()).hexdigest()
        tomb_id = "TOMB-" + uuid.uuid4().hex[:12]

        conn = self._conn()
        redacted_seqs: list[int] = []
        counts: dict[str, int] = {}
        with self._write_lock, conn.cursor() as cur:
            cur.execute("SELECT pg_advisory_lock(%s)", (_AUDIT_LOCK_KEY,))
            try:
                with conn.transaction():
                    cur.execute(
                        "SELECT seq, actor, details FROM audit_events WHERE actor = %s OR details LIKE %s",
                        (actor, f"%{actor}%"),
                    )
                    rows = cur.fetchall()
                    for row in rows:
                        seq, ev_actor, details = row["seq"], row["actor"], row["details"]
                        new_actor = redacted_placeholder if ev_actor == actor else ev_actor
                        new_details = details or ""
                        if actor in new_details:
                            new_details = new_details.replace(actor, redacted_placeholder)
                        if new_actor != ev_actor or new_details != (details or ""):
                            cur.execute(
                                "UPDATE audit_events SET actor = %s, details = %s WHERE seq = %s",
                                (new_actor, new_details, seq),
                            )
                            redacted_seqs.append(seq)

                    cur.execute("SELECT hash FROM audit_events ORDER BY seq DESC LIMIT 1")
                    last = cur.fetchone()
                    prev_hash = last["hash"] if last else ""
                    event_details = {
                        "subject_hash": selector_hash,
                        "tombstone_id": tomb_id,
                        "privacy_request_id": request_id,
                        "reason": "GDPR art. 17 erasure",
                        "redacted_seqs_count": len(redacted_seqs),
                    }
                    record = {
                        "timestamp": ts, "actor": "system", "action": "account_erased_dsar",
                        "details": event_details, "previous_hash": prev_hash,
                    }
                    record["hash"] = event_hash(record)
                    cur.execute(
                        """
                        INSERT INTO audit_events (timestamp, actor, action, details, previous_hash, hash)
                        VALUES (%(timestamp)s, %(actor)s, %(action)s, %(details)s, %(previous_hash)s, %(hash)s)
                        """,
                        {**record, "details": json.dumps(event_details, ensure_ascii=False, sort_keys=True)},
                    )

                    cur.execute(
                        "INSERT INTO dsar_tombstones (id, selector_sha256, erased_at, actor, scope, audit_hash) "
                        "VALUES (%s, %s, %s, %s, %s, %s)",
                        (
                            tomb_id, selector_hash, ts, "system",
                            json.dumps({
                                "subject_kind": "user_account",
                                "redacted_audit_events": len(redacted_seqs),
                                "redacted_seqs": redacted_seqs,
                                "privacy_request_id": request_id,
                            }, sort_keys=True),
                            record["hash"],
                        ),
                    )

                    for table in self._PRIVACY_ERASABLE_TABLES:
                        cols_present = [c for c in self._PRIVACY_OWNERSHIP_COLUMNS if c in self.table_columns(table)]
                        if not cols_present:
                            counts[table] = 0
                            continue
                        where = " OR ".join(f"{c} = %s" for c in cols_present)
                        cur.execute(f"DELETE FROM {table} WHERE {where}", tuple([actor] * len(cols_present)))
                        counts[table] = cur.rowcount

                    cur.execute("DELETE FROM users WHERE username = %s", (actor,))
                    counts["users"] = cur.rowcount
            finally:
                cur.execute("SELECT pg_advisory_unlock(%s)", (_AUDIT_LOCK_KEY,))

        return {
            "tombstone_id": tomb_id,
            "selector_sha256": selector_hash,
            "erased_at": ts,
            "redacted_events_count": len(redacted_seqs),
            "deleted_counts": counts,
        }
