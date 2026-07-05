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

import json
import threading
from datetime import datetime, timezone
from typing import Any

from .audit import event_hash
from .storage import (
    _mask,
    _row_to_artifact,
    _row_to_case,
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
        verified_at TEXT
    )""",
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
]

# Advisory lock key arbitraria ma stabile per serializzare la catena audit.
_AUDIT_LOCK_KEY = 918273645


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class PostgresStorage:
    """Backend Postgres con una connessione per thread (come il backend SQLite)."""

    def __init__(self, dsn: str):
        import psycopg  # import ritardato: opzionale
        from psycopg.rows import dict_row

        self._psycopg = psycopg
        self._dict_row = dict_row
        self._dsn = dsn
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
            "SELECT username, password, plan, created_at, disabled, email, verified, verified_at "
            "FROM users WHERE username = %s", (username,))
        return _row_to_user(row) if row else None

    def all_users(self) -> dict[str, dict]:
        rows = self._fetchall(
            "SELECT username, password, plan, created_at, disabled, email, verified, verified_at FROM users")
        return {row["username"]: _row_to_user(row) for row in rows}

    def put_user(self, user: dict) -> None:
        self._exec(
            """
            INSERT INTO users (username, password, plan, created_at, disabled, email, verified, verified_at)
            VALUES (%(username)s, %(password)s, %(plan)s, %(created_at)s, %(disabled)s, %(email)s, %(verified)s, %(verified_at)s)
            ON CONFLICT (username) DO UPDATE SET
                password = EXCLUDED.password, plan = EXCLUDED.plan,
                disabled = EXCLUDED.disabled, email = EXCLUDED.email,
                verified = EXCLUDED.verified, verified_at = EXCLUDED.verified_at
            """,
            {
                "username": user["username"], "password": user.get("password", ""),
                "plan": user.get("plan", "free"),
                "created_at": user.get("created_at", _now_iso()),
                "disabled": 1 if user.get("disabled") else 0,
                "email": user.get("email") or None,
                "verified": 1 if user.get("verified") else 0,
                "verified_at": user.get("verified_at") or None,
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
        }
        self._exec(
            """
            INSERT INTO cases (id, tenant_id, owner, title, status, legal_basis, purpose,
                               retention_until, collaborators, created_at, updated_at, notes, allowed_targets)
            VALUES (%(id)s, %(tenant_id)s, %(owner)s, %(title)s, %(status)s, %(legal_basis)s, %(purpose)s,
                    %(retention_until)s, %(collaborators)s, %(created_at)s, %(updated_at)s, %(notes)s, %(allowed_targets)s)
            ON CONFLICT (id) DO UPDATE SET
                title = EXCLUDED.title, status = EXCLUDED.status,
                legal_basis = EXCLUDED.legal_basis, purpose = EXCLUDED.purpose,
                retention_until = EXCLUDED.retention_until, collaborators = EXCLUDED.collaborators,
                updated_at = EXCLUDED.updated_at, notes = EXCLUDED.notes,
                allowed_targets = EXCLUDED.allowed_targets
            """, record)

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
        self._exec(
            """
            INSERT INTO api_keys (username, service, value, updated_at)
            VALUES (%(username)s, %(service)s, %(value)s, %(updated_at)s)
            ON CONFLICT (username, service) DO UPDATE SET
                value = EXCLUDED.value, updated_at = EXCLUDED.updated_at
            """,
            {"username": username, "service": service, "value": value, "updated_at": _now_iso()})

    def get_api_key(self, username: str, service: str) -> str | None:
        row = self._fetchone(
            "SELECT value FROM api_keys WHERE username = %s AND service = %s", (username, service))
        return row["value"] if row else None

    def list_api_keys(self, username: str) -> list[dict]:
        rows = self._fetchall(
            "SELECT service, value, updated_at FROM api_keys WHERE username = %s ORDER BY service",
            (username,))
        return [{"service": r["service"], "masked": _mask(r["value"]), "updated_at": r["updated_at"]}
                for r in rows]

    def delete_api_key(self, username: str, service: str) -> None:
        self._exec("DELETE FROM api_keys WHERE username = %s AND service = %s", (username, service))

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

    def verify_audit_chain(self) -> bool:
        previous = ""
        for record in self.all_audit_events():
            if record["previous_hash"] != previous:
                return False
            if event_hash(record) != record["hash"]:
                return False
            previous = record["hash"]
        return True
