"""SQLite-backed storage for jobs, users and audit events.

Replaces the file-based ``web_jobs/*.json`` + ``users.json`` + ``audit.log``
that the web layer used to write. SQLite gives us, for free:

* atomic writes (no tmpfile dance — every COMMIT is atomic)
* concurrent readers without blocking the writer (WAL mode)
* a real transaction around the (read last hash → compute → insert) of the
  audit chain, eliminating the L0.1 race at the storage level

The on-disk file is a single ``gufo.sqlite3`` under JOB_ROOT. Plain reports
(*.md / *.json / *.pdf) still live in JOB_ROOT/<job_id>/reports/ — those are
analyst artifacts, not state.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .audit import event_hash


_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password TEXT NOT NULL,
    plan TEXT NOT NULL DEFAULT 'free',
    created_at TEXT NOT NULL,
    disabled INTEGER NOT NULL DEFAULT 0,
    email TEXT,
    verified INTEGER NOT NULL DEFAULT 0,
    verified_at TEXT
);

CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    owner TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    payload TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS jobs_owner_updated ON jobs(owner, updated_at DESC);
CREATE INDEX IF NOT EXISTS jobs_status ON jobs(status);

CREATE TABLE IF NOT EXISTS audit_events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    details TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS api_keys (
    username TEXT NOT NULL,
    service TEXT NOT NULL,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (username, service),
    FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS api_keys_by_user ON api_keys(username);

-- Pillar 0.1: Case is the top-level investigation unit. Every job belongs
-- to exactly one case so authorisation, audit, retention and DSAR have a
-- single anchor. tenant_id defaults to the owner username today; the Pro
-- profile will overlay a real organisation id without changing call-sites.
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
    allowed_targets TEXT NOT NULL DEFAULT '[]'  -- JSON list di entry scope autorizzate
);

CREATE INDEX IF NOT EXISTS cases_by_owner_updated ON cases(owner, updated_at DESC);
CREATE INDEX IF NOT EXISTS cases_by_tenant_updated ON cases(tenant_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS cases_by_status ON cases(status);

-- Pillar 0.2: Rules of Engagement. One active RoE per case at a time.
-- scope/allowed_classes are JSON. signed_at uses ISO timestamp.
CREATE TABLE IF NOT EXISTS roes (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
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
    notes TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS roes_by_case ON roes(case_id, signed_at DESC);

-- Pillar 0.3: Artifacts table. Every tool output, archive or connector JSON
-- is hashed (SHA-256) and recorded here, linked to job/case/finding.
-- content_sha256 is the primary integrity anchor; storage_path is optional
-- (empty means the content was ephemeral — only the hash was recorded).
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
    -- no FK on case_id: artifacts exist independently of cases (CLI path, orphans)
);
CREATE INDEX IF NOT EXISTS artifacts_by_job ON artifacts(job_id);
CREATE INDEX IF NOT EXISTS artifacts_by_case ON artifacts(case_id);

-- Pillar 0.4: DSAR tombstones. When a selector is erased, a tombstone row
-- replaces the PII with its hash so the audit chain remains verifiable.
CREATE TABLE IF NOT EXISTS dsar_tombstones (
    id TEXT PRIMARY KEY,
    selector_sha256 TEXT NOT NULL,
    erased_at TEXT NOT NULL,
    actor TEXT NOT NULL,
    scope TEXT NOT NULL DEFAULT '',
    audit_hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS tombstones_by_selector ON dsar_tombstones(selector_sha256);
"""


class Storage:
    """SQLite-backed storage with one connection per calling thread.

    ``sqlite3.Connection`` is NOT safe to share across threads even with
    ``check_same_thread=False`` — the Python docs warn that application-level
    serialisation is required. We sidestep that by giving each thread its own
    connection (lazily on first use). Concurrent readers + writer go through
    SQLite's WAL machinery, which is built exactly for this. ``_write_lock``
    only serialises the audit chain's read-last + insert transaction so we
    never get two appends sharing the same previous_hash.
    """

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._write_lock = threading.Lock()
        self._connections: list[sqlite3.Connection] = []
        self._connections_lock = threading.Lock()
        # Init schema on a bootstrap connection that is then discarded.
        boot = sqlite3.connect(str(self.db_path), check_same_thread=False, isolation_level=None)
        try:
            boot.execute("PRAGMA journal_mode=WAL")
            boot.execute("PRAGMA synchronous=NORMAL")
            boot.execute("PRAGMA foreign_keys=ON")
            boot.executescript(_SCHEMA)
            _migrate_jobs_case_id(boot)
            _migrate_users_email_verified(boot)
            _migrate_cases_allowed_targets(boot)
        finally:
            boot.close()

    def _open_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            str(self.db_path),
            check_same_thread=False,
            isolation_level=None,  # autocommit; we manage transactions explicitly
            timeout=10.0,  # wait up to 10s for a write lock instead of failing immediately
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        with self._connections_lock:
            self._connections.append(conn)
        return conn

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = self._open_connection()
            self._local.conn = conn
        return conn

    def close(self) -> None:
        """Close every per-thread connection opened by this Storage instance.

        Important on Windows where a held file handle blocks tempdir cleanup.
        """
        with self._connections_lock:
            for conn in self._connections:
                try:
                    conn.close()
                except Exception:
                    pass
            self._connections.clear()
        self._local = threading.local()

    # ------------------------------------------------------------------ users

    def get_user(self, username: str) -> dict | None:
        row = self._conn().execute(
            "SELECT username, password, plan, created_at, disabled, email, verified, verified_at "
            "FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        return _row_to_user(row) if row else None

    def all_users(self) -> dict[str, dict]:
        rows = self._conn().execute(
            "SELECT username, password, plan, created_at, disabled, email, verified, verified_at FROM users"
        ).fetchall()
        return {row["username"]: _row_to_user(row) for row in rows}

    def put_user(self, user: dict) -> None:
        self._conn().execute(
            """
            INSERT INTO users (username, password, plan, created_at, disabled, email, verified, verified_at)
            VALUES (:username, :password, :plan, :created_at, :disabled, :email, :verified, :verified_at)
            ON CONFLICT(username) DO UPDATE SET
                password = excluded.password,
                plan = excluded.plan,
                disabled = excluded.disabled,
                email = excluded.email,
                verified = excluded.verified,
                verified_at = excluded.verified_at
            """,
            {
                "username": user["username"],
                "password": user.get("password", ""),
                "plan": user.get("plan", "free"),
                "created_at": user.get("created_at", _now_iso()),
                "disabled": 1 if user.get("disabled") else 0,
                "email": user.get("email") or None,
                "verified": 1 if user.get("verified") else 0,
                "verified_at": user.get("verified_at") or None,
            },
        )

    # ------------------------------------------------------------------- jobs

    def put_job(self, job_id: str, job: dict) -> None:
        payload = json.dumps(job, ensure_ascii=False)
        self._conn().execute(
            """
            INSERT INTO jobs (id, owner, status, created_at, updated_at, payload, case_id)
            VALUES (:id, :owner, :status, :created_at, :updated_at, :payload, :case_id)
            ON CONFLICT(id) DO UPDATE SET
                owner = excluded.owner,
                status = excluded.status,
                updated_at = excluded.updated_at,
                payload = excluded.payload,
                case_id = COALESCE(excluded.case_id, jobs.case_id)
            """,
            {
                "id": job_id,
                "owner": job.get("owner", "anonymous"),
                "status": job.get("status", "queued"),
                "created_at": job.get("created_at", _now_iso()),
                "updated_at": job.get("updated_at", _now_iso()),
                "payload": payload,
                "case_id": job.get("case_id"),
            },
        )

    def list_jobs_by_case(self, case_id: str, limit: int = 200) -> list[dict]:
        rows = self._conn().execute(
            "SELECT payload FROM jobs WHERE case_id = ? ORDER BY updated_at DESC LIMIT ?",
            (case_id, limit),
        ).fetchall()
        return [json.loads(row["payload"]) for row in rows]

    def list_jobs_without_case(self) -> list[dict]:
        """All jobs that pre-date 0.1 and need to be back-filled into a legacy case."""
        rows = self._conn().execute(
            "SELECT payload FROM jobs WHERE case_id IS NULL ORDER BY updated_at ASC"
        ).fetchall()
        return [json.loads(row["payload"]) for row in rows]

    def set_job_case(self, job_id: str, case_id: str) -> None:
        self._conn().execute(
            "UPDATE jobs SET case_id = ? WHERE id = ?",
            (case_id, job_id),
        )

    def get_job(self, job_id: str) -> dict | None:
        row = self._conn().execute(
            "SELECT payload FROM jobs WHERE id = ?", (job_id,)
        ).fetchone()
        if not row:
            return None
        return json.loads(row["payload"])

    def list_jobs(self, owner: str = "", limit: int = 50) -> list[dict]:
        if owner:
            rows = self._conn().execute(
                "SELECT payload FROM jobs WHERE owner = ? ORDER BY updated_at DESC LIMIT ?",
                (owner, limit),
            ).fetchall()
        else:
            rows = self._conn().execute(
                "SELECT payload FROM jobs ORDER BY updated_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [json.loads(row["payload"]) for row in rows]

    # ------------------------------------------------------------------ cases

    def put_case(self, case: dict) -> None:
        """Upsert a case. Required: id, owner, title. Defaults applied for the rest."""
        record = {
            "id": case["id"],
            "tenant_id": case.get("tenant_id") or case["owner"],
            "owner": case["owner"],
            "title": case.get("title", "Caso senza titolo"),
            "status": case.get("status", "open"),
            "legal_basis": json.dumps(case.get("legal_basis") or {}, ensure_ascii=False),
            "purpose": case.get("purpose", ""),
            "retention_until": case.get("retention_until"),
            "collaborators": json.dumps(case.get("collaborators") or [], ensure_ascii=False),
            "created_at": case.get("created_at", _now_iso()),
            "updated_at": _now_iso(),
            "notes": case.get("notes", ""),
            "allowed_targets": json.dumps(case.get("allowed_targets") or [], ensure_ascii=False),
        }
        self._conn().execute(
            """
            INSERT INTO cases (id, tenant_id, owner, title, status, legal_basis, purpose,
                               retention_until, collaborators, created_at, updated_at, notes,
                               allowed_targets)
            VALUES (:id, :tenant_id, :owner, :title, :status, :legal_basis, :purpose,
                    :retention_until, :collaborators, :created_at, :updated_at, :notes,
                    :allowed_targets)
            ON CONFLICT(id) DO UPDATE SET
                title = excluded.title,
                status = excluded.status,
                legal_basis = excluded.legal_basis,
                purpose = excluded.purpose,
                retention_until = excluded.retention_until,
                collaborators = excluded.collaborators,
                updated_at = excluded.updated_at,
                notes = excluded.notes,
                allowed_targets = excluded.allowed_targets
            """,
            record,
        )

    def get_case(self, case_id: str) -> dict | None:
        row = self._conn().execute(
            "SELECT * FROM cases WHERE id = ?", (case_id,)
        ).fetchone()
        return _row_to_case(row) if row else None

    def list_cases(self, owner: str = "", tenant_id: str = "", limit: int = 100) -> list[dict]:
        """List cases visible to the given owner. Collaborators are included.

        Today owner-based; once RBAC arrives (6.3) this becomes a permission check.
        """
        if owner:
            rows = self._conn().execute(
                "SELECT * FROM cases WHERE owner = ? OR collaborators LIKE ? "
                "ORDER BY updated_at DESC LIMIT ?",
                (owner, f'%"{owner}"%', limit),
            ).fetchall()
        elif tenant_id:
            rows = self._conn().execute(
                "SELECT * FROM cases WHERE tenant_id = ? ORDER BY updated_at DESC LIMIT ?",
                (tenant_id, limit),
            ).fetchall()
        else:
            rows = self._conn().execute(
                "SELECT * FROM cases ORDER BY updated_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [_row_to_case(row) for row in rows]

    # ------------------------------------------------------------------- roes

    def put_roe(self, roe: dict) -> None:
        record = {
            "id": roe["id"],
            "case_id": roe["case_id"],
            "signed_by": roe["signed_by"],
            "signed_at": roe.get("signed_at", _now_iso()),
            "mandate_reference": roe.get("mandate_reference", ""),
            "scope": json.dumps(roe.get("scope") or {}, ensure_ascii=False),
            "valid_from": roe.get("valid_from"),
            "valid_to": roe.get("valid_to"),
            "allowed_classes": json.dumps(roe.get("allowed_classes") or [], ensure_ascii=False),
            "requires_second_signature": 1 if roe.get("requires_second_signature") else 0,
            "second_signed_by": roe.get("second_signed_by"),
            "second_signed_at": roe.get("second_signed_at"),
            "revoked_at": roe.get("revoked_at"),
            "notes": roe.get("notes", ""),
        }
        self._conn().execute(
            """
            INSERT INTO roes (id, case_id, signed_by, signed_at, mandate_reference,
                              scope, valid_from, valid_to, allowed_classes,
                              requires_second_signature, second_signed_by,
                              second_signed_at, revoked_at, notes)
            VALUES (:id, :case_id, :signed_by, :signed_at, :mandate_reference,
                    :scope, :valid_from, :valid_to, :allowed_classes,
                    :requires_second_signature, :second_signed_by,
                    :second_signed_at, :revoked_at, :notes)
            ON CONFLICT(id) DO UPDATE SET
                signed_by = excluded.signed_by,
                signed_at = excluded.signed_at,
                mandate_reference = excluded.mandate_reference,
                scope = excluded.scope,
                valid_from = excluded.valid_from,
                valid_to = excluded.valid_to,
                allowed_classes = excluded.allowed_classes,
                requires_second_signature = excluded.requires_second_signature,
                second_signed_by = excluded.second_signed_by,
                second_signed_at = excluded.second_signed_at,
                revoked_at = excluded.revoked_at,
                notes = excluded.notes
            """,
            record,
        )

    def get_active_roe(self, case_id: str) -> dict | None:
        """Return the most recently signed, non-revoked RoE for *case_id*."""
        row = self._conn().execute(
            "SELECT * FROM roes WHERE case_id = ? AND revoked_at IS NULL "
            "ORDER BY signed_at DESC LIMIT 1",
            (case_id,),
        ).fetchone()
        return _row_to_roe(row) if row else None

    def list_roes(self, case_id: str) -> list[dict]:
        rows = self._conn().execute(
            "SELECT * FROM roes WHERE case_id = ? ORDER BY signed_at DESC",
            (case_id,),
        ).fetchall()
        return [_row_to_roe(r) for r in rows]

    def revoke_roe(self, roe_id: str) -> None:
        self._conn().execute(
            "UPDATE roes SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
            (_now_iso(), roe_id),
        )

    # --------------------------------------------------------------- artifacts

    def put_artifact(self, artifact: dict) -> None:
        """Upsert an artifact record (Pillar 0.3)."""
        self._conn().execute(
            """
            INSERT INTO artifacts
                (id, artifact_type, tool_name, command_hash, collected_at,
                 actor, content_sha256, content_size, storage_path,
                 job_id, case_id, finding_id)
            VALUES
                (:id, :artifact_type, :tool_name, :command_hash, :collected_at,
                 :actor, :content_sha256, :content_size, :storage_path,
                 :job_id, :case_id, :finding_id)
            ON CONFLICT(id) DO UPDATE SET
                storage_path = excluded.storage_path,
                finding_id   = excluded.finding_id
            """,
            {
                "id": artifact["id"],
                "artifact_type": artifact.get("artifact_type", "tool_output"),
                "tool_name": artifact.get("tool_name", ""),
                "command_hash": artifact.get("command_hash", ""),
                "collected_at": artifact.get("collected_at", _now_iso()),
                "actor": artifact.get("actor", "system"),
                "content_sha256": artifact["content_sha256"],
                "content_size": artifact.get("content_size", 0),
                "storage_path": artifact.get("storage_path", ""),
                "job_id": artifact.get("job_id", ""),
                "case_id": artifact.get("case_id") or None,
                "finding_id": artifact.get("finding_id", ""),
            },
        )

    def list_artifacts(self, case_id: str = "", job_id: str = "") -> list[dict]:
        """Return artifact records, optionally filtered by case or job."""
        if case_id:
            rows = self._conn().execute(
                "SELECT * FROM artifacts WHERE case_id = ? ORDER BY collected_at ASC",
                (case_id,),
            ).fetchall()
        elif job_id:
            rows = self._conn().execute(
                "SELECT * FROM artifacts WHERE job_id = ? ORDER BY collected_at ASC",
                (job_id,),
            ).fetchall()
        else:
            rows = self._conn().execute(
                "SELECT * FROM artifacts ORDER BY collected_at ASC"
            ).fetchall()
        return [_row_to_artifact(r) for r in rows]

    def get_artifact(self, artifact_id: str) -> dict | None:
        row = self._conn().execute(
            "SELECT * FROM artifacts WHERE id = ?", (artifact_id,)
        ).fetchone()
        return _row_to_artifact(row) if row else None

    def delete_case(self, case_id: str) -> None:
        """Hard delete a case row. Job rows are NOT cascaded — they keep the
        orphan case_id so audit trail integrity is preserved. Use
        tombstone_case() (gdpr.py) for GDPR-compliant PII erasure.
        """
        self._conn().execute("DELETE FROM cases WHERE id = ?", (case_id,))

    # --------------------------------------------------------------- api keys

    def put_api_key(self, username: str, service: str, value: str) -> None:
        """Upsert one secret for one user/service pair.

        Empty value means "delete" — keeps the wire protocol simple from
        the UI side: PUT with empty input removes the key.
        """
        if not value:
            self.delete_api_key(username, service)
            return
        self._conn().execute(
            """
            INSERT INTO api_keys (username, service, value, updated_at)
            VALUES (:username, :service, :value, :updated_at)
            ON CONFLICT(username, service) DO UPDATE SET
                value = excluded.value,
                updated_at = excluded.updated_at
            """,
            {
                "username": username,
                "service": service,
                "value": value,
                "updated_at": _now_iso(),
            },
        )

    def get_api_key(self, username: str, service: str) -> str | None:
        row = self._conn().execute(
            "SELECT value FROM api_keys WHERE username = ? AND service = ?",
            (username, service),
        ).fetchone()
        return row["value"] if row else None

    def list_api_keys(self, username: str) -> list[dict]:
        """Return the user's keys as {service, masked, updated_at} — never plain."""
        rows = self._conn().execute(
            "SELECT service, value, updated_at FROM api_keys WHERE username = ? ORDER BY service",
            (username,),
        ).fetchall()
        return [
            {
                "service": row["service"],
                "masked": _mask(row["value"]),
                "updated_at": row["updated_at"],
            }
            for row in rows
        ]

    def delete_api_key(self, username: str, service: str) -> None:
        self._conn().execute(
            "DELETE FROM api_keys WHERE username = ? AND service = ?",
            (username, service),
        )

    # ------------------------------------------------------------------ audit

    def append_audit_event(
        self,
        actor: str,
        action: str,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Append one event to the chain inside a single SQLite transaction.

        Holding ``_write_lock`` + wrapping the SELECT-last + INSERT in a
        BEGIN/COMMIT means two concurrent appends can never share the same
        previous_hash (which would bifurcate the chain).
        """
        record = {
            "timestamp": _now_iso(),
            "actor": actor or "system",
            "action": action,
            "details": details or {},
        }
        conn = self._conn()
        with self._write_lock:
            try:
                conn.execute("BEGIN IMMEDIATE")
                prev_row = conn.execute(
                    "SELECT hash FROM audit_events ORDER BY seq DESC LIMIT 1"
                ).fetchone()
                previous_hash = prev_row["hash"] if prev_row else ""
                record["previous_hash"] = previous_hash
                record["hash"] = event_hash(record)
                conn.execute(
                    """
                    INSERT INTO audit_events
                        (timestamp, actor, action, details, previous_hash, hash)
                    VALUES (:timestamp, :actor, :action, :details, :previous_hash, :hash)
                    """,
                    {
                        "timestamp": record["timestamp"],
                        "actor": record["actor"],
                        "action": record["action"],
                        "details": json.dumps(record["details"], ensure_ascii=False, sort_keys=True),
                        "previous_hash": record["previous_hash"],
                        "hash": record["hash"],
                    },
                )
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
        return record

    def all_audit_events(self) -> list[dict[str, Any]]:
        rows = self._conn().execute(
            "SELECT timestamp, actor, action, details, previous_hash, hash "
            "FROM audit_events ORDER BY seq ASC"
        ).fetchall()
        events: list[dict[str, Any]] = []
        for row in rows:
            events.append(
                {
                    "timestamp": row["timestamp"],
                    "actor": row["actor"],
                    "action": row["action"],
                    "details": json.loads(row["details"]) if row["details"] else {},
                    "previous_hash": row["previous_hash"],
                    "hash": row["hash"],
                }
            )
        return events

    def verify_audit_chain(self) -> bool:
        previous = ""
        for record in self.all_audit_events():
            stored_hash = record["hash"]
            if record["previous_hash"] != previous:
                return False
            # event_hash ignores the "hash" key, so passing the full record is fine.
            if event_hash(record) != stored_hash:
                return False
            previous = stored_hash
        return True

    # ------------------------------------------------------------- migration

    def migrate_from_files(self, job_root: Path) -> dict[str, int]:
        """One-shot import of legacy ``web_jobs/*.json`` + ``users.json``.

        Idempotent: ``put_user`` and ``put_job`` upsert. Audit log migration
        replays the chain in seq order so hashes line up with the file form.
        Returns counts for visibility in logs.
        """
        counts = {"users": 0, "jobs": 0, "audit": 0}
        users_file = job_root / "users.json"
        if users_file.is_file():
            try:
                users = json.loads(users_file.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                users = {}
            for username, user in (users or {}).items():
                user.setdefault("username", username)
                self.put_user(user)
                counts["users"] += 1

        if job_root.is_dir():
            for path in sorted(job_root.glob("*.json")):
                if path.name == "users.json":
                    continue
                try:
                    job = json.loads(path.read_text(encoding="utf-8"))
                except (json.JSONDecodeError, OSError):
                    continue
                if not isinstance(job, dict) or not job.get("id"):
                    continue
                self.put_job(job["id"], job)
                counts["jobs"] += 1

        # Audit log: only migrate if the DB table is empty (replays would
        # corrupt the chain otherwise).
        conn = self._conn()
        existing = conn.execute("SELECT COUNT(*) AS n FROM audit_events").fetchone()["n"]
        audit_file = job_root / "audit.log"
        if existing == 0 and audit_file.is_file():
            with audit_file.open("r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    # Re-insert verbatim — preserve original hashes so the chain
                    # remains verifiable end-to-end.
                    conn.execute(
                        """
                        INSERT INTO audit_events
                            (timestamp, actor, action, details, previous_hash, hash)
                        VALUES (:timestamp, :actor, :action, :details, :previous_hash, :hash)
                        """,
                        {
                            "timestamp": record.get("timestamp", _now_iso()),
                            "actor": record.get("actor", "system"),
                            "action": record.get("action", ""),
                            "details": json.dumps(
                                record.get("details", {}),
                                ensure_ascii=False,
                                sort_keys=True,
                            ),
                            "previous_hash": record.get("previous_hash", ""),
                            "hash": record.get("hash", ""),
                        },
                    )
                    counts["audit"] += 1
        return counts


def _migrate_jobs_case_id(conn: sqlite3.Connection) -> None:
    """Add jobs.case_id column if a pre-0.1 DB doesn't have it yet.

    SQLite has no IF NOT EXISTS for ADD COLUMN, so we probe PRAGMA first.
    The migration is idempotent: re-running on an already-migrated DB is a
    no-op. The actual back-fill of orphan rows (assigning them to a legacy
    case per owner) happens at the web layer where we know the case service.
    """
    cols = {row[1] for row in conn.execute("PRAGMA table_info(jobs)").fetchall()}
    if "case_id" not in cols:
        conn.execute("ALTER TABLE jobs ADD COLUMN case_id TEXT")
        conn.execute("CREATE INDEX IF NOT EXISTS jobs_by_case ON jobs(case_id)")


def _migrate_users_email_verified(conn: sqlite3.Connection) -> None:
    """Add users.email/verified/verified_at if a pre-0.2 DB doesn't have them."""
    cols = {row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
    if "email" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN email TEXT")
    if "verified" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN verified INTEGER NOT NULL DEFAULT 0")
    if "verified_at" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN verified_at TEXT")


def _migrate_cases_allowed_targets(conn: sqlite3.Connection) -> None:
    """Add cases.allowed_targets per scope enforcement (round 6)."""
    cols = {row[1] for row in conn.execute("PRAGMA table_info(cases)").fetchall()}
    if "allowed_targets" not in cols:
        conn.execute(
            "ALTER TABLE cases ADD COLUMN allowed_targets TEXT NOT NULL DEFAULT '[]'"
        )


def _mask(value: str) -> str:
    """Return a UI-safe redacted preview: 4 last chars after a fixed dot run."""
    if not value:
        return ""
    tail = value[-4:] if len(value) > 4 else value
    return "•" * 6 + tail


def _row_to_user(row: sqlite3.Row) -> dict:
    # row may or may not have new columns depending on migration state — handle both
    keys = row.keys() if hasattr(row, "keys") else []
    return {
        "username": row["username"],
        "password": row["password"],
        "plan": row["plan"],
        "created_at": row["created_at"],
        "disabled": bool(row["disabled"]),
        "email": row["email"] if "email" in keys else None,
        "verified": bool(row["verified"]) if "verified" in keys else False,
        "verified_at": row["verified_at"] if "verified_at" in keys else None,
    }


def _row_to_roe(row: sqlite3.Row) -> dict:
    try:
        scope = json.loads(row["scope"] or "{}")
    except json.JSONDecodeError:
        scope = {}
    try:
        allowed_classes = json.loads(row["allowed_classes"] or "[]")
    except json.JSONDecodeError:
        allowed_classes = []
    return {
        "id": row["id"],
        "case_id": row["case_id"],
        "signed_by": row["signed_by"],
        "signed_at": row["signed_at"],
        "mandate_reference": row["mandate_reference"],
        "scope": scope,
        "valid_from": row["valid_from"],
        "valid_to": row["valid_to"],
        "allowed_classes": allowed_classes,
        "requires_second_signature": bool(row["requires_second_signature"]),
        "second_signed_by": row["second_signed_by"],
        "second_signed_at": row["second_signed_at"],
        "revoked_at": row["revoked_at"],
        "notes": row["notes"],
    }


def _row_to_case(row: sqlite3.Row) -> dict:
    try:
        legal_basis = json.loads(row["legal_basis"] or "{}")
    except json.JSONDecodeError:
        legal_basis = {}
    try:
        collaborators = json.loads(row["collaborators"] or "[]")
    except json.JSONDecodeError:
        collaborators = []
    # Migration-friendly: la colonna allowed_targets potrebbe non esistere su
    # DB non ancora migrati. La lettura difensiva preserva i job legacy.
    keys = row.keys() if hasattr(row, "keys") else []
    allowed_targets: list = []
    if "allowed_targets" in keys:
        try:
            allowed_targets = json.loads(row["allowed_targets"] or "[]")
            if not isinstance(allowed_targets, list):
                allowed_targets = []
        except (json.JSONDecodeError, TypeError):
            allowed_targets = []
    return {
        "id": row["id"],
        "tenant_id": row["tenant_id"],
        "owner": row["owner"],
        "title": row["title"],
        "status": row["status"],
        "legal_basis": legal_basis,
        "purpose": row["purpose"],
        "retention_until": row["retention_until"],
        "collaborators": collaborators,
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "notes": row["notes"],
        "allowed_targets": allowed_targets,
    }


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _row_to_artifact(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "artifact_type": row["artifact_type"],
        "tool_name": row["tool_name"],
        "command_hash": row["command_hash"],
        "collected_at": row["collected_at"],
        "actor": row["actor"],
        "content_sha256": row["content_sha256"],
        "content_size": row["content_size"],
        "storage_path": row["storage_path"],
        "job_id": row["job_id"],
        "case_id": row["case_id"],
        "finding_id": row["finding_id"],
    }
