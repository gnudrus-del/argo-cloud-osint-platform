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

import hashlib
import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import secrets_crypto
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

-- Agenti IA (LLM, opt-in) — ogni chiamata a un provider LLM (sintesi
-- narrativa / entity-resolution / triage) lascia una riga qui, successo o
-- fallimento. input_summary/output_json sono JSON di metadati/risultato
-- strutturato — MAI il prompt grezzo o la api_key.
CREATE TABLE IF NOT EXISTS ai_runs (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    actor TEXT NOT NULL,
    provider TEXT NOT NULL,
    model TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    status TEXT NOT NULL,
    input_summary TEXT NOT NULL DEFAULT '{}',
    output_json TEXT NOT NULL DEFAULT '{}',
    error TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS ai_runs_by_case ON ai_runs(case_id, created_at DESC);
CREATE INDEX IF NOT EXISTS ai_runs_by_case_kind ON ai_runs(case_id, kind, created_at DESC);

-- Decisioni umane su coppie di entità suggerite dall'IA come possibile
-- stesso soggetto. Annotazione fuori-banda: non tocca mai il grafo
-- deterministico di link_analysis.resolve_entities() né l'Investigation JSON
-- salvata — i merge non sono mai applicati automaticamente.
CREATE TABLE IF NOT EXISTS entity_merge_decisions (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    entity_id_a TEXT NOT NULL,
    entity_id_b TEXT NOT NULL,
    decision TEXT NOT NULL,
    decided_by TEXT NOT NULL,
    decided_at TEXT NOT NULL,
    ai_run_id TEXT,
    ai_confidence REAL,
    ai_rationale TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX IF NOT EXISTS entity_merge_decisions_pair
    ON entity_merge_decisions(case_id, entity_id_a, entity_id_b);

-- Sigilli dei report: firma Ed25519 locale (sempre presente, calcolata al
-- completamento di ogni job) + timestamp RFC3161 opzionale su una TSA esterna
-- configurata dall'operatore (colonne tsa_* vuote finché non richiesto).
-- manifest_hash copre sia le evidenze raccolte sia i file di report finali
-- (vedi custody.py: register_report_artifacts + export_case_manifest).
CREATE TABLE IF NOT EXISTS report_seals (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
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
    tsa_requested_at TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX IF NOT EXISTS report_seals_by_job ON report_seals(job_id);
CREATE INDEX IF NOT EXISTS report_seals_by_case ON report_seals(case_id, sealed_at DESC);
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
        # Master key for BYOK API key encryption lives here by default —
        # sibling to the DB file, never a row inside it. See secrets_crypto.py.
        self._job_root = self.db_path.parent
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
            _migrate_cases_ai_enrichment(boot)
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
            "ai_enrichment_enabled": 1 if case.get("ai_enrichment_enabled") else 0,
        }
        self._conn().execute(
            """
            INSERT INTO cases (id, tenant_id, owner, title, status, legal_basis, purpose,
                               retention_until, collaborators, created_at, updated_at, notes,
                               allowed_targets, ai_enrichment_enabled)
            VALUES (:id, :tenant_id, :owner, :title, :status, :legal_basis, :purpose,
                    :retention_until, :collaborators, :created_at, :updated_at, :notes,
                    :allowed_targets, :ai_enrichment_enabled)
            ON CONFLICT(id) DO UPDATE SET
                title = excluded.title,
                status = excluded.status,
                legal_basis = excluded.legal_basis,
                purpose = excluded.purpose,
                retention_until = excluded.retention_until,
                collaborators = excluded.collaborators,
                updated_at = excluded.updated_at,
                notes = excluded.notes,
                allowed_targets = excluded.allowed_targets,
                ai_enrichment_enabled = excluded.ai_enrichment_enabled
            """,
            record,
        )

    def set_case_ai_enrichment(self, case_id: str, enabled: bool) -> None:
        """Toggle mirato — evita di dover ripassare l'intero record da put_case
        per un singolo flag di consenso."""
        self._conn().execute(
            "UPDATE cases SET ai_enrichment_enabled = ?, updated_at = ? WHERE id = ?",
            (1 if enabled else 0, _now_iso(), case_id),
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

    def delete_job(self, job_id: str) -> int:
        """Hard delete one job row. The audit event registering the deletion
        is appended by the caller (web.py handle_job_delete) so chain-of-custody
        integrity is preserved. Returns the number of rows removed (0 or 1).
        """
        cur = self._conn().execute("DELETE FROM jobs WHERE id = ?", (job_id,))
        return cur.rowcount or 0

    # ------------------------------------------------------------- ai agents

    def put_ai_run(self, run: dict) -> None:
        """Insert-only: un run IA non viene mai aggiornato dopo la scrittura
        (successo o fallimento sono lo stato finale)."""
        self._conn().execute(
            """
            INSERT INTO ai_runs (id, case_id, kind, actor, provider, model,
                                 created_at, status, input_summary, output_json, error)
            VALUES (:id, :case_id, :kind, :actor, :provider, :model,
                    :created_at, :status, :input_summary, :output_json, :error)
            """,
            {
                "id": run["id"],
                "case_id": run["case_id"],
                "kind": run["kind"],
                "actor": run.get("actor", "system"),
                "provider": run.get("provider", ""),
                "model": run.get("model", ""),
                "created_at": run.get("created_at", _now_iso()),
                "status": run.get("status", "error"),
                "input_summary": json.dumps(run.get("input_summary") or {}, ensure_ascii=False),
                "output_json": json.dumps(run.get("output_json") or {}, ensure_ascii=False),
                "error": run.get("error", ""),
            },
        )

    def get_ai_run(self, run_id: str) -> dict | None:
        row = self._conn().execute(
            "SELECT * FROM ai_runs WHERE id = ?", (run_id,)
        ).fetchone()
        return _row_to_ai_run(row) if row else None

    def list_ai_runs(self, case_id: str, kind: str = "", limit: int = 50) -> list[dict]:
        if kind:
            rows = self._conn().execute(
                "SELECT * FROM ai_runs WHERE case_id = ? AND kind = ? "
                "ORDER BY created_at DESC LIMIT ?",
                (case_id, kind, limit),
            ).fetchall()
        else:
            rows = self._conn().execute(
                "SELECT * FROM ai_runs WHERE case_id = ? ORDER BY created_at DESC LIMIT ?",
                (case_id, limit),
            ).fetchall()
        return [_row_to_ai_run(r) for r in rows]

    def latest_ai_run(self, case_id: str, kind: str) -> dict | None:
        row = self._conn().execute(
            "SELECT * FROM ai_runs WHERE case_id = ? AND kind = ? "
            "ORDER BY created_at DESC LIMIT 1",
            (case_id, kind),
        ).fetchone()
        return _row_to_ai_run(row) if row else None

    def put_entity_merge_decision(self, decision: dict) -> dict:
        """Upsert su (case_id, entity_id_a, entity_id_b) — ridecidere una
        coppia sostituisce la decisione precedente. Gli id vengono ordinati
        canonicamente (a < b) dal chiamante (entity_resolution_ai.py) prima
        di arrivare qui, così l'unique index non permette righe duplicate
        per la stessa coppia in ordine invertito."""
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
        self._conn().execute(
            """
            INSERT INTO entity_merge_decisions
                (id, case_id, entity_id_a, entity_id_b, decision, decided_by,
                 decided_at, ai_run_id, ai_confidence, ai_rationale)
            VALUES
                (:id, :case_id, :entity_id_a, :entity_id_b, :decision, :decided_by,
                 :decided_at, :ai_run_id, :ai_confidence, :ai_rationale)
            ON CONFLICT(case_id, entity_id_a, entity_id_b) DO UPDATE SET
                decision = excluded.decision,
                decided_by = excluded.decided_by,
                decided_at = excluded.decided_at,
                ai_run_id = excluded.ai_run_id,
                ai_confidence = excluded.ai_confidence,
                ai_rationale = excluded.ai_rationale
            """,
            record,
        )
        # ON CONFLICT non tocca la colonna id: su un update la riga mantiene
        # il suo id originale, diverso dal uuid4 appena generato in `record`.
        # Rileggiamo la riga vera invece di restituire il dict fabbricato,
        # altrimenti il chiamante riceverebbe un id che non esiste su disco.
        row = self._conn().execute(
            "SELECT * FROM entity_merge_decisions WHERE case_id = ? AND entity_id_a = ? AND entity_id_b = ?",
            (record["case_id"], record["entity_id_a"], record["entity_id_b"]),
        ).fetchone()
        return _row_to_entity_merge_decision(row)

    def list_entity_merge_decisions(self, case_id: str) -> list[dict]:
        rows = self._conn().execute(
            "SELECT * FROM entity_merge_decisions WHERE case_id = ? ORDER BY decided_at DESC",
            (case_id,),
        ).fetchall()
        return [_row_to_entity_merge_decision(r) for r in rows]

    # ----------------------------------------------------------- report seals

    def put_report_seal(self, seal: dict) -> dict:
        """Upsert su job_id (un solo sigillo per job — risigillare sostituisce
        firma/manifest_hash precedenti). L'id non cambia su un conflitto,
        stesso motivo di put_entity_merge_decision: si rilegge la riga vera
        invece di restituire il dict fabbricato."""
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
        self._conn().execute(
            """
            INSERT INTO report_seals
                (id, case_id, job_id, manifest_hash, artifact_count, signature_b64,
                 signing_pubkey_b64, signing_pubkey_fingerprint, sealed_at, sealed_by)
            VALUES
                (:id, :case_id, :job_id, :manifest_hash, :artifact_count, :signature_b64,
                 :signing_pubkey_b64, :signing_pubkey_fingerprint, :sealed_at, :sealed_by)
            ON CONFLICT(job_id) DO UPDATE SET
                manifest_hash = excluded.manifest_hash,
                artifact_count = excluded.artifact_count,
                signature_b64 = excluded.signature_b64,
                signing_pubkey_b64 = excluded.signing_pubkey_b64,
                signing_pubkey_fingerprint = excluded.signing_pubkey_fingerprint,
                sealed_at = excluded.sealed_at,
                sealed_by = excluded.sealed_by
            """,
            record,
        )
        return self.get_report_seal(record["job_id"])

    def get_report_seal(self, job_id: str) -> dict | None:
        row = self._conn().execute(
            "SELECT * FROM report_seals WHERE job_id = ?", (job_id,)
        ).fetchone()
        return _row_to_report_seal(row) if row else None

    def list_report_seals(self, case_id: str) -> list[dict]:
        rows = self._conn().execute(
            "SELECT * FROM report_seals WHERE case_id = ? ORDER BY sealed_at DESC",
            (case_id,),
        ).fetchall()
        return [_row_to_report_seal(r) for r in rows]

    def update_report_seal_tsa(
        self, job_id: str, *, tsa_url_host: str, tsa_status: str,
        tsa_token_der_b64: str = "", tsa_gen_time: str = "", tsa_requested_at: str = "",
    ) -> dict | None:
        """Attacca l'esito di una richiesta di timestamp RFC3161 a un sigillo
        già esistente. Chiamata sia su successo che su fallimento (tsa_status
        riporta l'esito, mai silenzioso)."""
        self._conn().execute(
            """
            UPDATE report_seals SET
                tsa_url_host = :tsa_url_host,
                tsa_status = :tsa_status,
                tsa_token_der_b64 = :tsa_token_der_b64,
                tsa_gen_time = :tsa_gen_time,
                tsa_requested_at = :tsa_requested_at
            WHERE job_id = :job_id
            """,
            {
                "job_id": job_id, "tsa_url_host": tsa_url_host, "tsa_status": tsa_status,
                "tsa_token_der_b64": tsa_token_der_b64, "tsa_gen_time": tsa_gen_time,
                "tsa_requested_at": tsa_requested_at,
            },
        )
        return self.get_report_seal(job_id)

    # ------------------------------------------------------------ privacy/dsar

    _PRIVACY_OWNERSHIP_COLUMNS = ("owner", "actor", "signed_by", "tenant_id", "username")
    _PRIVACY_ERASABLE_TABLES = ("artifacts", "roes", "jobs", "cases", "api_keys", "privacy_requests")

    def ensure_privacy_table(self) -> None:
        self._conn().execute(
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
        self._conn().execute(
            "INSERT OR IGNORE INTO privacy_requests (id, owner, type, status, reason, created_at) "
            "VALUES (:id, :owner, :type, :status, :reason, :created_at)",
            record,
        )

    def list_privacy_requests(self, owner: str, limit: int = 50) -> list[dict]:
        self.ensure_privacy_table()
        rows = self._conn().execute(
            "SELECT id, type, status, reason, created_at, processed_at FROM privacy_requests "
            "WHERE owner = ? ORDER BY created_at DESC LIMIT ?",
            (owner, limit),
        ).fetchall()
        return [dict(r) for r in rows]

    def mark_privacy_request_processed(self, request_id: str) -> None:
        self._conn().execute(
            "UPDATE privacy_requests SET status = ?, processed_at = ? WHERE id = ?",
            ("processed", _now_iso(), request_id),
        )

    def table_columns(self, table: str) -> list[str]:
        """Nomi colonna di *table*, o [] se assente. Usato per rendere il
        collettore DSAR tollerante allo schema (tabelle create con schema
        diverso da versioni precedenti/future)."""
        try:
            rows = self._conn().execute(f"PRAGMA table_info({table})").fetchall()
            return [r["name"] for r in rows]
        except Exception:
            return []

    def select_owned_columns(self, table: str, owner_col: str, owner: str, wanted: list[str]) -> list[dict]:
        """SELECT solo le colonne *wanted* che esistono davvero su *table*,
        filtrate per proprietario. [] su qualunque fallimento."""
        cols = [c for c in wanted if c in self.table_columns(table)]
        if not cols:
            return []
        query = f"SELECT {', '.join(cols)} FROM {table} WHERE {owner_col} = ?"
        try:
            rows = self._conn().execute(query, (owner,)).fetchall()
        except Exception:
            return []
        return [dict(zip(cols, tuple(r), strict=False)) for r in rows]

    def erase_actor_data(self, actor: str, *, request_id: str, redacted_placeholder: str) -> dict:
        """GDPR Art. 17 — cancellazione reale, atomica (singola transazione,
        tutto o niente).

        1. Redige gli identificativi dell'attore da ogni riga di audit_events
           che lo menziona.
        2. Appende un evento account_erased_dsar nella STESSA transazione,
           con lo stesso event_hash() usato da append_audit_event — prima di
           questo fix, il codice calcolava un hash diverso (stringa pipe-
           concatenata inclusiva di seq) che non corrispondeva mai a quello
           ricalcolato da verify_audit_chain(): il risultato era che OGNI
           cancellazione GDPR rompeva silenziosamente l'indicatore di
           integrità della catena audit. Bug reale, non solo un problema di
           portabilità Postgres — verificato empiricamente prima del fix.
        3. Tombstone con il selettore SHA-256 del soggetto.
        4. Cancella le righe dell'attore da cases/jobs/artifacts/roes/
           api_keys/privacy_requests e infine users — tollerante allo schema
           (sonda le colonne di proprietà presenti prima di cancellare).

        Ritorna tombstone_id, selector_sha256, erased_at, redacted_events_count,
        deleted_counts. Solleva su qualunque fallimento — l'intera transazione
        va in rollback, l'account resta intatto (garanzia invariata rispetto
        al comportamento precedente).
        """
        ts = _now_iso()
        selector_hash = hashlib.sha256(f"user:{actor.lower()}".encode()).hexdigest()
        tomb_id = "TOMB-" + uuid.uuid4().hex[:12]

        conn = self._conn()
        with self._write_lock:
            try:
                conn.execute("BEGIN IMMEDIATE")

                rows = conn.execute(
                    "SELECT seq, actor, details FROM audit_events WHERE actor = ? OR details LIKE ?",
                    (actor, f"%{actor}%"),
                ).fetchall()
                redacted_seqs: list[int] = []
                for row in rows:
                    seq, ev_actor, details = row["seq"], row["actor"], row["details"]
                    new_actor = redacted_placeholder if ev_actor == actor else ev_actor
                    new_details = details or ""
                    if actor in new_details:
                        new_details = new_details.replace(actor, redacted_placeholder)
                    if new_actor != ev_actor or new_details != (details or ""):
                        conn.execute(
                            "UPDATE audit_events SET actor = ?, details = ? WHERE seq = ?",
                            (new_actor, new_details, seq),
                        )
                        redacted_seqs.append(seq)

                last = conn.execute("SELECT hash FROM audit_events ORDER BY seq DESC LIMIT 1").fetchone()
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
                conn.execute(
                    """
                    INSERT INTO audit_events (timestamp, actor, action, details, previous_hash, hash)
                    VALUES (:timestamp, :actor, :action, :details, :previous_hash, :hash)
                    """,
                    {**record, "details": json.dumps(event_details, ensure_ascii=False, sort_keys=True)},
                )

                conn.execute(
                    "INSERT INTO dsar_tombstones (id, selector_sha256, erased_at, actor, scope, audit_hash) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        tomb_id, selector_hash, ts, "system",
                        json.dumps({
                            "subject_kind": "user_account",
                            "redacted_audit_events": len(redacted_seqs),
                            # Elenco esplicito dei seq redatti (non solo il
                            # conteggio) — verify_audit_chain lo usa per
                            # distinguere una redazione GDPR documentata da
                            # una manomissione vera. Il nuovo evento
                            # account_erased_dsar appena creato NON è qui:
                            # il suo hash è corretto per costruzione, non è
                            # mai stato redatto.
                            "redacted_seqs": redacted_seqs,
                            "privacy_request_id": request_id,
                        }, sort_keys=True),
                        record["hash"],
                    ),
                )

                counts: dict[str, int] = {}
                for table in self._PRIVACY_ERASABLE_TABLES:
                    cols_present = [c for c in self._PRIVACY_OWNERSHIP_COLUMNS if c in self.table_columns(table)]
                    if not cols_present:
                        counts[table] = 0
                        continue
                    where = " OR ".join(f"{c} = ?" for c in cols_present)
                    try:
                        cur = conn.execute(f"DELETE FROM {table} WHERE {where}", tuple([actor] * len(cols_present)))
                        counts[table] = cur.rowcount
                    except sqlite3.OperationalError:
                        counts[table] = 0

                cur = conn.execute("DELETE FROM users WHERE username = ?", (actor,))
                counts["users"] = cur.rowcount

                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise

        return {
            "tombstone_id": tomb_id,
            "selector_sha256": selector_hash,
            "erased_at": ts,
            "redacted_events_count": len(redacted_seqs),
            "deleted_counts": counts,
        }

    # --------------------------------------------------------------- api keys

    def put_api_key(self, username: str, service: str, value: str) -> None:
        """Upsert one secret for one user/service pair, encrypted at rest.

        Empty value means "delete" — keeps the wire protocol simple from
        the UI side: PUT with empty input removes the key. The value is
        envelope-encrypted (secrets_crypto.py) before it ever reaches SQL —
        a row in ``api_keys`` never holds plaintext from this call onward,
        including for keys that predate this feature (a plaintext legacy row
        is silently upgraded the next time it is written).
        """
        if not value:
            self.delete_api_key(username, service)
            return
        encrypted = secrets_crypto.encrypt_secret(value, secrets_crypto.get_master_key(self._job_root))
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
                "value": encrypted,
                "updated_at": _now_iso(),
            },
        )
        self.append_audit_event(username, "api_key_stored", {"service": service})

    def get_api_key(self, username: str, service: str) -> str | None:
        row = self._conn().execute(
            "SELECT value FROM api_keys WHERE username = ? AND service = ?",
            (username, service),
        ).fetchone()
        if not row:
            return None
        plaintext = secrets_crypto.decrypt_secret(row["value"], secrets_crypto.get_master_key(self._job_root))
        self.append_audit_event(username, "api_key_accessed", {"service": service})
        return plaintext

    def list_api_keys(self, username: str) -> list[dict]:
        """Return the user's keys as {service, masked, updated_at} — never plain.

        Does not emit an access audit event: a masked preview for the "Chiavi
        API" tab is not the key being *used*, only ``get_api_key`` (an actual
        connector resolving a key to make a request) is.
        """
        rows = self._conn().execute(
            "SELECT service, value, updated_at FROM api_keys WHERE username = ? ORDER BY service",
            (username,),
        ).fetchall()
        master_key = secrets_crypto.get_master_key(self._job_root)
        return [
            {
                "service": row["service"],
                "masked": _mask(secrets_crypto.decrypt_secret(row["value"], master_key)),
                "updated_at": row["updated_at"],
            }
            for row in rows
        ]

    def delete_api_key(self, username: str, service: str) -> None:
        self._conn().execute(
            "DELETE FROM api_keys WHERE username = ? AND service = ?",
            (username, service),
        )
        self.append_audit_event(username, "api_key_deleted", {"service": service})

    def all_api_keys(self) -> list[dict]:
        """Every (username, service, raw encrypted value) row across every
        user — master-key rotation only, never exposed through a user-facing
        API route (a per-user scope check belongs at the web layer for
        everything else; this is intentionally instance-admin-only)."""
        rows = self._conn().execute(
            "SELECT username, service, value FROM api_keys ORDER BY username, service"
        ).fetchall()
        return [{"username": r["username"], "service": r["service"], "value": r["value"]} for r in rows]

    def set_api_key_encrypted(self, username: str, service: str, encrypted_value: str) -> None:
        """Write an already-encrypted blob verbatim, bypassing ``encrypt_secret``.

        Used only by the master-key rotation routine, which must write values
        re-wrapped under the *new* key without re-running them through the
        (now stale-cached) default key lookup, and without emitting one
        ``api_key_stored`` audit event per row during a bulk rotation (the
        rotation itself logs a single summary event instead).
        """
        self._conn().execute(
            "UPDATE api_keys SET value = :value, updated_at = :updated_at "
            "WHERE username = :username AND service = :service",
            {
                "username": username,
                "service": service,
                "value": encrypted_value,
                "updated_at": _now_iso(),
            },
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

    def _redacted_seqs_from_tombstones(self) -> set[int]:
        """Numeri di seq degli eventi audit redatti da una cancellazione GDPR
        documentata (tombstoned) — usati da verify_audit_chain per distinguere
        una redazione legittima da una manomissione vera."""
        redacted: set[int] = set()
        rows = self._conn().execute("SELECT scope FROM dsar_tombstones").fetchall()
        for row in rows:
            try:
                scope = json.loads(row["scope"] or "{}")
            except json.JSONDecodeError:
                continue
            redacted.update(scope.get("redacted_seqs") or [])
        return redacted

    def verify_audit_chain(self) -> bool:
        """Verifica la catena hash.

        Le righe redatte da una cancellazione GDPR documentata (presenti in
        ``dsar_tombstones.scope.redacted_seqs``) sono escluse dal controllo
        di auto-hash — il loro contenuto è cambiato legittimamente e in modo
        tracciato (il tombstone stesso è la prova), non è manomissione. Il
        collegamento previous_hash → hash resta invece verificato SEMPRE,
        anche per le righe redatte: una redazione cambia solo actor/details,
        mai l'hash memorizzato, quindi l'integrità dell'ordinamento non è mai
        indebolita da una redazione legittima — solo una riga NON tombstonata
        con hash che non torna è manomissione vera.
        """
        redacted_seqs = self._redacted_seqs_from_tombstones()
        previous = ""
        rows = self._conn().execute(
            "SELECT seq, timestamp, actor, action, details, previous_hash, hash "
            "FROM audit_events ORDER BY seq ASC"
        ).fetchall()
        for row in rows:
            try:
                details = json.loads(row["details"]) if row["details"] else {}
            except json.JSONDecodeError:
                return False  # details corrotto/non-JSON: manomissione, non un chain-break silenzioso
            record = {
                "timestamp": row["timestamp"],
                "actor": row["actor"],
                "action": row["action"],
                "details": details,
                "previous_hash": row["previous_hash"],
            }
            stored_hash = row["hash"]
            if record["previous_hash"] != previous:
                return False
            if row["seq"] not in redacted_seqs and event_hash(record) != stored_hash:
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


def _migrate_cases_ai_enrichment(conn: sqlite3.Connection) -> None:
    """Add cases.ai_enrichment_enabled — consenso per-caso alle capability IA
    opt-in (indipendente dal kill-switch OSINT_AI_AGENTS_ENABLED)."""
    cols = {row[1] for row in conn.execute("PRAGMA table_info(cases)").fetchall()}
    if "ai_enrichment_enabled" not in cols:
        conn.execute(
            "ALTER TABLE cases ADD COLUMN ai_enrichment_enabled INTEGER NOT NULL DEFAULT 0"
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
    # Stesso trattamento difensivo di allowed_targets: colonna assente su DB
    # non ancora migrati -> default sicuro (IA disattivata).
    ai_enrichment_enabled = bool(row["ai_enrichment_enabled"]) if "ai_enrichment_enabled" in keys else False
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
        "ai_enrichment_enabled": ai_enrichment_enabled,
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


def _row_to_ai_run(row: sqlite3.Row) -> dict:
    try:
        input_summary = json.loads(row["input_summary"] or "{}")
    except json.JSONDecodeError:
        input_summary = {}
    try:
        output_json = json.loads(row["output_json"] or "{}")
    except json.JSONDecodeError:
        output_json = {}
    return {
        "id": row["id"],
        "case_id": row["case_id"],
        "kind": row["kind"],
        "actor": row["actor"],
        "provider": row["provider"],
        "model": row["model"],
        "created_at": row["created_at"],
        "status": row["status"],
        "input_summary": input_summary,
        "output_json": output_json,
        "error": row["error"],
    }


def _row_to_entity_merge_decision(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "case_id": row["case_id"],
        "entity_id_a": row["entity_id_a"],
        "entity_id_b": row["entity_id_b"],
        "decision": row["decision"],
        "decided_by": row["decided_by"],
        "decided_at": row["decided_at"],
        "ai_run_id": row["ai_run_id"],
        "ai_confidence": row["ai_confidence"],
        "ai_rationale": row["ai_rationale"],
    }


def _row_to_report_seal(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "case_id": row["case_id"],
        "job_id": row["job_id"],
        "manifest_hash": row["manifest_hash"],
        "artifact_count": row["artifact_count"],
        "signature_b64": row["signature_b64"],
        "signing_pubkey_b64": row["signing_pubkey_b64"],
        "signing_pubkey_fingerprint": row["signing_pubkey_fingerprint"],
        "sealed_at": row["sealed_at"],
        "sealed_by": row["sealed_by"],
        "tsa_url_host": row["tsa_url_host"],
        "tsa_status": row["tsa_status"],
        "tsa_token_der_b64": row["tsa_token_der_b64"],
        "tsa_gen_time": row["tsa_gen_time"],
        "tsa_requested_at": row["tsa_requested_at"],
    }
