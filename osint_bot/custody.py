"""Pillar 0.3 — Chain of custody and probatory integrity.

Every external tool output and connector response that may end up in a report
is hashed (SHA-256) and recorded immutably in the artifacts table, linked to
the job and optionally to the finding that cites it.  The export_case_manifest
function produces a manifest over all artifacts in a case so an external
verifier can confirm that nothing was altered after collection.

Public API:
  artifact_sha256(content)          -> hex digest
  command_hash(argv)                -> hex digest of JSON-encoded argv
  save_artifact(...)                -> artifact dict (also upserted in storage)
  export_case_manifest(case_id, storage, job_root) -> manifest dict
"""
from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def artifact_sha256(content: str | bytes) -> str:
    """SHA-256 of content (str encoded to UTF-8, bytes passed as-is)."""
    if isinstance(content, str):
        content = content.encode("utf-8")
    return hashlib.sha256(content).hexdigest()


def command_hash(argv: list[str]) -> str:
    """SHA-256 of the JSON-encoded argv list.

    Deterministic: the same command always hashes to the same digest, so a
    re-run with the same parameters can be verified without re-executing.
    """
    payload = json.dumps(argv, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def save_artifact(
    *,
    artifact_type: str,
    content: str | bytes,
    job_id: str = "",
    case_id: str = "",
    finding_id: str = "",
    tool_name: str = "",
    argv: list[str] | None = None,
    actor: str = "system",
    storage_path: str = "",
    storage=None,
) -> dict[str, Any]:
    """Hash *content*, build an artifact record and persist it.

    Parameters
    ----------
    artifact_type : str
        One of ``tool_output``, ``archive``, ``screenshot``, ``connector_json``.
    content : str | bytes
        The raw content to hash and record.
    storage : optional
        A ``Storage`` instance.  When provided, the artifact is upserted into
        the ``artifacts`` table.  Callers in the CLI path may omit it.
    """
    artifact_id = secrets.token_hex(16)
    chash = command_hash(argv) if argv else ""
    record: dict[str, Any] = {
        "id": artifact_id,
        "artifact_type": artifact_type,
        "tool_name": tool_name,
        "command_hash": chash,
        "collected_at": _now_iso(),
        "actor": actor,
        "content_sha256": artifact_sha256(content),
        "content_size": len(content) if isinstance(content, (bytes, str)) else 0,
        "storage_path": storage_path,
        "job_id": job_id,
        "case_id": case_id,
        "finding_id": finding_id,
    }
    if storage is not None:
        try:
            storage.put_artifact(record)
        except Exception:
            pass  # never let custody bookkeeping break the analysis pipeline
    return record


def export_case_manifest(
    case_id: str,
    storage,
    job_root: Path,
) -> dict[str, Any]:
    """Produce a verifiable manifest of all artifacts collected for *case_id*.

    For each artifact that has a ``storage_path``, the file on disk is re-hashed
    and compared with the recorded ``content_sha256``.  A tampered or missing
    file results in ``verified=False`` for that artifact.

    Returns a dict with:
    - ``case_id``
    - ``artifacts``: list with a ``verified`` boolean per entry
    - ``all_verified``: True only when every artifact with a storage path matches
    - ``manifest_hash``: SHA-256 of the canonical artifact list (sorted by id),
      suitable for RFC 3161 timestamping
    """
    artifacts = storage.list_artifacts(case_id=case_id)
    verified_artifacts: list[dict[str, Any]] = []
    for a in artifacts:
        verified: bool
        path_str = a.get("storage_path", "")
        if path_str:
            artifact_path = job_root / path_str
            if artifact_path.exists():
                actual = artifact_sha256(artifact_path.read_bytes())
                verified = actual == a.get("content_sha256", "")
            else:
                verified = False
        else:
            # No on-disk file — only the hash was recorded (e.g. ephemeral stdout).
            verified = True
        verified_artifacts.append({**a, "verified": verified})

    canonical = json.dumps(
        sorted(verified_artifacts, key=lambda x: x.get("id", "")),
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return {
        "case_id": case_id,
        "artifacts": verified_artifacts,
        "artifact_count": len(verified_artifacts),
        "all_verified": all(v["verified"] for v in verified_artifacts),
        "manifest_hash": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        "generated_at": _now_iso(),
    }
