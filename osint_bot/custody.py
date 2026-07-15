"""Pillar 0.3 — Chain of custody and probatory integrity.

Every external tool output and connector response that may end up in a report
is hashed (SHA-256) and recorded immutably in the artifacts table, linked to
the job and optionally to the finding that cites it.  The export_case_manifest
function produces a manifest over all artifacts in a case so an external
verifier can confirm that nothing was altered after collection.

register_report_artifacts extends this to the OUTPUT side: the final report
files (report.md/json/pdf, forensic.*, redteam.*) are registered the same way
as collection-time evidence, as artifact_type="report_output" — so a single
call to export_case_manifest, once report_signing.py signs its manifest_hash,
covers both "what evidence did we collect" and "what did we hand to the
analyst", with no second/parallel manifest mechanism.

Note: export_case_manifest is CASE-scoped, not job-scoped (list_artifacts'
job_id filter is only usable when case_id is absent — evidence artifacts
recorded from plugins.py never carry a job_id today). web.handle_seal_job
triggers a seal at the completion of one job, but the manifest_hash it signs
covers every artifact of the whole CASE as of that moment — a later job in
the same case produces a new, larger, cumulative seal. This is intentional,
not a workaround: a verifier cares about the case's integrity, not an
arbitrary job boundary.

Public API:
  artifact_sha256(content)          -> hex digest
  command_hash(argv)                -> hex digest of JSON-encoded argv
  save_artifact(...)                -> artifact dict (also upserted in storage)
  register_report_artifacts(...)    -> registers report output files as artifacts
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
        One of ``tool_output``, ``archive``, ``screenshot``, ``connector_json``,
        ``report_output`` (a final generated report file — see
        :func:`register_report_artifacts`).
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


def register_report_artifacts(
    *,
    job_id: str,
    case_id: str,
    report_paths: dict[str, str],
    storage,
    job_root: Path,
    actor: str = "system",
) -> list[dict[str, Any]]:
    """Register a job's final report files as ``artifact_type="report_output"``.

    *report_paths* is a ``{field_name: absolute_path}`` mapping, e.g. the job
    dict's ``{"markdown_path": ..., "json_path": ..., "pdf_path": ...}``.
    Missing/empty entries and files that no longer exist on disk are skipped
    (best-effort — same principle as :func:`save_artifact`: never let custody
    bookkeeping break the job pipeline). Paths are stored relative to
    *job_root* so the manifest stays portable across a backup/restore to a
    different install path.

    Returns the list of artifact records that were actually registered.
    """
    registered: list[dict[str, Any]] = []
    for field_name, path_str in report_paths.items():
        if not path_str:
            continue
        artifact_path = Path(path_str)
        if not artifact_path.exists():
            continue
        try:
            rel_path = artifact_path.relative_to(job_root)
        except ValueError:
            rel_path = artifact_path  # fuori da job_root: fallback al path assoluto
        record = save_artifact(
            artifact_type="report_output",
            content=artifact_path.read_bytes(),
            job_id=job_id,
            case_id=case_id,
            tool_name=field_name,
            actor=actor,
            storage_path=str(rel_path),
            storage=storage,
        )
        registered.append(record)
    return registered


def _build_manifest(artifacts: list[dict[str, Any]], job_root: Path) -> dict[str, Any]:
    """Shared verify-and-hash core for :func:`export_case_manifest`."""
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
        "artifacts": verified_artifacts,
        "artifact_count": len(verified_artifacts),
        "all_verified": all(v["verified"] for v in verified_artifacts),
        "manifest_hash": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        "generated_at": _now_iso(),
    }


def export_case_manifest(
    case_id: str,
    storage,
    job_root: Path,
) -> dict[str, Any]:
    """Produce a verifiable manifest of all artifacts collected for *case_id*
    (every job in the case, cumulative).

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
    manifest = _build_manifest(storage.list_artifacts(case_id=case_id), job_root)
    return {"case_id": case_id, **manifest}
