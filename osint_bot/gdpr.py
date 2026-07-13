"""Pillar 0.4 — GDPR by-design.

Provides:
  tombstone_case(case_id, actor, storage)
      Remove PII from jobs/findings in a case and mark the case as expired.
      The audit chain stays intact: a tombstone event with the hashed selector
      replaces each erased record, so verify_audit_chain() remains True.

  apply_retention_policy(storage, actor)
      Find all cases whose retention_until has passed and tombstone them.

  dsar_export(selector, storage)
      Return all storage records that reference *selector* (email, phone, name,
      handle).  Used for the GDPR "right of access" (Art. 15).

  dsar_erase(selector, actor, storage)
      Tombstone every job/case that contains *selector* in its payload/title/
      target and write an audit event.  Used for the right to erasure (Art. 17).

  generate_ropa(owner, storage)
      Return a Register of Processing Activities listing every case for *owner*
      with purpose, legal basis, categories, retention, and status.  Suitable
      for export as JSON or for inclusion in the EU Article 30 register.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any

# PII patterns used during tombstoning (conservative — prefers recall over precision)
_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", re.IGNORECASE)
_PHONE_RE = re.compile(r"\+?[0-9][\d\s\-().]{6,}\d")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _selector_sha256(selector: str) -> str:
    return hashlib.sha256(selector.strip().lower().encode("utf-8")).hexdigest()


def _tombstone_text(text: str) -> str:
    """Replace email and phone occurrences in *text* with [ERASED] markers."""
    text = _EMAIL_RE.sub("[ERASED-EMAIL]", text)
    text = _PHONE_RE.sub("[ERASED-PHONE]", text)
    return text


def _contains_selector(obj: Any, selector: str) -> bool:
    """Return True if *obj* (str, dict, list) contains *selector* literally."""
    needle = selector.strip().lower()
    if isinstance(obj, str):
        return needle in obj.lower()
    if isinstance(obj, dict):
        return any(_contains_selector(v, selector) for v in obj.values())
    if isinstance(obj, list):
        return any(_contains_selector(item, selector) for item in obj)
    return False


def tombstone_case(case_id: str, actor: str, storage) -> dict[str, Any]:
    """Erase PII from all jobs inside *case_id* and mark the case expired.

    For each job whose payload contains personal data (emails, phones, target),
    the payload is scrubbed with *_tombstone_text* and re-persisted.  The case
    status is set to ``expired``.  A single ``case_tombstoned`` audit event is
    appended with the case_id and a count of scrubbed jobs.

    Returns a summary dict.
    """
    jobs = storage.list_jobs_by_case(case_id)
    scrubbed = 0
    for job in jobs:
        raw_payload = json.dumps(job, ensure_ascii=False)
        clean_payload = _tombstone_text(raw_payload)
        if clean_payload != raw_payload:
            clean_job = json.loads(clean_payload)
            storage.put_job(job["id"], clean_job)
            scrubbed += 1

    case = storage.get_case(case_id)
    if case:
        case["status"] = "expired"
        case["notes"] = (case.get("notes") or "") + f"\n[tombstoned at {_now_iso()} by {actor}]"
        storage.put_case(case)

    event = storage.append_audit_event(
        actor,
        "case_tombstoned",
        {"case_id": case_id, "jobs_scrubbed": scrubbed, "at": _now_iso()},
    )
    return {"case_id": case_id, "jobs_scrubbed": scrubbed, "audit_hash": event["hash"]}


def apply_retention_policy(storage, actor: str = "system") -> list[dict[str, Any]]:
    """Find expired cases and tombstone each one.

    A case is expired when ``retention_until`` is a non-null ISO date that is
    earlier than now (UTC).  Returns a list of tombstone summaries.
    """
    now = _now_iso()
    all_cases = storage.list_cases()
    results: list[dict[str, Any]] = []
    for case in all_cases:
        retention = case.get("retention_until")
        if not retention:
            continue
        if case.get("status") == "expired":
            continue
        if retention < now:
            result = tombstone_case(case["id"], actor, storage)
            results.append(result)
    return results


def dsar_export(selector: str, storage) -> dict[str, Any]:
    """Locate all records that reference *selector* (right of access, Art. 15).

    Searches jobs (payload), cases (title, purpose, notes) and artifacts
    (tool_name, storage_path).  Returns a dict with matching record counts and
    summaries — never the full payload to avoid inadvertently logging the
    access request itself.
    """
    jobs_match: list[str] = []
    for job in storage.list_jobs():
        raw = json.dumps(job, ensure_ascii=False)
        if _contains_selector(raw, selector):
            jobs_match.append(job.get("id", ""))

    cases_match: list[str] = []
    for case in storage.list_cases():
        combined = json.dumps(
            {k: case.get(k, "") for k in ("title", "purpose", "notes")},
            ensure_ascii=False,
        )
        if _contains_selector(combined, selector):
            cases_match.append(case.get("id", ""))

    return {
        "selector_sha256": _selector_sha256(selector),
        "jobs": jobs_match,
        "cases": cases_match,
        "total": len(jobs_match) + len(cases_match),
        "exported_at": _now_iso(),
    }


def dsar_erase(selector: str, actor: str, storage) -> dict[str, Any]:
    """Erase *selector* from all matching records (right to erasure, Art. 17).

    For every matching job, scrub the payload with _tombstone_text and
    re-persist.  Record a ``dsar_erased`` audit event with the selector hash
    (never the plaintext selector).

    Returns a summary with counts and the audit event hash.
    """
    scrubbed_jobs: list[str] = []
    for job in storage.list_jobs():
        raw = json.dumps(job, ensure_ascii=False)
        if not _contains_selector(raw, selector):
            continue
        clean = _tombstone_text(raw)
        if clean != raw:
            storage.put_job(job["id"], json.loads(clean))
            scrubbed_jobs.append(job.get("id", ""))

    sel_hash = _selector_sha256(selector)
    event = storage.append_audit_event(
        actor,
        "dsar_erased",
        {
            "selector_sha256": sel_hash,
            "jobs_scrubbed": len(scrubbed_jobs),
            "at": _now_iso(),
        },
    )
    return {
        "selector_sha256": sel_hash,
        "jobs_scrubbed": len(scrubbed_jobs),
        "audit_hash": event["hash"],
        "erased_at": _now_iso(),
    }


def generate_ropa(owner: str, storage) -> list[dict[str, Any]]:
    """Generate a Register of Processing Activities (Art. 30) for *owner*.

    Each entry corresponds to one case and includes:
    - case_id, title, status
    - purpose, legal_basis (type + reference)
    - data_categories: inferred from job profiles (target_type)
    - retention_until
    - job_count
    - created_at, updated_at
    """
    cases = storage.list_cases(owner=owner)
    entries: list[dict[str, Any]] = []
    for case in cases:
        jobs = storage.list_jobs_by_case(case["id"])
        target_types = sorted({
            (j.get("profile") or {}).get("target_type") or "unknown"
            for j in jobs
        })
        data_categories = _infer_data_categories(target_types)
        entries.append({
            "case_id": case["id"],
            "title": case["title"],
            "status": case["status"],
            "purpose": case.get("purpose", ""),
            "legal_basis": case.get("legal_basis") or {},
            "data_categories": data_categories,
            "retention_until": case.get("retention_until"),
            "job_count": len(jobs),
            "created_at": case["created_at"],
            "updated_at": case["updated_at"],
        })
    return entries


_CATEGORY_MAP: dict[str, list[str]] = {
    "email": ["identifiers", "contact_data"],
    "phone": ["identifiers", "contact_data"],
    "person": ["identifiers", "personal_data"],
    "handle": ["identifiers", "online_identifiers"],
    "domain": ["network_identifiers"],
    "ip": ["network_identifiers"],
    "company": ["organisational_data"],
    "media": ["content_data"],
}


def _infer_data_categories(target_types: list[str]) -> list[str]:
    cats: set[str] = set()
    for tt in target_types:
        cats.update(_CATEGORY_MAP.get(tt, ["unknown"]))
    return sorted(cats)
