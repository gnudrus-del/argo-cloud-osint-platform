from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_APPEND_LOCK = threading.Lock()


def append_audit_event(root: Path, actor: str, action: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
    root.mkdir(parents=True, exist_ok=True)
    log_path = root / "audit.log"
    with _APPEND_LOCK:
        previous_hash = last_hash(log_path)
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "actor": actor or "system",
            "action": action,
            "details": details or {},
            "previous_hash": previous_hash,
        }
        record["hash"] = event_hash(record)
        line = json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n"
        _atomic_append(log_path, line)
    return record


def _atomic_append(log_path: Path, line: str) -> None:
    existing = log_path.read_bytes() if log_path.is_file() else b""
    payload = existing + line.encode("utf-8")
    tmp_path = log_path.with_name(log_path.name + ".tmp")
    with tmp_path.open("wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp_path, log_path)


def last_hash(log_path: Path) -> str:
    if not log_path.is_file():
        return ""
    last = ""
    with log_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                last = json.loads(line).get("hash", "")
            except json.JSONDecodeError:
                continue
    return last


def event_hash(record: dict[str, Any]) -> str:
    unsigned = {key: value for key, value in record.items() if key != "hash"}
    payload = json.dumps(unsigned, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def verify_audit_log(log_path: Path) -> bool:
    previous = ""
    if not log_path.is_file():
        return True
    with log_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            record = json.loads(line)
            expected_hash = record.get("hash", "")
            if record.get("previous_hash", "") != previous:
                return False
            if event_hash(record) != expected_hash:
                return False
            previous = expected_hash
    return True
