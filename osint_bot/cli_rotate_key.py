"""``argo-rotate-master-key`` — rotate the master key that wraps every stored
BYOK API key (see ``osint_bot/secrets_crypto.py`` for the envelope-encryption
scheme this rotates).

    argo-rotate-master-key                          # dry run, no changes
    argo-rotate-master-key --yes                     # rotate, key source permitting
    argo-rotate-master-key --yes --new-key-output PATH   # required when the
                                                           # master key comes
                                                           # from OSINT_MASTER_KEY
                                                           # or a read-only
                                                           # systemd-credential
                                                           # mount this process
                                                           # cannot overwrite

What this does NOT do: restart the running Argo web server. A live process
caches its master key in memory (``secrets_crypto.get_master_key``) and has
no way to learn from outside that a rotation happened — after a successful
rotation you MUST restart the service, or every subsequent ``get_api_key``
call in that still-running process will fail to decrypt (it is reading rows
re-wrapped under a key it does not have). This tool prints that instruction
every time it completes a real rotation; it is not optional advice.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import secrets_crypto
from .storage_base import create_storage


def _job_root() -> Path:
    return Path(os.getenv("OSINT_JOB_DIR", "web_jobs"))


def rotate(storage, job_root: Path, *, new_key_output: Path | None) -> tuple[bool, list[str]]:
    """Perform the rotation. Returns (ok, lines) for the CLI to print."""
    lines: list[str] = []
    source = secrets_crypto.master_key_source(job_root)
    rows = storage.all_api_keys()
    lines.append(f"Master key source: {source}")
    lines.append(f"Keys to re-wrap:   {len(rows)}")

    old_key = secrets_crypto.get_master_key(job_root)
    new_key = secrets_crypto.generate_master_key()

    in_place_path: Path | None = None
    if source.startswith("env:"):
        if new_key_output is None:
            lines.append(
                "ERROR: the master key comes from OSINT_MASTER_KEY (an environment "
                "variable) — this process cannot rewrite its own parent's "
                "environment or any secret manager on your behalf. Re-run with "
                "--new-key-output <path> and I will write the new key there; "
                "you then update OSINT_MASTER_KEY (or your secret manager) "
                "with its contents yourself."
            )
            return False, lines
    else:
        # "file-override:<path>" or "auto-generated:<path>" — try to write
        # in place; a systemd-managed read-only credential mount will raise
        # and we fall back to requiring --new-key-output just like the env case.
        candidate = secrets_crypto.master_key_path(job_root)
        if new_key_output is not None:
            in_place_path = None  # operator explicitly asked for a separate file
        else:
            try:
                secrets_crypto.persist_master_key_file(candidate, new_key)
                in_place_path = candidate
            except OSError as exc:
                lines.append(
                    f"ERROR: could not write the new key to {candidate} ({exc}). "
                    "If this path is a read-only systemd-credential mount, "
                    "re-run with --new-key-output <path> instead."
                )
                return False, lines

    # Re-wrap every stored key under the new master key.
    reencrypted = 0
    for row in rows:
        plaintext = secrets_crypto.decrypt_secret(row["value"], old_key)
        new_blob = secrets_crypto.encrypt_secret(plaintext, new_key)
        storage.set_api_key_encrypted(row["username"], row["service"], new_blob)
        reencrypted += 1

    if new_key_output is not None:
        secrets_crypto.persist_master_key_file(new_key_output, new_key)
        lines.append(f"New master key written to: {new_key_output}")
        lines.append(
            "Update your secret manager / systemd credential / OSINT_MASTER_KEY "
            f"with the contents of {new_key_output}, THEN restart Argo. Until you "
            "do, Argo will fail to decrypt API keys — do not delete this file "
            "until the new key is confirmed live."
        )
    else:
        lines.append(f"New master key written to: {in_place_path}")

    secrets_crypto.invalidate_cache()
    storage.append_audit_event(
        "system", "api_master_key_rotated",
        {"keys_reencrypted": reencrypted, "key_source_before": source},
    )
    lines.append(f"Re-wrapped {reencrypted} key(s).")
    lines.append("")
    lines.append("RESTART THE ARGO WEB SERVICE NOW. A running process keeps the old "
                  "master key cached in memory and cannot decrypt keys re-wrapped "
                  "under the new one until it is restarted.")
    return True, lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="argo-rotate-master-key",
        description="Rotate the master key that wraps every stored BYOK API key.",
    )
    parser.add_argument("--yes", action="store_true", help="perform the rotation (default: dry run)")
    parser.add_argument(
        "--new-key-output", type=Path, default=None,
        help="write the new key here instead of in place — required when the "
             "current key comes from OSINT_MASTER_KEY or a read-only mount",
    )
    args = parser.parse_args(argv)

    job_root = _job_root()
    storage = create_storage(job_root)
    try:
        if not args.yes:
            print(f"Master key source: {secrets_crypto.master_key_source(job_root)}")
            print(f"Keys that would be re-wrapped: {len(storage.all_api_keys())}")
            print("\nDry run only — no changes made. Re-run with --yes to rotate.")
            return 0

        ok, lines = rotate(storage, job_root, new_key_output=args.new_key_output)
        for line in lines:
            print(line)
        return 0 if ok else 1
    finally:
        storage.close()


if __name__ == "__main__":
    sys.exit(main())
