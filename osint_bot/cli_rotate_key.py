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

    if source.startswith("env:") and new_key_output is None:
        lines.append(
            "ERROR: the master key comes from OSINT_MASTER_KEY (an environment "
            "variable) — this process cannot rewrite its own parent's "
            "environment or any secret manager on your behalf. Re-run with "
            "--new-key-output <path> and I will write the new key there; "
            "you then update OSINT_MASTER_KEY (or your secret manager) "
            "with its contents yourself."
        )
        return False, lines

    # Determine (but do NOT yet write) where the new key will land, and
    # pre-flight that the destination is actually writable. Writing the new
    # key file happens ONLY after every row has been successfully re-wrapped
    # below (see the try/except) — writing it earlier would mean a crash
    # mid-loop deletes the only copy of the OLD key (which lived solely in
    # the `old_key` variable) while some rows are still encrypted under it,
    # making them permanently unrecoverable. This ordering is deliberate:
    # the old key file must remain on disk, untouched, until the new key
    # provably decrypts everything the old one did.
    in_place_path: Path | None = None
    if new_key_output is None and not source.startswith("env:"):
        in_place_path = secrets_crypto.master_key_path(job_root)
        try:
            in_place_path.parent.mkdir(parents=True, exist_ok=True)
            probe = in_place_path.with_suffix(in_place_path.suffix + ".rotate-probe")
            probe.write_text("", encoding="utf-8")
            probe.unlink()
        except OSError as exc:
            lines.append(
                f"ERROR: {in_place_path} does not look writable ({exc}). "
                "If this path is a read-only systemd-credential mount, "
                "re-run with --new-key-output <path> instead."
            )
            return False, lines

    # Re-wrap every stored key under the new master key. The OLD key file
    # (or OSINT_MASTER_KEY env var) is untouched throughout this loop, so a
    # crash here is always recoverable: nothing has been destroyed yet.
    reencrypted = 0
    try:
        for row in rows:
            row_aad = secrets_crypto.api_key_aad(row["username"], row["service"])
            plaintext = secrets_crypto.decrypt_secret(row["value"], old_key, aad=row_aad)
            new_blob = secrets_crypto.encrypt_secret(plaintext, new_key, aad=row_aad)
            storage.set_api_key_encrypted(row["username"], row["service"], new_blob)
            reencrypted += 1
    except Exception as exc:
        lines.append(
            f"ERROR: re-wrap failed after {reencrypted}/{len(rows)} key(s) ({exc}). "
            "The OLD master key was NOT touched and is still active — nothing was "
            "lost. Fix the underlying issue and re-run the rotation from scratch."
        )
        return False, lines

    # Only now, with every row provably re-wrapped, persist the new key.
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
        secrets_crypto.persist_master_key_file(in_place_path, new_key)
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

        print(
            "WARNING: stop the Argo web service before continuing. This tool takes "
            "one snapshot of stored keys and re-wraps it; a key written by a still-"
            "running server during rotation can end up saved under the old key with "
            "no record of that having happened, or overwritten by this tool's stale "
            "snapshot. There is no locking against a concurrent writer.\n"
        )
        ok, lines = rotate(storage, job_root, new_key_output=args.new_key_output)
        for line in lines:
            print(line)
        return 0 if ok else 1
    finally:
        storage.close()


if __name__ == "__main__":
    sys.exit(main())
