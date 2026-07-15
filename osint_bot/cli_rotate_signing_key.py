"""``argo-rotate-signing-key`` — rotate the instance's Ed25519 report-signing key.

    argo-rotate-signing-key            # dry run: shows the current fingerprint, no changes
    argo-rotate-signing-key --yes      # rotates: retires the current key, generates a new one

Unlike the API-key master key (``argo-rotate-master-key``), rotating this key
never requires re-processing anything: every sealed report already carries
its own public key inline, so past signatures stay verifiable forever with
no action needed. Rotation only changes which key signs reports from this
point forward. The retired private key is archived on disk (never deleted),
in case an operator needs to prove continuity between the old and new
identity later.

A running argo-osint web process caches its signing key in memory
(``report_signing.get_signing_key``) with no way to learn a rotation
happened elsewhere — exactly like the API-key master key, restarting the
service after rotation is REQUIRED, not optional, or it keeps signing new
reports with the retired key.

Rotate this periodically as key hygiene, or immediately if you suspect the
key file may have been exposed (e.g. a leaked backup, a compromised host
later re-secured).
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import report_signing
from .storage_base import create_storage


def _job_root() -> Path:
    return Path(os.getenv("OSINT_JOB_DIR", "web_jobs"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="argo-rotate-signing-key",
        description="Rotate the instance's Ed25519 report-signing key.",
    )
    parser.add_argument("--yes", action="store_true", help="perform the rotation (default: dry run)")
    args = parser.parse_args(argv)

    job_root = _job_root()
    path = report_signing.signing_key_path(job_root)

    if not args.yes:
        if path.exists():
            current = report_signing.load_or_create_signing_key(path)
            fp = report_signing.public_key_fingerprint(current.public_key())
            print(f"Current signing key fingerprint: {fp}")
        else:
            print("No signing key exists yet — one will be auto-generated on first use.")
        print(f"Key file: {path}")
        print("\nDry run only — no changes made. Re-run with --yes to rotate.")
        return 0

    result = report_signing.rotate_signing_key(job_root)

    storage = create_storage(job_root)
    try:
        storage.append_audit_event(
            "system", "report_signing_key_rotated",
            {
                "retired_fingerprint_sha256": result["retired_fingerprint_sha256"],
                "new_fingerprint_sha256": result["new_fingerprint_sha256"],
            },
        )
    finally:
        storage.close()

    print(f"Retired key fingerprint: {result['retired_fingerprint_sha256'] or '(none — first key generated)'}")
    print(f"New key fingerprint:     {result['new_fingerprint_sha256']}")
    print(f"Rotated at:              {result['rotated_at']}")
    print()
    print("Past sealed reports remain verifiable unchanged — each embeds its own")
    print("public key. This only affects the key used to sign reports from now on.")
    print()
    print("RESTART THE ARGO WEB SERVICE NOW. A running process keeps the old signing")
    print("key cached in memory and will keep signing NEW reports with the retired")
    print("key — silently — until it is restarted. This matters most if you rotated")
    print("because the old key may have been exposed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
