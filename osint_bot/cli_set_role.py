"""``argo-set-role`` — assign the RBAC role ('analyst' or 'admin') for a user.

    argo-set-role alice admin          # dry run: shows current vs requested role
    argo-set-role alice admin --yes    # actually changes it

Deliberately a local CLI command, not a web endpoint: granting admin is an
operator action that requires shell/filesystem access to the machine Argo
runs on, the same trust boundary as generating ARGO_ADMIN_PASSWORD_HASH in
the first place (see docs/CONFIGURATION.md). There is no "an admin can grant
admin to any other user over the web" surface in Argo by design — an account
with the 'admin' role can unlock admin-only UI/API features for itself
(POST /api/admin/unlock still works exactly as before, unchanged), but
cannot mint new admins.

A running argo-osint web process re-reads the user's role from storage on
every admin-gated request (see ``web.session_is_admin``) rather than caching
it in the session, so a role change here takes effect on that user's very
next request — no service restart needed.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .storage_base import create_storage

_VALID_ROLES = ("analyst", "admin")


def _job_root() -> Path:
    return Path(os.getenv("OSINT_JOB_DIR", "web_jobs"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="argo-set-role",
        description="Assign the RBAC role ('analyst' or 'admin') for an existing Argo user.",
    )
    parser.add_argument("username", help="existing Argo account username")
    parser.add_argument("role", choices=_VALID_ROLES, help="role to assign")
    parser.add_argument("--yes", action="store_true", help="apply the change (default: dry run)")
    args = parser.parse_args(argv)

    storage = create_storage(_job_root())
    try:
        user = storage.get_user(args.username) or storage.all_users().get(args.username)
        if user is None:
            print(f"No such user: {args.username!r}")
            print("Users authenticate via signup or Google Sign-In first; this command")
            print("changes the role of an existing account, it does not create one.")
            return 1

        current_role = user.get("role", "analyst")
        print(f"User:         {args.username}")
        print(f"Current role: {current_role}")
        print(f"New role:     {args.role}")

        if current_role == args.role:
            print("\nAlready set to that role — nothing to do.")
            return 0

        if not args.yes:
            print("\nDry run only — no changes made. Re-run with --yes to apply.")
            return 0

        user["role"] = args.role
        storage.put_user(user)
        storage.append_audit_event(
            "system",
            "admin_role_changed",
            {
                "target_username": args.username,
                "previous_role": current_role,
                "new_role": args.role,
                "changed_via": "cli",
            },
        )
        print(f"\nDone. {args.username!r} is now {args.role!r}.")
        if args.role == "admin":
            print("Takes effect on their very next request — no restart needed.")
        return 0
    finally:
        storage.close()


if __name__ == "__main__":
    sys.exit(main())
