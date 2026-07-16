"""Tests for the argo-set-role CLI (osint_bot/cli_set_role.py)."""
import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from osint_bot.cli_set_role import main
from osint_bot.storage import Storage


class SetRoleCliTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.job_root = Path(self._tmp.name)
        self.db_path = self.job_root / "gufo.sqlite3"
        store = Storage(self.db_path)
        store.put_user({
            "username": "alice", "password": "x", "plan": "free",
            "created_at": "2026-01-01T00:00:00+00:00", "disabled": False,
            "email": "alice@example.com", "verified": True,
            "verified_at": "2026-01-01T00:00:00+00:00",
        })
        store.close()
        self._env_patch = patch.dict("os.environ", {"OSINT_JOB_DIR": str(self.job_root)})
        self._env_patch.start()

    def tearDown(self):
        self._env_patch.stop()
        self._tmp.cleanup()

    def _role_of(self, username: str) -> str | None:
        store = Storage(self.db_path)
        try:
            user = store.get_user(username)
            return user["role"] if user else None
        finally:
            store.close()

    def test_dry_run_does_not_change_role(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["alice", "admin"])
        self.assertEqual(code, 0)
        self.assertIn("Dry run only", buf.getvalue())
        self.assertEqual(self._role_of("alice"), "analyst")

    def test_yes_flag_applies_the_change(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["alice", "admin", "--yes"])
        self.assertEqual(code, 0)
        self.assertIn("Done", buf.getvalue())
        self.assertEqual(self._role_of("alice"), "admin")

    def test_already_at_target_role_is_a_noop(self):
        main(["alice", "admin", "--yes"])
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["alice", "admin", "--yes"])
        self.assertEqual(code, 0)
        self.assertIn("nothing to do", buf.getvalue())

    def test_demote_back_to_analyst(self):
        main(["alice", "admin", "--yes"])
        main(["alice", "analyst", "--yes"])
        self.assertEqual(self._role_of("alice"), "analyst")

    def test_unknown_user_returns_nonzero_and_does_not_create_one(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["bob", "admin", "--yes"])
        self.assertEqual(code, 1)
        self.assertIn("No such user", buf.getvalue())
        self.assertIsNone(self._role_of("bob"))

    def test_invalid_role_rejected_by_argparse(self):
        with self.assertRaises(SystemExit) as ctx:
            main(["alice", "superuser"])
        self.assertEqual(ctx.exception.code, 2)

    def test_role_change_is_audited(self):
        main(["alice", "admin", "--yes"])
        store = Storage(self.db_path)
        try:
            events = store.all_audit_events()
        finally:
            store.close()
        role_events = [e for e in events if e.get("action") == "admin_role_changed"]
        self.assertEqual(len(role_events), 1)
        self.assertEqual(role_events[0]["details"]["target_username"], "alice")
        self.assertEqual(role_events[0]["details"]["new_role"], "admin")
        self.assertEqual(role_events[0]["details"]["changed_via"], "cli")


if __name__ == "__main__":
    unittest.main()
