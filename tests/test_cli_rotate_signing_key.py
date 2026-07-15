"""osint_bot.cli_rotate_signing_key — orchestration around report_signing's
rotate_signing_key: dry-run reporting and the audit event on a real rotation.
The crypto itself is covered by tests/test_report_signing.py::KeyRotationTests."""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from osint_bot import cli_rotate_signing_key, report_signing
from osint_bot.storage import Storage


class _IsolatedKeyCacheMixin:
    def setUp(self):
        super().setUp()
        report_signing._cached_key = None
        report_signing._cached_key_path = None

    def tearDown(self):
        report_signing._cached_key = None
        report_signing._cached_key_path = None
        super().tearDown()


class RotateSigningKeyCliTests(_IsolatedKeyCacheMixin, unittest.TestCase):
    def test_dry_run_makes_no_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_signing.get_signing_key(root)  # pre-existing key
            key_path = report_signing.signing_key_path(root)
            before = key_path.read_text(encoding="utf-8")
            with patch.dict(os.environ, {"OSINT_JOB_DIR": str(root)}):
                rc = cli_rotate_signing_key.main([])
            self.assertEqual(rc, 0)
            self.assertEqual(key_path.read_text(encoding="utf-8"), before)
            self.assertEqual(list(root.glob(".report_signing_key.retired-*")), [])

    def test_dry_run_with_no_prior_key_does_not_create_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.dict(os.environ, {"OSINT_JOB_DIR": str(root)}):
                rc = cli_rotate_signing_key.main([])
            self.assertEqual(rc, 0)
            self.assertFalse(report_signing.signing_key_path(root).exists())

    def test_real_rotation_logs_audit_event_without_leaking_key_material(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_signing.get_signing_key(root)
            with patch.dict(os.environ, {"OSINT_JOB_DIR": str(root)}):
                rc = cli_rotate_signing_key.main(["--yes"])
            self.assertEqual(rc, 0)

            store = Storage(root / "gufo.sqlite3")
            try:
                events = [e for e in store.all_audit_events() if e["action"] == "report_signing_key_rotated"]
                self.assertEqual(len(events), 1)
                details = events[0]["details"]
                self.assertIn("new_fingerprint_sha256", details)
                self.assertIn("retired_fingerprint_sha256", details)
                # Only fingerprints (hex SHA-256), never key material, ever hit the audit log.
                self.assertNotIn("private", str(details).lower())
                self.assertEqual(len(details["new_fingerprint_sha256"]), 64)
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
