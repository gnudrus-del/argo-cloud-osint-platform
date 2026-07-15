"""osint_bot.report_signing — firma Ed25519 locale dei sigilli di report.
Nessuna chiamata di rete qui: e' puro calcolo locale su file temporanei."""
from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from osint_bot import report_signing


def _digest_hex(data: bytes = b"hello world") -> str:
    return hashlib.sha256(data).hexdigest()


class _IsolatedKeyCacheMixin:
    """Ogni test riparte con la cache di processo vuota, cosi un test non
    contamina il successivo con una chiave caricata per un job_root diverso."""

    def setUp(self):
        super().setUp()
        report_signing._cached_key = None
        report_signing._cached_key_path = None

    def tearDown(self):
        report_signing._cached_key = None
        report_signing._cached_key_path = None
        super().tearDown()


class SigningKeyPathTests(_IsolatedKeyCacheMixin, unittest.TestCase):
    def test_default_under_job_root(self):
        root = Path("/tmp/some-job-root")
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("OSINT_REPORT_SIGNING_KEY_PATH", None)
            path = report_signing.signing_key_path(root)
        self.assertEqual(path, root / ".report_signing_key")

    def test_env_override(self):
        with patch.dict(os.environ, {"OSINT_REPORT_SIGNING_KEY_PATH": "/custom/key.b64"}):
            path = report_signing.signing_key_path(Path("/tmp/ignored"))
        self.assertEqual(path, Path("/custom/key.b64"))


class KeyPersistenceTests(_IsolatedKeyCacheMixin, unittest.TestCase):
    def test_generates_and_persists_on_first_use(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            key_path = report_signing.signing_key_path(root)
            self.assertFalse(key_path.exists())
            report_signing.get_signing_key(root)
            self.assertTrue(key_path.exists())

    def test_reload_from_disk_yields_same_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            digest_hex = _digest_hex()
            first = report_signing.sign_digest(digest_hex, root)
            # invalida la cache di processo per forzare una vera rilettura da disco
            report_signing._cached_key = None
            report_signing._cached_key_path = None
            second = report_signing.sign_digest(digest_hex, root)
            self.assertEqual(first["public_key_b64"], second["public_key_b64"])
            self.assertEqual(first["fingerprint_sha256"], second["fingerprint_sha256"])

    def test_different_job_roots_get_different_keys(self):
        with tempfile.TemporaryDirectory() as tmp_a, tempfile.TemporaryDirectory() as tmp_b:
            digest_hex = _digest_hex()
            sig_a = report_signing.sign_digest(digest_hex, Path(tmp_a))
            sig_b = report_signing.sign_digest(digest_hex, Path(tmp_b))
            self.assertNotEqual(sig_a["fingerprint_sha256"], sig_b["fingerprint_sha256"])


class SignVerifyTests(_IsolatedKeyCacheMixin, unittest.TestCase):
    def test_valid_signature_verifies(self):
        with tempfile.TemporaryDirectory() as tmp:
            digest_hex = _digest_hex()
            sig = report_signing.sign_digest(digest_hex, Path(tmp))
            self.assertTrue(report_signing.verify_signature(
                digest_hex, sig["signature_b64"], sig["public_key_b64"]))

    def test_tampered_digest_fails_verification(self):
        with tempfile.TemporaryDirectory() as tmp:
            sig = report_signing.sign_digest(_digest_hex(b"original"), Path(tmp))
            tampered = _digest_hex(b"tampered")
            self.assertFalse(report_signing.verify_signature(
                tampered, sig["signature_b64"], sig["public_key_b64"]))

    def test_wrong_public_key_fails_verification(self):
        with tempfile.TemporaryDirectory() as tmp_a, tempfile.TemporaryDirectory() as tmp_b:
            digest_hex = _digest_hex()
            sig_a = report_signing.sign_digest(digest_hex, Path(tmp_a))
            sig_b = report_signing.sign_digest(digest_hex, Path(tmp_b))
            self.assertFalse(report_signing.verify_signature(
                digest_hex, sig_a["signature_b64"], sig_b["public_key_b64"]))

    def test_malformed_inputs_return_false_not_raise(self):
        self.assertFalse(report_signing.verify_signature("not-hex", "not-b64!!", "not-b64!!"))

    def test_signature_includes_algorithm_and_fingerprint(self):
        with tempfile.TemporaryDirectory() as tmp:
            sig = report_signing.sign_digest(_digest_hex(), Path(tmp))
            self.assertEqual(sig["algorithm"], "Ed25519")
            self.assertEqual(len(sig["fingerprint_sha256"]), 64)  # hex SHA-256


class ExportPublicKeyTests(_IsolatedKeyCacheMixin, unittest.TestCase):
    def test_matches_signing_key_fingerprint(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sig = report_signing.sign_digest(_digest_hex(), root)
            exported = report_signing.export_public_key(root)
            self.assertEqual(sig["fingerprint_sha256"], exported["fingerprint_sha256"])
            self.assertEqual(sig["public_key_b64"], exported["public_key_b64"])

    def test_no_private_key_material_in_export(self):
        with tempfile.TemporaryDirectory() as tmp:
            exported = report_signing.export_public_key(Path(tmp))
            self.assertEqual(set(exported), {"algorithm", "public_key_b64", "fingerprint_sha256"})


if __name__ == "__main__":
    unittest.main()
