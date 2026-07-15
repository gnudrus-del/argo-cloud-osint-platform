"""osint_bot.secrets_crypto — envelope encryption for BYOK API keys at rest.
Pure local computation, no network here."""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.exceptions import InvalidTag

from osint_bot import secrets_crypto
from osint_bot.storage import Storage


class _IsolatedKeyCacheMixin:
    """Every test starts with an empty process-level key cache, so one test's
    loaded key never leaks into the next test's (different) job_root."""

    def setUp(self):
        super().setUp()
        secrets_crypto.invalidate_cache()

    def tearDown(self):
        secrets_crypto.invalidate_cache()
        super().tearDown()


class EnvelopeRoundtripTests(_IsolatedKeyCacheMixin, unittest.TestCase):
    def test_encrypt_decrypt_roundtrip(self):
        key = secrets_crypto.generate_master_key()
        blob = secrets_crypto.encrypt_secret("SHODANSECRET123", key)
        self.assertTrue(blob.startswith(secrets_crypto.ENVELOPE_PREFIX))
        self.assertNotIn("SHODANSECRET123", blob)
        self.assertEqual(secrets_crypto.decrypt_secret(blob, key), "SHODANSECRET123")

    def test_empty_value_stays_empty(self):
        key = secrets_crypto.generate_master_key()
        self.assertEqual(secrets_crypto.encrypt_secret("", key), "")
        self.assertEqual(secrets_crypto.decrypt_secret("", key), "")

    def test_legacy_plaintext_passes_through_unchanged(self):
        """Rows written before this module existed have no enc:v1: prefix —
        they must still read back correctly instead of raising."""
        key = secrets_crypto.generate_master_key()
        self.assertFalse(secrets_crypto.is_encrypted("OLDPLAINKEY789"))
        self.assertEqual(secrets_crypto.decrypt_secret("OLDPLAINKEY789", key), "OLDPLAINKEY789")

    def test_wrong_master_key_fails_to_decrypt(self):
        key_a = secrets_crypto.generate_master_key()
        key_b = secrets_crypto.generate_master_key()
        blob = secrets_crypto.encrypt_secret("SECRET", key_a)
        with self.assertRaises(InvalidTag):
            secrets_crypto.decrypt_secret(blob, key_b)

    def test_two_encryptions_of_same_value_differ(self):
        """Random per-secret DEK + nonce: no two ciphertexts of the same
        plaintext should ever be identical (rules out ECB-style determinism)."""
        key = secrets_crypto.generate_master_key()
        blob1 = secrets_crypto.encrypt_secret("SAME", key)
        blob2 = secrets_crypto.encrypt_secret("SAME", key)
        self.assertNotEqual(blob1, blob2)
        self.assertEqual(secrets_crypto.decrypt_secret(blob1, key), "SAME")
        self.assertEqual(secrets_crypto.decrypt_secret(blob2, key), "SAME")


class AssociatedDataTests(_IsolatedKeyCacheMixin, unittest.TestCase):
    """AAD row-binding, added after an adversarial review found stored
    ciphertext wasn't bound to its (username, service) row — see
    docs/THREAT_MODEL.md."""

    def test_correct_aad_decrypts(self):
        key = secrets_crypto.generate_master_key()
        aad = secrets_crypto.api_key_aad("alice", "shodan")
        blob = secrets_crypto.encrypt_secret("SECRET", key, aad=aad)
        self.assertEqual(secrets_crypto.decrypt_secret(blob, key, aad=aad), "SECRET")

    def test_wrong_aad_fails_to_decrypt(self):
        key = secrets_crypto.generate_master_key()
        blob = secrets_crypto.encrypt_secret("SECRET", key, aad=secrets_crypto.api_key_aad("alice", "shodan"))
        with self.assertRaises(InvalidTag):
            secrets_crypto.decrypt_secret(blob, key, aad=secrets_crypto.api_key_aad("bob", "shodan"))

    def test_missing_aad_fails_to_decrypt_a_v2_value(self):
        key = secrets_crypto.generate_master_key()
        blob = secrets_crypto.encrypt_secret("SECRET", key, aad=secrets_crypto.api_key_aad("alice", "shodan"))
        with self.assertRaises(InvalidTag):
            secrets_crypto.decrypt_secret(blob, key)  # no aad passed

    def test_new_writes_use_v2_format(self):
        key = secrets_crypto.generate_master_key()
        blob = secrets_crypto.encrypt_secret("SECRET", key)
        self.assertTrue(blob.startswith(secrets_crypto.ENVELOPE_PREFIX_V2))

    def test_v1_value_decrypts_ignoring_any_aad(self):
        """A value written before AAD support existed (enc:v1:, produced by
        directly building the old envelope shape) must still decrypt --
        v1 never had AAD, so decrypt_secret must not require or check one
        for it, regardless of what a caller passes."""
        key = secrets_crypto.generate_master_key()
        v2_blob = secrets_crypto.encrypt_secret("SECRET", key, aad=b"whatever")
        # Re-pack the same envelope under the v1 prefix to simulate a
        # pre-AAD row (the on-wire *format* is identical; only the prefix
        # and the absence of AAD at encryption time differ in practice).
        v1_blob = secrets_crypto.ENVELOPE_PREFIX_V1 + v2_blob[len(secrets_crypto.ENVELOPE_PREFIX_V2):]
        no_aad_blob = secrets_crypto.encrypt_secret("SECRET", key)  # no aad -> valid under v1 semantics
        v1_of_no_aad = secrets_crypto.ENVELOPE_PREFIX_V1 + no_aad_blob[len(secrets_crypto.ENVELOPE_PREFIX_V2):]
        self.assertEqual(secrets_crypto.decrypt_secret(v1_of_no_aad, key), "SECRET")
        self.assertEqual(secrets_crypto.decrypt_secret(v1_of_no_aad, key, aad=b"ignored-for-v1"), "SECRET")

    def test_different_rows_get_different_aad(self):
        self.assertNotEqual(
            secrets_crypto.api_key_aad("alice", "shodan"),
            secrets_crypto.api_key_aad("alice", "hibp"),
        )
        self.assertNotEqual(
            secrets_crypto.api_key_aad("alice", "shodan"),
            secrets_crypto.api_key_aad("bob", "shodan"),
        )

    def test_storage_layer_rejects_ciphertext_moved_to_a_different_row(self):
        """The actual attack scenario the AAD fix defends against: an
        attacker with direct DB-write access copies one row's ciphertext
        into a different row. Before the fix this decrypted successfully
        under the shared master key (silent misattribution); now it must
        raise instead of returning a plausible-looking wrong secret."""
        with tempfile.TemporaryDirectory() as tmp:
            store = Storage(Path(tmp) / "gufo.sqlite3")
            store.put_user({"username": "alice", "password": "p", "plan": "free", "created_at": "x", "disabled": False})
            store.put_user({"username": "bob", "password": "p", "plan": "free", "created_at": "x", "disabled": False})
            store.put_api_key("alice", "shodan", "ALICE-SECRET")

            alice_row = store._conn().execute(
                "SELECT value FROM api_keys WHERE username = ? AND service = ?", ("alice", "shodan")
            ).fetchone()["value"]

            # Simulate an attacker relocating alice's ciphertext into bob's row,
            # bypassing put_api_key entirely (direct SQL, as a DB-write attacker would).
            store._conn().execute(
                "INSERT INTO api_keys (username, service, value, updated_at) VALUES (?, ?, ?, ?)",
                ("bob", "shodan", alice_row, "2020-01-01T00:00:00+00:00"),
            )

            with self.assertRaises(InvalidTag):
                store.get_api_key("bob", "shodan")
            store.close()


class MasterKeyLoadingTests(_IsolatedKeyCacheMixin, unittest.TestCase):
    def test_auto_generated_and_persisted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop("OSINT_MASTER_KEY", None)
                os.environ.pop("OSINT_MASTER_KEY_FILE", None)
                key1 = secrets_crypto.get_master_key(root)
                self.assertTrue((root / ".master_key").exists())
                secrets_crypto.invalidate_cache()
                key2 = secrets_crypto.get_master_key(root)
        self.assertEqual(key1, key2)

    def test_different_job_roots_get_different_keys(self):
        with tempfile.TemporaryDirectory() as tmp_a, tempfile.TemporaryDirectory() as tmp_b:
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop("OSINT_MASTER_KEY", None)
                os.environ.pop("OSINT_MASTER_KEY_FILE", None)
                key_a = secrets_crypto.get_master_key(Path(tmp_a))
                key_b = secrets_crypto.get_master_key(Path(tmp_b))
        self.assertNotEqual(key_a, key_b)

    def test_env_var_overrides_file(self):
        import base64
        forced = secrets_crypto.generate_master_key()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.dict(os.environ, {"OSINT_MASTER_KEY": base64.b64encode(forced).decode("ascii")}):
                key = secrets_crypto.get_master_key(root)
        self.assertEqual(key, forced)
        self.assertFalse((root / ".master_key").exists())

    def test_master_key_source_reporting(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop("OSINT_MASTER_KEY", None)
                os.environ.pop("OSINT_MASTER_KEY_FILE", None)
                self.assertTrue(secrets_crypto.master_key_source(root).startswith("auto-generated:"))
                os.environ["OSINT_MASTER_KEY"] = "x"
                self.assertTrue(secrets_crypto.master_key_source(root).startswith("env:"))
                os.environ.pop("OSINT_MASTER_KEY")


class StorageIntegrationTests(_IsolatedKeyCacheMixin, unittest.TestCase):
    def _make_storage(self, tmp: str) -> Storage:
        return Storage(Path(tmp) / "gufo.sqlite3")

    def test_value_stored_encrypted_not_plaintext(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = self._make_storage(tmp)
            store.put_user({"username": "alice", "password": "p", "plan": "free", "created_at": "x", "disabled": False})
            store.put_api_key("alice", "shodan", "SHODANSECRET123")

            raw = store._conn().execute(
                "SELECT value FROM api_keys WHERE username = ? AND service = ?", ("alice", "shodan")
            ).fetchone()["value"]
            self.assertTrue(raw.startswith(secrets_crypto.ENVELOPE_PREFIX))
            self.assertNotIn("SHODANSECRET123", raw)
            self.assertEqual(store.get_api_key("alice", "shodan"), "SHODANSECRET123")
            store.close()

    def test_legacy_plaintext_row_still_readable_and_gets_upgraded(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = self._make_storage(tmp)
            store.put_user({"username": "alice", "password": "p", "plan": "free", "created_at": "x", "disabled": False})
            # Simulate a row written before this feature existed: raw plaintext,
            # bypassing put_api_key's encryption entirely.
            store._conn().execute(
                "INSERT INTO api_keys (username, service, value, updated_at) VALUES (?, ?, ?, ?)",
                ("alice", "hibp", "LEGACYPLAINVALUE", "2020-01-01T00:00:00+00:00"),
            )
            self.assertEqual(store.get_api_key("alice", "hibp"), "LEGACYPLAINVALUE")

            # Any subsequent write transparently upgrades it to ciphertext.
            store.put_api_key("alice", "hibp", "LEGACYPLAINVALUE")
            raw = store._conn().execute(
                "SELECT value FROM api_keys WHERE username = ? AND service = ?", ("alice", "hibp")
            ).fetchone()["value"]
            self.assertTrue(raw.startswith(secrets_crypto.ENVELOPE_PREFIX))
            self.assertEqual(store.get_api_key("alice", "hibp"), "LEGACYPLAINVALUE")
            store.close()

    def test_list_api_keys_masks_the_decrypted_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = self._make_storage(tmp)
            store.put_user({"username": "alice", "password": "p", "plan": "free", "created_at": "x", "disabled": False})
            store.put_api_key("alice", "shodan", "SHODANSECRET123")
            masked = store.list_api_keys("alice")[0]["masked"]
            self.assertNotIn("SHODANSECRET123", masked)
            self.assertTrue(masked.endswith("T123"))
            store.close()

    def test_access_events_are_audited(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = self._make_storage(tmp)
            store.put_user({"username": "alice", "password": "p", "plan": "free", "created_at": "x", "disabled": False})
            store.put_api_key("alice", "shodan", "SECRET")
            store.get_api_key("alice", "shodan")
            store.delete_api_key("alice", "shodan")

            actions = [e["action"] for e in store.all_audit_events() if e["actor"] == "alice"]
            self.assertIn("api_key_stored", actions)
            self.assertIn("api_key_accessed", actions)
            self.assertIn("api_key_deleted", actions)
            # None of the audit events leak the plaintext value.
            for event in store.all_audit_events():
                self.assertNotIn("SECRET", str(event.get("details", "")))
            store.close()

    def test_list_api_keys_does_not_emit_access_event(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = self._make_storage(tmp)
            store.put_user({"username": "alice", "password": "p", "plan": "free", "created_at": "x", "disabled": False})
            store.put_api_key("alice", "shodan", "SECRET")
            before = len(store.all_audit_events())
            store.list_api_keys("alice")
            after = len(store.all_audit_events())
            self.assertEqual(before, after)
            store.close()


class RotationTests(_IsolatedKeyCacheMixin, unittest.TestCase):
    def _make_storage(self, tmp: str) -> Storage:
        return Storage(Path(tmp) / "gufo.sqlite3")

    def test_rotation_reencrypts_all_keys_and_old_key_no_longer_works(self):
        from osint_bot.cli_rotate_key import rotate

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop("OSINT_MASTER_KEY", None)
                os.environ.pop("OSINT_MASTER_KEY_FILE", None)

                store = self._make_storage(tmp)
                store.put_user({"username": "alice", "password": "p", "plan": "free", "created_at": "x", "disabled": False})
                store.put_api_key("alice", "shodan", "SHODANSECRET123")
                store.put_api_key("alice", "hibp", "HIBPSECRET456")

                old_key = secrets_crypto.get_master_key(root)
                ok, lines = rotate(store, root, new_key_output=None)
                self.assertTrue(ok, msg="\n".join(lines))

                new_key = secrets_crypto.get_master_key(root)
                self.assertNotEqual(old_key, new_key)

                # Every value is still correctly readable through the normal API...
                self.assertEqual(store.get_api_key("alice", "shodan"), "SHODANSECRET123")
                self.assertEqual(store.get_api_key("alice", "hibp"), "HIBPSECRET456")

                # ...but the raw stored blob no longer decrypts under the old key.
                raw = store._conn().execute(
                    "SELECT value FROM api_keys WHERE username = ? AND service = ?", ("alice", "shodan")
                ).fetchone()["value"]
                with self.assertRaises(InvalidTag):
                    secrets_crypto.decrypt_secret(raw, old_key)

                actions = [e["action"] for e in store.all_audit_events() if e["actor"] == "system"]
                self.assertIn("api_master_key_rotated", actions)
                store.close()

    def test_rotation_with_zero_keys_configured(self):
        from osint_bot.cli_rotate_key import rotate

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop("OSINT_MASTER_KEY", None)
                os.environ.pop("OSINT_MASTER_KEY_FILE", None)
                store = self._make_storage(tmp)
                ok, lines = rotate(store, root, new_key_output=None)
                self.assertTrue(ok, msg="\n".join(lines))
                store.close()

    def test_env_sourced_key_requires_explicit_output_path(self):
        """Rotation must refuse to proceed silently when it cannot rewrite the
        active key source (OSINT_MASTER_KEY) — losing the new key here would
        make every stored API key permanently unrecoverable."""
        import base64

        from osint_bot.cli_rotate_key import rotate

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            forced = secrets_crypto.generate_master_key()
            with patch.dict(os.environ, {"OSINT_MASTER_KEY": base64.b64encode(forced).decode("ascii")}):
                store = self._make_storage(tmp)
                store.put_user({"username": "alice", "password": "p", "plan": "free", "created_at": "x", "disabled": False})
                store.put_api_key("alice", "shodan", "SECRET")

                ok, lines = rotate(store, root, new_key_output=None)
                self.assertFalse(ok)
                # Nothing was touched: the original value must still decrypt.
                self.assertEqual(store.get_api_key("alice", "shodan"), "SECRET")
                store.close()


if __name__ == "__main__":
    unittest.main()
