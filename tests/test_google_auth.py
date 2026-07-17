"""Tests for google_auth.py — Google Sign-In ID token verification.

All tests mock ``google.oauth2.id_token.verify_oauth2_token`` (no real
network call, no real Google credential needed).
"""
import os
import unittest
from unittest.mock import patch

from osint_bot.google_auth import (
    GoogleTokenError,
    google_client_id,
    google_login_enabled,
    username_from_email,
    verify_google_id_token,
)

# The ID-token verification tests below patch ``google.oauth2.id_token``, which
# unittest.mock has to import to install the patch. That module ships in the
# optional ``[auth]`` extra (google-auth); without it, entering the patch
# context raises ModuleNotFoundError before the test can assert anything. Gate
# those tests on the extra being present — same discipline as the Postgres
# tests gated on TEST_DATABASE_URL — so a bare ``pip install -e .[dev]`` clone
# (and CI without the extra) skips them gracefully instead of erroring. CI's
# python job installs ``.[dev,auth]`` so they still run there for real coverage.
try:
    import google.oauth2.id_token  # noqa: F401  (imported only to detect availability)

    _HAS_GOOGLE_AUTH = True
except ImportError:
    _HAS_GOOGLE_AUTH = False

_needs_google_auth = unittest.skipUnless(
    _HAS_GOOGLE_AUTH,
    "requires the optional [auth] extra (google-auth) to patch google.oauth2.id_token",
)


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self._orig = os.environ.pop("GOOGLE_OAUTH_CLIENT_ID", None)

    def tearDown(self):
        if self._orig is not None:
            os.environ["GOOGLE_OAUTH_CLIENT_ID"] = self._orig
        else:
            os.environ.pop("GOOGLE_OAUTH_CLIENT_ID", None)

    def test_disabled_when_unset(self):
        self.assertFalse(google_login_enabled())
        self.assertEqual(google_client_id(), "")

    def test_enabled_when_set(self):
        os.environ["GOOGLE_OAUTH_CLIENT_ID"] = "abc.apps.googleusercontent.com"
        self.assertTrue(google_login_enabled())
        self.assertEqual(google_client_id(), "abc.apps.googleusercontent.com")


class VerifyTokenTests(unittest.TestCase):
    def setUp(self):
        os.environ["GOOGLE_OAUTH_CLIENT_ID"] = "test-client-id"

    def tearDown(self):
        os.environ.pop("GOOGLE_OAUTH_CLIENT_ID", None)

    def _valid_claims(self, **overrides):
        claims = {
            "iss": "accounts.google.com",
            "aud": "test-client-id",
            "email": "Analyst@Example.com",
            "email_verified": True,
            "sub": "1234567890",
            "name": "Analyst Example",
        }
        claims.update(overrides)
        return claims

    def test_disabled_raises(self):
        os.environ.pop("GOOGLE_OAUTH_CLIENT_ID", None)
        with self.assertRaises(GoogleTokenError):
            verify_google_id_token("whatever")

    def test_empty_credential_raises(self):
        with self.assertRaises(GoogleTokenError):
            verify_google_id_token("")

    @_needs_google_auth
    def test_valid_token_returns_identity_and_lowercases_email(self):
        with patch("google.oauth2.id_token.verify_oauth2_token",
                   return_value=self._valid_claims()):
            identity = verify_google_id_token("fake.jwt.token")
        self.assertEqual(identity.email, "analyst@example.com")
        self.assertEqual(identity.google_sub, "1234567890")
        self.assertEqual(identity.name, "Analyst Example")

    @_needs_google_auth
    def test_wrong_issuer_rejected(self):
        with patch("google.oauth2.id_token.verify_oauth2_token",
                   return_value=self._valid_claims(iss="evil.example.com")):
            with self.assertRaises(GoogleTokenError):
                verify_google_id_token("fake.jwt.token")

    @_needs_google_auth
    def test_unverified_email_rejected(self):
        with patch("google.oauth2.id_token.verify_oauth2_token",
                   return_value=self._valid_claims(email_verified=False)):
            with self.assertRaises(GoogleTokenError):
                verify_google_id_token("fake.jwt.token")

    @_needs_google_auth
    def test_missing_email_rejected(self):
        with patch("google.oauth2.id_token.verify_oauth2_token",
                   return_value=self._valid_claims(email="")):
            with self.assertRaises(GoogleTokenError):
                verify_google_id_token("fake.jwt.token")

    @_needs_google_auth
    def test_missing_sub_rejected(self):
        with patch("google.oauth2.id_token.verify_oauth2_token",
                   return_value=self._valid_claims(sub="")):
            with self.assertRaises(GoogleTokenError):
                verify_google_id_token("fake.jwt.token")

    @_needs_google_auth
    def test_library_exception_wrapped(self):
        with patch("google.oauth2.id_token.verify_oauth2_token",
                   side_effect=ValueError("bad signature")):
            with self.assertRaises(GoogleTokenError):
                verify_google_id_token("fake.jwt.token")

    @_needs_google_auth
    def test_missing_name_falls_back_to_email_local_part(self):
        with patch("google.oauth2.id_token.verify_oauth2_token",
                   return_value=self._valid_claims(name="")):
            identity = verify_google_id_token("fake.jwt.token")
        self.assertEqual(identity.name, "analyst")


class UsernameFromEmailTests(unittest.TestCase):
    def test_basic_local_part(self):
        self.assertEqual(username_from_email("francesco.vigo@gmail.com", set()), "francesco.vigo")

    def test_sanitizes_invalid_chars(self):
        # '+' tags and other RFC5322-legal-but-Argo-illegal chars get stripped.
        uname = username_from_email("f+tag@gmail.com", set())
        self.assertRegex(uname, r"^[a-z0-9_.-]{3,40}$")

    def test_collision_gets_numeric_suffix(self):
        taken = {"jdoe"}
        self.assertEqual(username_from_email("jdoe@example.com", taken), "jdoe2")

    def test_multiple_collisions_increment(self):
        taken = {"jdoe", "jdoe2", "jdoe3"}
        self.assertEqual(username_from_email("jdoe@example.com", taken), "jdoe4")

    def test_short_local_part_padded_to_minimum(self):
        uname = username_from_email("a@example.com", set())
        self.assertGreaterEqual(len(uname), 3)

    def test_result_never_exceeds_max_length(self):
        long_local = "a" * 80
        uname = username_from_email(f"{long_local}@example.com", set())
        self.assertLessEqual(len(uname), 40)


if __name__ == "__main__":
    unittest.main()
