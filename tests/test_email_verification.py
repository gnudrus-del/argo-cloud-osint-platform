"""Tests for email_verification.py — token + senders."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from osint_bot import email_verification as ev
from osint_bot.email_verification import (
    EmailSendError,
    generate_token,
    send_verification_email,
    send_via_console,
    verify_token,
)

# ---------------------------------------------------------------------------
# Token generation & verification
# ---------------------------------------------------------------------------

class TestToken:
    def setup_method(self):
        os.environ["EMAIL_VERIFICATION_SECRET"] = "test-secret-fixed"

    def teardown_method(self):
        os.environ.pop("EMAIL_VERIFICATION_SECRET", None)

    def test_generate_token_is_url_safe(self):
        token = generate_token("alice", "alice@example.com")
        # Token is body.sig, both base64url (no /, +, =)
        assert "/" not in token
        assert "+" not in token
        assert "=" not in token
        assert "." in token

    def test_verify_returns_claims(self):
        token = generate_token("bob", "bob@x.com")
        claims = verify_token(token)
        assert claims.username == "bob"
        assert claims.email == "bob@x.com"
        assert claims.expires_at > int(time.time())

    def test_verify_lowercases_email(self):
        token = generate_token("alice", "ALICE@Example.COM")
        claims = verify_token(token)
        assert claims.email == "alice@example.com"

    def test_verify_rejects_tampered_payload(self):
        token = generate_token("alice", "alice@x.com")
        # Modify a char in the body
        body, sig = token.split(".")
        tampered = body[:-1] + ("A" if body[-1] != "A" else "B") + "." + sig
        with pytest.raises(ValueError, match="Firma"):
            verify_token(tampered)

    def test_verify_rejects_tampered_signature(self):
        token = generate_token("alice", "alice@x.com")
        body, sig = token.split(".")
        # Tamper the FIRST sig char (top 6 bits of byte 0 — always significant).
        # The last base64url char of a 32-byte HMAC carries 2 redundant low bits,
        # so flipping it can decode to identical bytes → intermittent false pass.
        tampered = body + "." + ("X" if sig[0] != "X" else "Y") + sig[1:]
        with pytest.raises(ValueError, match="Firma"):
            verify_token(tampered)

    def test_verify_rejects_expired_token(self):
        token = generate_token("alice", "alice@x.com", ttl_seconds=-10)
        with pytest.raises(ValueError, match="scaduto"):
            verify_token(token)

    def test_verify_rejects_malformed(self):
        with pytest.raises(ValueError, match="malformato"):
            verify_token("")
        with pytest.raises(ValueError, match="malformato"):
            verify_token("nodot")
        with pytest.raises(ValueError):
            verify_token("a.b.c")

    def test_different_secrets_yield_different_signatures(self):
        os.environ["EMAIL_VERIFICATION_SECRET"] = "secret-one"
        t1 = generate_token("alice", "x@x.com", ttl_seconds=3600)
        os.environ["EMAIL_VERIFICATION_SECRET"] = "secret-two"
        # The same token cannot be verified with a different secret
        with pytest.raises(ValueError, match="Firma"):
            verify_token(t1)

    def test_token_payload_is_canonical(self):
        # Same input → same token (deterministic except for timestamp inside ttl window)
        # We can't assert byte-equality because of `exp`, but we can assert structure
        token = generate_token("u", "u@e.com")
        body_b64, sig_b64 = token.split(".")
        # Body must base64-decode to JSON
        import base64 as b64
        padding = "=" * (-len(body_b64) % 4)
        body = b64.urlsafe_b64decode((body_b64 + padding).encode()).decode()
        payload = json.loads(body)
        assert set(payload.keys()) == {"u", "e", "exp"}


# ---------------------------------------------------------------------------
# Console sender (no real email)
# ---------------------------------------------------------------------------

class TestConsoleSender:
    def test_writes_to_log_file(self, tmp_path):
        os.environ["OSINT_JOB_DIR"] = str(tmp_path)
        try:
            path = send_via_console("alice@x.com", "Subject", "<p>HTML</p>", "Text")
            log_path = Path(path)
            assert log_path.exists()
            content = log_path.read_text(encoding="utf-8")
            entry = json.loads(content.strip())
            assert entry["to"] == "alice@x.com"
            assert entry["subject"] == "Subject"
            assert entry["text"] == "Text"
        finally:
            os.environ.pop("OSINT_JOB_DIR", None)

    def test_appends_multiple_entries(self, tmp_path):
        os.environ["OSINT_JOB_DIR"] = str(tmp_path)
        try:
            send_via_console("a@x.com", "S1", "<>", "t1")
            send_via_console("b@x.com", "S2", "<>", "t2")
            log_path = tmp_path / "email_log.jsonl"
            lines = log_path.read_text(encoding="utf-8").strip().split("\n")
            assert len(lines) == 2
            assert json.loads(lines[0])["to"] == "a@x.com"
            assert json.loads(lines[1])["to"] == "b@x.com"
        finally:
            os.environ.pop("OSINT_JOB_DIR", None)


# ---------------------------------------------------------------------------
# Provider routing
# ---------------------------------------------------------------------------

class TestSendVerificationEmail:
    def setup_method(self):
        os.environ["EMAIL_VERIFICATION_SECRET"] = "test-secret"

    def teardown_method(self):
        for k in ("EMAIL_PROVIDER", "EMAIL_VERIFICATION_SECRET",
                  "RESEND_API_KEY", "SMTP_HOST", "EMAIL_FROM_ADDR"):
            os.environ.pop(k, None)

    def test_console_provider_default(self, tmp_path):
        os.environ.pop("EMAIL_PROVIDER", None)  # default = console
        os.environ["OSINT_JOB_DIR"] = str(tmp_path)
        try:
            token = generate_token("alice", "alice@x.com")
            result = send_verification_email("alice@x.com", token)
            assert result["provider"] == "console"
            assert result["status"] == "logged"
            assert "link" in result
        finally:
            os.environ.pop("OSINT_JOB_DIR", None)

    def test_resend_missing_key_raises(self):
        os.environ["EMAIL_PROVIDER"] = "resend"
        os.environ.pop("RESEND_API_KEY", None)
        with pytest.raises(EmailSendError, match="RESEND_API_KEY"):
            send_verification_email("a@x.com", "tok")

    def test_smtp_missing_host_raises(self):
        os.environ["EMAIL_PROVIDER"] = "smtp"
        os.environ.pop("SMTP_HOST", None)
        with pytest.raises(EmailSendError, match="SMTP_HOST"):
            send_verification_email("a@x.com", "tok")

    def test_unknown_provider_raises(self):
        os.environ["EMAIL_PROVIDER"] = "unknown-provider-xyz"
        with pytest.raises(EmailSendError, match="non supportato"):
            send_verification_email("a@x.com", "tok")

    def test_resend_send_success_mocked(self):
        os.environ["EMAIL_PROVIDER"] = "resend"
        os.environ["RESEND_API_KEY"] = "re_fake"
        os.environ["EMAIL_FROM_ADDR"] = "noreply@gufo.test"

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = lambda self: self
        mock_resp.__exit__ = lambda self, *a: None
        with patch("osint_bot.email_verification.urllib.request.urlopen", return_value=mock_resp):
            result = send_verification_email("alice@x.com", "tok123")
            assert result == {"provider": "resend", "status": "sent"}

    def test_smtp_send_success_mocked(self):
        os.environ["EMAIL_PROVIDER"] = "smtp"
        os.environ["SMTP_HOST"] = "smtp.test.example"
        os.environ["SMTP_PORT"] = "587"
        os.environ["SMTP_USER"] = "u"
        os.environ["SMTP_PASSWORD"] = "p"

        mock_server = MagicMock()
        with patch("osint_bot.email_verification.smtplib.SMTP") as mock_smtp_cls:
            mock_smtp_cls.return_value.__enter__.return_value = mock_server
            mock_smtp_cls.return_value.__exit__.return_value = None
            result = send_verification_email("alice@x.com", "tok")
            assert result == {"provider": "smtp", "status": "sent"}
            mock_server.login.assert_called_with("u", "p")
            mock_server.send_message.assert_called_once()


class TestLinkBuilder:
    def setup_method(self):
        os.environ["EMAIL_VERIFICATION_SECRET"] = "test-secret"

    def teardown_method(self):
        for k in ("EMAIL_VERIFICATION_BASE_URL", "EMAIL_VERIFICATION_SECRET"):
            os.environ.pop(k, None)

    def test_default_base_url(self):
        os.environ.pop("EMAIL_VERIFICATION_BASE_URL", None)
        link = ev._verification_link("abc.def")
        assert link.startswith("http://127.0.0.1:7655")
        assert "token=abc.def" in link

    def test_custom_base_url(self):
        os.environ["EMAIL_VERIFICATION_BASE_URL"] = "https://gufo.example.com/"
        link = ev._verification_link("xyz")
        assert link == "https://gufo.example.com/api/auth/verify?token=xyz"
