"""Email verification module — signup verification via signed token + SMTP.

Security model:
  - Token is HMAC-SHA256 signed with EMAIL_VERIFICATION_SECRET (rotated → all tokens invalid).
  - Token payload is base64url-encoded JSON: {u: username, e: email, exp: unix_ts}.
  - Default TTL: 24h. After expiry, token rejected.
  - No DB lookup needed for verification — the token IS the proof (stateless).
  - User row is created with `verified=False`; only `/api/auth/verify?token=...` flips it true.
  - Unverified users cannot login (handle_login refuses).

Provider abstraction:
  - SMTPSender: generic smtplib backend (works with Resend, Mailgun, SendGrid, Gmail, …).
  - ConsoleSender: dev mode — writes to file + audit log, no real email.
  - Selected via EMAIL_PROVIDER env var (resend|mailgun|sendgrid|smtp|console).

Configuration via env vars (all required for real send except where noted):
  EMAIL_VERIFICATION_SECRET   — HMAC secret (mandatory; auto-generated if missing → warns)
  EMAIL_PROVIDER              — "resend"|"smtp"|"console" (default "console")
  EMAIL_FROM_ADDR             — From: header (default "argo@localhost")
  EMAIL_FROM_NAME             — From name (default "Argo")
  EMAIL_VERIFICATION_BASE_URL — base for the link e.g. "https://gufo.example.com" (default "http://127.0.0.1:7655")
  EMAIL_TOKEN_TTL_SECONDS     — token TTL (default 86400 = 24h)

For Resend (recommended):
  EMAIL_PROVIDER=resend
  RESEND_API_KEY=re_xxxxxxxxxxxx

For generic SMTP (Gmail, Mailgun, …):
  EMAIL_PROVIDER=smtp
  SMTP_HOST=smtp.resend.com (or smtp.gmail.com / smtp.mailgun.org / …)
  SMTP_PORT=465 (SSL) or 587 (STARTTLS)
  SMTP_USER=resend or apikey or your-email
  SMTP_PASSWORD=...

For console (dev only):
  EMAIL_PROVIDER=console — links written to web_jobs/email_log.jsonl
"""
from __future__ import annotations

from ._ua import user_agent as _ua

import base64
import hashlib
import hmac
import json
import logging
import os
import smtplib
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

LOG = logging.getLogger("osint_bot.email_verification")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
def _get_secret() -> bytes:
    secret = os.getenv("EMAIL_VERIFICATION_SECRET", "")
    if not secret:
        # Dev fallback — warns. In prod set env var explicitly.
        LOG.warning(
            "EMAIL_VERIFICATION_SECRET non impostato: uso fallback dev "
            "(non sicuro in produzione)."
        )
        secret = "dev-secret-change-me-please"
    return secret.encode("utf-8")


def _token_ttl_seconds() -> int:
    try:
        return int(os.getenv("EMAIL_TOKEN_TTL_SECONDS", "86400"))
    except ValueError:
        return 86400


def _base_url() -> str:
    return os.getenv("EMAIL_VERIFICATION_BASE_URL", "http://127.0.0.1:7655").rstrip("/")


def _from_address() -> tuple[str, str]:
    addr = os.getenv("EMAIL_FROM_ADDR", "argo@localhost")
    name = os.getenv("EMAIL_FROM_NAME", "Argo")
    return name, addr


# ---------------------------------------------------------------------------
# Token: HMAC-signed stateless verification token
# ---------------------------------------------------------------------------
def _b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_decode(s: str) -> bytes:
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + padding).encode("ascii"))


def generate_token(username: str, email: str, ttl_seconds: int | None = None) -> str:
    """Create a verification token. Returns base64url payload.signature."""
    ttl = ttl_seconds if ttl_seconds is not None else _token_ttl_seconds()
    payload = {"u": username, "e": email.lower(), "exp": int(time.time()) + ttl}
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    body_b64 = _b64u_encode(body)
    sig = hmac.new(_get_secret(), body_b64.encode("ascii"), hashlib.sha256).digest()
    return f"{body_b64}.{_b64u_encode(sig)}"


@dataclass
class TokenClaims:
    username: str
    email: str
    expires_at: int


def verify_token(token: str) -> TokenClaims:
    """Validate a verification token. Raises ValueError if invalid/expired."""
    if not token or "." not in token:
        raise ValueError("Token malformato.")
    parts = token.split(".", 1)
    if len(parts) != 2:
        raise ValueError("Token malformato.")
    body_b64, sig_b64 = parts
    try:
        expected_sig = hmac.new(_get_secret(), body_b64.encode("ascii"), hashlib.sha256).digest()
        actual_sig = _b64u_decode(sig_b64)
    except Exception as exc:
        raise ValueError("Token malformato.") from exc
    if not hmac.compare_digest(expected_sig, actual_sig):
        raise ValueError("Firma token non valida.")
    try:
        payload = json.loads(_b64u_decode(body_b64).decode("utf-8"))
    except Exception as exc:
        raise ValueError("Payload token corrotto.") from exc
    exp = int(payload.get("exp", 0))
    if exp < int(time.time()):
        raise ValueError("Token scaduto. Richiedi un nuovo link.")
    return TokenClaims(
        username=str(payload.get("u", "")),
        email=str(payload.get("e", "")),
        expires_at=exp,
    )


# ---------------------------------------------------------------------------
# Email senders
# ---------------------------------------------------------------------------
class EmailSendError(Exception):
    """Raised when email delivery fails. Signup should rollback the user row."""


def _verification_link(token: str) -> str:
    return f"{_base_url()}/api/auth/verify?token={token}"


def _build_message(to_email: str, link: str) -> tuple[str, str]:
    """Return (subject, html_body, text_body)."""
    subject = "Conferma il tuo account Argo"
    html = f"""<!doctype html><html><body style="font-family:sans-serif;background:#0b1a30;color:#e6edf6;padding:32px;">
<h2 style="color:#65a8ff;">Benvenuto su Argo</h2>
<p>Per attivare il tuo account, clicca sul link di verifica:</p>
<p><a href="{link}" style="background:#65a8ff;color:#0b1a30;padding:12px 20px;border-radius:6px;text-decoration:none;font-weight:600;">Verifica email</a></p>
<p style="color:#94a3b8;font-size:0.9em;">Oppure copia questo URL nel browser:<br><code style="word-break:break-all;">{link}</code></p>
<p style="color:#94a3b8;font-size:0.85em;margin-top:32px;">Se non hai richiesto questa registrazione, ignora questa email.<br>Link valido per 24 ore.</p>
</body></html>"""
    text = f"Benvenuto su Argo.\n\nPer attivare il tuo account, apri questo link:\n{link}\n\nLink valido per 24 ore.\n"
    return subject, html, text


def send_via_resend(to_email: str, subject: str, html: str, text: str) -> None:
    """Send via Resend API (https://resend.com)."""
    api_key = os.getenv("RESEND_API_KEY", "")
    if not api_key:
        raise EmailSendError("RESEND_API_KEY non configurata.")
    from_name, from_addr = _from_address()
    body = json.dumps({
        "from": f"{from_name} <{from_addr}>",
        "to": [to_email],
        "subject": subject,
        "html": html,
        "text": text,
    }).encode("utf-8")
    req = urllib.request.Request(
        "https://api.resend.com/emails",
        data=body,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": _ua(),
            "Accept": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            if resp.status >= 300:
                raise EmailSendError(f"Resend status {resp.status}")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:300]
        raise EmailSendError(f"Resend HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise EmailSendError(f"Resend irraggiungibile: {exc}") from exc


def send_via_smtp(to_email: str, subject: str, html: str, text: str) -> None:
    """Generic SMTP (SSL or STARTTLS)."""
    host = os.getenv("SMTP_HOST", "")
    if not host:
        raise EmailSendError("SMTP_HOST non configurato.")
    port = int(os.getenv("SMTP_PORT", "587"))
    user = os.getenv("SMTP_USER", "")
    password = os.getenv("SMTP_PASSWORD", "")
    from_name, from_addr = _from_address()

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"{from_name} <{from_addr}>"
    msg["To"] = to_email
    msg.attach(MIMEText(text, "plain", "utf-8"))
    msg.attach(MIMEText(html, "html", "utf-8"))

    context = ssl.create_default_context()
    try:
        if port == 465:
            with smtplib.SMTP_SSL(host, port, context=context, timeout=15) as server:
                if user:
                    server.login(user, password)
                server.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=15) as server:
                server.ehlo()
                server.starttls(context=context)
                server.ehlo()
                if user:
                    server.login(user, password)
                server.send_message(msg)
    except smtplib.SMTPException as exc:
        raise EmailSendError(f"SMTP errore: {exc}") from exc
    except OSError as exc:
        raise EmailSendError(f"SMTP irraggiungibile: {exc}") from exc


def send_via_console(to_email: str, subject: str, html: str, text: str) -> str:
    """Dev mode: write to file + return link. NO real email sent."""
    log_dir = Path(os.getenv("OSINT_JOB_DIR", "web_jobs"))
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / "email_log.jsonl"
    entry = {
        "ts": int(time.time()),
        "to": to_email,
        "subject": subject,
        "text": text,
    }
    with log_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    LOG.info("Email (console mode) salvata in %s per %s", log_path, to_email)
    return str(log_path)


def send_verification_email(to_email: str, token: str) -> dict:
    """Send a verification email via configured provider.

    Returns dict {provider: str, status: "sent"|"logged"}.
    Raises EmailSendError on failure.
    """
    link = _verification_link(token)
    subject, html, text = _build_message(to_email, link)
    provider = os.getenv("EMAIL_PROVIDER", "console").lower()

    if provider == "resend":
        send_via_resend(to_email, subject, html, text)
        return {"provider": "resend", "status": "sent"}
    if provider == "smtp":
        send_via_smtp(to_email, subject, html, text)
        return {"provider": "smtp", "status": "sent"}
    if provider == "console":
        log_path = send_via_console(to_email, subject, html, text)
        return {"provider": "console", "status": "logged", "log_path": log_path, "link": link}
    raise EmailSendError(f"EMAIL_PROVIDER '{provider}' non supportato.")
