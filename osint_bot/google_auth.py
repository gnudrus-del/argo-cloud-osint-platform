"""Google Sign-In — optional additional login method (alongside email+password).

Verifies a Google Identity Services ID token (a signed JWT) server-side and
returns the caller's verified identity. Does not replace the existing
email/password signup+login flow in ``web.py`` — this is purely an extra
door into the same user table.

Config:
    GOOGLE_OAUTH_CLIENT_ID   OAuth 2.0 Client ID from Google Cloud Console
                             (Credentials -> OAuth client ID -> Web application).
                             Required as the token's ``aud`` claim; without it
                             the feature is disabled (invisible), same pattern
                             as ``TSA_URL`` for report timestamping.

Requires the optional ``auth`` extra (``pip install argo-cloud-osint[auth]``):
google-auth + requests. Importing this module without the extra installed
raises ImportError only when a caller actually tries to verify a token —
``google_login_enabled()`` itself has no import-time dependency, so the rest
of the app works fine without the extra when the feature is unconfigured.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass

_CLIENT_ID_ENV = "GOOGLE_OAUTH_CLIENT_ID"
_ACCEPTED_ISSUERS = ("accounts.google.com", "https://accounts.google.com")


def google_client_id() -> str:
    return os.getenv(_CLIENT_ID_ENV, "").strip()


def google_login_enabled() -> bool:
    return bool(google_client_id())


@dataclass
class GoogleIdentity:
    email: str
    name: str
    google_sub: str  # stable Google account ID


class GoogleTokenError(ValueError):
    """Raised when an ID token fails verification for any reason."""


def verify_google_id_token(credential: str) -> GoogleIdentity:
    """Verify a Google Identity Services credential (ID token JWT).

    Raises GoogleTokenError on any invalid/unverifiable token, including:
    bad signature, wrong audience, wrong issuer, expired, or an email the
    token itself doesn't mark as verified by Google.
    """
    client_id = google_client_id()
    if not client_id:
        raise GoogleTokenError("Google login non configurato su questa istanza.")
    if not credential or not isinstance(credential, str):
        raise GoogleTokenError("Credential mancante.")

    try:
        from google.auth.transport.requests import Request as GoogleRequest
        from google.oauth2 import id_token as google_id_token
    except ImportError as exc:
        raise GoogleTokenError(
            "Dipendenze Google login non installate sul server "
            "(pip install 'argo-cloud-osint[auth]')."
        ) from exc

    try:
        claims = google_id_token.verify_oauth2_token(
            credential, GoogleRequest(), audience=client_id,
        )
    except Exception as exc:  # library raises several distinct exception types
        raise GoogleTokenError(f"Token Google non valido: {exc}") from exc

    issuer = claims.get("iss", "")
    if issuer not in _ACCEPTED_ISSUERS:
        raise GoogleTokenError(f"Issuer non atteso: {issuer!r}.")
    if not claims.get("email_verified"):
        raise GoogleTokenError("Google non ha verificato questa email.")
    email = str(claims.get("email", "")).strip().lower()
    if not email or "@" not in email:
        raise GoogleTokenError("Email assente nel token.")
    sub = str(claims.get("sub", "")).strip()
    if not sub:
        raise GoogleTokenError("Identificativo account assente nel token.")
    name = str(claims.get("name") or email.split("@")[0])

    return GoogleIdentity(email=email, name=name, google_sub=sub)


_USERNAME_SANITIZE_RE = re.compile(r"[^a-z0-9_.-]")


def username_from_email(email: str, taken: set[str]) -> str:
    """Derive a valid, unused Argo username from an email's local part.

    Matches the same charset/length rule as ``normalize_username`` in
    ``web.py`` (``[a-z0-9_.-]{3,40}``). Appends a numeric suffix on
    collision; falls back to a fixed stem if the local part sanitizes to
    nothing usable (e.g. an all-unicode local part).
    """
    local = email.split("@", 1)[0].lower()
    stem = _USERNAME_SANITIZE_RE.sub("", local) or "user"
    stem = stem[:36]  # leave room for a numeric suffix under the 40-char cap
    if len(stem) < 3:
        stem = (stem + "___")[:3]
    candidate = stem
    n = 2
    while candidate in taken:
        candidate = f"{stem}{n}"
        n += 1
    return candidate
