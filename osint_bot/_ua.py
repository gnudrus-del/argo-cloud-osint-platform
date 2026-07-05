"""User-Agent condiviso per tutti gli outbound HTTP.

Alcuni servizi pubblici (Nominatim, SEC EDGAR) richiedono un UA identificativo
con contatto. Non hardcodiamo l'indirizzo email/dominio del maintainer: chi
deploya lo imposta via env ``ARGO_CONTACT_URL`` (email o URL).

Default: ``+https://github.com/argo-osint/argo`` — generico e privo di PII.
"""
from __future__ import annotations

import os

_DEFAULT_CONTACT = "+https://github.com/argo-osint/argo"


def user_agent() -> str:
    """Ritorna lo UA canonico Argo per outbound HTTP passivi."""
    contact = os.getenv("ARGO_CONTACT_URL", _DEFAULT_CONTACT).strip() or _DEFAULT_CONTACT
    return f"Argo-OSINT/1.0 ({contact})"
