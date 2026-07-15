"""Firma Ed25519 locale dei sigilli di report (manifest_hash).

Zero rete in uscita: puro calcolo locale, sempre attivo (nessun kill switch,
nessun consenso per-caso — a differenza delle capability IA che mandano
contenuto del caso a un provider terzo, qui non esce nulla). La chiave privata
Ed25519 dell'istanza viene generata al primo uso e persistita su disco: la
garanzia è "questa istanza di Argo, chiave stabile nel tempo", non
un'identità certificata da una CA — non c'è alcuna PKI qui.

Non logghiamo mai la chiave privata. Solo fingerprint (SHA-256 della chiave
pubblica) finiscono negli eventi audit.
"""
from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

SIGNING_ALGORITHM = "Ed25519"

_cached_key: Ed25519PrivateKey | None = None
_cached_key_path: Path | None = None


def signing_key_path(job_root: Path) -> Path:
    """Path del file che contiene il seed (base64) della chiave di firma.

    Override via ``OSINT_REPORT_SIGNING_KEY_PATH``; default un file nascosto
    sotto ``job_root`` (stessa cartella dati di ``.maigret-home``/``.ghunt-home``).
    """
    override = os.getenv("OSINT_REPORT_SIGNING_KEY_PATH", "").strip()
    if override:
        return Path(override)
    return job_root / ".report_signing_key"


def load_or_create_signing_key(path: Path) -> Ed25519PrivateKey:
    """Carica il seed da *path* se esiste, altrimenti ne genera uno nuovo e lo persiste.

    La persistenza è essenziale: rigenerare la chiave a ogni riavvio
    invaliderebbe silenziosamente tutte le firme precedenti.
    """
    if path.exists():
        seed_b64 = path.read_text(encoding="utf-8").strip()
        seed = base64.b64decode(seed_b64)
        return Ed25519PrivateKey.from_private_bytes(seed)
    key = Ed25519PrivateKey.generate()
    seed = key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(base64.b64encode(seed).decode("ascii"), encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass  # best-effort: filesystem senza permessi POSIX (es. Windows/FAT)
    return key


def get_signing_key(job_root: Path) -> Ed25519PrivateKey:
    """Loader cacheato a livello di processo, chiave per *job_root*."""
    global _cached_key, _cached_key_path
    path = signing_key_path(job_root)
    if _cached_key is not None and _cached_key_path == path:
        return _cached_key
    _cached_key = load_or_create_signing_key(path)
    _cached_key_path = path
    return _cached_key


def _public_key_bytes(pubkey: Ed25519PublicKey) -> bytes:
    return pubkey.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def public_key_fingerprint(pubkey: Ed25519PublicKey) -> str:
    return hashlib.sha256(_public_key_bytes(pubkey)).hexdigest()


def sign_digest(digest_hex: str, job_root: Path) -> dict:
    """Firma i byte grezzi di *digest_hex* (hex SHA-256) con la chiave dell'istanza.

    Si firmano i byte grezzi del digest (``bytes.fromhex``), non la stringa
    hex ri-codificata — stessa rappresentazione usata per il MessageImprint
    RFC3161, cosi lo stesso digest produce lo stesso materiale in entrambi i
    meccanismi.
    """
    key = get_signing_key(job_root)
    signature = key.sign(bytes.fromhex(digest_hex))
    pubkey = key.public_key()
    return {
        "algorithm": SIGNING_ALGORITHM,
        "signature_b64": base64.b64encode(signature).decode("ascii"),
        "public_key_b64": base64.b64encode(_public_key_bytes(pubkey)).decode("ascii"),
        "fingerprint_sha256": public_key_fingerprint(pubkey),
    }


def verify_signature(digest_hex: str, signature_b64: str, public_key_b64: str) -> bool:
    """True se *signature_b64* è una firma Ed25519 valida di *digest_hex* per la chiave data."""
    try:
        pubkey = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64))
        pubkey.verify(base64.b64decode(signature_b64), bytes.fromhex(digest_hex))
        return True
    except Exception:
        return False


def export_public_key(job_root: Path) -> dict:
    """Chiave pubblica dell'istanza, pensata per essere condivisa liberamente."""
    pubkey = get_signing_key(job_root).public_key()
    return {
        "algorithm": SIGNING_ALGORITHM,
        "public_key_b64": base64.b64encode(_public_key_bytes(pubkey)).decode("ascii"),
        "fingerprint_sha256": public_key_fingerprint(pubkey),
    }


__all__ = [
    "SIGNING_ALGORITHM",
    "signing_key_path",
    "load_or_create_signing_key",
    "get_signing_key",
    "public_key_fingerprint",
    "sign_digest",
    "verify_signature",
    "export_public_key",
]
