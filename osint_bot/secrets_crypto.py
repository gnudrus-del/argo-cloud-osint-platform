"""Envelope encryption for BYOK API keys at rest.

Threat model: protect connector API keys against a *database-only* leak (a
stolen SQLite file, a Postgres dump, a leaked Postgres credential) without
requiring a cloud KMS — Argo is self-hosted by design (see
``docs/THREAT_MODEL.md``). The master key that makes this work lives outside
the database, as a file the DB dump does not contain.

Scheme, per stored secret:

1. A random 256-bit Data Encryption Key (DEK) encrypts the plaintext with
   AES-256-GCM (authenticated encryption — a tampered ciphertext fails to
   decrypt rather than silently returning garbage).
2. The DEK itself is "wrapped" (encrypted) with the instance's master key,
   also AES-256-GCM. Both the wrapped DEK and the ciphertext are stored
   together as one opaque blob in place of the old plaintext column value.

This indirection is the actual point of "envelope" encryption: rotating the
master key only requires re-wrapping the (small) DEKs, never touching or
re-deriving the underlying secret values themselves.

Master key resolution, in priority order (mirrors ``report_signing.py``'s
Ed25519 key loader):

1. ``OSINT_MASTER_KEY`` env var — base64, 32 bytes. For deployments where a
   secret manager or orchestrator injects the key directly into the process
   environment.
2. ``OSINT_MASTER_KEY_FILE`` — path to a file containing the base64 key. This
   is the systemd-credentials-friendly option: ``LoadCredential=argo_master_key:
   /path/to/encrypted-credential`` exposes the decrypted value at
   ``${CREDENTIALS_DIRECTORY}/argo_master_key`` at runtime, readable only by
   the service's own user — set ``OSINT_MASTER_KEY_FILE=${CREDENTIALS_DIRECTORY}/argo_master_key``.
3. Neither set: auto-generate a key on first use and persist it to
   ``<job_root>/.master_key`` (``chmod 600``), sibling to the SQLite database
   file, never inside it. Zero-config default, same UX as the Ed25519
   report-signing key — "works out of the box" without giving up the "the
   master key is not a database row" property the whole design exists for.

Values written before this module existed are plain, unprefixed strings.
``decrypt_secret`` treats anything without the ``enc:v1:`` prefix as such
legacy plaintext and returns it unchanged — the next ``put_api_key`` call
transparently upgrades it to an encrypted blob. There is no blocking
migration step; a full re-encryption of every stored key at once (rather
than waiting for a natural rewrite) is exactly what ``cli_rotate_key.py``
(``argo-rotate-master-key``) already does via ``all_api_keys`` +
``set_api_key_encrypted`` on the storage backend, since a master-key
rotation and a proactive legacy-plaintext upgrade are the same operation.
"""
from __future__ import annotations

import base64
import json
import logging
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_log = logging.getLogger("osint_bot.secrets_crypto")

ENVELOPE_PREFIX_V1 = "enc:v1:"  # legacy: no AAD, kept for backward-compat reads only
ENVELOPE_PREFIX_V2 = "enc:v2:"  # current: AAD binds ciphertext to its (username, service) row
ENVELOPE_PREFIX = ENVELOPE_PREFIX_V2  # what new writes use; kept for callers checking the prefix
_NONCE_BYTES = 12  # standard AES-GCM nonce size
_KEY_BITS = 256

_master_key_cache: dict[str, bytes] = {}


def master_key_path(job_root: Path) -> Path:
    """Where the auto-generated master key file lives, absent an override."""
    override = os.getenv("OSINT_MASTER_KEY_FILE", "").strip()
    if override:
        return Path(override)
    return Path(job_root) / ".master_key"


def master_key_source(job_root: Path) -> str:
    """Human-readable description of which of the three sources is active —
    used by the rotation CLI to decide whether it can safely rewrite the key
    in place or must hand the new key to the operator instead."""
    if os.getenv("OSINT_MASTER_KEY", "").strip():
        return "env:OSINT_MASTER_KEY"
    if os.getenv("OSINT_MASTER_KEY_FILE", "").strip():
        return f"file-override:{master_key_path(job_root)}"
    return f"auto-generated:{master_key_path(job_root)}"


def generate_master_key() -> bytes:
    """A fresh random 256-bit key — used for first-run auto-generation and
    for rotation. Exposed publicly for the rotation CLI."""
    return AESGCM.generate_key(bit_length=_KEY_BITS)


def persist_master_key_file(path: Path, key: bytes) -> None:
    """Write *key* (base64) to *path*, chmod 600, best-effort on platforms
    without POSIX permissions. Shared by first-run auto-generation and by
    the rotation CLI's in-place-rewrite path."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(base64.b64encode(key).decode("ascii"), encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError as exc:
        # Best-effort: expected on filesystems without POSIX permissions
        # (Windows/FAT). Logged (not swallowed silently) because on a POSIX
        # host where this fails for another reason, the master key could sit
        # group/world-readable with nothing telling the operator.
        _log.warning("Could not chmod 600 master key file %s: %s", path, exc)


def load_or_create_master_key(job_root: Path) -> bytes:
    env_key = os.getenv("OSINT_MASTER_KEY", "").strip()
    if env_key:
        return base64.b64decode(env_key)

    path = master_key_path(job_root)
    if path.exists():
        return base64.b64decode(path.read_text(encoding="utf-8").strip())

    key = generate_master_key()
    persist_master_key_file(path, key)
    return key


def get_master_key(job_root: Path) -> bytes:
    """Process-cached loader, keyed by resolved source so multiple job_roots
    in the same process (as in the test suite) never share a cached key."""
    cache_key = (
        os.getenv("OSINT_MASTER_KEY_FILE", "").strip()
        or os.getenv("OSINT_MASTER_KEY", "").strip()
        or str(Path(job_root).resolve())
    )
    cached = _master_key_cache.get(cache_key)
    if cached is not None:
        return cached
    key = load_or_create_master_key(job_root)
    _master_key_cache[cache_key] = key
    return key


def invalidate_cache() -> None:
    """Drop every cached master key. Call after a rotation writes a new key
    to disk, so the next lookup re-reads it instead of serving the stale
    in-memory copy — without this, a long-running process that rotates its
    own key would keep decrypting with the old one until restarted."""
    _master_key_cache.clear()


def api_key_aad(username: str, service: str) -> bytes:
    """Canonical AAD for one ``api_keys`` row. A single shared function (not
    each caller formatting its own string) so storage.py, storage_postgres.py
    and the rotation CLI can never drift into using slightly different AAD
    for the same row, which would make a value written by one and read by
    the other fail to decrypt."""
    return f"api_key:{username}:{service}".encode()


def is_encrypted(value: str) -> bool:
    return bool(value) and (value.startswith(ENVELOPE_PREFIX_V2) or value.startswith(ENVELOPE_PREFIX_V1))


def encrypt_secret(plaintext: str, master_key: bytes, *, aad: bytes = b"") -> str:
    """Envelope-encrypt *plaintext*. Empty input returns empty output — an
    empty API key value means "no key configured", not a secret to protect.

    *aad* (Additional Authenticated Data) should be a stable identifier for
    the row this value belongs to, e.g. ``f"{username}:{service}".encode()``.
    It is not secret and is not stored, but AES-GCM cryptographically binds
    the ciphertext to it: decrypting with a different *aad* fails loudly
    instead of silently succeeding. Without this, direct database write
    access (SQL injection, a rogue script, a compromised low-privilege DB
    credential — a different threat than the "read-only DB leak" this module
    otherwise defends against) could copy one row's ciphertext into another
    row and have it decrypt "successfully" there, silently misattributing a
    secret. Every new write goes through this; omitting *aad* (default)
    keeps it backward-compatible for callers that have none available.
    """
    if not plaintext:
        return ""
    dek = AESGCM.generate_key(bit_length=_KEY_BITS)
    data_nonce = os.urandom(_NONCE_BYTES)
    ciphertext = AESGCM(dek).encrypt(data_nonce, plaintext.encode("utf-8"), aad or None)
    wrap_nonce = os.urandom(_NONCE_BYTES)
    wrapped_dek = AESGCM(master_key).encrypt(wrap_nonce, dek, aad or None)
    envelope = {
        "wrap_nonce": base64.b64encode(wrap_nonce).decode("ascii"),
        "wrapped_dek": base64.b64encode(wrapped_dek).decode("ascii"),
        "data_nonce": base64.b64encode(data_nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }
    packed = base64.b64encode(json.dumps(envelope).encode("utf-8")).decode("ascii")
    return ENVELOPE_PREFIX_V2 + packed


def decrypt_secret(value: str, master_key: bytes, *, aad: bytes = b"") -> str:
    """Decrypt a value produced by ``encrypt_secret``. Legacy plaintext
    (no ``enc:v1:``/``enc:v2:`` prefix, written before this module existed)
    passes through unchanged — see the module docstring.

    *aad* must match what ``encrypt_secret`` was called with for this value
    to decrypt (v2 envelopes only — v1 predates AAD support and is always
    decrypted without it, regardless of what the caller passes here, since
    it was never bound to any). A mismatched *aad* raises ``InvalidTag``,
    same as a wrong key — the row-binding only has teeth if verification is
    unconditional, not best-effort.
    """
    if not value or not is_encrypted(value):
        return value
    if value.startswith(ENVELOPE_PREFIX_V2):
        prefix, use_aad = ENVELOPE_PREFIX_V2, (aad or None)
    else:
        prefix, use_aad = ENVELOPE_PREFIX_V1, None  # v1 never had AAD
    envelope = json.loads(base64.b64decode(value[len(prefix):]))
    wrap_nonce = base64.b64decode(envelope["wrap_nonce"])
    wrapped_dek = base64.b64decode(envelope["wrapped_dek"])
    data_nonce = base64.b64decode(envelope["data_nonce"])
    ciphertext = base64.b64decode(envelope["ciphertext"])
    dek = AESGCM(master_key).decrypt(wrap_nonce, wrapped_dek, use_aad)
    plaintext = AESGCM(dek).decrypt(data_nonce, ciphertext, use_aad)
    return plaintext.decode("utf-8")


__all__ = [
    "ENVELOPE_PREFIX",
    "ENVELOPE_PREFIX_V1",
    "ENVELOPE_PREFIX_V2",
    "master_key_path",
    "master_key_source",
    "generate_master_key",
    "persist_master_key_file",
    "load_or_create_master_key",
    "get_master_key",
    "invalidate_cache",
    "api_key_aad",
    "is_encrypted",
    "encrypt_secret",
    "decrypt_secret",
]
