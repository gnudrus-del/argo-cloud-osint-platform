"""Client RFC 3161 (Time-Stamp Protocol) per il timestamp opzionale sui sigilli
di report.

Feature opt-in a un solo gate leggero (a differenza del modello a 3 gate degli
agenti IA): verso la TSA esce **solo** un digest SHA-256 di 32 byte, mai
contenuto del caso — un digest non è invertibile al contenuto originale, è una
categoria di esposizione radicalmente diversa dall'inviare prosa dei finding a
un LLM. Nessuna chiamata parte se ``TSA_URL`` non è configurato (vedi web.py).

Ogni richiesta passa da ``_safe_http`` come ogni altro outbound HTTP di Argo —
mai ``allow_private``, una TSA è per definizione un host pubblico.

Non verifichiamo la catena di certificati della TSA né la firma CMS della
risposta: salviamo il token grezzo (DER) così come arriva e lo restituiamo
fedelmente. La verifica del token è responsabilità di chi la esegue con
strumenti standard (``openssl ts -verify``) — Argo non si mette a fare da
unico arbitro della propria prova di fiducia.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass

from asn1crypto import algos, tsp

from . import _safe_http

_GRANTED_STATUSES = {"granted", "granted_with_mods"}


@dataclass
class TSAResult:
    ok: bool
    status: str = ""
    status_string: str = ""
    token_der_b64: str = ""
    gen_time: str = ""
    http_status: int | None = None
    error: str = ""
    # "" | "invalid_request" | "ssrf_blocked" | "network_error" | "http_error" |
    # "invalid_response" | "rejected"
    error_class: str = ""


def build_timestamp_request(digest: bytes, *, nonce: int | None = None, cert_req: bool = True) -> bytes:
    """DER-encoded ``TimeStampReq`` (RFC 3161 §2.4.1) su un digest SHA-256 a 32 byte."""
    if len(digest) != 32:
        raise ValueError("digest deve essere SHA-256 (32 byte)")
    message_imprint = tsp.MessageImprint({
        "hash_algorithm": algos.DigestAlgorithm({"algorithm": "sha256"}),
        "hashed_message": digest,
    })
    fields = {"version": 1, "message_imprint": message_imprint, "cert_req": cert_req}
    if nonce is not None:
        fields["nonce"] = nonce
    return tsp.TimeStampReq(fields).dump()


def _parse_timestamp_response(body: bytes, *, http_status: int) -> TSAResult:
    resp = tsp.TimeStampResp.load(body)
    pki_status = resp["status"]["status"].native
    status_string_native = resp["status"]["status_string"].native
    status_string = "; ".join(status_string_native) if status_string_native else ""

    if pki_status not in _GRANTED_STATUSES:
        return TSAResult(
            ok=False, status=pki_status or "", status_string=status_string,
            http_status=http_status, error=status_string or f"TSA status: {pki_status}",
            error_class="rejected",
        )

    token = resp["time_stamp_token"]
    token_der = token.dump()
    gen_time = ""
    try:
        econtent = token["content"]["encap_content_info"]["content"]
        gen_time = econtent.parsed["gen_time"].native.isoformat()
    except Exception:
        gen_time = ""  # il token è comunque salvato; solo il display gen_time non disponibile

    return TSAResult(
        ok=True, status=pki_status, status_string=status_string,
        token_der_b64=base64.b64encode(token_der).decode("ascii"),
        gen_time=gen_time, http_status=http_status,
    )


def request_timestamp(tsa_url: str, digest_hex: str, *, timeout: int = 20) -> TSAResult:
    """Richiede un timestamp RFC3161 su *digest_hex* (hex SHA-256) a *tsa_url*.

    Non solleva mai — ogni fallimento (rete, HTTP, SSRF, risposta malformata,
    rifiuto della TSA) torna come ``TSAResult(ok=False, ...)`` cosi il
    chiamante lo audita sempre, successo o fallimento.
    """
    try:
        digest = bytes.fromhex(digest_hex)
    except ValueError:
        return TSAResult(ok=False, error="digest_hex non valido", error_class="invalid_request")
    try:
        der = build_timestamp_request(digest)
    except ValueError as exc:
        return TSAResult(ok=False, error=str(exc), error_class="invalid_request")

    try:
        status, body, _headers = _safe_http.open_url(
            tsa_url,
            data=der,
            headers={
                "Content-Type": "application/timestamp-query",
                "Accept": "application/timestamp-reply",
            },
            method="POST",
            timeout=timeout,
        )
    except _safe_http.SSRFBlocked as exc:
        return TSAResult(ok=False, error=str(exc), error_class="ssrf_blocked")
    except Exception as exc:
        http_status = getattr(exc, "code", None)
        return TSAResult(ok=False, error=str(exc), error_class="network_error", http_status=http_status)

    if status != 200:
        return TSAResult(ok=False, http_status=status, error=f"HTTP {status}", error_class="http_error")

    try:
        return _parse_timestamp_response(body, http_status=status)
    except Exception as exc:
        return TSAResult(ok=False, http_status=status, error=str(exc), error_class="invalid_response")


__all__ = ["TSAResult", "build_timestamp_request", "request_timestamp"]
