"""Connector: TLS certificate inspector.

Fa un TLS handshake su ``target:443`` (default) e legge il certificato del
server. Estrae issuer, subject, SAN, date, SHA-256 fingerprint.

Zero API key. Passivo (una connessione TCP, no scan).
Input: ``domain`` (opzionale: ``domain:port``).
"""
from __future__ import annotations

import hashlib
import socket
import ssl

from ..connector import (
    ACTION_PASSIVE,
    BaseConnector,
    ConnectorContext,
    ConnectorResult,
    ConnectorSpec,
    RateLimit,
)
from ..models import Evidence, Finding

_SPEC = ConnectorSpec(
    name="tls_cert",
    label="TLS certificate",
    action_class=ACTION_PASSIVE,
    input_types=("domain",),
    output_categories=("tls",),
    required_key="",
    cache_ttl=3600,
    rate_limit=RateLimit(per_minute=30, per_day=5000, burst=3),
    legal_note="Una connessione TCP al target:443 per leggere il cert pubblico. Passivo.",
    health_check_url="",
)


def _fetch_cert(host: str, port: int, timeout: int) -> dict | None:
    """Ritorna il certificato in formato dict (come ``ssl.SSLSocket.getpeercert()``)
    piu' il DER per calcolare il fingerprint. None se il handshake fallisce.
    """
    ctx = ssl.create_default_context()
    # Non verifico la CA: voglio anche cert self-signed o scaduti (utile per OSINT).
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
                # Nota: getpeercert() con CERT_NONE ritorna {} — parso il DER a mano.
        return {"der": der}
    except (OSError, ssl.SSLError):
        return None


def _parse_der(der: bytes) -> dict:
    """Parsing minimale del cert DER: fingerprint + estrazione naïve dei campi.

    ``ssl`` di stdlib non espone un parser DER completo. Uso ``ssl.DER_cert_to_PEM_cert``
    per ottenere PEM, poi ``socket`` non aiuta oltre. Per estrazione dei campi
    servirebbe cryptography, ma per non aggiungere dipendenze mi limito al
    fingerprint SHA-256 + una lettura minima da un secondo handshake con
    ``check_hostname=True`` che restituisce dict popolato.
    """
    return {
        "sha256_fingerprint": hashlib.sha256(der).hexdigest(),
        "size_bytes": len(der),
    }


def _fetch_cert_with_meta(host: str, port: int, timeout: int) -> dict | None:
    """Combina i due modi: legge DER + tenta anche parsing meta via CERT_REQUIRED
    (funziona solo su cert validi; se fallisce, va bene lo stesso — abbiamo il DER)."""
    result = _fetch_cert(host, port, timeout)
    if result is None:
        return None
    # Secondo handshake per estrarre i field parsati (issuer, subject, SAN)
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ssl.create_default_context().wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                if cert:
                    result.update(cert)
    except (OSError, ssl.SSLError):
        pass
    return result


class TLSCertConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        target = (context.target or "").strip()
        if not target:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error="Target vuoto.")
        host, _, port_s = target.partition(":")
        try:
            port = int(port_s) if port_s else 443
        except ValueError:
            port = 443

        cert = _fetch_cert_with_meta(host, port, context.timeout)
        if not cert:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=f"Impossibile ottenere cert TLS da {host}:{port}.")

        der_info = _parse_der(cert.get("der", b""))
        fp = der_info["sha256_fingerprint"]

        findings: list[Finding] = []
        ev = [Evidence(url=f"https://crt.sh/?q={host}", title="crt.sh (log CT)")]

        # SAN
        san_list: list[str] = []
        for entry in (cert.get("subjectAltName") or []):
            if isinstance(entry, tuple) and len(entry) == 2:
                san_list.append(entry[1])
        for name in san_list[:15]:
            findings.append(Finding(
                kind="tls_san",
                value=name,
                confidence=0.95, source_reliability="A", info_credibility=1,
                evidence=ev,
                notes=f"Subject Alt Name presente nel certificato di {host}:{port}",
            ))

        # Issuer / Subject
        def _flatten(rdn):
            if not rdn: return ""
            return ", ".join(f"{k}={v}" for group in rdn for k, v in group)
        issuer = _flatten(cert.get("issuer"))
        subject = _flatten(cert.get("subject"))
        if issuer:
            findings.append(Finding(
                kind="tls_issuer", value=issuer,
                confidence=0.95, source_reliability="A", info_credibility=1,
                evidence=ev,
                notes=f"CA emittente del cert di {host}:{port}",
            ))
        if subject:
            findings.append(Finding(
                kind="tls_subject", value=subject,
                confidence=0.90, source_reliability="A", info_credibility=1,
                evidence=ev,
            ))
        # Validity
        if cert.get("notBefore"):
            findings.append(Finding(
                kind="tls_valid_from", value=str(cert["notBefore"]),
                confidence=0.99, source_reliability="A", info_credibility=1,
                evidence=ev,
            ))
        if cert.get("notAfter"):
            findings.append(Finding(
                kind="tls_valid_until", value=str(cert["notAfter"]),
                confidence=0.99, source_reliability="A", info_credibility=1,
                evidence=ev,
            ))
        # Fingerprint
        findings.append(Finding(
            kind="tls_fingerprint_sha256", value=fp,
            confidence=1.0, source_reliability="A", info_credibility=1,
            evidence=ev,
            notes=f"SHA-256 del cert DER (identificatore univoco).",
        ))

        raw = {k: v for k, v in cert.items() if k != "der"}
        raw["sha256_fingerprint"] = fp
        raw["san_count"] = len(san_list)
        return ConnectorResult(connector=self.spec.name, status="ok",
                               findings=findings, raw=raw)

    def health_check(self) -> bool:
        return True  # ssl e' stdlib
