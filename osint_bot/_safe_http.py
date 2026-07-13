"""Difesa SSRF condivisa per gli outbound HTTP dei connector.

Blocca URL che risolvono a target "interni":
  * schema diverso da http/https
  * loopback (127.0.0.0/8, ::1)
  * link-local (169.254.0.0/16 → metadata cloud AWS/Oracle/GCP/Azure)
  * private IPv4 (RFC1918: 10/8, 172.16/12, 192.168/16) — bloccati by default,
    sbloccabili solo se ``allow_private=True`` (utile per test in LAN).
  * multicast, unspecified, reserved.

Uso::

    from ._safe_http import guard_ssrf
    guard_ssrf(url)  # solleva ValueError se il target è interno
"""
from __future__ import annotations

import ipaddress
import socket
import urllib.parse


class SSRFBlocked(ValueError):
    """L'URL punta a un target di rete interna e va rifiutato."""


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (
        addr.is_loopback or addr.is_link_local or addr.is_private
        or addr.is_multicast or addr.is_reserved or addr.is_unspecified
    )


def guard_ssrf(url: str, *, allow_private: bool = False) -> None:
    """Alza ``SSRFBlocked`` se l'URL è pericoloso.

    Non fa il fetch — solo la validazione. Fai la chiamata solo se questa
    ritorna senza sollevare.
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise SSRFBlocked(f"Schema non consentito: {parsed.scheme!r}.")
    host = (parsed.hostname or "").strip()
    if not host:
        raise SSRFBlocked("Host mancante nell'URL.")
    # Se l'host è un IP letterale, controllo diretto.
    try:
        if _is_private(host) and not allow_private:
            raise SSRFBlocked(f"IP interno bloccato: {host}.")
        # se non è IP, socket.gethostbyname_ex risolve
    except SSRFBlocked:
        raise
    if not any(ch.isdigit() for ch in host.split(".")[0][:1]) and ":" not in host:
        try:
            _, _, ips = socket.gethostbyname_ex(host)
        except (socket.gaierror, OSError) as exc:
            raise SSRFBlocked(f"Host non risolvibile: {host}.") from exc
        for ip in ips:
            if _is_private(ip) and not allow_private:
                raise SSRFBlocked(f"L'host {host} risolve a IP interno {ip}.")
