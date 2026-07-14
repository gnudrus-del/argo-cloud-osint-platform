"""Difesa SSRF condivisa per gli outbound HTTP dei connector.

Questo modulo è **l'unico** modo sanzionato con cui il codice di Argo esce
verso la rete. Il check ``scripts/enforce_safe_http.py`` fallisce la CI se un
connettore importa ``urllib.request``/``httpx``/``requests``/``aiohttp``
direttamente invece di passare da qui.

Cosa blocca ``guard_ssrf`` (e, di conseguenza, tutti gli helper qui sotto):
  * schema diverso da http/https
  * loopback (127.0.0.0/8, ::1)
  * link-local (169.254.0.0/16 → metadata cloud AWS/Oracle/GCP/Azure)
  * private IPv4 (RFC1918: 10/8, 172.16/12, 192.168/16) — bloccati by default,
    sbloccabili solo se ``allow_private=True`` (utile per test in LAN).
  * multicast, unspecified, reserved.

Il guard viene applicato **su ogni redirect**: un endpoint pubblico che
risponde ``302 Location: http://169.254.169.254/...`` non può dirottare il
client verso un target interno, perché il redirect handler ri-valida ogni
hop prima di seguirlo.

Uso::

    from .. import _safe_http

    data = _safe_http.get_json("https://api.example.com/x")
    text = _safe_http.get_text("https://example.com/robots.txt")
    data = _safe_http.post_json("https://api.example.com/y", {"q": "z"})

    # controllo puro senza fetch (per codice che apre il socket a mano):
    _safe_http.guard_ssrf(url)

Limite noto (TOCTOU / DNS rebinding): ``guard_ssrf`` risolve l'host una
volta e poi lascia che ``urllib`` risolva di nuovo al momento della
connessione. Un attaccante che controlla il DNS del target e risponde con
un IP pubblico al primo lookup e un IP interno al secondo potrebbe
teoricamente aggirare il check. Il modello di deployment single-tenant di
Argo (vedi ``docs/THREAT_MODEL.md``) rende lo scenario a basso rischio;
l'hardening a "resolve-once + connect-by-IP" è tracciato come lavoro
futuro.
"""
from __future__ import annotations

import ipaddress
import json as _json
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from ._ua import user_agent

# Timeout di default (secondi) per gli helper quando il chiamante non lo passa.
DEFAULT_TIMEOUT = 20
# Tetto sui byte letti da una risposta, per non far esplodere la memoria su
# un endpoint ostile che risponde con un flusso infinito.
MAX_RESPONSE_BYTES = 25 * 1024 * 1024  # 25 MiB


class SSRFBlocked(ValueError):
    """L'URL punta a un target di rete interna e va rifiutato."""


def _always_blocked(ip: str) -> bool:
    """IP che NON sono mai un target legittimo, nemmeno con ``allow_private``.

    Sono i range che un attaccante userebbe per pivotare verso l'interno o
    per leggere le credenziali dell'istanza cloud:
      * link-local (169.254.0.0/16, fe80::/10) → metadata AWS/Oracle/GCP/Azure
      * multicast, reserved, unspecified
    Il loopback e gli RFC1918 privati restano gestiti da ``allow_private``.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (
        addr.is_link_local or addr.is_multicast
        or addr.is_reserved or addr.is_unspecified
    )


def _is_private(ip: str) -> bool:
    """Loopback + RFC1918 — sbloccabili con ``allow_private`` per test in LAN.
    Il resto (metadata cloud, ecc.) è coperto da :func:`_always_blocked`.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_loopback or addr.is_private


def _check_ip(ip: str, host: str, allow_private: bool) -> None:
    if _always_blocked(ip):
        raise SSRFBlocked(f"IP sempre bloccato (metadata/reserved): {ip} ({host}).")
    if _is_private(ip) and not allow_private:
        raise SSRFBlocked(f"IP interno bloccato: {ip} ({host}).")


def guard_ssrf(url: str, *, allow_private: bool = False) -> None:
    """Alza ``SSRFBlocked`` se l'URL è pericoloso.

    Non fa il fetch — solo la validazione. Fai la chiamata solo se questa
    ritorna senza sollevare.

    ``allow_private`` sblocca **solo** loopback + RFC1918 (per test in LAN).
    I range di metadata cloud (link-local) e riservati restano bloccati
    incondizionatamente: non sono mai un target legittimo.
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise SSRFBlocked(f"Schema non consentito: {parsed.scheme!r}.")
    host = (parsed.hostname or "").strip()
    if not host:
        raise SSRFBlocked("Host mancante nell'URL.")
    # Se l'host è un IP letterale, controllo diretto.
    if _always_blocked(host) or _is_private(host):
        _check_ip(host, host, allow_private)
        return
    # Altrimenti risolvi (solo se non è già un IP letterale).
    if not any(ch.isdigit() for ch in host.split(".")[0][:1]) and ":" not in host:
        try:
            _, _, ips = socket.gethostbyname_ex(host)
        except (socket.gaierror, OSError) as exc:
            raise SSRFBlocked(f"Host non risolvibile: {host}.") from exc
        for ip in ips:
            _check_ip(ip, host, allow_private)


class _GuardedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Ri-applica ``guard_ssrf`` a ogni redirect prima di seguirlo.

    ``allow_private`` viene propagato dal chiamante via attributo di istanza,
    così il comportamento del redirect è coerente con quello della richiesta
    iniziale.
    """

    allow_private = False

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Valida il target del redirect: se è interno, blocca.
        guard_ssrf(newurl, allow_private=self.allow_private)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _build_opener(allow_private: bool,
                  insecure_tls: bool = False,
                  proxy_url: str = "") -> urllib.request.OpenerDirector:
    handler = _GuardedRedirectHandler()
    handler.allow_private = allow_private
    handlers: list = [handler]
    if proxy_url:
        handlers.append(
            urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
        )
    if insecure_tls:
        # Only used for operator-configured internal endpoints with a
        # self-signed certificate (e.g. a private MISP instance). The
        # SSRF guard + allow_private still gate the destination.
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    return urllib.request.build_opener(*handlers)


def _merge_headers(headers: dict[str, str] | None) -> dict[str, str]:
    merged = {"User-Agent": user_agent()}
    if headers:
        merged.update(headers)
    return merged


def open_url(
    url: str,
    *,
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
    method: str | None = None,
    timeout: int = DEFAULT_TIMEOUT,
    allow_private: bool = False,
    insecure_tls: bool = False,
    proxy_url: str = "",
) -> tuple[int, bytes, dict[str, str]]:
    """Esegue una richiesta HTTP(S) sanzionata e ritorna ``(status, body, headers)``.

    Applica ``guard_ssrf`` sull'URL iniziale e su ogni redirect. Solleva
    ``SSRFBlocked`` se un target è interno, ``urllib.error.URLError`` /
    ``HTTPError`` per gli errori di rete/HTTP (il chiamante li cattura come
    fa già oggi con ``except Exception``).

    ``allow_private`` sblocca loopback + RFC1918 (per endpoint interni
    configurati dall'operatore, es. un MISP privato). ``insecure_tls``
    disabilita la verifica del certificato — usare SOLO per quegli stessi
    endpoint interni con certificato self-signed. ``proxy_url`` instrada la
    richiesta (e i suoi redirect) attraverso un outbound proxy operatore
    (es. Tor/HTTP proxy egress) senza indebolire il guard: ogni hop, incluso
    quello riscritto dal proxy, resta validato da ``guard_ssrf``.
    """
    guard_ssrf(url, allow_private=allow_private)
    req = urllib.request.Request(
        url, data=data, headers=_merge_headers(headers), method=method
    )
    opener = _build_opener(allow_private, insecure_tls=insecure_tls, proxy_url=proxy_url)
    with opener.open(req, timeout=timeout) as resp:
        body = resp.read(MAX_RESPONSE_BYTES + 1)
        if len(body) > MAX_RESPONSE_BYTES:
            raise SSRFBlocked(
                f"Risposta troppo grande (> {MAX_RESPONSE_BYTES} byte) da {url}."
            )
        status = getattr(resp, "status", None) or resp.getcode()
        resp_headers = {k.lower(): v for k, v in resp.headers.items()}
    return status, body, resp_headers


def get_bytes(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: int = DEFAULT_TIMEOUT,
    allow_private: bool = False,
) -> bytes:
    """GET → corpo grezzo in byte."""
    _, body, _ = open_url(
        url, headers=headers, timeout=timeout, allow_private=allow_private
    )
    return body


def get_text(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: int = DEFAULT_TIMEOUT,
    encoding: str = "utf-8",
    allow_private: bool = False,
) -> str:
    """GET → testo decodificato (errors='replace')."""
    body = get_bytes(
        url, headers=headers, timeout=timeout, allow_private=allow_private
    )
    return body.decode(encoding, errors="replace")


def get_json(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: int = DEFAULT_TIMEOUT,
    allow_private: bool = False,
) -> Any:
    """GET → JSON parsato. Imposta ``Accept: application/json`` se non fornito."""
    hdrs = {"Accept": "application/json"}
    if headers:
        hdrs.update(headers)
    text = get_text(
        url, headers=hdrs, timeout=timeout, allow_private=allow_private
    )
    return _json.loads(text)


def post_json(
    url: str,
    payload: Any,
    *,
    headers: dict[str, str] | None = None,
    timeout: int = DEFAULT_TIMEOUT,
    allow_private: bool = False,
) -> Any:
    """POST di un body JSON → risposta JSON parsata."""
    body = _json.dumps(payload).encode("utf-8")
    hdrs = {"Content-Type": "application/json", "Accept": "application/json"}
    if headers:
        hdrs.update(headers)
    _, resp_body, _ = open_url(
        url, data=body, headers=hdrs, method="POST",
        timeout=timeout, allow_private=allow_private,
    )
    return _json.loads(resp_body.decode("utf-8", errors="replace"))


def post_form(
    url: str,
    fields: dict[str, str],
    *,
    headers: dict[str, str] | None = None,
    timeout: int = DEFAULT_TIMEOUT,
    allow_private: bool = False,
) -> tuple[int, bytes]:
    """POST ``application/x-www-form-urlencoded`` → ``(status, body)``."""
    body = urllib.parse.urlencode(fields).encode("utf-8")
    hdrs = {"Content-Type": "application/x-www-form-urlencoded"}
    if headers:
        hdrs.update(headers)
    status, resp_body, _ = open_url(
        url, data=body, headers=hdrs, method="POST",
        timeout=timeout, allow_private=allow_private,
    )
    return status, resp_body


__all__ = [
    "SSRFBlocked",
    "guard_ssrf",
    "open_url",
    "get_bytes",
    "get_text",
    "get_json",
    "post_json",
    "post_form",
    "DEFAULT_TIMEOUT",
    "MAX_RESPONSE_BYTES",
]
