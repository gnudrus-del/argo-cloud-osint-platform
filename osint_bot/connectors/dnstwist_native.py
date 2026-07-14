"""Connector: typosquatting / lookalike domains (sostituto nativo di dnstwist).

Genera permutazioni del dominio (omoglifi, inserzioni, omissioni, sostituzioni,
TLD swap, bitsquatting parziale) e verifica quali risolvono → candidati
typosquat / phishing. Passivo (solo risoluzione DNS dei candidati).

Input: ``domain``.
"""
from __future__ import annotations

import concurrent.futures as _cf
import socket

from ..connector import (
    ACTION_PASSIVE,
    BaseConnector,
    ConnectorContext,
    ConnectorResult,
    ConnectorSpec,
    RateLimit,
)
from ..i18n import t as _t
from ..models import Evidence, Finding

_SPEC = ConnectorSpec(
    name="dnstwist_native",
    label="Typosquat / lookalike",
    action_class=ACTION_PASSIVE,
    input_types=("domain",),
    output_categories=("typosquat",),
    required_key="",
    cache_ttl=86_400,
    rate_limit=RateLimit(per_minute=6, per_day=500, burst=1),
    legal_note="dnstwist_native.legal_note",
    health_check_url="",
)

_KEYBOARD_NEAR = {
    "a": "qsz", "b": "vgn", "c": "xvd", "d": "sfe", "e": "wrd", "f": "dgr",
    "g": "fht", "h": "gjy", "i": "uok", "j": "hkn", "k": "jli", "l": "ko",
    "m": "n", "n": "bm", "o": "ip", "p": "o", "q": "wa", "r": "et",
    "s": "adw", "t": "ry", "u": "yi", "v": "cb", "w": "qe", "x": "zc",
    "y": "tu", "z": "xs",
}
_COMMON_TLDS = ["com", "net", "org", "co", "io", "info", "biz", "xyz", "online", "site"]


def _permutations(domain: str) -> set[str]:
    parts = domain.rsplit(".", 1)
    if len(parts) != 2:
        return set()
    name, tld = parts
    out: set[str] = set()

    # Omissione carattere
    for i in range(len(name)):
        out.add(name[:i] + name[i + 1:] + "." + tld)
    # Ripetizione carattere (doubling: abc -> aabc/abbc/abcc)
    for i in range(len(name)):
        out.add(name[:i] + name[i] * 2 + name[i + 1:] + "." + tld)
    # Sostituzione tastiera-vicina
    for i, ch in enumerate(name):
        for alt in _KEYBOARD_NEAR.get(ch, ""):
            out.add(name[:i] + alt + name[i + 1:] + "." + tld)
    # Transposizione caratteri adiacenti
    for i in range(len(name) - 1):
        lst = list(name)
        lst[i], lst[i + 1] = lst[i + 1], lst[i]
        out.add("".join(lst) + "." + tld)
    # Inserzione trattino
    for i in range(1, len(name)):
        out.add(name[:i] + "-" + name[i:] + "." + tld)
    # TLD swap
    for t in _COMMON_TLDS:
        if t != tld:
            out.add(name + "." + t)
    # Omoglifi comuni
    homo = name.replace("o", "0").replace("l", "1").replace("i", "1").replace("e", "3")
    if homo != name:
        out.add(homo + "." + tld)

    out.discard(domain)
    # cap prudente per non esplodere le query DNS
    return set(list(out)[:200])


def _resolve(host: str) -> str | None:
    try:
        return socket.gethostbyname(host)
    except (socket.gaierror, OSError):
        return None


class DNSTwistNativeConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        domain = (context.target or "").strip().lower().rstrip(".")
        if not domain or "." not in domain:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=_t("dnstwist_native.invalid_target", context.lang))
        candidates = _permutations(domain)
        if not candidates:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=_t("dnstwist_native.no_permutations", context.lang))

        registered: dict[str, str] = {}
        with _cf.ThreadPoolExecutor(max_workers=20) as ex:
            futures = {ex.submit(_resolve, c): c for c in candidates}
            for f in _cf.as_completed(futures):
                host = futures[f]
                ip = f.result()
                if ip:
                    registered[host] = ip

        findings: list[Finding] = []
        for host in sorted(registered):
            findings.append(Finding(
                kind="typosquat_domain", value=host,
                confidence=0.7, source_reliability="B", info_credibility=2,
                evidence=[Evidence(url=f"http://{host}", title=host)],
                notes=_t("dnstwist_native.variant_registered", context.lang,
                         domain=domain, ip=registered[host]),
                severity="medium",
            ))
        return ConnectorResult(
            connector=self.spec.name, status="ok",
            findings=findings,
            raw={"candidates": len(candidates), "registered": len(registered)},
        )

    def health_check(self) -> bool:
        return True
