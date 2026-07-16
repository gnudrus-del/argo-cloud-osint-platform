"""Connector: Email security posture (SPF/DMARC/DKIM/MTA-STS/DNSSEC).

Zero API key. Usa ``dig`` via ``subprocess`` (stesso pattern di
``dns_query.py``): interroga solo record DNS TXT/SOA pubblici del dominio
target. Nessun contatto con server di posta o altri host del dominio.

Action class: passive. Input: ``domain``.

Controlli eseguiti:
* SPF (record TXT sull'apex): presenza + qualifier finale (``-all`` hardfail,
  ``~all`` softfail, ``?all``/assente permissivo). Rileva anche alcuni
  tenant SaaS noti via ``include:``.
* DMARC (``_dmarc.<domain>`` TXT): presenza + policy (``p=none|quarantine|
  reject``) + ``pct=``.
* MTA-STS (``_mta-sts.<domain>`` TXT): presenza.
* DNSSEC (``dig +dnssec <domain> SOA``): presenza di un record ``RRSIG``
  nella risposta. Se ``dig`` manca del tutto, il controllo viene saltato
  senza far fallire il connettore.
* BIMI (``default._bimi.<domain>`` TXT, opzionale/informativo).
"""
from __future__ import annotations

import re
import shutil
import subprocess

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
    name="email_security",
    label="Email security posture (SPF/DMARC/DKIM/MTA-STS/DNSSEC)",
    action_class=ACTION_PASSIVE,
    input_types=("domain",),
    output_categories=("email_security",),
    required_key="",
    cache_ttl=3600,
    rate_limit=RateLimit(per_minute=30, per_day=2000, burst=5),
    legal_note="email_security.legal_note",
    health_check_url="",
)

# include: noti che indicano un tenant SaaS di posta (euristica leggera, non
# esaustiva: aggiungerne altri e' sicuro, non cambia il comportamento base).
_KNOWN_SAAS_INCLUDES: dict[str, str] = {
    "include:_spf.google.com": "Google Workspace",
    "include:spf.protection.outlook.com": "Microsoft 365",
}

_TXT_STRING_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')


def _dig(name: str, rtype: str, timeout: int) -> list[str] | None:
    """Esegue ``dig +short <rtype> <name>``.

    Ritorna ``None`` se ``dig`` non e' installato o la chiamata fallisce
    (timeout, errore OS) — segnale che il tool stesso non e' utilizzabile.
    Ritorna ``[]`` se ``dig`` ha risposto ma non ci sono record (segnale
    diverso: la query ha funzionato, il record semplicemente non esiste).
    """
    dig = shutil.which("dig")
    if not dig:
        return None
    try:
        p = subprocess.run(
            [dig, "+short", "+time=3", "+tries=1", rtype, name],
            capture_output=True, text=True, timeout=timeout,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    return [line.strip() for line in (p.stdout or "").splitlines() if line.strip()][:20]


def _dig_dnssec_soa(domain: str, timeout: int) -> str | None:
    """Esegue ``dig +dnssec <domain> SOA`` (output completo, non ``+short``).

    Ritorna ``None`` se ``dig`` non e' installato o la chiamata fallisce —
    in quel caso il controllo DNSSEC viene saltato senza generare un
    finding (non possiamo distinguere "non abilitato" da "non verificabile").
    """
    dig = shutil.which("dig")
    if not dig:
        return None
    try:
        p = subprocess.run(
            [dig, "+dnssec", "+time=3", "+tries=1", domain, "SOA"],
            capture_output=True, text=True, timeout=timeout,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    return p.stdout or ""


def _clean_txt(raw_lines: list[str]) -> list[str]:
    """Pulisce le righe ``dig +short TXT``: rimuove le virgolette e concatena
    le stringhe multiple di un singolo record TXT lungo (dig stampa record
    TXT > 255 char come ``"parte1" "parte2"`` sulla stessa riga)."""
    cleaned: list[str] = []
    for line in raw_lines:
        parts = _TXT_STRING_RE.findall(line)
        cleaned.append("".join(parts) if parts else line.strip().strip('"'))
    return cleaned


def find_spf_record(txt_records: list[str]) -> str | None:
    for rec in txt_records:
        if rec.lower().startswith("v=spf1"):
            return rec
    return None


def find_dmarc_record(txt_records: list[str]) -> str | None:
    for rec in txt_records:
        if rec.lower().startswith("v=dmarc1"):
            return rec
    return None


def parse_spf_all_qualifier(spf_record: str) -> str:
    """Ritorna il qualifier del meccanismo ``all`` (``-``, ``~``, ``?``,
    ``+``) oppure ``""`` se ``all`` non e' presente nel record."""
    for token in spf_record.split():
        if token in ("-all", "~all", "?all", "+all"):
            return token[0]
        if token == "all":
            return "+"  # qualifier di default quando omesso
    return ""


def parse_dmarc_tag(dmarc_record: str, tag: str) -> str | None:
    """Estrae il valore di un tag ``chiave=valore`` (es. ``p``, ``pct``) da
    un record DMARC separato da ``;``."""
    for part in dmarc_record.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        key, _, value = part.partition("=")
        if key.strip().lower() == tag.lower():
            return value.strip()
    return None


def detect_saas_from_spf(spf_record: str) -> list[str]:
    """Riconosce tenant SaaS noti citati via ``include:`` nel record SPF."""
    lower = spf_record.lower()
    return [label for pattern, label in _KNOWN_SAAS_INCLUDES.items() if pattern in lower]


class EmailSecurityConnector(BaseConnector):
    spec = _SPEC

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        target = (context.target or "").strip().rstrip(".").lower()
        if not target:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=_t("email_security.empty_target", context.lang))

        spf_raw = _dig(target, "TXT", context.timeout)
        dmarc_raw = _dig(f"_dmarc.{target}", "TXT", context.timeout)
        mta_sts_raw = _dig(f"_mta-sts.{target}", "TXT", context.timeout)
        bimi_raw = _dig(f"default._bimi.{target}", "TXT", context.timeout)

        # dig non installato / irraggiungibile per ogni query: non possiamo
        # dire nulla sulla postura, quindi errore esplicito invece di
        # inventare finding di "tutto mancante".
        if spf_raw is None and dmarc_raw is None and mta_sts_raw is None:
            return ConnectorResult(connector=self.spec.name, status="error",
                                   error=_t("email_security.dig_unavailable", context.lang))

        findings: list[Finding] = []

        # ------------------------------------------------------------ SPF --
        spf_records = _clean_txt(spf_raw or [])
        spf = find_spf_record(spf_records)
        spf_evidence = [Evidence(
            url=f"https://dns.google/query?name={target}&rr_type=TXT", title="DNS TXT")]
        if not spf:
            findings.append(Finding(
                kind="spf_missing", value=target,
                confidence=0.95, source_reliability="A", info_credibility=1,
                evidence=spf_evidence, severity="medium",
                notes=_t("email_security.spf_missing", context.lang, domain=target),
            ))
        else:
            qualifier = parse_spf_all_qualifier(spf)
            if qualifier == "-":
                findings.append(Finding(
                    kind="spf_hardfail", value=spf,
                    confidence=0.95, source_reliability="A", info_credibility=1,
                    evidence=spf_evidence, severity="info",
                    notes=_t("email_security.spf_hardfail", context.lang, domain=target),
                ))
            elif qualifier == "~":
                findings.append(Finding(
                    kind="spf_softfail", value=spf,
                    confidence=0.95, source_reliability="A", info_credibility=1,
                    evidence=spf_evidence, severity="low",
                    notes=_t("email_security.spf_softfail", context.lang, domain=target),
                ))
            else:
                # '?all', 'all' (+) o nessun meccanismo 'all': permissivo.
                findings.append(Finding(
                    kind="spf_permissive", value=spf,
                    confidence=0.9, source_reliability="A", info_credibility=1,
                    evidence=spf_evidence, severity="medium",
                    notes=_t("email_security.spf_permissive", context.lang, domain=target),
                ))
            for saas in detect_saas_from_spf(spf):
                findings.append(Finding(
                    kind="saas_tenant_inferred", value=saas,
                    confidence=0.7, source_reliability="B", info_credibility=2,
                    evidence=spf_evidence, severity="info",
                    notes=_t("email_security.saas_tenant", context.lang, domain=target, provider=saas),
                ))

        # --------------------------------------------------------- DMARC --
        dmarc_records = _clean_txt(dmarc_raw or [])
        dmarc = find_dmarc_record(dmarc_records)
        dmarc_evidence = [Evidence(
            url=f"https://dns.google/query?name=_dmarc.{target}&rr_type=TXT", title="DNS TXT")]
        if not dmarc:
            findings.append(Finding(
                kind="dmarc_missing", value=target,
                confidence=0.95, source_reliability="A", info_credibility=1,
                evidence=dmarc_evidence, severity="medium",
                notes=_t("email_security.dmarc_missing", context.lang, domain=target),
            ))
        else:
            policy = (parse_dmarc_tag(dmarc, "p") or "").lower()
            pct = parse_dmarc_tag(dmarc, "pct")
            pct_note = (_t("email_security.dmarc_pct_note", context.lang, pct=pct)
                        if pct and pct.strip() != "100" else "")
            if policy == "none":
                findings.append(Finding(
                    kind="dmarc_policy_none", value=dmarc,
                    confidence=0.95, source_reliability="A", info_credibility=1,
                    evidence=dmarc_evidence, severity="medium",
                    notes=_t("email_security.dmarc_none", context.lang, domain=target) + pct_note,
                ))
            elif policy == "quarantine":
                findings.append(Finding(
                    kind="dmarc_policy_quarantine", value=dmarc,
                    confidence=0.9, source_reliability="A", info_credibility=1,
                    evidence=dmarc_evidence, severity="low",
                    notes=_t("email_security.dmarc_quarantine", context.lang, domain=target) + pct_note,
                ))
            elif policy == "reject":
                findings.append(Finding(
                    kind="dmarc_policy_reject", value=dmarc,
                    confidence=0.95, source_reliability="A", info_credibility=1,
                    evidence=dmarc_evidence, severity="info",
                    notes=_t("email_security.dmarc_reject", context.lang, domain=target) + pct_note,
                ))
            # policy assente/malformata (p= non parsabile): non inventiamo
            # un finding negativo su un valore che non sappiamo interpretare.

        # ------------------------------------------------------- MTA-STS --
        mta_sts_records = _clean_txt(mta_sts_raw or [])
        mta_sts_present = any(r.lower().startswith("v=stsv1") for r in mta_sts_records)
        if not mta_sts_present:
            findings.append(Finding(
                kind="mta_sts_missing", value=target,
                confidence=0.85, source_reliability="A", info_credibility=1,
                evidence=[Evidence(
                    url=f"https://dns.google/query?name=_mta-sts.{target}&rr_type=TXT",
                    title="DNS TXT")],
                severity="low",
                notes=_t("email_security.mta_sts_missing", context.lang, domain=target),
            ))

        # ------------------------------------------------------- DNSSEC --
        dnssec_output = _dig_dnssec_soa(target, context.timeout)
        if dnssec_output is not None and "RRSIG" not in dnssec_output:
            findings.append(Finding(
                kind="dnssec_not_enabled", value=target,
                confidence=0.85, source_reliability="A", info_credibility=1,
                evidence=[Evidence(
                    url=f"https://dns.google/query?name={target}&rr_type=SOA",
                    title="DNS SOA")],
                severity="low",
                notes=_t("email_security.dnssec_not_enabled", context.lang, domain=target),
            ))

        # ------------------------------------------------ BIMI (opzionale) --
        bimi_records = _clean_txt(bimi_raw or [])
        bimi_present = any(r.lower().startswith("v=bimi1") for r in bimi_records)
        if not bimi_present:
            findings.append(Finding(
                kind="bimi_absent", value=target,
                confidence=0.6, source_reliability="A", info_credibility=1,
                evidence=[Evidence(
                    url=f"https://dns.google/query?name=default._bimi.{target}&rr_type=TXT",
                    title="DNS TXT")],
                severity="info",
                notes=_t("email_security.bimi_absent", context.lang, domain=target),
            ))

        return ConnectorResult(
            connector=self.spec.name, status="ok", findings=findings,
            raw={"spf": spf_records, "dmarc": dmarc_records,
                 "mta_sts": mta_sts_records, "bimi": bimi_records},
        )

    def health_check(self) -> bool:
        return shutil.which("dig") is not None
