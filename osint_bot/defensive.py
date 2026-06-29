"""Pillar 3 — Defensive OSINT.

Modules for continuous external monitoring, brand/executive protection, threat
intelligence enrichment, and takedown workflow management.

All functions are pure (no I/O) except where storage is explicitly accepted.
Network-free: the enrichment layer uses connectors from Pillar 1 when available.

Public API
----------
  monitor_surface(domain, baseline_findings, current_findings)
      Diff-based EASM monitoring.  Returns MonitorReport with new exposures,
      resolved exposures, and risk delta.

  assess_brand_impersonation(brand_name, observed_domains, observed_handles)
      Identifies typosquats, lookalike handles, and impersonation signals.

  enrich_ioc(ioc_value, ioc_type)
      Classifies and enriches an IOC (IP, domain, hash, URL) with context and
      ATT&CK TTP references for threat hunting.

  TakedownCase
      Dataclass for managing a content/abuse takedown workflow (evidence, status,
      contacts, timeline).  Persisted via storage when storage is provided.

  score_digital_footprint(findings)
      Heuristic scoring of an entity's defensive digital footprint (0–100,
      lower = less exposed).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .models import Evidence, Finding
from .red_team import ScanDiff, diff_scan_findings


# ---------------------------------------------------------------------------
# Pillar 3.1 — Continuous EASM monitoring
# ---------------------------------------------------------------------------

@dataclass
class MonitorReport:
    domain: str
    checked_at: str
    new_exposures: list[Finding] = field(default_factory=list)
    resolved_exposures: list[Finding] = field(default_factory=list)
    unchanged: list[Finding] = field(default_factory=list)
    risk_delta: int = 0   # positive = surface increased, negative = reduced

    def summary(self) -> str:
        parts = []
        if self.new_exposures:
            parts.append(f"+{len(self.new_exposures)} nuove esposizioni")
        if self.resolved_exposures:
            parts.append(f"-{len(self.resolved_exposures)} risolte")
        if not parts:
            return "Nessuna variazione rilevata."
        return "; ".join(parts) + f" (delta rischio: {self.risk_delta:+d})"


_SEVERITY_WEIGHT = {"critical": 10, "high": 5, "medium": 2, "low": 1, "info": 0, "": 1}


def _finding_risk(f: Finding) -> int:
    return _SEVERITY_WEIGHT.get(f.severity, 1)


def monitor_surface(
    domain: str,
    baseline_findings: list[Finding],
    current_findings: list[Finding],
) -> MonitorReport:
    """Diff two EASM scans and produce a monitor report.

    New high/critical findings raise the risk delta; resolved ones lower it.
    """
    diff: ScanDiff = diff_scan_findings(baseline_findings, current_findings)
    risk_delta = sum(_finding_risk(f) for f in diff.new_findings) - \
                 sum(_finding_risk(f) for f in diff.removed_findings)
    return MonitorReport(
        domain=domain,
        checked_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        new_exposures=diff.new_findings,
        resolved_exposures=diff.removed_findings,
        unchanged=diff.unchanged_findings,
        risk_delta=risk_delta,
    )


# ---------------------------------------------------------------------------
# Pillar 3.2 — Brand / executive impersonation detection
# ---------------------------------------------------------------------------

# Common typosquat transformation types
_TYPO_TRANSFORMATIONS = [
    ("homoglyph", re.compile(r"[0oO1lI]")),        # character substitution signal
    ("hyphen_insert", re.compile(r"[a-z]{4,}")),    # long words often hyphen-split
]


@dataclass
class ImpersonationSignal:
    kind: str             # typosquat | lookalike_handle | brand_mention_context
    value: str            # domain or handle
    target_brand: str
    similarity: float     # 0.0 – 1.0
    technique: str        # e.g. "hyphen_insert", "tld_swap", "keyword_prefix"
    notes: str = ""

    def to_finding(self) -> Finding:
        sev = "high" if self.similarity > 0.80 else "medium"
        return Finding(
            kind=f"brand_{self.kind}",
            value=self.value,
            confidence=self.similarity,
            severity=sev,
            attck_ttps=["T1583.001", "T1566"],  # Acquire Infrastructure + Phishing
            remediation=(
                "Registrare il dominio difensivamente e/o procedere con takedown UDRP / "
                "abuse report al registrar. Monitorare con Google Alerts."
            ),
            notes=(
                f"Potenziale impersonificazione del brand '{self.target_brand}': "
                f"{self.technique} — {self.notes}"
            ),
        )


def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        a, b = b, a
    row = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        new_row = [i + 1]
        for j, cb in enumerate(b):
            new_row.append(min(
                row[j + 1] + 1,         # delete
                new_row[j] + 1,         # insert
                row[j] + (ca != cb),    # replace
            ))
        row = new_row
    return row[-1]


def _similarity(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    dist = _levenshtein(a.lower(), b.lower())
    return 1.0 - dist / max(len(a), len(b))


_COMMON_TLDS = (".com", ".net", ".org", ".io", ".co", ".info", ".biz", ".online",
                ".site", ".xyz", ".app", ".dev")
_SUSPICIOUS_PREFIXES = ("my-", "the-", "get-", "login-", "secure-", "account-",
                        "signin-", "verify-", "support-", "help-")
_SUSPICIOUS_SUFFIXES = ("-login", "-secure", "-account", "-verify", "-support",
                        "-official", "-real", "-online", "-app", "-portal")


def assess_brand_impersonation(
    brand_name: str,
    observed_domains: list[str],
    observed_handles: list[str],
) -> list[ImpersonationSignal]:
    """Identify impersonation signals from observed domains and social handles.

    Scores each input against brand_name using Levenshtein similarity and
    pattern heuristics.  Returns signals sorted by similarity descending.
    """
    brand_core = brand_name.lower().replace(" ", "").replace("-", "").replace("_", "")
    signals: list[ImpersonationSignal] = []

    for domain in observed_domains:
        d_lower = domain.lower()
        # Strip TLD for name comparison
        core = d_lower
        for tld in sorted(_COMMON_TLDS, key=len, reverse=True):
            if core.endswith(tld):
                core = core[: -len(tld)]
                break
        core = core.strip("-.")

        # TLD swap: same core different TLD — handle first to avoid falling
        # through to the sim >= 0.70 && core != brand_core guard below.
        if core == brand_core and d_lower != f"{brand_core}.com":
            signals.append(ImpersonationSignal(
                kind="typosquat",
                value=domain,
                target_brand=brand_name,
                similarity=0.95,
                technique="tld_swap",
                notes=f"Stesso nome brand '{brand_core}' ma TLD diverso da .com.",
            ))
            continue

        sim = _similarity(core, brand_core)
        technique = "near_match"

        # Suspicious keyword wrappers
        for pfx in _SUSPICIOUS_PREFIXES:
            pfx_stripped = pfx.rstrip("-")
            if core.startswith(pfx_stripped):
                inner = core[len(pfx_stripped):].lstrip("-")
                if _similarity(inner, brand_core) >= 0.80:
                    technique = "prefix_wrap"
                    sim = max(sim, 0.85)
                    break
        for sfx in _SUSPICIOUS_SUFFIXES:
            sfx_stripped = sfx.lstrip("-")
            if core.endswith(sfx_stripped):
                inner = core[: -len(sfx_stripped)].rstrip("-")
                if _similarity(inner, brand_core) >= 0.80:
                    technique = "suffix_wrap"
                    sim = max(sim, 0.85)
                    break

        # Homoglyph simple check
        normalized = (core.replace("0", "o").replace("1", "l").replace("3", "e")
                      .replace("@", "a").replace("5", "s"))
        if normalized == brand_core and core != brand_core:
            technique = "homoglyph"
            sim = 0.92

        if sim >= 0.70 and core != brand_core:
            signals.append(ImpersonationSignal(
                kind="typosquat",
                value=domain,
                target_brand=brand_name,
                similarity=round(sim, 2),
                technique=technique,
                notes=f"Dominio osservato sospetto: core='{core}' vs brand='{brand_core}'.",
            ))

    for handle in observed_handles:
        h_core = re.sub(r"[^a-z0-9]", "", handle.lower())
        sim = _similarity(h_core, brand_core)
        # Also catch containment (e.g. "@acme_official" → "acmeofficial" contains "acme")
        if brand_core in h_core and h_core != brand_core:
            sim = max(sim, 0.80)
        if sim >= 0.75 and h_core != brand_core:
            signals.append(ImpersonationSignal(
                kind="lookalike_handle",
                value=handle,
                target_brand=brand_name,
                similarity=round(sim, 2),
                technique="handle_similarity",
                notes=f"Handle sospetto: '{handle}' — similarità {sim:.0%} con '{brand_name}'.",
            ))

    signals.sort(key=lambda s: s.similarity, reverse=True)
    return signals


# ---------------------------------------------------------------------------
# Pillar 3.3 — IOC enrichment
# ---------------------------------------------------------------------------

_IOC_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("ipv4", re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")),
    ("ipv6", re.compile(r"^[0-9a-fA-F:]+:[0-9a-fA-F:]*$")),
    ("md5", re.compile(r"^[0-9a-fA-F]{32}$")),
    ("sha1", re.compile(r"^[0-9a-fA-F]{40}$")),
    ("sha256", re.compile(r"^[0-9a-fA-F]{64}$")),
    ("url", re.compile(r"^https?://", re.IGNORECASE)),
    ("domain", re.compile(r"^(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}$")),
    ("email", re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")),
    ("cve", re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)),
]

_IOC_ATTCK_HINTS: dict[str, list[str]] = {
    "ipv4": ["T1071", "T1219", "T1090"],            # C2, RAT, Proxy
    "ipv6": ["T1071"],
    "domain": ["T1568", "T1584.001"],               # Dynamic Resolution, Infra Compromise
    "url": ["T1566.002", "T1189"],                  # Spearphishing, Drive-by
    "md5": ["T1588.001"],                           # Obtain Capabilities: Malware
    "sha1": ["T1588.001"],
    "sha256": ["T1588.001"],
    "email": ["T1589.002", "T1566.001"],            # Phishing (email)
    "cve": ["T1190"],                               # Exploit Public-Facing Application
}


@dataclass
class IOCEnrichment:
    ioc_value: str
    ioc_type: str           # detected or provided
    attck_ttps: list[str]
    confidence: float
    hunt_queries: list[str] = field(default_factory=list)
    notes: str = ""

    def to_finding(self) -> Finding:
        return Finding(
            kind=f"ioc_{self.ioc_type}",
            value=self.ioc_value,
            confidence=self.confidence,
            severity="medium",
            attck_ttps=self.attck_ttps,
            remediation=(
                "Aggiungere l'IOC al blocklist SIEM/EDR/firewall. "
                "Cercare nei log storici (SIEM backward hunt). "
                "Verificare su VT/OTX/AbuseIPDB."
            ),
            notes=self.notes,
        )


def enrich_ioc(ioc_value: str, ioc_type: str = "auto") -> IOCEnrichment:
    """Classify and enrich an indicator of compromise.

    Parameters
    ----------
    ioc_value :
        Raw IOC string (IP, domain, hash, URL, CVE, email).
    ioc_type :
        Explicit type or ``"auto"`` to detect from the value.

    Returns
    -------
    IOCEnrichment
        Contains detected type, ATT&CK TTPs, and hunt query templates.
    """
    detected_type = ioc_type if ioc_type != "auto" else "unknown"
    if ioc_type == "auto":
        for type_name, pattern in _IOC_PATTERNS:
            if pattern.match(ioc_value.strip()):
                detected_type = type_name
                break

    ttps = _IOC_ATTCK_HINTS.get(detected_type, ["T1588"])
    confidence = 0.70 if detected_type != "unknown" else 0.40

    # Hunt query templates per type
    hunt_queries: list[str] = []
    if detected_type == "ipv4":
        hunt_queries = [
            f"network.dst_ip == \"{ioc_value}\"",
            f"dns.query CONTAINS \"{ioc_value}\"",
            f"process.network_connections ip:\"{ioc_value}\"",
        ]
    elif detected_type == "domain":
        hunt_queries = [
            f"dns.query.name == \"{ioc_value}\"",
            f"http.request.host == \"{ioc_value}\"",
            f"ssl.server_name == \"{ioc_value}\"",
        ]
    elif detected_type in ("md5", "sha1", "sha256"):
        hunt_queries = [
            f"file.hash.{detected_type} == \"{ioc_value}\"",
            f"process.pe.imphash == \"{ioc_value}\"",
        ]
    elif detected_type == "url":
        hunt_queries = [
            f"http.request.url == \"{ioc_value}\"",
            f"proxy.url STARTSWITH \"{ioc_value[:60]}\"",
        ]
    elif detected_type == "cve":
        hunt_queries = [
            f"vulnerability.id == \"{ioc_value.upper()}\"",
            f"event.type:alert AND rule.cve:\"{ioc_value.upper()}\"",
        ]

    notes = (
        f"IOC classificato come '{detected_type}'. "
        f"ATT&CK: {', '.join(ttps)}. "
        f"Cercare nei log degli ultimi 90 giorni. "
        f"Arricchire con VirusTotal / OTX / AbuseIPDB prima di bloccare."
    )

    return IOCEnrichment(
        ioc_value=ioc_value,
        ioc_type=detected_type,
        attck_ttps=ttps,
        confidence=confidence,
        hunt_queries=hunt_queries,
        notes=notes,
    )


# ---------------------------------------------------------------------------
# Pillar 3.4 — Takedown workflow
# ---------------------------------------------------------------------------

TAKEDOWN_STATUS = ("draft", "evidence_collected", "submitted", "acknowledged",
                   "resolved", "rejected", "escalated")

TAKEDOWN_CONTACTS: dict[str, dict[str, str]] = {
    "github.com": {
        "name": "GitHub Trust & Safety",
        "url": "https://support.github.com/contact/dmca",
        "email": "copyright@github.com",
        "typical_sla_days": "2–5",
    },
    "twitter.com": {
        "name": "X/Twitter Report",
        "url": "https://help.twitter.com/forms/impersonation",
        "typical_sla_days": "3–7",
    },
    "facebook.com": {
        "name": "Meta IP Report",
        "url": "https://www.facebook.com/help/contact/1758255661104383",
        "typical_sla_days": "3–14",
    },
    "cloudflare.com": {
        "name": "Cloudflare Abuse",
        "url": "https://abuse.cloudflare.com/phishing",
        "typical_sla_days": "1–3",
    },
    "google.com": {
        "name": "Google Safe Browsing Report",
        "url": "https://safebrowsing.google.com/safebrowsing/report_phish/",
        "typical_sla_days": "1–3",
    },
    "namecheap.com": {
        "name": "Namecheap Abuse",
        "email": "abuse@namecheap.com",
        "typical_sla_days": "1–5",
    },
    "godaddy.com": {
        "name": "GoDaddy Abuse",
        "email": "abuse@godaddy.com",
        "typical_sla_days": "1–3",
    },
}


@dataclass
class TakedownCase:
    id: str
    kind: str               # phishing | impersonation | content | malware | trademark
    target_url: str
    brand: str
    status: str = "draft"
    evidence_urls: list[str] = field(default_factory=list)
    evidence_hashes: dict[str, str] = field(default_factory=dict)  # url → sha256
    submitted_to: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    created_at: str = ""
    updated_at: str = ""

    def __post_init__(self) -> None:
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        if not self.created_at:
            self.created_at = now
        if not self.updated_at:
            self.updated_at = now

    def advance(self, new_status: str, note: str = "") -> None:
        if new_status not in TAKEDOWN_STATUS:
            raise ValueError(f"Status sconosciuto: {new_status}")
        self.status = new_status
        self.updated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        if note:
            self.notes.append(f"[{self.updated_at}] {note}")

    def contact_for(self, platform: str) -> dict[str, str]:
        return TAKEDOWN_CONTACTS.get(platform.lower(), {})

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "target_url": self.target_url,
            "brand": self.brand,
            "status": self.status,
            "evidence_urls": self.evidence_urls,
            "evidence_hashes": self.evidence_hashes,
            "submitted_to": self.submitted_to,
            "notes": self.notes,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


# ---------------------------------------------------------------------------
# Pillar 3.5 — Digital footprint scoring
# ---------------------------------------------------------------------------

_FOOTPRINT_KIND_SCORES: dict[str, int] = {
    # High penalty = high exposure
    "red_team_aws_access_key": 25,
    "red_team_private_key_header": 25,
    "red_team_connection_string": 20,
    "red_team_github_token": 15,
    "red_team_slack_token": 15,
    "red_team_jwt_token": 10,
    "red_team_password_in_url": 15,
    "red_team_google_api_key": 8,
    "red_team_breach_mention": 10,
    "red_team_takeover_candidate": 12,
    "red_team_exposed_path": 5,
    # Medium
    "shodan_vuln": 8,
    "shodan_open_port": 3,
    "subdomain_ct": 1,
    "whois_registrar": 0,   # neutral
}


def score_digital_footprint(findings: list[Finding]) -> dict[str, Any]:
    """Heuristic digital footprint score: 0 (fully exposed) → 100 (minimal exposure).

    Lower score = higher risk exposure.  Returns score + breakdown by category.
    """
    raw = 0
    breakdown: dict[str, int] = {}
    for f in findings:
        penalty = _FOOTPRINT_KIND_SCORES.get(f.kind, 0)
        # Severity multiplier
        sev_mult = {"critical": 3, "high": 2, "medium": 1, "low": 0.5, "info": 0}.get(
            f.severity, 1
        )
        contribution = int(penalty * sev_mult)
        if contribution:
            breakdown[f.kind] = breakdown.get(f.kind, 0) + contribution
            raw += contribution

    score = max(0, 100 - raw)
    risk_level = "critical" if score < 20 else (
        "high" if score < 45 else (
            "medium" if score < 70 else (
                "low" if score < 90 else "info"
            )
        )
    )

    return {
        "score": score,
        "risk_level": risk_level,
        "raw_penalty": raw,
        "breakdown": dict(sorted(breakdown.items(), key=lambda kv: kv[1], reverse=True)),
        "finding_count": len(findings),
    }
