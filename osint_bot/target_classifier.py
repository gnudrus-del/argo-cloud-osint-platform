"""Target classification — robust per-type detector for OSINT pipeline.

Replaces the fragile `infer_target_type()` heuristic with a real classifier
that:

  * Validates the candidate against the proper format (ipaddress, email split,
    BTC/ETH checksums-ish, E.164 phone, domain shape).
  * Normalizes the value (lowercase host, strip @ from handle, E.164 phone).
  * Returns a confidence score and explains the decision.
  * Picks the module set to activate downstream.

Public API:
    classify_target(raw, *, hint=None) -> TargetSpec
    suggest_modules(spec) -> list[str]
    suggest_external_tools(spec, *, authorized, allow_active) -> list[str]

The classifier is deterministic and pure — easy to unit-test. The
orchestrator can call it both at plan time (preview) and at run time
(execution), getting the same answer.
"""
from __future__ import annotations

import ipaddress
import re
import urllib.parse
from collections.abc import Iterable
from dataclasses import dataclass, field

from .patterns import (
    BTC_RE,
    DOMAIN_RE,
    EMAIL_RE,
    ETH_RE,
    HANDLE_RE,
    IP_RE,
    PHONE_LOOSE_RE,
    URL_RE,
)

# Canonical target types — single source of truth.
T_DOMAIN     = "domain"
T_SUBDOMAIN  = "subdomain"
T_IP         = "ip"
T_CIDR       = "cidr"
T_URL        = "url"
T_EMAIL      = "email"
T_PHONE      = "phone"
T_HANDLE     = "handle"        # social handle without @
T_PERSON     = "person"
T_COMPANY    = "company"
T_ORG        = "org"
T_BTC        = "crypto_btc"
T_ETH        = "crypto_eth"
T_CRYPTO     = "crypto"        # generic crypto bucket
T_MEDIA      = "media"
T_FILE_HASH  = "file_hash"
T_UNKNOWN    = "unknown"

VALID_TYPES = {
    T_DOMAIN, T_SUBDOMAIN, T_IP, T_CIDR, T_URL, T_EMAIL, T_PHONE, T_HANDLE,
    T_PERSON, T_COMPANY, T_ORG, T_BTC, T_ETH, T_CRYPTO, T_MEDIA, T_FILE_HASH,
    T_UNKNOWN,
}


@dataclass(frozen=True)
class TargetSpec:
    """Result of classify_target().

    Attributes:
        type: one of the T_* constants.
        value: normalized canonical value (lowercase host, E.164 phone, …).
        raw: the original input string for traceability.
        confidence: 0.0..1.0 — how sure we are about the type.
        rationale: short Italian explanation of the decision.
        attributes: extra fields per type (e.g. domain → {apex, tld};
                    email → {local, domain}; phone → {country, national}).
        warnings: non-fatal issues to surface in the report.
    """
    type: str
    value: str
    raw: str
    confidence: float
    rationale: str
    attributes: dict = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


# Module → activation map. Each target type lists the OSINT modules that
# make sense to activate downstream.
_MODULE_BY_TYPE: dict[str, tuple[str, ...]] = {
    T_DOMAIN:    ("company_domain", "opsec", "geo", "media", "contacts"),
    T_SUBDOMAIN: ("company_domain", "opsec", "contacts"),
    T_IP:        ("company_domain", "opsec", "geo"),
    T_CIDR:      ("company_domain", "opsec"),
    T_URL:       ("company_domain", "opsec", "media", "contacts"),
    T_EMAIL:     ("phone_email", "socmint", "opsec", "contacts"),
    T_PHONE:     ("phone_email", "socmint", "opsec", "contacts"),
    T_HANDLE:    ("socmint", "phone_email"),
    T_PERSON:    ("socmint", "phone_email", "humint"),
    T_COMPANY:   ("company_domain", "opsec", "geo", "contacts"),
    T_ORG:       ("company_domain", "opsec", "geo", "contacts"),
    T_BTC:       ("crypto",),
    T_ETH:       ("crypto",),
    T_CRYPTO:    ("crypto",),
    T_MEDIA:     ("media", "geo"),
    T_FILE_HASH: ("opsec",),
    T_UNKNOWN:   ("company_domain", "opsec"),
}

# Tools that are reasonable to run for each target type. The orchestrator
# further filters by authorization/active-scan flags.
_TOOLS_BY_TYPE: dict[str, tuple[str, ...]] = {
    T_DOMAIN: (
        "theharvester", "amass", "subfinder", "waybackurls", "gau",
        "dnsx", "dnstwist", "whatweb", "httpx", "katana",
        "gospider", "hakrawler", "metagoofil", "wafw00f", "testssl",
        "spiderfoot", "recon_ng",
    ),
    T_SUBDOMAIN: (
        "httpx", "whatweb", "wafw00f", "katana",
    ),
    T_IP: (
        "spiderfoot", "whatweb",
    ),
    T_URL: (
        "httpx", "whatweb", "katana", "hakrawler", "gospider",
    ),
    T_EMAIL: (
        "holehe", "socialscan", "h8mail", "ghunt", "mosint",
    ),
    T_PHONE: (
        "phoneinfoga", "phunter",
    ),
    T_HANDLE: (
        "sherlock", "maigret", "socialscan", "social_analyzer", "toutatis",
        "osintgram",
    ),
    T_PERSON: (
        "sherlock", "maigret", "spiderfoot",
    ),
    T_COMPANY: (
        "theharvester", "spiderfoot", "recon_ng", "dnstwist", "metagoofil",
    ),
    T_ORG: (
        "theharvester", "spiderfoot", "recon_ng",
    ),
    T_MEDIA: (
        "exiftool", "ffprobe",
    ),
}

# Active-only tools (network scan or invasive enumeration) — gated.
_ACTIVE_TOOLS = {
    "nmap", "naabu", "nuclei", "masscan", "nikto", "wpscan",
    "feroxbuster", "ffuf", "dalfox", "dirsearch", "arjun",
    "gitdumper", "enum4linux", "smbmap", "snmpwalk", "subjack",
    "cloud_enum", "trufflehog", "gitleaks",
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def classify_target(raw: str, *, hint: str | None = None) -> TargetSpec:
    """Best-effort classification.

    Args:
        raw: user-provided text. Whitespace-trimmed before classification.
        hint: optional explicit type from the UI ("domain", "email", …). When
              provided AND coherent with the value, takes precedence over
              auto-detection. When incoherent, we still trust hint but raise
              a warning.
    """
    raw = (raw or "").strip()
    if not raw:
        return TargetSpec(
            type=T_UNKNOWN, value="", raw="", confidence=0.0,
            rationale="Stringa vuota: nessuna classificazione possibile.",
        )
    # Normalize a single trailing dot on FQDNs ("example.com." → "example.com").
    # Only strip when the result still looks like a domain (has a dot).
    if raw.endswith(".") and "." in raw[:-1]:
        raw = raw.rstrip(".")

    # If the UI provides an explicit hint that maps to a known type, try it
    # first; if validation matches, trust it. Otherwise fall back to auto.
    if hint and hint in VALID_TYPES and hint not in {T_UNKNOWN}:
        forced = _classify_with_hint(raw, hint)
        if forced is not None:
            return forced

    # Auto-detection order — strict patterns first.
    detectors = (
        _try_url,
        _try_email,
        _try_cidr,
        _try_ip,
        _try_eth,
        _try_btc,
        _try_phone,
        _try_file_hash,   # before _try_handle: MD5 (32 hex) would match handle shape
        _try_handle,
        _try_domain,
    )
    for detect in detectors:
        spec = detect(raw)
        if spec is not None:
            return spec

    # Fallback: treat as a free-text company/person identifier.
    is_personlike = bool(re.fullmatch(r"[A-Za-zÀ-ÿ' \-\.]{3,80}", raw))
    if is_personlike and " " in raw:
        return TargetSpec(
            type=T_PERSON, value=raw, raw=raw, confidence=0.45,
            rationale="Stringa libera con spazi → possibile nome di persona.",
            warnings=["Classificazione inferita: verifica manuale consigliata."],
        )
    return TargetSpec(
        type=T_COMPANY, value=raw, raw=raw, confidence=0.4,
        rationale="Stringa libera senza pattern noti → trattata come azienda/identificativo.",
        warnings=["Tipo non determinato univocamente; downstream userà i moduli generici."],
    )


def suggest_modules(spec: TargetSpec) -> list[str]:
    """Return the canonical module ids to activate for a target."""
    return list(_MODULE_BY_TYPE.get(spec.type, _MODULE_BY_TYPE[T_UNKNOWN]))


def suggest_external_tools(
    spec: TargetSpec, *, authorized: bool, allow_active: bool,
    extra: Iterable[str] = (),
) -> list[str]:
    """Return the external CLI tools to invoke for a target.

    Authorization gates:
      * authorized=False  → only fully-passive tools (no PII enumeration,
                            no active probes).
      * allow_active=False→ no scanning/fuzzing/active enumeration tools.

    The orchestrator can pass extra tools the user explicitly requested.
    """
    base = list(_TOOLS_BY_TYPE.get(spec.type, ()))
    base.extend(extra)

    # PII-targeted enumeration tools require authorization
    pii_tools = {
        "sherlock", "maigret", "socialscan", "social_analyzer",
        "holehe", "h8mail", "phoneinfoga", "phunter",
        "ghunt", "toutatis", "osintgram", "mosint",
    }
    if not authorized:
        base = [t for t in base if t not in pii_tools]

    if not allow_active:
        base = [t for t in base if t not in _ACTIVE_TOOLS]

    # Deduplicate preserving order
    seen: set[str] = set()
    out = []
    for t in base:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out


# ---------------------------------------------------------------------------
# Per-type detectors — each returns TargetSpec or None.
# ---------------------------------------------------------------------------

def _classify_with_hint(raw: str, hint: str) -> TargetSpec | None:
    """Validate the value against the user's stated type."""
    mapping = {
        T_DOMAIN: _try_domain,
        T_IP: _try_ip,
        T_CIDR: _try_cidr,
        T_URL: _try_url,
        T_EMAIL: _try_email,
        T_PHONE: _try_phone,
        T_HANDLE: _try_handle,
        T_BTC: _try_btc,
        T_ETH: _try_eth,
        T_FILE_HASH: _try_file_hash,
    }
    fn = mapping.get(hint)
    if not fn:
        # Hints with no validator (person, company, org, media, crypto, …):
        # accept the raw value at face value with mid-low confidence.
        return TargetSpec(
            type=hint, value=raw, raw=raw, confidence=0.6,
            rationale=f"Tipo dichiarato dall'utente ({hint}); nessuna validazione strutturale disponibile.",
        )
    spec = fn(raw)
    if spec is None:
        return TargetSpec(
            type=hint, value=raw, raw=raw, confidence=0.35,
            rationale=f"Tipo dichiarato dall'utente come {hint} ma il valore non passa la validazione.",
            warnings=[f"Valore non valido per il tipo dichiarato {hint}."],
        )
    return spec


def _try_url(raw: str) -> TargetSpec | None:
    if not URL_RE.match(raw):
        return None
    try:
        parsed = urllib.parse.urlparse(raw)
    except ValueError:
        return None
    if not parsed.scheme or not parsed.netloc:
        return None
    host = parsed.hostname or ""
    return TargetSpec(
        type=T_URL, value=raw, raw=raw, confidence=0.98,
        rationale=f"URL valido con schema {parsed.scheme!r} e host {host!r}.",
        attributes={"scheme": parsed.scheme, "host": host, "path": parsed.path or "/"},
    )


def _try_email(raw: str) -> TargetSpec | None:
    if not EMAIL_RE.fullmatch(raw):
        return None
    local, _, domain = raw.partition("@")
    return TargetSpec(
        type=T_EMAIL, value=raw.lower(), raw=raw, confidence=0.95,
        rationale="Formato email valido (local@dominio).",
        attributes={"local": local.lower(), "domain": domain.lower()},
    )


def _try_cidr(raw: str) -> TargetSpec | None:
    if "/" not in raw:
        return None
    try:
        net = ipaddress.ip_network(raw, strict=False)
    except ValueError:
        return None
    return TargetSpec(
        type=T_CIDR, value=str(net), raw=raw, confidence=0.95,
        rationale=f"CIDR valido: {net.num_addresses} indirizzi nel range.",
        attributes={"version": net.version, "num_addresses": net.num_addresses},
    )


def _try_ip(raw: str) -> TargetSpec | None:
    if not IP_RE.fullmatch(raw):
        return None
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        return None
    is_private = addr.is_private
    warnings: list[str] = []
    if is_private:
        warnings.append("Indirizzo IP privato: niente lookup pubblici diretti.")
    return TargetSpec(
        type=T_IP, value=str(addr), raw=raw, confidence=0.95,
        rationale=f"Indirizzo IPv{addr.version} valido.",
        attributes={"version": addr.version, "private": is_private},
        warnings=warnings,
    )


def _try_eth(raw: str) -> TargetSpec | None:
    if not ETH_RE.fullmatch(raw):
        return None
    return TargetSpec(
        type=T_ETH, value=raw.lower(), raw=raw, confidence=0.95,
        rationale="Formato address EVM (0x + 40 hex). Checksum non verificato.",
        attributes={"chain_family": "evm"},
        warnings=["Checksum EIP-55 non verificato: vale per qualunque chain EVM."],
    )


def _try_btc(raw: str) -> TargetSpec | None:
    if not BTC_RE.fullmatch(raw):
        return None
    is_bech32 = raw.lower().startswith("bc1")
    return TargetSpec(
        type=T_BTC, value=raw, raw=raw, confidence=0.9,
        rationale="Formato address Bitcoin (P2PKH/P2SH/bech32).",
        attributes={"bech32": is_bech32},
    )


def _try_phone(raw: str) -> TargetSpec | None:
    """Phone detection — requires E.164-ish or strong digit pattern.

    Returns confidence 0.85 for full E.164 (+CC...), 0.6 for ambiguous.
    """
    digits = re.sub(r"\D+", "", raw)
    if len(digits) < 7 or len(digits) > 15:
        return None
    if raw.startswith("+") and PHONE_LOOSE_RE.fullmatch(raw):
        e164 = "+" + digits
        return TargetSpec(
            type=T_PHONE, value=e164, raw=raw, confidence=0.85,
            rationale=f"Formato E.164 esplicito (+, {len(digits)} digits).",
            attributes={"e164": e164, "country_unknown": True},
        )
    # Without explicit +, only accept if it's clearly a phone shape: brackets,
    # spaces, dashes, country prefix. Reject bare digit strings.
    has_separators = bool(re.search(r"[\s.\-()]", raw))
    has_country = bool(re.match(r"^\s*(00|\+)\d{1,3}", raw))
    if not (has_separators or has_country):
        return None
    return TargetSpec(
        type=T_PHONE, value=raw.strip(), raw=raw, confidence=0.6,
        rationale="Sembra un numero di telefono ma manca il prefisso internazionale esplicito.",
        attributes={"e164": None},
        warnings=["Normalizza a E.164 (+prefisso paese) per ricerche più precise."],
    )


def _try_handle(raw: str) -> TargetSpec | None:
    # Accept "@handle" or bare "handle" if it matches handle shape and is
    # NOT a valid domain (handle takes precedence only when starts with @).
    if raw.startswith("@"):
        m = HANDLE_RE.match(raw)
        if m:
            return TargetSpec(
                type=T_HANDLE, value=m.group(1), raw=raw, confidence=0.9,
                rationale="Handle social esplicito (prefix @).",
                attributes={"display": raw},
            )
        return None
    # Bare handle-like string: must NOT contain '.' (would be a domain).
    if "." in raw:
        return None
    if re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", raw):
        # Too ambiguous on its own → return with low confidence.
        return TargetSpec(
            type=T_HANDLE, value=raw, raw=raw, confidence=0.55,
            rationale="Stringa compatibile con handle social (senza @).",
            warnings=["Ambiguo: potrebbe essere anche un username generico."],
        )
    return None


def _try_file_hash(raw: str) -> TargetSpec | None:
    # MD5 (32 hex), SHA-1 (40), SHA-256 (64), SHA-512 (128)
    if not re.fullmatch(r"[a-fA-F0-9]+", raw):
        return None
    n = len(raw)
    alg = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}.get(n)
    if not alg:
        return None
    return TargetSpec(
        type=T_FILE_HASH, value=raw.lower(), raw=raw, confidence=0.9,
        rationale=f"Hash file di {n} caratteri esadecimali ({alg.upper()}).",
        attributes={"algorithm": alg},
    )


def _try_domain(raw: str) -> TargetSpec | None:
    # A domain is dotted labels, must include at least one dot, TLD ≥ 2 letters.
    if not DOMAIN_RE.fullmatch(raw):
        return None
    host = raw.lower().rstrip(".")
    labels = host.split(".")
    if len(labels) < 2:
        return None
    apex = ".".join(labels[-2:])
    is_sub = len(labels) > 2
    return TargetSpec(
        type=T_SUBDOMAIN if is_sub else T_DOMAIN,
        value=host, raw=raw, confidence=0.85,
        rationale=(
            f"Sottodominio di {apex}." if is_sub
            else "Dominio apex (due label)."
        ),
        attributes={"apex": apex, "tld": labels[-1], "is_subdomain": is_sub},
    )
