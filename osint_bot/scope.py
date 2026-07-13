"""Scope enforcement — per-case allowlist for Red Team / active modules.

The Red Team module must only touch assets the user has explicitly
authorised. We model the allowlist as a flat set of `ScopeEntry` records
attached to a case. An entry is one of:

  * exact domain ("example.com")
  * domain wildcard ("*.example.com" — apex and subdomains)
  * IPv4 / IPv6 address
  * CIDR ("10.0.0.0/24")
  * URL prefix ("https://example.com/api/")
  * handle ("@alice")

`in_scope(target, allowlist)` returns a `ScopeDecision` with:
  * allowed: bool
  * matched_entry: ScopeEntry or None
  * rationale: short Italian explanation

Out-of-scope attempts must be appended to the audit log by the caller using
`audit_scope_attempt()`.
"""
from __future__ import annotations

import ipaddress
import re
import urllib.parse
from dataclasses import asdict, dataclass, field

from .target_classifier import (
    T_CIDR,
    T_HANDLE,
    T_IP,
    T_URL,
    TargetSpec,
)

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

ENTRY_DOMAIN   = "domain"
ENTRY_WILDCARD = "wildcard_domain"
ENTRY_IP       = "ip"
ENTRY_CIDR     = "cidr"
ENTRY_URL      = "url_prefix"
ENTRY_HANDLE   = "handle"


@dataclass(frozen=True)
class ScopeEntry:
    kind: str          # ENTRY_*
    value: str         # canonical value
    note: str = ""     # human comment (RoE reference, asset owner, …)
    added_by: str = "" # actor who added it
    added_at: str = "" # ISO8601 UTC


@dataclass
class ScopeDecision:
    allowed: bool
    rationale: str
    matched_entry: ScopeEntry | None = None

    def to_dict(self) -> dict:
        d = {"allowed": self.allowed, "rationale": self.rationale}
        if self.matched_entry is not None:
            d["matched_entry"] = asdict(self.matched_entry)
        return d


@dataclass
class CaseScope:
    """Aggregator for one case's allowlist."""
    case_id: str
    entries: list[ScopeEntry] = field(default_factory=list)

    def add(self, entry: ScopeEntry) -> None:
        if entry not in self.entries:
            self.entries.append(entry)

    def to_dict(self) -> dict:
        return {"case_id": self.case_id, "entries": [asdict(e) for e in self.entries]}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_entry(raw: str, *, note: str = "", added_by: str = "", added_at: str = "") -> ScopeEntry | None:
    """Parse a free-form user input into a ScopeEntry."""
    raw = (raw or "").strip()
    if not raw:
        return None
    # IPv4/v6 / CIDR
    if "/" in raw:
        try:
            net = ipaddress.ip_network(raw, strict=False)
            return ScopeEntry(kind=ENTRY_CIDR, value=str(net),
                              note=note, added_by=added_by, added_at=added_at)
        except ValueError:
            pass
    try:
        ip = ipaddress.ip_address(raw)
        return ScopeEntry(kind=ENTRY_IP, value=str(ip),
                          note=note, added_by=added_by, added_at=added_at)
    except ValueError:
        pass
    # URL
    if raw.startswith(("http://", "https://")):
        try:
            parsed = urllib.parse.urlparse(raw)
            if parsed.scheme and parsed.netloc:
                # Normalize: lowercase host, ensure trailing slash on path.
                path = parsed.path or "/"
                if not path.endswith("/"):
                    path = path + "/"
                value = urllib.parse.urlunparse((
                    parsed.scheme.lower(),
                    (parsed.hostname or "").lower() + (f":{parsed.port}" if parsed.port else ""),
                    path, "", parsed.query, "",
                ))
                return ScopeEntry(kind=ENTRY_URL, value=value,
                                  note=note, added_by=added_by, added_at=added_at)
        except ValueError:
            pass
    # Handle
    if raw.startswith("@"):
        return ScopeEntry(kind=ENTRY_HANDLE, value=raw[1:].lower(),
                          note=note, added_by=added_by, added_at=added_at)
    # Wildcard domain
    if raw.startswith("*."):
        host = raw[2:].lower().rstrip(".")
        if "." in host:
            return ScopeEntry(kind=ENTRY_WILDCARD, value=host,
                              note=note, added_by=added_by, added_at=added_at)
        return None
    # Plain domain
    if _is_domainish(raw):
        return ScopeEntry(kind=ENTRY_DOMAIN, value=raw.lower().rstrip("."),
                          note=note, added_by=added_by, added_at=added_at)
    return None


def in_scope(target: TargetSpec, scope: CaseScope) -> ScopeDecision:
    """Decide whether `target` falls within the case's allowlist."""
    if not scope.entries:
        return ScopeDecision(
            allowed=False,
            rationale="Scope vuoto: aggiungi almeno un asset autorizzato al caso.",
        )

    for entry in scope.entries:
        if _matches(target, entry):
            return ScopeDecision(
                allowed=True,
                rationale=f"In scope: regola {entry.kind!r} = {entry.value!r}.",
                matched_entry=entry,
            )

    return ScopeDecision(
        allowed=False,
        rationale=(
            f"Target {target.value!r} ({target.type}) non trovato nello scope del caso "
            f"({len(scope.entries)} regole verificate)."
        ),
    )


def assert_in_scope(target: TargetSpec, scope: CaseScope) -> None:
    """Raise `OutOfScopeError` when not in scope."""
    decision = in_scope(target, scope)
    if not decision.allowed:
        raise OutOfScopeError(decision.rationale)


class OutOfScopeError(Exception):
    """Raised by assert_in_scope when target is not authorised."""


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _matches(target: TargetSpec, entry: ScopeEntry) -> bool:
    tval = (target.value or target.raw or "").lower().rstrip(".")
    apex = ""
    if target.attributes:
        apex = (target.attributes.get("apex") or "").lower()

    if entry.kind == ENTRY_DOMAIN:
        return tval == entry.value or apex == entry.value
    if entry.kind == ENTRY_WILDCARD:
        if tval == entry.value or apex == entry.value:
            return True
        return tval.endswith("." + entry.value)
    if entry.kind == ENTRY_IP:
        return target.type == T_IP and tval == entry.value
    if entry.kind == ENTRY_CIDR:
        try:
            net = ipaddress.ip_network(entry.value, strict=False)
        except ValueError:
            return False
        if target.type == T_IP:
            try:
                ip = ipaddress.ip_address(tval)
            except ValueError:
                return False
            return ip in net
        if target.type == T_CIDR:
            try:
                sub = ipaddress.ip_network(tval, strict=False)
            except ValueError:
                return False
            return sub.subnet_of(net)
        return False
    if entry.kind == ENTRY_URL:
        if target.type != T_URL:
            return False
        return tval.startswith(entry.value.rstrip("/"))
    if entry.kind == ENTRY_HANDLE:
        return target.type == T_HANDLE and tval == entry.value
    return False


def _is_domainish(raw: str) -> bool:
    return bool(re.fullmatch(r"(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\.?", raw))


# ---------------------------------------------------------------------------
# Audit helper (Italian event names)
# ---------------------------------------------------------------------------

def audit_scope_attempt(
    *, actor: str, case_id: str, target: TargetSpec, decision: ScopeDecision,
) -> dict:
    """Build a dict ready to be appended via storage.append_audit_event().

    Caller is responsible for actually writing it; we keep this module pure.
    """
    return {
        "actor": actor,
        "event": "scope_allowed" if decision.allowed else "scope_denied",
        "payload": {
            "case_id": case_id,
            "target": target.value or target.raw,
            "target_type": target.type,
            "rationale": decision.rationale,
            "matched_entry": (
                asdict(decision.matched_entry) if decision.matched_entry else None
            ),
        },
    }
