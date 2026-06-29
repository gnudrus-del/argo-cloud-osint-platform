"""Contact discovery — email + phone from public sources, with anti-false-positive.

The orchestrator already harvests web pages; this module extracts contacts
from their text/links and decides which ones are *actually* associated with
the investigation target.

Key principles (Priority 9 from the engineering brief):

  * Only pull contacts from publicly visible sources (mailto:/tel: links,
    visible page text, schema.org Person/Organization JSON-LD blocks).
  * NEVER alter the value the source published: if the source masked the
    address ("a***@example.com") the masked form stays masked, with an
    `incomplete` flag and the reason.
  * Score each contact for *target association* using semantic proximity:
    domain match, host containment of target name, context-keyword density,
    label proximity in the surrounding text.
  * Classify the contact (personal / business / role / technical / commercial)
    based on the local part and surrounding labels.
  * Deduplicate by canonical key (lowercased email; E.164 phone).
  * Every record carries provenance: page URL, title, snippet, timestamp.

The module never raises. Callers pass a list of `Page` objects + the target
spec; we return a list of `Contact` records ready to be embedded in a report
or surfaced in the UI.
"""
from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from html import unescape
from typing import Iterable

from .models import Page
from .target_classifier import TargetSpec, T_DOMAIN, T_SUBDOMAIN

LOG = logging.getLogger("osint_bot.contact_discovery")


# ---------------------------------------------------------------------------
# Patterns — stricter than patterns.EMAIL_RE / PHONE_RE for extraction over
# arbitrary text. Designed to limit false positives.
# ---------------------------------------------------------------------------

# Email: full RFC-ish, but excludes wrapping quotes and angle brackets cleanly.
# We require at least one dot in the domain to avoid local-only hits.
_EMAIL_EXTRACT = re.compile(
    # Lookahead permette il punto finale di frase (es. "Scrivi a info@example.com.")
    # ma non altri alphanum-dash che indicherebbero parte del dominio.
    r"(?<![\w.+-])([A-Za-z0-9][A-Za-z0-9._%+-]{0,63})@([A-Za-z0-9][A-Za-z0-9.-]{0,253}\.[A-Za-z]{2,24})(?![\w-])",
)
# Masked email (source-side redaction): "a***@example.com", "n.r…@acme.it",
# "***@example.com". Detect them so we can mark `incomplete=True`.
_EMAIL_MASKED = re.compile(
    r"(?<![\w.+-])([A-Za-z0-9._%+-]*[\*…\.]{2,}[A-Za-z0-9._%+-]*)@([A-Za-z0-9.-]+\.[A-Za-z]{2,24})(?![\w.-])",
)

# Phone: optional + or 00 prefix, 7-15 digits with allowed separators
# (space, dot, dash, paren).
_PHONE_EXTRACT = re.compile(
    r"(?:(?:\+|00)\d{1,3}[\s.\-]?)?(?:\(?\d{2,4}\)?[\s.\-]?){2,5}\d{3,4}",
)

# mailto: / tel: links — strongest possible signal.
_MAILTO_RE = re.compile(r'(?:href\s*=\s*["\']?)?mailto:([^"\'\s>?]+)', re.IGNORECASE)
_TELHREF_RE = re.compile(r'(?:href\s*=\s*["\']?)?tel:([+0-9()\s\-.]+)', re.IGNORECASE)

# Context labels that strongly suggest a contact role.
_ROLE_KEYWORDS = {
    # Order matters: first match wins.
    "commercial":("sales", "vendite", "marketing", "press", "stampa", "billing",
                  "fatturazione", "amministrazione"),
    "technical": ("dev", "developer", "devops", "tech", "tecnico", "engineering",
                  "ingegneria", "it@", "ops", "sre"),
    "legal":     ("legal", "legale", "privacy", "dpo", "compliance", "gdpr"),
    "hr":        ("hr@", "jobs", "careers", "lavora", "recruit"),
    "role":      ("noreply", "no-reply", "admin", "administrator", "amministratore",
                  "webmaster", "postmaster", "abuse", "hostmaster"),
    "business":  ("info", "contact", "contatti", "contatto", "support", "supporto",
                  "office", "ufficio", "hello", "ciao"),
    "personal":  ("personal", "personale", "private", "privato"),
}

# Local-part fragments that strongly indicate role/generic (deprioritize as
# personal contact).
_GENERIC_LOCALS = {
    "info", "noreply", "no-reply", "donotreply", "admin", "support", "sales",
    "contact", "contatti", "press", "media", "marketing", "hello", "ciao",
    "webmaster", "postmaster", "abuse", "hostmaster", "billing", "office",
    "ufficio", "amministrazione", "fatturazione", "privacy", "dpo", "legal",
    "hr", "jobs", "careers",
}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Contact:
    """One contact record with provenance + scoring."""
    kind: str                       # "email" | "phone"
    value: str                      # canonical form (lowercase email / E.164)
    display: str                    # what the source displayed (may equal value)
    source_url: str
    source_title: str = ""
    snippet: str = ""               # ±120 chars around the match
    timestamp: str = ""             # ISO8601 UTC collection time
    category: str = "unknown"       # personal | business | role | technical | …
    confidence: float = 0.0         # 0..1 — target-association confidence
    confidence_label: str = ""      # "certo" | "probabile" | "non_confermato"
    rationale: str = ""             # explain why we kept (or de-prioritized) it
    incomplete: bool = False        # True if the source published a masked value
    incomplete_reason: str = ""     # e.g. "fonte ha mascherato il dato"
    attributes: dict = field(default_factory=dict)


@dataclass
class ContactReport:
    """Aggregated discovery result."""
    target: str
    target_type: str
    certain: list[Contact] = field(default_factory=list)
    probable: list[Contact] = field(default_factory=list)
    unconfirmed: list[Contact] = field(default_factory=list)
    pages_scanned: int = 0
    sources_with_hits: int = 0

    def all(self) -> list[Contact]:
        return [*self.certain, *self.probable, *self.unconfirmed]

    def count_by_kind(self) -> dict:
        out = {"email": 0, "phone": 0}
        for c in self.all():
            out[c.kind] = out.get(c.kind, 0) + 1
        return out


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def discover_contacts(
    target: TargetSpec,
    pages: Iterable[Page],
) -> ContactReport:
    """Extract and score contacts from the harvested pages."""
    pages_list = list(pages or [])
    report = ContactReport(
        target=target.value or target.raw,
        target_type=target.type,
        pages_scanned=len(pages_list),
    )

    seen_keys: set[tuple[str, str]] = set()  # (kind, canonical)
    sources_with_hits: set[str] = set()

    for page in pages_list:
        if getattr(page, "error", None):
            continue
        text = getattr(page, "text", "") or ""
        if not text:
            continue
        page_url = page.url
        page_title = (page.title or "").strip()

        # Anchor-link extractions are the strongest signal.
        for match in _MAILTO_RE.finditer(text):
            value = unescape(match.group(1).split("?")[0]).strip()
            contact = _maybe_email(value, page=page, target=target,
                                   strong_signal=True, label="mailto link")
            if contact and _commit(contact, seen_keys, sources_with_hits, report):
                pass
        for match in _TELHREF_RE.finditer(text):
            value = match.group(1).strip()
            contact = _maybe_phone(value, page=page, target=target,
                                   strong_signal=True, label="tel link")
            if contact and _commit(contact, seen_keys, sources_with_hits, report):
                pass

        # Plain-text extractions (weaker, gated by anti-FP scoring).
        for match in _EMAIL_EXTRACT.finditer(text):
            local, domain = match.group(1), match.group(2)
            value = f"{local}@{domain}"
            contact = _maybe_email(value, page=page, target=target,
                                   strong_signal=False, match_span=match.span(),
                                   text=text)
            if contact and _commit(contact, seen_keys, sources_with_hits, report):
                pass

        for match in _EMAIL_MASKED.finditer(text):
            local, domain = match.group(1), match.group(2)
            display = f"{local}@{domain}"
            contact = _maybe_email_masked(display, page=page, target=target,
                                          text=text, span=match.span())
            if contact and _commit(contact, seen_keys, sources_with_hits, report):
                pass

        for match in _PHONE_EXTRACT.finditer(text):
            raw_phone = match.group(0)
            contact = _maybe_phone(raw_phone, page=page, target=target,
                                   strong_signal=False, match_span=match.span(),
                                   text=text)
            if contact and _commit(contact, seen_keys, sources_with_hits, report):
                pass

    report.sources_with_hits = len(sources_with_hits)
    # Sort each bucket by confidence desc, then by source.
    for bucket in (report.certain, report.probable, report.unconfirmed):
        bucket.sort(key=lambda c: (-c.confidence, c.source_url))
    return report


# ---------------------------------------------------------------------------
# Per-kind extraction with scoring + categorization
# ---------------------------------------------------------------------------

def _maybe_email(
    value: str,
    *,
    page: Page,
    target: TargetSpec,
    strong_signal: bool,
    match_span: tuple[int, int] | None = None,
    text: str | None = None,
    label: str = "",
) -> Contact | None:
    value = value.lower().strip()
    if "@" not in value or value.count("@") != 1:
        return None
    local, _, domain = value.partition("@")
    if not _looks_like_valid_email(local, domain):
        return None
    # Avoid the most common false-positive: extension snippets like "image@2x".
    if re.fullmatch(r"\d+x", local):
        return None
    snippet = _snippet_for(text, match_span) if text and match_span else ""
    category = _categorize_email(local)
    confidence, rationale = _score_target_match(
        local=local, domain=domain, target=target, page=page,
        snippet=snippet, strong_signal=strong_signal, label=label,
    )
    return Contact(
        kind="email",
        value=value,
        display=value,
        source_url=page.url,
        source_title=page.title or "",
        snippet=snippet,
        timestamp=_now_iso(),
        category=category,
        confidence=confidence,
        confidence_label=_label_for(confidence),
        rationale=rationale,
        attributes={"local": local, "domain": domain},
    )


def _maybe_email_masked(
    display: str, *, page: Page, target: TargetSpec, text: str, span: tuple[int, int],
) -> Contact | None:
    """Capture a masked email like 'a***@example.com' without un-masking it."""
    local, _, domain = display.partition("@")
    if not domain or "." not in domain:
        return None
    snippet = _snippet_for(text, span)
    # Target match is weaker since we can't confirm the local part. We score
    # purely on domain proximity + signal context.
    confidence, rationale = _score_target_match(
        local=local, domain=domain, target=target, page=page,
        snippet=snippet, strong_signal=False, label="masked",
    )
    # Cap masked confidence — never claim "certo" for masked data.
    confidence = min(confidence, 0.55)
    return Contact(
        kind="email",
        value=display.lower(),
        display=display,
        source_url=page.url,
        source_title=page.title or "",
        snippet=snippet,
        timestamp=_now_iso(),
        category=_categorize_email(local),
        confidence=confidence,
        confidence_label=_label_for(confidence),
        rationale=rationale + " Fonte ha pubblicato il dato mascherato.",
        incomplete=True,
        incomplete_reason="La fonte ha pubblicato il valore in forma mascherata; "
                          "non integriamo il dato.",
        attributes={"domain": domain.lower()},
    )


def _maybe_phone(
    value: str,
    *,
    page: Page,
    target: TargetSpec,
    strong_signal: bool,
    match_span: tuple[int, int] | None = None,
    text: str | None = None,
    label: str = "",
) -> Contact | None:
    normalized = _normalize_phone(value)
    if not normalized:
        return None
    canonical, display, is_e164 = normalized
    snippet = _snippet_for(text, match_span) if text and match_span else ""
    confidence, rationale = _score_phone_match(
        page=page, target=target, snippet=snippet,
        strong_signal=strong_signal, is_e164=is_e164, label=label,
    )
    return Contact(
        kind="phone",
        value=canonical,
        display=display,
        source_url=page.url,
        source_title=page.title or "",
        snippet=snippet,
        timestamp=_now_iso(),
        category="business" if strong_signal else "unknown",
        confidence=confidence,
        confidence_label=_label_for(confidence),
        rationale=rationale,
        attributes={"e164": canonical if is_e164 else None},
    )


# ---------------------------------------------------------------------------
# Scoring — target association
# ---------------------------------------------------------------------------

def _score_target_match(
    *, local: str, domain: str, target: TargetSpec, page: Page,
    snippet: str, strong_signal: bool, label: str,
) -> tuple[float, str]:
    """Return (confidence 0..1, italian rationale)."""
    score = 0.0
    reasons: list[str] = []

    if strong_signal:
        score += 0.45
        reasons.append("link diretto (mailto/tel) in pagina pubblica")

    target_value = (target.value or target.raw).lower()
    target_apex = target.attributes.get("apex", target_value) if target.attributes else target_value
    page_host = _host_of(page.url)

    # Domain match between contact email and target apex → strong signal.
    if target.type in (T_DOMAIN, T_SUBDOMAIN):
        if domain == target_apex or domain.endswith("." + target_apex):
            score += 0.45
            reasons.append(f"dominio contatto ({domain}) coincide col target ({target_apex})")
        elif domain == page_host:
            score += 0.15
            reasons.append("dominio contatto = dominio pagina pubblicante")

    # If page itself is the target (target=domain, page=that domain) → boost.
    if target.type in (T_DOMAIN, T_SUBDOMAIN, "url") and page_host == target_apex:
        score += 0.2
        reasons.append("contatto trovato sul sito ufficiale del target")
    elif target.type in (T_DOMAIN, T_SUBDOMAIN) and page_host.endswith("." + target_apex):
        score += 0.15
        reasons.append("contatto trovato su un host appartenente al target")

    # Snippet/title proximity for non-domain targets (person/company name).
    if target.type in ("person", "company", "org", "handle"):
        name_low = target_value.lower()
        if name_low and (name_low in (page.title or "").lower() or name_low in snippet.lower()):
            score += 0.25
            reasons.append("nome target compare nel titolo o nel contesto")

    # Local part vs target — useful for person targets.
    if target.type == "person":
        parts = re.findall(r"[a-zA-Z]+", target_value.lower())
        if any(p in local for p in parts if len(p) >= 3):
            score += 0.15
            reasons.append("local part contiene token del nome del target")

    # Generic mailbox → de-prioritize as "personal".
    if local in _GENERIC_LOCALS:
        score = max(0.0, score - 0.1)
        reasons.append("local part generica (info/sales/noreply…)")

    # Cap and clean.
    score = max(0.0, min(1.0, score))
    rationale = "; ".join(reasons) if reasons else "nessun segnale di associazione al target"
    if label:
        rationale = f"{label}: {rationale}"
    return score, rationale


def _score_phone_match(
    *, page: Page, target: TargetSpec, snippet: str,
    strong_signal: bool, is_e164: bool, label: str,
) -> tuple[float, str]:
    score = 0.0
    reasons: list[str] = []
    if strong_signal:
        score += 0.5
        reasons.append("link diretto tel: in pagina pubblica")
    if is_e164:
        score += 0.1
        reasons.append("formato E.164 esplicito")
    if target.type in ("company", "org", "person") and target.value.lower() in (page.title or "").lower():
        score += 0.2
        reasons.append("titolo pagina menziona il target")
    page_host = _host_of(page.url)
    target_apex = target.attributes.get("apex") if target.attributes else None
    if target_apex and (page_host == target_apex or page_host.endswith("." + target_apex)):
        score += 0.2
        reasons.append("contatto sul sito del target")
    score = max(0.0, min(1.0, score))
    rationale = "; ".join(reasons) if reasons else "nessun segnale di associazione al target"
    if label:
        rationale = f"{label}: {rationale}"
    return score, rationale


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _commit(contact: Contact, seen: set, sources_with_hits: set, report: ContactReport) -> bool:
    key = (contact.kind, contact.value)
    if key in seen:
        return False
    seen.add(key)
    sources_with_hits.add(contact.source_url)
    # Bucket by confidence.
    if contact.confidence >= 0.75:
        report.certain.append(contact)
    elif contact.confidence >= 0.45:
        report.probable.append(contact)
    else:
        report.unconfirmed.append(contact)
    return True


def _label_for(confidence: float) -> str:
    if confidence >= 0.75:
        return "certo"
    if confidence >= 0.45:
        return "probabile"
    return "non_confermato"


def _categorize_email(local: str) -> str:
    low = local.lower()
    for category, keywords in _ROLE_KEYWORDS.items():
        for kw in keywords:
            if kw.rstrip("@") in low:
                return category
    if low in _GENERIC_LOCALS:
        return "role"
    return "personal"


def _looks_like_valid_email(local: str, domain: str) -> bool:
    if len(local) < 1 or len(local) > 64:
        return False
    if "." not in domain:
        return False
    if domain.startswith(".") or domain.endswith("."):
        return False
    if ".." in local or ".." in domain:
        return False
    # Block obvious junk patterns.
    if local.startswith(".") or local.endswith("."):
        return False
    return True


def _normalize_phone(raw: str) -> tuple[str, str, bool] | None:
    """Return (canonical_value, display_value, is_e164) or None."""
    raw = raw.strip()
    if not raw:
        return None
    digits = re.sub(r"\D+", "", raw)
    if len(digits) < 7 or len(digits) > 15:
        return None
    if raw.startswith("+"):
        return "+" + digits, raw, True
    if raw.startswith("00"):
        # 00CC… → +CC…
        return "+" + digits[2:], raw, True
    # Bare digit string with separators — keep as-is, mark non-E.164.
    if re.search(r"[\s().\-]", raw):
        return raw, raw, False
    # Pure digit run, no separators, no prefix → too ambiguous (could be a
    # timestamp, an ID). Skip.
    return None


def _host_of(url: str) -> str:
    try:
        import urllib.parse
        return (urllib.parse.urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def _snippet_for(text: str | None, span: tuple[int, int] | None) -> str:
    if not text or not span:
        return ""
    start, end = span
    pre = max(0, start - 100)
    post = min(len(text), end + 100)
    # Trim to word boundary.
    pre_text = text[pre:start].lstrip()
    if pre > 0 and " " in pre_text:
        pre_text = pre_text[pre_text.index(" ") + 1:]
    post_text = text[end:post].rstrip()
    if post < len(text) and " " in post_text:
        post_text = post_text[: post_text.rfind(" ")]
    return f"{pre_text}{text[start:end]}{post_text}".strip()


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
