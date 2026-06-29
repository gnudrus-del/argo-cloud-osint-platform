"""Ranking + deduplication of OSINT results.

The OSINT pipeline produces a flat list of `SearchResult`/`Finding` from many
providers. Before they hit the report, we:

  1. Deduplicate by canonical URL (drop tracking params, lowercase host,
     strip trailing slash) and by content signature.
  2. Score each item on four axes:
       * source_quality   — known-good providers and TLDs score higher
       * target_match     — proximity to the target value/apex/name
       * freshness        — recent year mentions / dates penalise nothing,
                            "old" timestamps degrade
       * specificity      — direct evidence (mailto, structured JSON-LD)
                            beats generic web text
  3. Aggregate to a single 0..1 score and explain why.

The module is pure — no I/O — and easy to unit-test. The orchestrator calls
`rank_results(results, target)` once before passing to the report.
"""
from __future__ import annotations

import hashlib
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Iterable

from .models import Finding, SearchResult
from .target_classifier import TargetSpec, T_DOMAIN, T_SUBDOMAIN


# ---------------------------------------------------------------------------
# Source quality tiers (Italian-style label → weight)
# ---------------------------------------------------------------------------

# Tier weights used in source_quality scoring (0..1).
TIER_OFFICIAL  = 1.00   # public registry, government, the target's own site
TIER_ESTABLISHED = 0.85 # known reputable site (linkedin, github, archive.org)
TIER_REGULAR   = 0.55   # generic news, blogs, forums
TIER_LOW       = 0.30   # paste sites, low-trust mirrors, ad farms
TIER_AGGREGATOR= 0.40   # search engine cache, link aggregators

# Domain → tier mapping. Order: explicit > suffix.
_DOMAIN_TIER: dict[str, float] = {
    # Registries / authorities
    "crt.sh":           TIER_OFFICIAL,
    "rdap.org":         TIER_OFFICIAL,
    "iana.org":         TIER_OFFICIAL,
    "icann.org":        TIER_OFFICIAL,
    "haveibeenpwned.com": TIER_OFFICIAL,
    "github.com":       TIER_ESTABLISHED,
    "linkedin.com":     TIER_ESTABLISHED,
    "archive.org":      TIER_ESTABLISHED,
    "web.archive.org":  TIER_ESTABLISHED,
    "shodan.io":        TIER_ESTABLISHED,
    "censys.io":        TIER_ESTABLISHED,
    "search.censys.io": TIER_ESTABLISHED,
    "virustotal.com":   TIER_ESTABLISHED,
    "abuseipdb.com":    TIER_ESTABLISHED,
    "leakix.net":       TIER_ESTABLISHED,
    "urlscan.io":       TIER_ESTABLISHED,
    "hunter.io":        TIER_ESTABLISHED,
    "intelx.io":        TIER_ESTABLISHED,
    "fullhunt.io":      TIER_ESTABLISHED,
    # Search engines (cache, not primary)
    "google.com":       TIER_AGGREGATOR,
    "bing.com":         TIER_AGGREGATOR,
    "duckduckgo.com":   TIER_AGGREGATOR,
    "yandex.com":       TIER_AGGREGATOR,
    "brave.com":        TIER_AGGREGATOR,
    "search.brave.com": TIER_AGGREGATOR,
    # Notorious low-trust
    "pastebin.com":     TIER_LOW,
    "ghostbin.com":     TIER_LOW,
    "rentry.co":        TIER_LOW,
}

# Suffix → tier (applies if no explicit hit).
_SUFFIX_TIER: dict[str, float] = {
    ".gov":  TIER_OFFICIAL,
    ".edu":  TIER_OFFICIAL,
    ".int":  TIER_OFFICIAL,
    ".mil":  TIER_OFFICIAL,
    ".gov.it": TIER_OFFICIAL,
    ".gov.uk": TIER_OFFICIAL,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

@dataclass
class RankedResult:
    """A SearchResult enriched with score + reasons. Keeps the original."""
    original: SearchResult
    canonical_url: str
    score: float
    source_quality: float
    target_match: float
    freshness: float
    specificity: float
    reasons: list[str] = field(default_factory=list)
    duplicate_of: str | None = None   # canonical URL this duplicates

    @property
    def url(self) -> str:
        return self.original.url

    def to_dict(self) -> dict:
        return {
            "title": self.original.title,
            "url": self.original.url,
            "canonical_url": self.canonical_url,
            "snippet": self.original.snippet,
            "provider": self.original.provider,
            "score": round(self.score, 3),
            "source_quality": round(self.source_quality, 3),
            "target_match": round(self.target_match, 3),
            "freshness": round(self.freshness, 3),
            "specificity": round(self.specificity, 3),
            "reasons": list(self.reasons),
        }


def rank_results(
    results: Iterable[SearchResult],
    target: TargetSpec,
    *,
    now_year: int | None = None,
) -> list[RankedResult]:
    """Dedupe + score + sort. Highest score first."""
    results = list(results or [])
    by_canon: dict[str, RankedResult] = {}
    duplicates: list[RankedResult] = []

    for r in results:
        canon = canonical_url(r.url)
        sq = score_source_quality(canon)
        tm = score_target_match(r, target)
        fr = score_freshness(r, now_year=now_year)
        sp = score_specificity(r)
        score = _aggregate(sq, tm, fr, sp)
        reasons = _explain(sq, tm, fr, sp, target)

        ranked = RankedResult(
            original=r, canonical_url=canon, score=score,
            source_quality=sq, target_match=tm, freshness=fr, specificity=sp,
            reasons=reasons,
        )

        existing = by_canon.get(canon)
        if existing is None:
            by_canon[canon] = ranked
        else:
            # Keep the higher-scoring one; record the loser as a duplicate.
            if score > existing.score:
                existing.duplicate_of = canon
                duplicates.append(existing)
                by_canon[canon] = ranked
            else:
                ranked.duplicate_of = canon
                duplicates.append(ranked)

    # Sort descending by score, with stable tiebreak by URL.
    ordered = sorted(by_canon.values(), key=lambda x: (-x.score, x.canonical_url))
    return ordered


def deduplicate_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Drop Finding duplicates by (kind, lowercased value)."""
    out: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for f in findings or []:
        key = (f.kind, (f.value or "").strip().lower())
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


# ---------------------------------------------------------------------------
# Canonical URL — strip tracking params, lowercase host, normalize trailing
# slash, drop fragment.
# ---------------------------------------------------------------------------

_TRACKING_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "gclid", "fbclid", "mc_eid", "mc_cid", "yclid", "_hsenc", "_hsmi",
    "ref", "ref_src", "ref_url", "icid",
}


def canonical_url(url: str) -> str:
    """Return a stable, comparable URL for dedup."""
    if not url:
        return ""
    try:
        parsed = urllib.parse.urlparse(url.strip())
    except ValueError:
        return url
    scheme = (parsed.scheme or "http").lower()
    netloc = (parsed.hostname or "").lower()
    if parsed.port and not (
        (scheme == "http" and parsed.port == 80) or
        (scheme == "https" and parsed.port == 443)
    ):
        netloc = f"{netloc}:{parsed.port}"
    path = parsed.path or "/"
    if len(path) > 1 and path.endswith("/"):
        path = path[:-1]
    # Drop tracking params, keep the rest sorted for stability.
    params = [
        (k, v) for k, v in urllib.parse.parse_qsl(parsed.query, keep_blank_values=False)
        if k.lower() not in _TRACKING_PARAMS
    ]
    params.sort()
    query = urllib.parse.urlencode(params, doseq=True)
    return urllib.parse.urlunparse((scheme, netloc, path, "", query, ""))


def content_hash(text: str) -> str:
    """Stable hash of a content blob — used as a secondary dedup key."""
    norm = " ".join((text or "").lower().split())
    return hashlib.sha256(norm.encode("utf-8", errors="replace")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Scoring components
# ---------------------------------------------------------------------------

def score_source_quality(canon_url: str) -> float:
    host = _host_of(canon_url)
    if not host:
        return TIER_REGULAR
    if host in _DOMAIN_TIER:
        return _DOMAIN_TIER[host]
    for suffix, tier in _SUFFIX_TIER.items():
        if host.endswith(suffix):
            return tier
    # Heuristic: subdomains of known providers inherit the parent tier.
    labels = host.split(".")
    if len(labels) >= 2:
        parent = ".".join(labels[-2:])
        if parent in _DOMAIN_TIER:
            return _DOMAIN_TIER[parent]
    return TIER_REGULAR


def score_target_match(result: SearchResult, target: TargetSpec) -> float:
    """How much this result mentions or comes from the target?"""
    if not target.value and not target.raw:
        return 0.0
    target_value = (target.value or target.raw).lower()
    target_apex = (target.attributes.get("apex") or target_value
                   if target.attributes else target_value).lower()
    text_blob = " ".join([
        (result.title or ""),
        (result.snippet or ""),
        (result.url or ""),
    ]).lower()
    host = _host_of(canonical_url(result.url))

    score = 0.0
    # Host = target (or subdomain) → very strong.
    if target.type in (T_DOMAIN, T_SUBDOMAIN) and host:
        if host == target_apex or host.endswith("." + target_apex):
            score += 0.6
    # Target value in text/title.
    if target_value and target_value in text_blob:
        score += 0.3
    # Target apex domain mentioned in text.
    elif target_apex and target_apex != target_value and target_apex in text_blob:
        score += 0.2
    # For person/company targets, partial token match.
    if target.type in ("person", "company", "org"):
        for tok in re.findall(r"[a-z]{3,}", target_value):
            if tok in text_blob:
                score += 0.05
    return min(1.0, score)


_YEAR_RE = re.compile(r"\b(?:19|20)\d{2}\b")


def score_freshness(result: SearchResult, *, now_year: int | None = None) -> float:
    """Year-of-mention freshness. Newer → higher. No date → neutral 0.5."""
    text = " ".join([(result.title or ""), (result.snippet or "")])
    years = [int(y) for y in _YEAR_RE.findall(text)]
    if not years:
        return 0.5
    cur = now_year or time.gmtime().tm_year
    newest = max(years)
    if newest > cur:
        # Future year mention — probably noise (e.g. dataset name); neutral.
        return 0.5
    age = cur - newest
    if age <= 1:
        return 1.0
    if age <= 3:
        return 0.85
    if age <= 5:
        return 0.65
    if age <= 10:
        return 0.45
    return 0.25


def score_specificity(result: SearchResult) -> float:
    """Higher when the result *is* the evidence vs. a pointer to it."""
    score = 0.5
    url = (result.url or "").lower()
    title = (result.title or "").lower()
    snippet = (result.snippet or "").lower()

    if url.endswith((".pdf", ".doc", ".docx", ".xls", ".xlsx")):
        score = max(score, 0.85)
    if "contact" in url or "contatti" in url or "about" in url or "chi-siamo" in url:
        score = max(score, 0.75)
    if any(tok in title or tok in snippet for tok in ("email:", "tel:", "phone:", "+39", "@")):
        score = max(score, 0.7)
    # Search engine results are pointers, not evidence — drop slightly.
    host = _host_of(canonical_url(url))
    if host in {"google.com", "bing.com", "duckduckgo.com", "yandex.com"}:
        score = min(score, 0.35)
    return score


def _aggregate(sq: float, tm: float, fr: float, sp: float) -> float:
    """Weighted combination. Target match dominates: a result that doesn't
    mention or come from the target is mostly noise."""
    weights = {"sq": 0.25, "tm": 0.40, "fr": 0.15, "sp": 0.20}
    raw = sq * weights["sq"] + tm * weights["tm"] + fr * weights["fr"] + sp * weights["sp"]
    return round(min(1.0, max(0.0, raw)), 3)


def _explain(sq: float, tm: float, fr: float, sp: float, target: TargetSpec) -> list[str]:
    reasons: list[str] = []
    if sq >= 0.85: reasons.append("fonte di alta affidabilità")
    elif sq >= 0.55: reasons.append("fonte standard")
    elif sq <= 0.35: reasons.append("fonte a bassa affidabilità")

    if tm >= 0.7: reasons.append("forte associazione al target")
    elif tm >= 0.3: reasons.append("associazione parziale al target")
    else: reasons.append("nessun riferimento esplicito al target nel testo")

    if fr >= 0.85: reasons.append("contenuto recente")
    elif fr <= 0.35: reasons.append("contenuto datato")

    if sp >= 0.75: reasons.append("evidenza diretta (documento o pagina contatti)")
    elif sp <= 0.4: reasons.append("link indiretto (motore di ricerca)")
    return reasons


def _host_of(url: str) -> str:
    try:
        host = (urllib.parse.urlparse(url).hostname or "").lower()
    except Exception:
        return ""
    # Strip leading "www." so "www.google.com" matches "google.com" in tiers.
    if host.startswith("www."):
        host = host[4:]
    return host
