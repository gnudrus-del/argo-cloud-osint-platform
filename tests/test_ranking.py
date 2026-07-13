"""Tests for ranking.py — canonical URL, scoring, dedup, freshness."""
from __future__ import annotations

from osint_bot.models import Finding, SearchResult
from osint_bot.ranking import (
    TIER_AGGREGATOR,
    TIER_ESTABLISHED,
    TIER_LOW,
    TIER_OFFICIAL,
    TIER_REGULAR,
    canonical_url,
    content_hash,
    deduplicate_findings,
    rank_results,
    score_freshness,
    score_source_quality,
    score_specificity,
    score_target_match,
)
from osint_bot.target_classifier import classify_target

# ---------------------------------------------------------------------------
# canonical_url
# ---------------------------------------------------------------------------

class TestCanonicalUrl:
    def test_strip_tracking_params(self):
        u = canonical_url("https://example.com/post?utm_source=x&id=42&utm_campaign=y")
        assert "utm_source" not in u
        assert "utm_campaign" not in u
        assert "id=42" in u

    def test_lowercase_host(self):
        u = canonical_url("HTTPS://EXAMPLE.COM/Path")
        assert u.startswith("https://example.com")
        assert "/Path" in u  # path case preserved

    def test_strip_trailing_slash(self):
        a = canonical_url("https://example.com/path/")
        b = canonical_url("https://example.com/path")
        assert a == b

    def test_root_keeps_slash(self):
        assert canonical_url("https://example.com").endswith("/")
        assert canonical_url("https://example.com/").endswith("/")

    def test_drop_fragment(self):
        u = canonical_url("https://example.com/post#section-2")
        assert "#" not in u

    def test_default_port_dropped(self):
        # urllib already drops default ports if absent; we keep non-default.
        u = canonical_url("https://example.com:443/x")
        assert ":443" not in u

    def test_nondefault_port_kept(self):
        u = canonical_url("https://example.com:8443/x")
        assert ":8443" in u


# ---------------------------------------------------------------------------
# Source quality
# ---------------------------------------------------------------------------

class TestSourceQuality:
    def test_known_official(self):
        assert score_source_quality("https://crt.sh/?q=x") == TIER_OFFICIAL

    def test_gov_suffix(self):
        assert score_source_quality("https://something.gov.uk/y") == TIER_OFFICIAL

    def test_aggregator(self):
        assert score_source_quality("https://www.google.com/search?q=foo") == TIER_AGGREGATOR

    def test_low_trust(self):
        assert score_source_quality("https://pastebin.com/raw/abc") == TIER_LOW

    def test_subdomain_inherits_parent(self):
        assert score_source_quality("https://api.github.com/x") == TIER_ESTABLISHED

    def test_unknown_is_regular(self):
        assert score_source_quality("https://random-site.example.net/") == TIER_REGULAR


# ---------------------------------------------------------------------------
# Target match
# ---------------------------------------------------------------------------

class TestTargetMatch:
    def test_same_domain_full(self):
        target = classify_target("acme.com")
        r = SearchResult(title="About", url="https://acme.com/about", snippet="...")
        assert score_target_match(r, target) >= 0.6

    def test_subdomain_of_target_apex(self):
        target = classify_target("acme.com")
        r = SearchResult(title="API", url="https://api.acme.com/", snippet="")
        assert score_target_match(r, target) >= 0.6

    def test_target_in_snippet(self):
        target = classify_target("acme.com")
        r = SearchResult(title="Post", url="https://blog.example.org/p",
                         snippet="A new article about acme.com and its products.")
        assert score_target_match(r, target) >= 0.3

    def test_unrelated_low(self):
        target = classify_target("acme.com")
        r = SearchResult(title="Random", url="https://other.net/", snippet="nothing here")
        assert score_target_match(r, target) <= 0.1


# ---------------------------------------------------------------------------
# Freshness
# ---------------------------------------------------------------------------

class TestFreshness:
    def test_recent_year_high(self):
        r = SearchResult(title="2026 report", url="x", snippet="latest 2026 data")
        assert score_freshness(r, now_year=2026) >= 0.85

    def test_old_year_low(self):
        r = SearchResult(title="From 2010", url="x", snippet="2010 release notes")
        assert score_freshness(r, now_year=2026) <= 0.45

    def test_no_year_neutral(self):
        r = SearchResult(title="No date", url="x", snippet="generic blob")
        assert score_freshness(r) == 0.5

    def test_future_year_ignored(self):
        r = SearchResult(title="dataset-2099", url="x", snippet="2099 marker")
        # Future = treated as no signal, neutral.
        assert score_freshness(r, now_year=2026) == 0.5


# ---------------------------------------------------------------------------
# Specificity
# ---------------------------------------------------------------------------

class TestSpecificity:
    def test_pdf_high(self):
        r = SearchResult(title="report", url="https://acme.com/report.pdf", snippet="")
        assert score_specificity(r) >= 0.85

    def test_contact_page(self):
        r = SearchResult(title="Contatti", url="https://acme.com/contatti", snippet="")
        assert score_specificity(r) >= 0.75

    def test_search_engine_low(self):
        r = SearchResult(title="acme", url="https://www.google.com/search?q=acme", snippet="")
        assert score_specificity(r) <= 0.4


# ---------------------------------------------------------------------------
# Integration: rank_results
# ---------------------------------------------------------------------------

class TestRankResults:
    def test_ordering(self):
        target = classify_target("acme.com")
        results = [
            SearchResult(title="Acme contatti", url="https://acme.com/contatti", snippet=""),
            SearchResult(title="Random blog", url="https://blog.unknown.net/x", snippet="nothing"),
            SearchResult(title="Search result", url="https://www.google.com/search?q=acme", snippet="acme"),
        ]
        ranked = rank_results(results, target)
        # First should be the contact page on the target's own site.
        assert ranked[0].url == "https://acme.com/contatti"

    def test_dedup_by_canonical(self):
        target = classify_target("acme.com")
        results = [
            SearchResult(title="A", url="https://acme.com/page?utm_source=x", snippet=""),
            SearchResult(title="B", url="https://acme.com/page", snippet=""),
            SearchResult(title="C", url="https://ACME.com/page?utm_campaign=y", snippet=""),
        ]
        ranked = rank_results(results, target)
        assert len(ranked) == 1, "All three should canonicalize to the same URL"

    def test_empty(self):
        target = classify_target("acme.com")
        assert rank_results([], target) == []

    def test_explain_reasons_present(self):
        target = classify_target("acme.com")
        results = [SearchResult(title="x", url="https://acme.com/", snippet="")]
        ranked = rank_results(results, target)
        assert ranked[0].reasons
        assert all(isinstance(r, str) for r in ranked[0].reasons)


# ---------------------------------------------------------------------------
# deduplicate_findings
# ---------------------------------------------------------------------------

class TestDeduplicateFindings:
    def test_same_kind_same_value(self):
        f1 = Finding(kind="email", value="x@y.com", confidence=0.5)
        f2 = Finding(kind="email", value="x@y.com", confidence=0.9)
        out = deduplicate_findings([f1, f2])
        assert len(out) == 1

    def test_case_insensitive(self):
        f1 = Finding(kind="email", value="X@Y.COM", confidence=0.5)
        f2 = Finding(kind="email", value="x@y.com", confidence=0.5)
        assert len(deduplicate_findings([f1, f2])) == 1

    def test_different_kinds_kept(self):
        f1 = Finding(kind="email", value="x@y.com", confidence=0.5)
        f2 = Finding(kind="contact_email", value="x@y.com", confidence=0.5)
        assert len(deduplicate_findings([f1, f2])) == 2


class TestContentHash:
    def test_stable(self):
        h1 = content_hash("Hello world")
        h2 = content_hash("hello   world")
        assert h1 == h2

    def test_different(self):
        assert content_hash("a") != content_hash("b")
