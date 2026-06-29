"""Tests for contact_discovery.py — extraction, scoring, anti-FP, dedupe."""
from __future__ import annotations

import pytest

from osint_bot.contact_discovery import (
    Contact, ContactReport, _categorize_email, _label_for, _normalize_phone,
    discover_contacts,
)
from osint_bot.models import Page
from osint_bot.target_classifier import classify_target


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _page(url, title, text):
    return Page(url=url, status=200, title=title, description="", text=text)


# ---------------------------------------------------------------------------
# Unit: normalization + categorization
# ---------------------------------------------------------------------------

class TestNormalizePhone:
    def test_e164_explicit(self):
        c, d, e164 = _normalize_phone("+39 333 1234567")
        assert c == "+393331234567"
        assert e164 is True

    def test_00_prefix_becomes_plus(self):
        # 00 prefix is the international escape; we strip it and prepend "+".
        # "0039 02 1234567" → digits "0039021234567" → strip "00" → "+39021234567"
        c, d, e164 = _normalize_phone("0039 02 1234567")
        assert c == "+39021234567"
        assert e164 is True

    def test_too_short_rejected(self):
        assert _normalize_phone("12345") is None

    def test_too_long_rejected(self):
        assert _normalize_phone("1234567890123456") is None

    def test_no_separators_no_prefix_rejected(self):
        # Could be a timestamp / ID.
        assert _normalize_phone("12345678901") is None

    def test_with_separators_no_prefix_kept(self):
        c, d, e164 = _normalize_phone("(415) 555-0172")
        assert c == "(415) 555-0172"
        assert e164 is False


class TestCategorizeEmail:
    def test_info_is_role(self):
        assert _categorize_email("info") == "business"
    def test_noreply_is_role(self):
        assert _categorize_email("noreply") == "role"
    def test_dev_is_technical(self):
        assert _categorize_email("devops") == "technical"
    def test_sales_is_commercial(self):
        assert _categorize_email("sales") == "commercial"
    def test_personal_default(self):
        assert _categorize_email("mario.rossi") == "personal"


class TestLabelFor:
    def test_thresholds(self):
        assert _label_for(0.95) == "certo"
        assert _label_for(0.75) == "certo"
        assert _label_for(0.5)  == "probabile"
        assert _label_for(0.45) == "probabile"
        assert _label_for(0.2)  == "non_confermato"


# ---------------------------------------------------------------------------
# Integration: discover_contacts
# ---------------------------------------------------------------------------

class TestDiscoverEmails:
    def test_mailto_link_strong_signal(self):
        target = classify_target("example.com")
        page = _page(
            "https://example.com/contact",
            "Contatti — Example Srl",
            'Per info scrivere a <a href="mailto:info@example.com">info@example.com</a>.',
        )
        report = discover_contacts(target, [page])
        all_c = report.all()
        assert len(all_c) >= 1
        e = next(c for c in all_c if c.kind == "email")
        assert e.value == "info@example.com"
        assert e.confidence >= 0.75  # certo
        assert e.confidence_label == "certo"
        assert "mailto" in e.rationale.lower()

    def test_text_email_target_domain_match(self):
        target = classify_target("acme.com")
        page = _page(
            "https://acme.com/about",
            "About Acme",
            "Contact our CEO at ceo@acme.com for any inquiries.",
        )
        report = discover_contacts(target, [page])
        emails = [c for c in report.all() if c.kind == "email"]
        assert any(c.value == "ceo@acme.com" for c in emails)
        c = next(c for c in emails if c.value == "ceo@acme.com")
        # Same domain → strong, but no mailto link → not certo
        assert c.confidence >= 0.45
        assert "dominio" in c.rationale.lower()

    def test_external_email_low_confidence(self):
        """Email su dominio diverso dal target → bassa confidenza."""
        target = classify_target("acme.com")
        page = _page(
            "https://blog.unknown.net/post",
            "Random blog post",
            "Send feedback to feedback@unknown.net or call us.",
        )
        report = discover_contacts(target, [page])
        emails = [c for c in report.all() if c.kind == "email"]
        if emails:
            assert all(c.confidence < 0.45 for c in emails), \
                f"expected low confidence, got {[c.confidence for c in emails]}"

    def test_dedupe_same_email(self):
        target = classify_target("example.com")
        page1 = _page("https://example.com/p1", "x", "Contact info@example.com")
        page2 = _page("https://example.com/p2", "y", "Or info@example.com again")
        report = discover_contacts(target, [page1, page2])
        emails = [c for c in report.all() if c.kind == "email" and c.value == "info@example.com"]
        assert len(emails) == 1, "duplicate email not deduped"

    def test_uppercase_email_normalized(self):
        target = classify_target("example.com")
        page = _page("https://example.com/x", "x", "Write to INFO@Example.COM.")
        report = discover_contacts(target, [page])
        emails = [c for c in report.all() if c.kind == "email"]
        assert any(c.value == "info@example.com" for c in emails)

    def test_role_account_categorized(self):
        target = classify_target("example.com")
        page = _page("https://example.com/x", "x",
                     "noreply@example.com and sales@example.com and ceo@example.com")
        report = discover_contacts(target, [page])
        by_value = {c.value: c for c in report.all() if c.kind == "email"}
        assert by_value["noreply@example.com"].category == "role"
        assert by_value["sales@example.com"].category == "commercial"
        assert by_value["ceo@example.com"].category == "personal"


class TestMaskedEmails:
    def test_masked_email_marked_incomplete(self):
        target = classify_target("example.com")
        page = _page(
            "https://example.com/contact",
            "x",
            "Write to a***@example.com for technical support.",
        )
        report = discover_contacts(target, [page])
        # Find any incomplete email
        all_c = report.all()
        masked = [c for c in all_c if c.incomplete]
        assert masked, "Masked email not captured"
        m = masked[0]
        assert m.incomplete is True
        assert "mascherato" in m.incomplete_reason.lower() or "masked" in m.incomplete_reason.lower() or "mascherato" in m.rationale.lower()
        assert m.confidence <= 0.55  # masked is capped

    def test_masked_keeps_original_display(self):
        target = classify_target("example.com")
        page = _page("https://example.com/x", "x", "Mail: m***@example.com only.")
        report = discover_contacts(target, [page])
        masked = next((c for c in report.all() if c.incomplete), None)
        assert masked is not None
        assert "***" in masked.display or "***" in masked.value


class TestDiscoverPhones:
    def test_tel_link(self):
        target = classify_target("acme.com")
        page = _page(
            "https://acme.com/contact",
            "Contatti Acme",
            'Call us: <a href="tel:+390212345678">+39 02 12345678</a>',
        )
        report = discover_contacts(target, [page])
        phones = [c for c in report.all() if c.kind == "phone"]
        assert phones, "Phone from tel link not found"
        p = phones[0]
        assert p.value.startswith("+39")
        assert p.confidence >= 0.6


class TestAntiFalsePositive:
    def test_image_at_2x_not_email(self):
        """Common asset path 'image@2x' should NOT match as email."""
        target = classify_target("example.com")
        page = _page("https://example.com/x", "x",
                     "Background: url(image@2x.png) and logo@3x.png.")
        report = discover_contacts(target, [page])
        emails = [c for c in report.all() if c.kind == "email"]
        # @2x or @3x patterns are filtered out
        assert all("2x" not in c.value.split("@")[0] for c in emails)
        assert all("3x" not in c.value.split("@")[0] for c in emails)

    def test_unrelated_email_in_unrelated_page(self):
        target = classify_target("acme.com")
        page = _page("https://random-blog.example.net/post",
                     "Tech post — Random Blog",
                     "Send PRs to dev@otherthing.org.")
        report = discover_contacts(target, [page])
        # Either skipped or unconfirmed bucket
        assert len(report.certain) == 0
        # All low-confidence
        for c in report.all():
            assert c.confidence < 0.5


class TestEmptyAndDegenerate:
    def test_no_pages(self):
        target = classify_target("example.com")
        report = discover_contacts(target, [])
        assert report.all() == []
        assert report.pages_scanned == 0

    def test_page_with_error(self):
        target = classify_target("example.com")
        page = Page(url="https://example.com", status=500, error="timeout")
        report = discover_contacts(target, [page])
        assert report.all() == []
        assert report.pages_scanned == 1

    def test_page_with_no_text(self):
        target = classify_target("example.com")
        page = _page("https://example.com", "x", "")
        report = discover_contacts(target, [page])
        assert report.all() == []


class TestReportFields:
    def test_report_has_target_metadata(self):
        target = classify_target("acme.com")
        page = _page("https://acme.com/contact", "x", "info@acme.com")
        report = discover_contacts(target, [page])
        assert report.target == "acme.com"
        assert report.target_type == "domain"
        assert report.pages_scanned == 1
        assert report.sources_with_hits >= 1

    def test_count_by_kind(self):
        target = classify_target("acme.com")
        page = _page("https://acme.com/contact", "x",
                     'mailto:info@acme.com and <a href="tel:+391234567890">call</a>')
        report = discover_contacts(target, [page])
        counts = report.count_by_kind()
        assert counts["email"] >= 1
        assert counts["phone"] >= 1
