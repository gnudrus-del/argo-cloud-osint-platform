import unittest

from osint_bot.entities import (
    enrich_investigation_entities,
    extract_entities_from_text,
    normalize_url,
    normalize_value,
)
from osint_bot.models import Evidence, Finding, Investigation, Page, SearchResult


class EntityGraphTests(unittest.TestCase):
    def test_enriches_domain_investigation_with_url_and_domain_entities(self):
        investigation = Investigation.create(
            target="example.com",
            target_type="domain",
            safety_note="ok",
            queries=["example.com"],
            search_results=[SearchResult(title="Example", url="https://www.example.com/contact", provider="manual")],
            pages=[Page(url="https://www.example.com/contact", status=200, emails=["info@example.com"])],
            findings=[Finding(kind="related_domain", value="www.example.com", confidence=0.7, evidence=[Evidence("https://www.example.com")])],
        )

        enrich_investigation_entities(investigation)

        values = {(entity.type, entity.value) for entity in investigation.entities}
        self.assertIn(("domain", "example.com"), values)
        self.assertIn(("url", "https://www.example.com/contact"), values)
        self.assertIn(("email", "info@example.com"), values)
        self.assertTrue(investigation.relationships)

    def test_email_display_value_is_redacted(self):
        investigation = Investigation.create(
            target="user@example.com",
            target_type="email",
            safety_note="ok",
            queries=[],
            search_results=[],
            pages=[],
            findings=[],
        )

        enrich_investigation_entities(investigation)

        email_entities = [entity for entity in investigation.entities if entity.type == "email"]
        self.assertEqual(email_entities[0].display_value, "u***r@example.com")

    def test_extractor_rejects_invalid_ip_and_bare_digit_runs(self):
        # version-like 1.2.3.4 is a valid IP; we keep it. But out-of-range octet
        # 999.0.0.1 must be rejected. And bare phone-like digit runs without a
        # leading '+' must not be extracted as phone entities.
        text = "release v999.0.0.1 timestamp 1700000000123 build 12345678"
        results = extract_entities_from_text(text)
        kinds = {entity_type for entity_type, _ in results}
        self.assertNotIn("ip", kinds)
        self.assertNotIn("phone", kinds)

    def test_extractor_accepts_explicit_phone(self):
        results = extract_entities_from_text("Chiamare +39 333 123 4567 per info")
        self.assertTrue(any(t == "phone" for t, _ in results))

    def test_normalize_phone_canonicalizes_to_e164_when_plus(self):
        self.assertEqual(normalize_value("phone", "+39 333 123 4567"), "+393331234567")
        self.assertEqual(normalize_value("phone", "+39-333.123.4567"), "+393331234567")
        # Same number without explicit "+" stays as digits — caller is expected
        # to know the country code is missing.
        self.assertEqual(normalize_value("phone", "39 333 123 4567"), "393331234567")

    def test_normalize_email_gmail_canonical_form(self):
        self.assertEqual(
            normalize_value("email", "John.Doe+work@gmail.com"),
            "johndoe@gmail.com",
        )
        self.assertEqual(
            normalize_value("email", "John.Doe@googlemail.com"),
            "johndoe@gmail.com",
        )

    def test_normalize_domain_idn_to_punycode(self):
        self.assertEqual(normalize_value("domain", "Bücher.example"), "xn--bcher-kva.example")

    def test_normalize_url_strips_utm_params(self):
        url = "https://example.com/path?id=42&utm_source=newsletter&utm_medium=email&gclid=xyz"
        normalized = normalize_url(url)
        self.assertIn("id=42", normalized)
        self.assertNotIn("utm_", normalized)
        self.assertNotIn("gclid", normalized)

    def test_entity_takes_best_grade_across_findings(self):
        """If two findings about the same value have different grades, the
        merged entity keeps the better one (A2 beats C3)."""
        investigation = Investigation.create(
            target="example.com",
            target_type="domain",
            safety_note="ok",
            queries=[],
            search_results=[],
            pages=[],
            findings=[
                Finding(
                    kind="related_domain", value="example.com", confidence=0.6,
                    evidence=[Evidence("https://example.com")],
                    source_reliability="C", info_credibility=3,
                ),
                Finding(
                    kind="related_domain", value="example.com", confidence=0.8,
                    evidence=[Evidence("https://example.com/contact")],
                    source_reliability="A", info_credibility=2,
                ),
            ],
        )
        enrich_investigation_entities(investigation)

        domain_entities = [e for e in investigation.entities if e.type == "domain" and e.value == "example.com"]
        self.assertTrue(domain_entities, "expected at least one domain entity")
        merged = domain_entities[0]
        self.assertEqual((merged.source_reliability, merged.info_credibility), ("A", 2))

    def test_finding_quote_does_not_produce_phone_entity(self):
        # Quote contains a unix timestamp; must not surface as a phone entity.
        investigation = Investigation.create(
            target="example.com",
            target_type="domain",
            safety_note="ok",
            queries=[],
            search_results=[],
            pages=[],
            findings=[
                Finding(
                    kind="related_domain",
                    value="example.com",
                    confidence=0.7,
                    evidence=[Evidence(url="https://example.com", quote="timestamp 1700000000123 id 9999999999")],
                )
            ],
        )

        enrich_investigation_entities(investigation)

        kinds = {entity.type for entity in investigation.entities}
        self.assertNotIn("phone", kinds)
        self.assertNotIn("ip", kinds)


if __name__ == "__main__":
    unittest.main()
