"""Test offline per enrichment_ai: le capability pure-python (summary, regex NER,
language heuristic, resolution) sono deterministiche e non richiedono deps opzionali."""
import unittest

from osint_bot.enrichment_ai import (
    capabilities,
    detect_language,
    enrich_text,
    extractive_summary,
    named_entities,
    resolve_named_entities,
)


class EnrichmentAITests(unittest.TestCase):
    def test_capabilities_always_has_summary_and_regex(self):
        caps = capabilities()
        self.assertTrue(caps["summarization"])
        self.assertTrue(caps["ner_regex_fallback"])
        # le altre sono bool (presenti o meno)
        for k in ("ocr", "ner_spacy", "language_id", "translate"):
            self.assertIn(k, caps)
            self.assertIsInstance(caps[k], bool)

    def test_regex_ner_extracts_structured_identifiers(self):
        text = ("Contatta mario.rossi@example.com oppure +39 06 6982 1234. "
                "Sito https://example.com e IP 93.184.216.34. "
                "Wallet 0x1234567890abcdef1234567890abcdef12345678.")
        ents = named_entities(text)
        labels = {(e.label, e.text) for e in ents}
        found_labels = {e.label for e in ents}
        self.assertIn("EMAIL", found_labels)
        self.assertIn("URL", found_labels)
        self.assertIn("IP", found_labels)
        self.assertIn("CRYPTO", found_labels)
        self.assertTrue(any(e.text == "mario.rossi@example.com" for e in ents))

    def test_person_candidate_from_capitalized_sequence(self):
        ents = named_entities("Il sospetto Mario Rossi ha incontrato Giuseppe Verdi.")
        persons = [e.text for e in ents if e.label == "PERSON"]
        self.assertIn("Mario Rossi", persons)

    def test_org_hint_detected(self):
        ents = named_entities("La società Acme Holding SRL opera a Roma.")
        orgs = [e.text for e in ents if e.label == "ORG"]
        self.assertTrue(any("Acme" in o for o in orgs))

    def test_extractive_summary_shorter_than_input(self):
        text = " ".join(
            f"Frase numero {i} che parla di dominio example e di indagine osint."
            for i in range(20)
        )
        summary = extractive_summary(text, max_sentences=3)
        self.assertTrue(summary)
        self.assertLessEqual(summary.count("."), 4)

    def test_summary_returns_full_when_short(self):
        text = "Una frase sola."
        self.assertEqual(extractive_summary(text, max_sentences=5), "Una frase sola.")

    def test_detect_language_heuristic(self):
        self.assertEqual(detect_language("questo che non per della sono"), "it")
        self.assertEqual(detect_language("the and for with that this from"), "en")

    def test_resolution_dedupes_by_normalized_value(self):
        from osint_bot.enrichment_ai import NamedEntity
        ents = [
            NamedEntity("Example.com", "DOMAIN", 0.6),
            NamedEntity("www.example.com", "DOMAIN", 0.7),
        ]
        resolved = resolve_named_entities(ents)
        domains = [e for e in resolved if e.label == "DOMAIN"]
        self.assertEqual(len(domains), 1)
        self.assertEqual(domains[0].confidence, 0.7)

    def test_enrich_text_end_to_end(self):
        out = enrich_text("Mario Rossi vive a Roma, email mario@example.com.",
                          summarize=True)
        self.assertIn("language", out)
        self.assertIn("entities", out)
        self.assertIn("summary", out)
        self.assertGreater(out["entity_count"], 0)

    def test_empty_text_safe(self):
        self.assertEqual(named_entities(""), [])
        self.assertEqual(extractive_summary(""), "")
        self.assertEqual(detect_language(""), "und")


if __name__ == "__main__":
    unittest.main()
