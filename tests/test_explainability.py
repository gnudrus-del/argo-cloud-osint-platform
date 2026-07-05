"""Fase 7 — spiegabilita': perche' collegato + cosa manca per confermare."""
import unittest

from osint_bot.explainability import explain_finding, enrich_investigation_explanations
from osint_bot.models import Evidence, Finding, Investigation, Provenance


def _f(**kw) -> Finding:
    base = dict(kind="contact_email", value="info@example.com",
                confidence=0.7, source_reliability="C", info_credibility=3)
    base.update(kw)
    return Finding(**base)


class WhyLinkedTests(unittest.TestCase):
    def test_exact_match_target_explained(self):
        f = explain_finding(_f(value="example.com"), target="example.com",
                            target_type="domain")
        self.assertTrue(any("identico al target" in w for w in f.why_linked))

    def test_substring_match_target_explained(self):
        f = explain_finding(_f(value="acme spa srl"), target="ACME",
                            target_type="company")
        self.assertTrue(any("sovrapposto" in w for w in f.why_linked))

    def test_provenance_tool_mentioned(self):
        prov = Provenance(tool="theHarvester", collected_at="2026-06-30T12:00:00Z")
        f = explain_finding(_f(provenance=prov))
        self.assertTrue(any("theHarvester" in w for w in f.why_linked))

    def test_admiralty_grade_mentioned(self):
        f = explain_finding(_f(source_reliability="B", info_credibility=2))
        self.assertTrue(any("B2" in w or "verificato" in w for w in f.why_linked))


class GapsTests(unittest.TestCase):
    def test_unrated_finding_says_no_verified_source(self):
        f = explain_finding(_f(source_reliability="F", info_credibility=6))
        self.assertTrue(any("nessuna fonte verificata" in g for g in f.gaps))

    def test_corroboration_hint_added_for_email_alone(self):
        f = explain_finding(_f(kind="contact_email", value="x@y.com"))
        self.assertTrue(any("corroborazione" in g for g in f.gaps))

    def test_corroboration_hint_skipped_when_already_corroborated(self):
        f1 = _f(value="x@y.com")
        f2 = _f(value="x@y.com")  # stesso kind + valore = corroborazione
        explain_finding(f1, siblings=[f1, f2])
        self.assertFalse(any("manca corroborazione" in g for g in f1.gaps))

    def test_missing_provenance_explained(self):
        f = explain_finding(_f(provenance=None))
        self.assertTrue(any("provenance assente" in g for g in f.gaps))

    def test_partial_provenance_flags_missing_pieces(self):
        prov = Provenance(tool="x", collected_at="")  # manca timestamp
        f = explain_finding(_f(provenance=prov))
        self.assertTrue(any("timestamp" in g for g in f.gaps))

    def test_contradictions_flagged(self):
        f1 = _f(kind="related_domain", value="acme.com")
        f2 = _f(kind="related_domain", value="acme.org")  # diverso valore stesso kind
        explain_finding(f1, siblings=[f1, f2])
        self.assertTrue(any("conflitto" in g for g in f1.gaps))

    def test_no_evidence_url_flagged(self):
        f = explain_finding(_f(evidence=[]))
        self.assertTrue(any("link-evidenza" in g for g in f.gaps))

    def test_low_confidence_no_notes_flagged(self):
        f = explain_finding(_f(confidence=0.2, notes=""))
        self.assertTrue(any("confidence bassa" in g for g in f.gaps))

    def test_low_confidence_with_notes_NOT_flagged(self):
        f = explain_finding(_f(confidence=0.2, notes="parsing parziale, da verificare"))
        self.assertFalse(any("confidence bassa" in g for g in f.gaps))


class IdempotenceTests(unittest.TestCase):
    def test_running_twice_does_not_duplicate(self):
        f = _f()
        explain_finding(f, target="example.com")
        first_why = list(f.why_linked); first_gaps = list(f.gaps)
        explain_finding(f, target="example.com")
        self.assertEqual(f.why_linked, first_why)
        self.assertEqual(f.gaps, first_gaps)


class InvestigationLevelTests(unittest.TestCase):
    def test_enrich_all_findings(self):
        inv = Investigation.create(
            target="example.com", target_type="domain",
            safety_note="", queries=[], search_results=[], pages=[],
            findings=[_f(value="example.com"), _f(value="acme.com")],
        )
        enrich_investigation_explanations(inv)
        for f in inv.findings:
            self.assertTrue(f.why_linked, "why_linked dovrebbe sempre essere popolato")
            self.assertTrue(f.gaps, "gaps dovrebbe sempre essere popolato")


if __name__ == "__main__":
    unittest.main()
