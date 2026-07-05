"""Fase 4 — scoring trasparente."""
import unittest
from datetime import datetime, timedelta, timezone

from osint_bot.scoring import (
    WEIGHTS,
    compute_score,
    score_contradictions,
    score_exact_match,
    score_fuzzy_match,
    score_recency,
    score_source_reliability,
)


class WeightsTests(unittest.TestCase):
    def test_weights_sum_to_one(self):
        # Invariante: la confidenza e' una media pesata, somma=1.0.
        self.assertAlmostEqual(sum(WEIGHTS.values()), 1.0, places=6)


class ExactMatchTests(unittest.TestCase):
    def test_exact_equal_after_normalization(self):
        s, r = score_exact_match("Example.com", "EXAMPLE.COM")
        self.assertEqual(s, 1.0)
        self.assertIn("combacia", r)

    def test_different_values_score_zero(self):
        s, _ = score_exact_match("alpha", "beta")
        self.assertEqual(s, 0.0)

    def test_empty_inputs(self):
        self.assertEqual(score_exact_match("", "x")[0], 0.0)
        self.assertEqual(score_exact_match("x", "")[0], 0.0)


class FuzzyMatchTests(unittest.TestCase):
    def test_substring_scores_high(self):
        s, _ = score_fuzzy_match("Acme Spa", "Acme")
        self.assertGreaterEqual(s, 0.8)

    def test_partial_overlap(self):
        s, _ = score_fuzzy_match("Rossi Mario Luca", "Mario Rossi")
        self.assertGreater(s, 0.0)
        self.assertLess(s, 1.0)

    def test_no_overlap(self):
        s, _ = score_fuzzy_match("foo bar", "qux quux")
        self.assertEqual(s, 0.0)


class SourceReliabilityTests(unittest.TestCase):
    def test_top_grade_high_score(self):
        s, r = score_source_reliability("A", 1)
        self.assertGreater(s, 0.9)
        self.assertIn("verificato", r)

    def test_unrated_low_score(self):
        s, r = score_source_reliability("F", 6)
        self.assertLess(s, 0.2)
        self.assertIn("non_disponibile", r)

    def test_safe_on_garbage(self):
        s, _ = score_source_reliability(None, None)  # type: ignore[arg-type]
        # Non solleva e restituisce un valore basso.
        self.assertLess(s, 0.2)


class RecencyTests(unittest.TestCase):
    def test_today_is_one(self):
        now = datetime.now(timezone.utc)
        s, _ = score_recency(now.isoformat(), now=now)
        self.assertAlmostEqual(s, 1.0, places=2)

    def test_six_months_about_half(self):
        now = datetime(2026, 6, 1, tzinfo=timezone.utc)
        past = now - timedelta(days=180)
        s, _ = score_recency(past.isoformat(), now=now)
        # half-life 180gg -> ~0.37 (exp(-1))
        self.assertGreater(s, 0.30)
        self.assertLess(s, 0.45)

    def test_very_old_near_zero(self):
        now = datetime(2026, 6, 1, tzinfo=timezone.utc)
        past = now - timedelta(days=365 * 10)
        s, _ = score_recency(past.isoformat(), now=now)
        self.assertLess(s, 0.001)

    def test_missing_timestamp_is_neutral(self):
        s, _ = score_recency("")
        self.assertEqual(s, 0.5)


class ContradictionsTests(unittest.TestCase):
    def test_no_conflicts_is_one(self):
        s, _ = score_contradictions("alpha", [])
        self.assertEqual(s, 1.0)

    def test_one_conflict(self):
        s, _ = score_contradictions("alpha", ["beta"])
        self.assertLess(s, 1.0)
        self.assertGreater(s, 0.4)

    def test_more_conflicts_lower_score(self):
        s2, _ = score_contradictions("alpha", ["beta", "gamma"])
        s3, _ = score_contradictions("alpha", ["beta", "gamma", "delta"])
        self.assertLess(s3, s2)

    def test_same_value_not_a_conflict(self):
        s, _ = score_contradictions("alpha", ["alpha", "alpha"])
        self.assertEqual(s, 1.0)


class ComputeScoreTests(unittest.TestCase):
    def test_perfect_finding_scores_near_one(self):
        now = datetime(2026, 6, 1, tzinfo=timezone.utc)
        breakdown = compute_score(
            value="example.com",
            target="example.com",
            reliability="A",
            credibility=1,
            collected_at=now.isoformat(),
            other_values_same_kind=[],
            now=now,
        )
        self.assertGreater(breakdown.confidence, 0.85)
        self.assertEqual(breakdown.level, "verificato")
        # Tutte le 5 rationale lines presenti.
        self.assertEqual(len(breakdown.rationale), 5)

    def test_unrated_with_conflicts_scores_low(self):
        breakdown = compute_score(
            value="probable name",
            target="totally different",
            reliability="F",
            credibility=6,
            collected_at="",
            other_values_same_kind=["other 1", "other 2", "other 3"],
        )
        self.assertLess(breakdown.confidence, 0.40)
        self.assertEqual(breakdown.level, "non_disponibile")

    def test_to_dict_serializable(self):
        b = compute_score(value="x", target="x", reliability="B", credibility=2, collected_at="")
        d = b.to_dict()
        self.assertIn("confidence", d)
        self.assertIn("rationale", d)
        self.assertIsInstance(d["rationale"], list)


if __name__ == "__main__":
    unittest.main()
