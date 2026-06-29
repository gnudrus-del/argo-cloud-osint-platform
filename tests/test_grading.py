import unittest

from osint_bot.grading import (
    Grade,
    apply_default_grades,
    better_grade,
    default_grade_for,
    distribution,
)
from osint_bot.models import Finding


class GradeValidationTests(unittest.TestCase):
    def test_valid_grade_construction(self):
        g = Grade("B", 2)
        self.assertEqual(g.code, "B2")
        self.assertIn("affidabile", g.label_it.casefold())

    def test_reliability_rejects_unknown_letter(self):
        with self.assertRaises(ValueError):
            Grade("Z", 1)

    def test_credibility_rejects_unknown_number(self):
        with self.assertRaises(ValueError):
            Grade("A", 7)


class GradeOrderingTests(unittest.TestCase):
    def test_a1_is_better_than_b2(self):
        self.assertTrue(Grade("A", 1).is_better_than(Grade("B", 2)))
        self.assertFalse(Grade("B", 2).is_better_than(Grade("A", 1)))

    def test_equal_grades_neither_is_better(self):
        self.assertFalse(Grade("C", 3).is_better_than(Grade("C", 3)))

    def test_b1_better_than_b2_same_reliability(self):
        self.assertTrue(Grade("B", 1).is_better_than(Grade("B", 2)))

    def test_a6_vs_b1_reliability_wins(self):
        # NATO ordering puts reliability first: A6 outranks B1 because the
        # source is more trustworthy even if the fact is unrated.
        self.assertTrue(Grade("A", 6).is_better_than(Grade("B", 1)))


class BetterGradeMergeTests(unittest.TestCase):
    def test_picks_better_when_one_is_obvious(self):
        self.assertEqual(better_grade("A", 1, "F", 6), ("A", 1))
        self.assertEqual(better_grade("F", 6, "B", 2), ("B", 2))

    def test_ties_keep_first(self):
        self.assertEqual(better_grade("C", 3, "C", 3), ("C", 3))


class DefaultGradeForKindTests(unittest.TestCase):
    def test_known_kind_returns_expected_default(self):
        self.assertEqual(default_grade_for("media_file_metadata"), ("A", 2))
        self.assertEqual(default_grade_for("opsec_possible_aws_access_key"), ("B", 2))
        self.assertEqual(default_grade_for("darkweb_onion_reference"), ("D", 4))

    def test_unknown_kind_defaults_to_unrated(self):
        # F6 is the honest "no idea" position.
        self.assertEqual(default_grade_for("kind_that_does_not_exist"), ("F", 6))


class ApplyDefaultGradesTests(unittest.TestCase):
    def test_back_fills_only_unrated_findings(self):
        findings = [
            Finding(kind="media_file_metadata", value="file.png", confidence=0.85),
            Finding(kind="opsec_possible_aws_access_key", value="x", confidence=0.65),
            Finding(kind="kind_does_not_exist", value="y", confidence=0.4),
            # This one was already graded by its agent — must not be overwritten.
            Finding(kind="opsec_possible_aws_access_key", value="z", confidence=0.6,
                    source_reliability="A", info_credibility=1),
        ]
        apply_default_grades(findings)
        self.assertEqual((findings[0].source_reliability, findings[0].info_credibility), ("A", 2))
        self.assertEqual((findings[1].source_reliability, findings[1].info_credibility), ("B", 2))
        self.assertEqual((findings[2].source_reliability, findings[2].info_credibility), ("F", 6))
        # Explicit grade preserved.
        self.assertEqual((findings[3].source_reliability, findings[3].info_credibility), ("A", 1))


class DistributionTests(unittest.TestCase):
    def test_counts_by_grade_code(self):
        findings = [
            Finding(kind="x", value="1", confidence=0.5, source_reliability="A", info_credibility=1),
            Finding(kind="x", value="2", confidence=0.5, source_reliability="A", info_credibility=1),
            Finding(kind="x", value="3", confidence=0.5, source_reliability="C", info_credibility=3),
        ]
        self.assertEqual(distribution(findings), {"A1": 2, "C3": 1})


if __name__ == "__main__":
    unittest.main()
