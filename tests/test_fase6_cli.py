"""Fase 6 — Bot CLI compliance.

Test:
  - classificazione operativa dei finding (verificato/probabile/...).
  - breakdown completo.
  - hook HighRiskResearchMode anche nel CLI: stampa banner su stderr.
"""
import io
import unittest
from contextlib import redirect_stderr
from unittest.mock import patch
from types import SimpleNamespace

from osint_bot.grading import (
    EVIDENCE_LEVEL_PROBABLE,
    EVIDENCE_LEVEL_UNKNOWN,
    EVIDENCE_LEVEL_UNVERIFIED,
    EVIDENCE_LEVEL_VERIFIED,
    classify_evidence_level,
    level_breakdown,
)
from osint_bot.models import Finding


class ClassifyEvidenceLevelTests(unittest.TestCase):
    def test_verified_for_top_admiralty(self):
        for rel, cred in [("A", 1), ("A", 2), ("B", 1), ("B", 2)]:
            self.assertEqual(classify_evidence_level(rel, cred), EVIDENCE_LEVEL_VERIFIED,
                             f"{rel}{cred}")

    def test_probable_for_middle(self):
        for rel, cred in [("A", 3), ("B", 3), ("C", 1), ("C", 2), ("C", 3)]:
            self.assertEqual(classify_evidence_level(rel, cred), EVIDENCE_LEVEL_PROBABLE,
                             f"{rel}{cred}")

    def test_unverified_for_lower(self):
        for rel, cred in [("B", 4), ("C", 4), ("C", 5), ("D", 2), ("E", 3)]:
            self.assertEqual(classify_evidence_level(rel, cred), EVIDENCE_LEVEL_UNVERIFIED,
                             f"{rel}{cred}")

    def test_unknown_for_f_or_credibility_6(self):
        for rel, cred in [("F", 6), ("F", 1), ("A", 6), ("D", 6)]:
            self.assertEqual(classify_evidence_level(rel, cred), EVIDENCE_LEVEL_UNKNOWN,
                             f"{rel}{cred}")

    def test_handles_invalid_input_safely(self):
        # Mai sollevare: una classifica errata diventa "non_disponibile".
        self.assertEqual(classify_evidence_level("", None), EVIDENCE_LEVEL_UNKNOWN)
        self.assertEqual(classify_evidence_level(None, "x"), EVIDENCE_LEVEL_UNKNOWN)


class LevelBreakdownTests(unittest.TestCase):
    def test_breakdown_always_has_all_4_keys(self):
        out = level_breakdown([])
        self.assertEqual(set(out.keys()),
                         {EVIDENCE_LEVEL_VERIFIED, EVIDENCE_LEVEL_PROBABLE,
                          EVIDENCE_LEVEL_UNVERIFIED, EVIDENCE_LEVEL_UNKNOWN})
        self.assertEqual(sum(out.values()), 0)

    def test_breakdown_counts_correctly(self):
        findings = [
            Finding(kind="x", value="a", confidence=0.9, source_reliability="A", info_credibility=1),
            Finding(kind="x", value="b", confidence=0.9, source_reliability="B", info_credibility=2),
            Finding(kind="x", value="c", confidence=0.6, source_reliability="C", info_credibility=3),
            Finding(kind="x", value="d", confidence=0.3, source_reliability="D", info_credibility=2),
            Finding(kind="x", value="e", confidence=0.1, source_reliability="F", info_credibility=6),
            Finding(kind="x", value="f", confidence=0.1, source_reliability="F", info_credibility=6),
        ]
        out = level_breakdown(findings)
        self.assertEqual(out[EVIDENCE_LEVEL_VERIFIED], 2)
        self.assertEqual(out[EVIDENCE_LEVEL_PROBABLE], 1)
        self.assertEqual(out[EVIDENCE_LEVEL_UNVERIFIED], 1)
        self.assertEqual(out[EVIDENCE_LEVEL_UNKNOWN], 2)


class CliOpsecBannerTests(unittest.TestCase):
    """Hook HighRiskResearchMode anche da CLI: stampa banner su stderr."""

    def _args(self, **kw):
        defaults = dict(target="example.com", type="domain", command="",
                        allow_darkweb=False, seed_url=[])
        defaults.update(kw)
        return SimpleNamespace(**defaults)

    def test_no_banner_for_benign_search(self):
        from osint_bot.cli import _print_opsec_banner_if_needed
        buf = io.StringIO()
        with redirect_stderr(buf):
            _print_opsec_banner_if_needed(self._args())
        self.assertEqual(buf.getvalue(), "")

    def test_banner_printed_when_allow_darkweb(self):
        from osint_bot.cli import _print_opsec_banner_if_needed
        buf = io.StringIO()
        with redirect_stderr(buf):
            _print_opsec_banner_if_needed(self._args(allow_darkweb=True))
        out = buf.getvalue()
        self.assertIn("OPSEC", out.upper())
        self.assertIn("dark/deep web", out)

    def test_banner_printed_when_onion_seed(self):
        from osint_bot.cli import _print_opsec_banner_if_needed
        buf = io.StringIO()
        with redirect_stderr(buf):
            _print_opsec_banner_if_needed(self._args(
                seed_url=["https://abc234xyzqrstuv.onion/forum"]))
        out = buf.getvalue()
        self.assertIn("onion", out.lower())

    def test_banner_printed_for_sensitive_tech_target(self):
        from osint_bot.cli import _print_opsec_banner_if_needed
        buf = io.StringIO()
        with redirect_stderr(buf):
            _print_opsec_banner_if_needed(self._args(target="vpn.example.com"))
        self.assertIn("sensibile", buf.getvalue())


class CliBreakdownPrintTests(unittest.TestCase):
    def test_breakdown_silent_on_empty(self):
        from osint_bot.cli import _print_evidence_breakdown
        buf = io.StringIO()
        with redirect_stderr(buf):
            _print_evidence_breakdown([])
        self.assertEqual(buf.getvalue(), "")

    def test_breakdown_prints_all_four_levels(self):
        from osint_bot.cli import _print_evidence_breakdown
        findings = [
            Finding(kind="x", value="a", confidence=0.9, source_reliability="A", info_credibility=1),
            Finding(kind="x", value="b", confidence=0.3, source_reliability="F", info_credibility=6),
        ]
        buf = io.StringIO()
        with redirect_stderr(buf):
            _print_evidence_breakdown(findings)
        out = buf.getvalue()
        for marker in ("verificato", "probabile", "non_verificato", "non_disponibile"):
            self.assertIn(marker, out)


if __name__ == "__main__":
    unittest.main()
