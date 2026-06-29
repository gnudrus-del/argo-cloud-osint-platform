"""NATO/Admiralty grading for findings and entities.

This is the language an intelligence analyst (and an institutional reviewer)
expects: every claim ships with a two-axis grade — how trustworthy the source
is and how credible the information is on its own merits — instead of a single
opaque "confidence" number.

NATO STANAG 2511 (the Admiralty Code) defines:

    Source reliability (A–F)
      A  Completely reliable           — verified history, official channel
      B  Usually reliable              — known good track record
      C  Fairly reliable               — sometimes correct, needs corroboration
      D  Not usually reliable          — frequently wrong but occasionally useful
      E  Unreliable                    — known to be untrustworthy
      F  Reliability cannot be judged  — first encounter, no track record

    Information credibility (1–6)
      1  Confirmed by other sources
      2  Probably true
      3  Possibly true
      4  Doubtful
      5  Improbable
      6  Truth cannot be judged

Together they form codes like A1, B2, F6. A1 = gold, F6 = unrated.

Why this matters for Gufo: a finding from a verified TLS-served corporate page
is not the same as a finding scraped from a 4chan paste, and an institutional
user needs to see the difference at a glance — not buried in a free-text note.
"""

from __future__ import annotations

from dataclasses import dataclass

# Ordered worst→best for arithmetic; numerically lower index == better.
RELIABILITY_ORDER = ("A", "B", "C", "D", "E", "F")
CREDIBILITY_ORDER = (1, 2, 3, 4, 5, 6)

RELIABILITY_LABELS_IT = {
    "A": "Completamente affidabile",
    "B": "Solitamente affidabile",
    "C": "Discretamente affidabile",
    "D": "Non solitamente affidabile",
    "E": "Inaffidabile",
    "F": "Affidabilità non valutabile",
}
CREDIBILITY_LABELS_IT = {
    1: "Confermata da altre fonti",
    2: "Probabilmente vera",
    3: "Possibilmente vera",
    4: "Dubbia",
    5: "Improbabile",
    6: "Veridicità non valutabile",
}

VALID_RELIABILITY = set(RELIABILITY_ORDER)
VALID_CREDIBILITY = set(CREDIBILITY_ORDER)


@dataclass(frozen=True)
class Grade:
    reliability: str
    credibility: int

    def __post_init__(self) -> None:
        if self.reliability not in VALID_RELIABILITY:
            raise ValueError(f"Reliability must be one of {sorted(VALID_RELIABILITY)}: got {self.reliability!r}")
        if self.credibility not in VALID_CREDIBILITY:
            raise ValueError(f"Credibility must be one of {sorted(VALID_CREDIBILITY)}: got {self.credibility!r}")

    @property
    def code(self) -> str:
        return f"{self.reliability}{self.credibility}"

    @property
    def label_it(self) -> str:
        return f"{RELIABILITY_LABELS_IT[self.reliability]}, {CREDIBILITY_LABELS_IT[self.credibility]}"

    def is_better_than(self, other: "Grade") -> bool:
        """A1 beats B2 beats F6. Equal grades are not "better"."""
        return _grade_rank(self) < _grade_rank(other)


def _grade_rank(grade: "Grade | tuple[str, int]") -> tuple[int, int]:
    if isinstance(grade, tuple):
        r, c = grade
    else:
        r, c = grade.reliability, grade.credibility
    return (RELIABILITY_ORDER.index(r), CREDIBILITY_ORDER.index(c))


def better_grade(a_rel: str, a_cred: int, b_rel: str, b_cred: int) -> tuple[str, int]:
    """Return the more authoritative of two grades, by Admiralty ordering.

    Used when two findings merge into the same entity: the resulting entity
    should advertise the *best* evidence seen, not the average — that's how
    analysts read graded sources.
    """
    if _grade_rank((a_rel, a_cred)) <= _grade_rank((b_rel, b_cred)):
        return (a_rel, a_cred)
    return (b_rel, b_cred)


# ----------------------------------------------------------- Heuristic defaults

# These are *defaults* — every call site should override when it has better
# knowledge of the source. The mapping is conservative: when in doubt, mark
# the source as "fairly reliable, possibly true" (C3) rather than overclaim.

_DEFAULT_GRADES: dict[str, tuple[str, int]] = {
    # Hard evidence we computed ourselves (file metadata, classification).
    "media_file_metadata": ("A", 2),
    "ip_classification": ("A", 1),

    # Web crawl observations (we fetched, we parsed): pretty reliable as
    # source, "probably true" as fact for what was visible.
    "web_presence": ("B", 2),
    "agent_web_coverage": ("B", 2),
    "related_domain": ("B", 2),
    "contact_email": ("B", 2),
    "redacted_contact_email": ("B", 2),

    # Hints surfaced by pattern-matching over public text — needs corroboration.
    "public_document": ("C", 2),
    "technology_mention": ("C", 3),
    "timeline_year_mention": ("C", 3),

    # OPSEC hints from public text or links — possibly true but never proof.
    "opsec_possible_token": ("C", 3),
    "opsec_possible_private_key": ("B", 2),  # leading marker is strong
    "opsec_possible_aws_access_key": ("B", 2),
    "opsec_sensitive_path_reference": ("C", 3),

    # Crypto: explorer-grade observations.
    "crypto_address": ("B", 2),

    # Phone normalization.
    "phone_format": ("C", 3),

    # Geo: coordinate mentions and map links are *signals*, not facts.
    "geo_coordinate_mention": ("C", 3),
    "geo_map_link": ("C", 3),

    # Profile candidates from socmint heuristics: hostname matches social, but
    # attribution is not automatic.
    "possible_profile": ("C", 3),
    "socmint_public_profile_reference": ("C", 3),
    "public_media_reference": ("C", 3),

    # External tool outputs default to D3: "not usually reliable" because their
    # output frequently includes false positives; "possibly true".
    # Per-tool overrides live below.
    "external_sherlock_profile": ("C", 3),
    "external_maigret_profile": ("C", 3),
    "external_social_analyzer_profile": ("D", 3),
    "external_toutatis_profile": ("D", 3),
    "external_osintgram_profile": ("D", 3),

    # Reverse-account aggregated matches: better than raw tool output because
    # they passed the agent's filter, but still need human attribution.
    "reverse_account_match": ("C", 2),

    # Red team hints: hard to forge fingerprints + exposed-path markers.
    "red_team_takeover_candidate": ("B", 3),
    "red_team_exposed_path": ("B", 3),

    # Darkweb references: source is anonymous, treat as not-usually-reliable.
    "darkweb_onion_reference": ("D", 4),

    # HUMINT/method artefacts: planner artefacts, not field facts.
    "humint_interview_plan": ("F", 6),
}


def default_grade_for(finding_kind: str) -> tuple[str, int]:
    """Return the conservative default (reliability, credibility) for a kind.

    Unknown kinds default to F6 — the honest "unrated" position. Callers
    should set the grade explicitly whenever the source is known.
    """
    return _DEFAULT_GRADES.get(finding_kind, ("F", 6))


def apply_default_grades(findings) -> None:
    """Back-fill the Admiralty grade on findings that still carry the F6 default.

    Run at the end of the pipeline so every agent doesn't have to remember to
    set a grade: anything left unrated gets the conservative default for its
    kind. Explicit grades set by an agent are *never* overwritten.
    """
    for finding in findings:
        if (finding.source_reliability, finding.info_credibility) == ("F", 6):
            r, c = default_grade_for(finding.kind)
            finding.source_reliability = r
            finding.info_credibility = c


def distribution(findings) -> dict[str, int]:
    """Histogram of finding grades, e.g. {'B2': 14, 'C3': 7, 'F6': 2}.

    Used by the report's narrative section so the analyst sees grading at a
    glance ("la maggior parte delle evidenze ha grado B2…").
    """
    bucket: dict[str, int] = {}
    for finding in findings:
        code = f"{finding.source_reliability}{finding.info_credibility}"
        bucket[code] = bucket.get(code, 0) + 1
    return bucket
