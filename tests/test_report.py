import unittest

from osint_bot.entities import enrich_investigation_entities
from osint_bot.models import AgentResult, Evidence, Finding, Investigation, SearchResult
from osint_bot.report import to_markdown


class ReportTests(unittest.TestCase):
    def test_entity_section_prioritizes_investigative_entities(self):
        investigation = Investigation.create(
            target="example.com",
            target_type="domain",
            safety_note="ok",
            queries=["site:example.com"],
            search_results=[
                SearchResult("Google dork", "https://www.google.com/search?q=site%3Aexample.com", provider="google_dork"),
                SearchResult("Home", "https://example.com", provider="seed"),
            ],
            pages=[],
            findings=[],
        )
        enrich_investigation_entities(investigation)

        markdown = to_markdown(investigation)

        self.assertIn("## Entita e relazioni", markdown)
        self.assertIn("**example.com** (`domain`)", markdown)
        self.assertIn("**https://example.com** (`url`)", markdown)
        self.assertNotIn("**google.com** (`domain`)", markdown)
        # Pillar 0.5: entity lines now carry an Admiralty grade.
        self.assertIn("grado `F6`", markdown)
        self.assertIn("## Affidabilità delle evidenze (Admiralty)", markdown)

    def test_finding_lines_show_admiralty_grade(self):
        investigation = Investigation.create(
            target="example.com",
            target_type="domain",
            safety_note="ok",
            queries=[],
            search_results=[],
            pages=[],
            findings=[
                Finding(
                    kind="related_domain", value="sub.example.com",
                    confidence=0.7,
                    evidence=[Evidence(url="https://sub.example.com")],
                    source_reliability="B", info_credibility=2,
                )
            ],
        )
        markdown = to_markdown(investigation)
        self.assertIn("grado **B2**", markdown)
        # Distribution block must list the grade with count.
        self.assertIn("`B2` — 1 evidenza", markdown)

    def test_narrative_runbook_mentions_agents_and_tools(self):
        investigation = Investigation.create(
            target="alice@example.com",
            target_type="email",
            safety_note="ok",
            queries=[],
            search_results=[],
            pages=[],
            findings=[],
            agent_results=[
                AgentResult(
                    name="reverse_account",
                    status="ok",
                    summary="Account associati a contatto: holehe: github.com; ghunt: linkedin.com",
                    findings=[Finding(kind="reverse_account_match", value="https://github.com/alice", confidence=0.7)],
                    notes=["holehe: ok (320 ms).", "ghunt: ok (1200 ms).", "h8mail: missing (5 ms)."],
                ),
                AgentResult(
                    name="darkweb",
                    status="skipped",
                    summary="darkweb non autorizzato",
                ),
            ],
        )
        markdown = to_markdown(investigation)
        self.assertIn("## Cosa abbiamo eseguito", markdown)
        # The narrative should mention the agent and the tools it invoked, in IT prose.
        self.assertIn("Reverse-account", markdown)
        self.assertIn("Holehe", markdown)
        self.assertIn("GHunt", markdown)
        # Skipped agent must be called out in a single closing sentence.
        self.assertIn("saltati", markdown.casefold())
        self.assertIn("Deep/dark web", markdown)


if __name__ == "__main__":
    unittest.main()
