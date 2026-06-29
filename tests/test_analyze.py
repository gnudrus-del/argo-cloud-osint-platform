import unittest

from osint_bot.analyze import analyze
from osint_bot.models import Page, SearchResult


class AnalyzeTests(unittest.TestCase):
    def test_analyze_redacts_contacts_by_default(self):
        pages = [
            Page(
                url="https://example.com",
                status=200,
                title="Example",
                text="Built with WordPress in 2024.",
                emails=["info@example.com"],
            )
        ]
        findings = analyze("example.com", "domain", [SearchResult("Example", "https://example.com")], pages, False)
        values = {finding.value for finding in findings}
        kinds = {finding.kind for finding in findings}

        self.assertIn("i***o@example.com", values)
        self.assertIn("technology_mention", kinds)
        self.assertIn("related_domain", kinds)


if __name__ == "__main__":
    unittest.main()

