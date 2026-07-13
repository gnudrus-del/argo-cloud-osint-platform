import unittest

from osint_bot.agents import AgentContext, RedTeamAgent
from osint_bot.models import Page


def _ctx(pages: list[Page], confirm: bool = True, target_type: str = "domain") -> AgentContext:
    return AgentContext(
        target="example.com",
        target_type=target_type,
        confirm_authorization=confirm,
        include_contact=False,
        allow_network_scan=False,
        search_results=[],
        pages=pages,
        external_tools=[],
        timeout=1,
    )


class RedTeamAgentTests(unittest.TestCase):
    def test_skipped_without_authorization(self):
        result = RedTeamAgent().run(_ctx([], confirm=False))
        self.assertEqual(result.status, "skipped")

    def test_flags_subdomain_takeover_candidate(self):
        page = Page(
            url="https://example.com",
            status=200,
            title="Home",
            text="Visit blog",
            links=["https://blog-example.github.io/posts/x"],
        )
        result = RedTeamAgent().run(_ctx([page]))
        kinds = {f.kind for f in result.findings}
        self.assertIn("red_team_takeover_candidate", kinds)
        values = [f.value for f in result.findings if f.kind == "red_team_takeover_candidate"]
        self.assertIn("blog-example.github.io", values)

    def test_flags_exposed_path_reference(self):
        page = Page(
            url="https://example.com",
            status=200,
            title="Home",
            text="Pages: /admin /server-status",
            links=[],
        )
        result = RedTeamAgent().run(_ctx([page]))
        labels = [f.value for f in result.findings if f.kind == "red_team_exposed_path"]
        self.assertIn("Apache server-status esposto", labels)


if __name__ == "__main__":
    unittest.main()
