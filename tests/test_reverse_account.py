import time
import unittest

from osint_bot.agents import AgentContext, ReverseAccountAgent, run_agents
from osint_bot.models import Evidence, Finding
from osint_bot.plugins import PluginRegistry, PluginResult


class _FakePlugin:
    """Plugin double that returns a canned URL finding."""

    def __init__(self, name: str, urls: list[str]):
        self.name = name
        self._urls = urls
        self.passive = True
        self.gated = True

    def run(self, _ctx):
        now = time.time()
        findings = [
            Finding(
                kind=f"external_{self.name}_profile",
                value=url,
                confidence=0.55,
                evidence=[Evidence(url=f"tool://{self.name}", title=self.name, quote=url)],
            )
            for url in self._urls
        ]
        return PluginResult(
            plugin=self.name,
            status="ok",
            started_at=now,
            finished_at=now,
            findings=findings,
        )


def _context(target: str, target_type: str, confirm: bool = True) -> AgentContext:
    return AgentContext(
        target=target,
        target_type=target_type,
        confirm_authorization=confirm,
        include_contact=False,
        allow_network_scan=False,
        search_results=[],
        pages=[],
        external_tools=[],
        timeout=1,
    )


class ReverseAccountAgentTests(unittest.TestCase):
    def test_skipped_for_non_email_phone_target(self):
        result = ReverseAccountAgent().run(_context("example.com", "domain"))
        self.assertEqual(result.status, "skipped")

    def test_skipped_without_authorization(self):
        result = ReverseAccountAgent().run(_context("alice@example.com", "email", confirm=False))
        self.assertEqual(result.status, "skipped")

    def test_aggregates_email_tool_results_into_platform_summary(self):
        # Patch the parallel runner so we don't actually shell out.
        registry = PluginRegistry()
        registry.register(_FakePlugin("holehe", ["https://github.com/alice"]))
        registry.register(_FakePlugin("h8mail", []))
        registry.register(_FakePlugin("ghunt", ["https://www.linkedin.com/in/alice"]))
        registry.register(_FakePlugin("mosint", []))
        registry.register(_FakePlugin("socialscan", ["https://twitter.com/alice"]))

        import osint_bot.agents as agents_module
        original = agents_module.run_plugins_parallel
        try:
            agents_module.run_plugins_parallel = lambda names, ctx: [registry.get(n).run(ctx) for n in names]
            result = ReverseAccountAgent().run(_context("alice@example.com", "email"))
        finally:
            agents_module.run_plugins_parallel = original

        urls = [f.value for f in result.findings]
        self.assertIn("https://github.com/alice", urls)
        self.assertIn("https://www.linkedin.com/in/alice", urls)
        self.assertIn("https://twitter.com/alice", urls)
        # Every match must be re-tagged as reverse_account_match.
        kinds = {f.kind for f in result.findings}
        self.assertEqual(kinds, {"reverse_account_match"})
        self.assertIn("github.com", result.summary)
        self.assertIn("linkedin.com", result.summary)

    def test_orchestrator_run_agents_includes_reverse_account_when_email(self):
        context = _context("alice@example.com", "email")
        # The reverse_account agent will hit real plugin lookups; since none of
        # the tools are installed, ExternalToolPlugin returns 'missing' for each
        # but the agent must still finish without raising.
        results = run_agents(context, ["planner", "reverse_account"])
        names = {r.name for r in results}
        self.assertIn("reverse_account", names)


if __name__ == "__main__":
    unittest.main()
