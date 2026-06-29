import argparse
import unittest

from osint_bot.safety import (
    SafetyError,
    assess_request,
    assert_darkweb_allowed,
    redact_email,
    redact_phone,
)


class SafetyTests(unittest.TestCase):
    def test_person_requires_authorization(self):
        with self.assertRaises(SafetyError):
            assess_request("Jane Doe", "person", False)

    def test_person_allowed_with_authorization(self):
        decision = assess_request("Jane Doe", "person", True)
        self.assertTrue(decision.allowed)

    def test_redacts_email_local_part(self):
        self.assertEqual(redact_email("security@example.com"), "s***y@example.com")

    def test_redacts_phone(self):
        self.assertEqual(redact_phone("+39 333 123 4567"), "********4567")


class WebPathGatesTests(unittest.TestCase):
    def test_assess_request_blocks_ssn_on_web_path(self):
        # The web job path runs run_investigation, which calls assess_request first.
        from osint_bot.cli import run_investigation

        ns = argparse.Namespace(
            target="123-45-6789",
            type="person",
            command=None,
            depth=1,
            provider="none",
            seed_url=[],
            max_results=1,
            max_pages=1,
            timeout=1,
            output_dir="reports",
            format="markdown",
            agent=["planner"],
            external_tool=[],
            proxy_url="",
            allow_network_scan=False,
            allow_darkweb=False,
            include_contact=False,
            confirm_authorization=True,
        )
        with self.assertRaises(SafetyError):
            run_investigation(ns)

    def test_assert_darkweb_allowed_blocks_without_flag(self):
        with self.assertRaises(SafetyError):
            assert_darkweb_allowed(False)
        # Should not raise when explicitly allowed.
        assert_darkweb_allowed(True)

    def test_run_agents_skips_darkweb_without_flag(self):
        from osint_bot.agents import AgentContext, run_agents

        context = AgentContext(
            target="example.com",
            target_type="domain",
            confirm_authorization=True,
            include_contact=False,
            allow_network_scan=False,
            search_results=[],
            pages=[],
            external_tools=[],
            timeout=1,
            allow_darkweb=False,
        )
        results = run_agents(context, ["planner", "darkweb"])
        names = {r.name for r in results}
        self.assertIn("planner", names)
        self.assertNotIn("darkweb", names)


if __name__ == "__main__":
    unittest.main()
