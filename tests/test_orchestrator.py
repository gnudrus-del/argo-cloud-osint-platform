import unittest

from osint_bot.orchestrator import plan_from_command


class OrchestratorTests(unittest.TestCase):
    def test_domain_command_selects_opsec_and_geo(self):
        profile = plan_from_command("Analizza example.com come dominio, valuta OPSEC e geo pubblica")
        self.assertEqual(profile.target, "example.com")
        self.assertEqual(profile.target_type, "domain")
        self.assertIn("opsec", profile.agents)
        self.assertIn("geo", profile.agents)

    def test_auto_tools_for_authorized_handle(self):
        profile = plan_from_command(
            "Cerca username @example con tool automatici",
            confirm_authorization=True,
        )
        self.assertEqual(profile.target_type, "handle")
        self.assertIn("sherlock", profile.external_tools)
        self.assertIn("maigret", profile.external_tools)

    def test_selected_modules_drive_agents(self):
        profile = plan_from_command(
            "Analizza example.com",
            selected_modules=["media", "crypto", "socmint"],
            search_engine="bing",
        )
        self.assertIn("media", profile.agents)
        self.assertIn("crypto", profile.agents)
        self.assertIn("socmint", profile.agents)
        self.assertTrue(any("bing" in note for note in profile.notes))

    def test_email_auto_tools_requires_authorization(self):
        profile = plan_from_command(
            "Cerca informazioni pubbliche su user@example.com con tool",
            confirm_authorization=False,
        )
        # No email-targeting tools should be auto-selected without authorization.
        for tool in ("holehe", "h8mail", "ghunt"):
            self.assertNotIn(tool, profile.external_tools)

    def test_email_auto_tools_selected_with_authorization(self):
        profile = plan_from_command(
            "Cerca informazioni pubbliche su user@example.com con tool",
            confirm_authorization=True,
        )
        self.assertIn("holehe", profile.external_tools)
        self.assertIn("h8mail", profile.external_tools)


if __name__ == "__main__":
    unittest.main()
