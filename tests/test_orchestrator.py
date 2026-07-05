import unittest

from osint_bot.orchestrator import ALWAYS_ON_AGENTS, choose_agents, plan_from_command


class OrchestratorTests(unittest.TestCase):
    def test_every_search_runs_all_always_on_agents(self):
        # Ogni ricerca del sito deve includere tutti gli agenti sempre-attivi,
        # a prescindere dal tipo di target o dai moduli selezionati.
        for target_type in ("domain", "email", "phone", "handle", "crypto", "media", "ip"):
            agents = choose_agents("ricerca generica", target_type, allow_darkweb=False, modules=[])
            for expected in ALWAYS_ON_AGENTS:
                self.assertIn(expected, agents, f"{expected} mancante per target_type={target_type}")

    def test_gated_agents_stay_out_without_flags(self):
        # darkweb e red_team NON devono comparire senza flag/modulo esplicito.
        agents = choose_agents("analizza example.com", "domain", allow_darkweb=False, modules=[])
        self.assertNotIn("darkweb", agents)
        self.assertNotIn("red_team", agents)

    def test_darkweb_agent_activates_with_flag(self):
        agents = choose_agents("analizza example.com", "domain", allow_darkweb=True, modules=[])
        self.assertIn("darkweb", agents)

    def test_red_team_agent_activates_with_module(self):
        agents = choose_agents("analizza example.com", "domain", allow_darkweb=False, modules=["red_team"])
        self.assertIn("red_team", agents)

    def test_plan_from_command_includes_full_agent_set(self):
        profile = plan_from_command("Analizza example.com")
        for expected in ALWAYS_ON_AGENTS:
            self.assertIn(expected, profile.agents)

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
