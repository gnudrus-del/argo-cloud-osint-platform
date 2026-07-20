import unittest

from osint_bot.orchestrator import (
    ALWAYS_ON_AGENTS,
    choose_agents,
    infer_target_type,
    plan_from_command,
)


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


class InferTargetTypeFallbackTests(unittest.TestCase):
    """Regression tests for the bug where a plain person name or username,
    with no Italian magic word ("persona"/"socmint"/"human"/"username"/
    "handle") in the surrounding text, silently fell through to "company"
    — which excludes the entire person/handle connector toolchain
    (sherlock_lite, maigret, toutatis, ...) for the single most common
    search on this product. The fallback now defers to target_classifier's
    already-tested free-text heuristic instead of hardcoding "company"."""

    def test_plain_person_name_is_not_company(self):
        self.assertEqual(infer_target_type("Mario Rossi", "Mario Rossi"), "person")

    def test_person_name_inside_a_sentence_without_magic_word(self):
        self.assertEqual(
            infer_target_type("Mario Rossi", "Cerca informazioni su Mario Rossi."),
            "person",
        )

    def test_bare_username_without_at_or_keyword_is_handle(self):
        self.assertEqual(infer_target_type("mariorossi93", "mariorossi93"), "handle")

    def test_explicit_magic_words_still_work_unchanged(self):
        self.assertEqual(infer_target_type("Mario Rossi", "socmint su Mario Rossi"), "person")
        self.assertEqual(infer_target_type("mrossi", "il suo username è mrossi"), "handle")

    def test_domain_classification_is_unaffected(self):
        self.assertEqual(infer_target_type("example.com", "example.com"), "domain")

    def test_email_ip_crypto_phone_classification_is_unaffected(self):
        eth_addr = "0x" + "a" * 40
        self.assertEqual(infer_target_type("user@example.com", "user@example.com"), "email")
        self.assertEqual(infer_target_type("8.8.8.8", "8.8.8.8"), "ip")
        self.assertEqual(infer_target_type(eth_addr, eth_addr), "crypto")
        self.assertEqual(infer_target_type("x", "telefono +39 333 1234567"), "phone")


if __name__ == "__main__":
    unittest.main()
