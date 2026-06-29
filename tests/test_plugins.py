import time
import unittest

from osint_bot.models import Finding
from osint_bot.plugins import (
    PluginContext,
    PluginRegistry,
    PluginResult,
    external_output_has_signal,
    external_profile_findings,
    redacted_command,
    run_plugins_parallel,
)


class FakePlugin:
    name = "fake"
    passive = True
    gated = False

    def run(self, context: PluginContext) -> PluginResult:
        now = time.time()
        return PluginResult(
            plugin=self.name,
            status="ok",
            started_at=now,
            finished_at=now,
            findings=[Finding(kind="external_fake", value=context.target, confidence=0.5)],
        )


class PluginTests(unittest.TestCase):
    def test_parallel_executor_returns_structured_result(self):
        registry = PluginRegistry()
        registry.register(FakePlugin())
        context = PluginContext(
            target="example",
            target_type="handle",
            confirm_authorization=True,
            include_contact=False,
            allow_network_scan=False,
            timeout=1,
        )

        results = run_plugins_parallel(["fake"], context, registry=registry)

        self.assertEqual(results[0].status, "ok")
        self.assertEqual(results[0].findings[0].kind, "external_fake")
        self.assertIn("duration_ms", results[0].to_dict())

    def test_missing_plugin_degrades_to_structured_error(self):
        context = PluginContext(
            target="example",
            target_type="handle",
            confirm_authorization=True,
            include_contact=False,
            allow_network_scan=False,
            timeout=1,
        )

        results = run_plugins_parallel(["missing"], context, registry=PluginRegistry())

        self.assertEqual(results[0].status, "missing")
        self.assertIn("Plugin non registrato", results[0].error)

    def test_h8mail_no_results_is_not_a_signal(self):
        self.assertFalse(external_output_has_signal("h8mail", "No results founds\nNot Compromised"))

    def test_redacted_command_masks_known_secret_flags(self):
        cmd = ["tool", "--api-key", "SUPERSECRET", "-k", "anothersecret", "target"]
        redacted = redacted_command(cmd)
        self.assertNotIn("SUPERSECRET", redacted)
        self.assertNotIn("anothersecret", redacted)
        self.assertEqual(redacted[redacted.index("--api-key") + 1], "***")
        self.assertEqual(redacted[redacted.index("-k") + 1], "***")
        self.assertIn("target", redacted)

    def test_redacted_command_masks_inline_equals_form(self):
        cmd = ["tool", "--api-key=SUPERSECRET", "target"]
        redacted = redacted_command(cmd)
        self.assertIn("--api-key=***", redacted)
        self.assertNotIn("--api-key=SUPERSECRET", redacted)

    def test_sherlock_parse_ignores_banner_and_negative_lines(self):
        sample = (
            ".----.,---.\n"  # ASCII banner with bogus URLs in it shouldn't matter
            "Sherlock 0.x https://sherlock-project.github.io/\n"
            "[*] Checking username target on:\n"
            "[+] Twitter: https://twitter.com/target\n"
            "[-] Foo: Not Found! https://foo.example/target\n"
            "[+] GitHub: https://github.com/target\n"
        )
        results = external_profile_findings("sherlock", sample)
        urls = [finding.value for finding in results]
        self.assertEqual(urls, ["https://twitter.com/target", "https://github.com/target"])
        # The banner / "Not Found" URL must not appear.
        self.assertNotIn("https://foo.example/target", urls)
        self.assertNotIn("https://sherlock-project.github.io/", urls)

    def test_maigret_parse_only_picks_positive_lines(self):
        sample = (
            "[*] Checking username target on 3000 sites\n"
            "[-] Instagram: not found\n"
            "[+] GitHub: https://github.com/target\n"
            "[!] some error mentioning https://random.example/oops\n"
        )
        results = external_profile_findings("maigret", sample)
        urls = [finding.value for finding in results]
        self.assertEqual(urls, ["https://github.com/target"])

    def test_holehe_parse_extracts_domains_from_found_lines_only(self):
        # holehe with --only-used suppresses [-] lines at the source; the regex
        # provides a second safety layer in case any stray negative line leaks.
        sample = (
            "[+] twitter.com : email used\n"
            "[-] facebook.com : email not used\n"
            "[~] instagram.com : rate limit or unknown\n"
            "[+] github.com : email used\n"
        )
        results = external_profile_findings("holehe", sample)
        values = [f.value for f in results]
        self.assertEqual(values, ["twitter.com", "github.com"],
                         "Only [+] lines should produce findings")
        self.assertNotIn("facebook.com", values, "[-] lines must never generate findings")
        self.assertNotIn("instagram.com", values, "[~] lines must never generate findings")
        # finding kind must distinguish registrations from generic profiles
        self.assertTrue(all(f.kind == "external_holehe_registration" for f in results))


if __name__ == "__main__":
    unittest.main()
