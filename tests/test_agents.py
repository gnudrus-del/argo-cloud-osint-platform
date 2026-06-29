import unittest

from osint_bot.agents import AgentContext, CryptoAgent, GeoAgent, PhoneAgent
from osint_bot.models import Page


class AgentTests(unittest.TestCase):
    def test_crypto_agent_detects_eth_target(self):
        context = AgentContext(
            target="0x0000000000000000000000000000000000000000",
            target_type="crypto",
            confirm_authorization=False,
            include_contact=False,
            allow_network_scan=False,
            search_results=[],
            pages=[],
            external_tools=[],
            timeout=1,
        )
        result = CryptoAgent().run(context)
        self.assertEqual(result.status, "ok")
        self.assertEqual(result.findings[0].kind, "crypto_address")

    def test_geo_agent_finds_public_coordinates(self):
        context = AgentContext(
            target="example",
            target_type="company",
            confirm_authorization=False,
            include_contact=False,
            allow_network_scan=False,
            search_results=[],
            pages=[Page(url="https://example.com", status=200, text="Office: 41.9028, 12.4964")],
            external_tools=[],
            timeout=1,
        )
        result = GeoAgent().run(context)
        self.assertEqual(result.findings[0].kind, "geo_coordinate_mention")

    def test_phone_agent_redacts(self):
        context = AgentContext(
            target="+39 333 123 4567",
            target_type="phone",
            confirm_authorization=True,
            include_contact=False,
            allow_network_scan=False,
            search_results=[],
            pages=[],
            external_tools=[],
            timeout=1,
        )
        result = PhoneAgent().run(context)
        self.assertTrue(result.findings[0].value.endswith("4567"))
        self.assertNotIn("333", result.findings[0].value)


if __name__ == "__main__":
    unittest.main()
