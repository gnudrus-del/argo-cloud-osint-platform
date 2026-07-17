"""ConnectorSweepAgent (agents.py) — runs every registered native connector
whose input_types match the target, together, as part of the always-on
agent pipeline. Before this agent existed, the 63+ connectors in
connectors/ were reachable ONLY through the manual single-connector UI
panel (POST /api/connectors/run); the automated search pipeline never
touched them. These tests use fake in-process connectors (no network) to
verify: (1) all matching connectors actually get invoked and their findings
aggregated, (2) target_type filtering via by_input_type, (3) the three
gated action classes stay off unless their corresponding AgentContext flag
is explicitly set, mirroring the same opt-in flags used elsewhere in the
pipeline (allow_darkweb, allow_network_scan, include_contact).
"""
from __future__ import annotations

import contextlib
import tempfile
import unittest
from pathlib import Path

from osint_bot.connector import (
    ACTION_ACTIVE_GATED,
    ACTION_DARKWEB_GATED,
    ACTION_PASSIVE,
    ACTION_PII_GATED,
    BaseConnector,
    ConnectorContext,
    ConnectorRegistry,
    ConnectorResult,
    ConnectorSpec,
    RateLimit,
)
from osint_bot.models import Finding


@contextlib.contextmanager
def _isolated_storage():
    """Same pattern as tests/test_privacy_*.py: ConnectorSweepAgent's
    deferred `from .web import resolve_api_key` touches get_storage(), so
    point it at a throwaway SQLite file instead of any real data."""
    import osint_bot.web as web
    from osint_bot.storage import Storage

    with tempfile.TemporaryDirectory() as tmp:
        original_storage = web.STORAGE
        web.STORAGE = Storage(Path(tmp) / "gufo.sqlite3")
        try:
            yield web
        finally:
            try:
                web.STORAGE.close()
            except Exception:
                pass
            web.STORAGE = original_storage


class _FakeConnector(BaseConnector):
    """Returns one deterministic Finding, no network I/O."""

    def __init__(self, name: str, action_class: str, input_types: tuple[str, ...]):
        super().__init__()
        self.spec = ConnectorSpec(
            name=name, label=name, action_class=action_class,
            input_types=input_types, output_categories=("test",),
            required_key="", cache_ttl=0, rate_limit=RateLimit(),
        )

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        return ConnectorResult(
            connector=self.spec.name, status="ok",
            findings=[Finding(kind=f"{self.spec.name}_hit", value=context.target, confidence=0.6)],
        )


def _fake_registry() -> ConnectorRegistry:
    reg = ConnectorRegistry()
    reg.register(_FakeConnector("fake_passive_a", ACTION_PASSIVE, ("domain",)))
    reg.register(_FakeConnector("fake_passive_b", ACTION_PASSIVE, ("domain", "ip")))
    reg.register(_FakeConnector("fake_ip_only", ACTION_PASSIVE, ("ip",)))
    reg.register(_FakeConnector("fake_darkweb", ACTION_DARKWEB_GATED, ("domain",)))
    reg.register(_FakeConnector("fake_active", ACTION_ACTIVE_GATED, ("domain",)))
    reg.register(_FakeConnector("fake_pii", ACTION_PII_GATED, ("domain",)))
    return reg


def _scoped_case(actor: str = "tester", target: str = "example.com") -> str:
    """Gated action classes need THREE independent things lined up before
    BaseConnector.run()'s own policy gate (policy.check_policy) allows the
    call: (1) the AgentContext opt-in flag ConnectorSweepAgent pre-filters
    on, (2) a case whose scope covers the target, and (3) a signed, active
    RoE whose allowed_classes explicitly lists that action class -- scope
    alone is NOT enough (discovered empirically while writing this test:
    check_policy denied a scoped-but-unsigned case with "no active Rules of
    Engagement"). Returns the new case's id."""
    from osint_bot.web import create_case, sign_roe

    case = create_case(
        {"title": f"scoped-{target}", "legal_basis": {"type": "consent"},
         "allowed_targets": [target]},
        actor=actor,
    )
    sign_roe(case["id"], {"allowed_classes": ["darkweb-gated", "active-gated", "pii-gated"]}, actor=actor)
    return case["id"]


def _context(target_type="domain", **overrides):
    from osint_bot.agents import AgentContext

    defaults = dict(
        target="example.com", target_type=target_type,
        confirm_authorization=True, include_contact=False,
        allow_network_scan=False, search_results=[], pages=[],
        external_tools=[], timeout=10, allow_darkweb=False,
        case_id="", actor="tester",
    )
    defaults.update(overrides)
    return AgentContext(**defaults)


class ConnectorSweepAgentTests(unittest.TestCase):
    def test_passive_connectors_run_and_findings_aggregate(self):
        from osint_bot.agents import ConnectorSweepAgent

        with _isolated_storage() as web:
            web.CONNECTOR_REGISTRY = _fake_registry()
            result = ConnectorSweepAgent().run(_context())

        self.assertEqual(result.status, "ok")
        kinds = {f.kind for f in result.findings}
        self.assertIn("fake_passive_a_hit", kinds)
        self.assertIn("fake_passive_b_hit", kinds)
        # ip-only connector must not fire for a domain target.
        self.assertNotIn("fake_ip_only_hit", kinds)

    def test_target_type_filters_by_input_types(self):
        from osint_bot.agents import ConnectorSweepAgent

        with _isolated_storage() as web:
            web.CONNECTOR_REGISTRY = _fake_registry()
            result = ConnectorSweepAgent().run(_context(target_type="ip", target="8.8.8.8"))

        kinds = {f.kind for f in result.findings}
        self.assertIn("fake_ip_only_hit", kinds)
        self.assertIn("fake_passive_b_hit", kinds)  # accepts both domain and ip
        self.assertNotIn("fake_passive_a_hit", kinds)  # domain-only

    def test_darkweb_gated_connector_stays_off_without_allow_darkweb(self):
        from osint_bot.agents import ConnectorSweepAgent

        with _isolated_storage() as web:
            web.CONNECTOR_REGISTRY = _fake_registry()
            case_id = _scoped_case()
            # Scope alone is NOT enough without the explicit flag.
            off = ConnectorSweepAgent().run(_context(allow_darkweb=False, case_id=case_id))
            on = ConnectorSweepAgent().run(_context(allow_darkweb=True, case_id=case_id))

        self.assertNotIn("fake_darkweb_hit", {f.kind for f in off.findings})
        self.assertIn("fake_darkweb_hit", {f.kind for f in on.findings})

    def test_active_gated_connector_stays_off_without_allow_network_scan(self):
        from osint_bot.agents import ConnectorSweepAgent

        with _isolated_storage() as web:
            web.CONNECTOR_REGISTRY = _fake_registry()
            case_id = _scoped_case()
            off = ConnectorSweepAgent().run(_context(allow_network_scan=False, case_id=case_id))
            on = ConnectorSweepAgent().run(_context(allow_network_scan=True, case_id=case_id))

        self.assertNotIn("fake_active_hit", {f.kind for f in off.findings})
        self.assertIn("fake_active_hit", {f.kind for f in on.findings})

    def test_pii_gated_connector_stays_off_without_include_contact(self):
        from osint_bot.agents import ConnectorSweepAgent

        with _isolated_storage() as web:
            web.CONNECTOR_REGISTRY = _fake_registry()
            case_id = _scoped_case()
            off = ConnectorSweepAgent().run(_context(include_contact=False, case_id=case_id))
            on = ConnectorSweepAgent().run(_context(include_contact=True, case_id=case_id))

        self.assertNotIn("fake_pii_hit", {f.kind for f in off.findings})
        self.assertIn("fake_pii_hit", {f.kind for f in on.findings})

    def test_gated_connector_still_blocked_by_empty_case_scope(self):
        """Defense in depth: even with the AgentContext flag on, a gated
        connector must NOT fire against a case that has no scope (or whose
        scope doesn't cover the target) -- BaseConnector.run()'s own policy
        gate is a second, independent layer, not redundant with the agent's
        pre-filter."""
        from osint_bot.agents import ConnectorSweepAgent
        from osint_bot.web import create_case

        with _isolated_storage() as web:
            web.CONNECTOR_REGISTRY = _fake_registry()
            empty_scope_case = create_case(
                {"title": "no-scope", "legal_basis": {"type": "consent"}}, actor="tester",
            )["id"]
            result = ConnectorSweepAgent().run(
                _context(allow_darkweb=True, allow_network_scan=True, include_contact=True,
                        case_id=empty_scope_case)
            )

        kinds = {f.kind for f in result.findings}
        self.assertNotIn("fake_darkweb_hit", kinds)
        self.assertNotIn("fake_active_hit", kinds)
        self.assertNotIn("fake_pii_hit", kinds)

    def test_no_matching_connectors_is_skipped_not_error(self):
        from osint_bot.agents import ConnectorSweepAgent

        with _isolated_storage() as web:
            web.CONNECTOR_REGISTRY = _fake_registry()
            result = ConnectorSweepAgent().run(_context(target_type="crypto", target="bc1..."))

        self.assertEqual(result.status, "skipped")
        self.assertEqual(result.findings, [])

    def test_registered_in_run_agents_and_always_on(self):
        from osint_bot.agents import run_agents
        from osint_bot.orchestrator import ALWAYS_ON_AGENTS

        self.assertIn("connectors", ALWAYS_ON_AGENTS)
        with _isolated_storage() as web:
            web.CONNECTOR_REGISTRY = _fake_registry()
            results = run_agents(_context(), ["connectors"])

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].name, "connectors")


if __name__ == "__main__":
    unittest.main()
