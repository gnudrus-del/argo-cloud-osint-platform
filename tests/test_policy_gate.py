"""Policy gate — BaseConnector.run must call check_policy for every
connector and refuse gated calls without a case + scope-check every
call that does have a case."""
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
    ConnectorResult,
    ConnectorSpec,
    RateLimit,
)


class _StubConnector(BaseConnector):
    """A connector whose _fetch() is a spy that records whether it was
    ever invoked. Used to assert that the policy gate short-circuits."""

    def __init__(self, spec: ConnectorSpec) -> None:
        super().__init__()
        self.spec = spec
        self.calls = 0

    def _fetch(self, context: ConnectorContext) -> ConnectorResult:
        self.calls += 1
        return ConnectorResult(connector=self.spec.name, status="ok")


def _spec(name: str, action_class: str) -> ConnectorSpec:
    return ConnectorSpec(
        name=name, label=name, action_class=action_class,
        input_types=("domain",), output_categories=("test",),
        required_key="", cache_ttl=0,
        rate_limit=RateLimit(per_minute=60, per_day=100, burst=1),
    )


@contextlib.contextmanager
def _isolated_storage():
    """Same trick as the privacy tests: swap the global storage so a
    fresh SQLite DB is used for the duration of the test."""
    import osint_bot.web as web
    from osint_bot.storage import Storage

    with tempfile.TemporaryDirectory() as tmp:
        original_root = web.JOB_ROOT
        original_storage = web.STORAGE
        web.JOB_ROOT = Path(tmp)
        web.STORAGE = Storage(Path(tmp) / "gufo.sqlite3")
        try:
            yield Path(tmp), web.STORAGE
        finally:
            try:
                web.STORAGE.close()
            except Exception:
                pass
            web.JOB_ROOT = original_root
            web.STORAGE = original_storage


class PolicyPassiveNoCaseTests(unittest.TestCase):
    def test_passive_call_without_case_is_allowed(self):
        c = _StubConnector(_spec("passive1", ACTION_PASSIVE))
        r = c.run(ConnectorContext(target="example.com", target_type="domain"))
        self.assertEqual(r.status, "ok", r.error)
        self.assertEqual(c.calls, 1)


class PolicyGatedRequiresCaseTests(unittest.TestCase):
    def test_active_gated_without_case_is_denied(self):
        c = _StubConnector(_spec("active1", ACTION_ACTIVE_GATED))
        r = c.run(ConnectorContext(target="example.com", target_type="domain"))
        self.assertEqual(r.status, "policy_denied")
        self.assertEqual(c.calls, 0)
        self.assertIn("requires an in-scope case", r.error)

    def test_pii_gated_without_case_is_denied(self):
        c = _StubConnector(_spec("pii1", ACTION_PII_GATED))
        r = c.run(ConnectorContext(target="alice@example.com", target_type="email"))
        self.assertEqual(r.status, "policy_denied")
        self.assertEqual(c.calls, 0)

    def test_darkweb_gated_without_case_is_denied(self):
        c = _StubConnector(_spec("dw1", ACTION_DARKWEB_GATED))
        r = c.run(ConnectorContext(target="example.com", target_type="domain"))
        self.assertEqual(r.status, "policy_denied")
        self.assertEqual(c.calls, 0)


class PolicyScopeEnforcementTests(unittest.TestCase):
    def _make_case(self, actor: str, allowed: list[str]) -> str:
        from osint_bot.web import create_case
        rec = create_case(
            {
                "title": "T",
                "legal_basis": {"type": "mandate"},
                "allowed_targets": allowed,
            },
            actor=actor,
        )
        return rec["id"]

    def test_target_in_scope_is_allowed(self):
        with _isolated_storage():
            case_id = self._make_case("alice", ["example.com"])
            c = _StubConnector(_spec("passive2", ACTION_PASSIVE))
            r = c.run(ConnectorContext(
                target="example.com", target_type="domain",
                actor="alice", case_id=case_id,
            ))
        self.assertEqual(r.status, "ok", r.error)
        self.assertEqual(c.calls, 1)

    def test_target_subdomain_in_scope_is_allowed(self):
        with _isolated_storage():
            case_id = self._make_case("alice", ["example.com"])
            c = _StubConnector(_spec("passive3", ACTION_PASSIVE))
            r = c.run(ConnectorContext(
                target="mail.example.com", target_type="domain",
                actor="alice", case_id=case_id,
            ))
        self.assertEqual(r.status, "ok", r.error)

    def test_target_out_of_scope_is_denied(self):
        with _isolated_storage():
            case_id = self._make_case("alice", ["example.com"])
            c = _StubConnector(_spec("passive4", ACTION_PASSIVE))
            r = c.run(ConnectorContext(
                target="attacker.evil", target_type="domain",
                actor="alice", case_id=case_id,
            ))
        self.assertEqual(r.status, "policy_denied")
        self.assertEqual(c.calls, 0)
        self.assertIn("not in the allowed_targets", r.error)

    def test_gated_call_with_case_but_empty_scope_is_denied(self):
        with _isolated_storage():
            case_id = self._make_case("alice", [])
            c = _StubConnector(_spec("act2", ACTION_ACTIVE_GATED))
            r = c.run(ConnectorContext(
                target="example.com", target_type="domain",
                actor="alice", case_id=case_id,
            ))
        self.assertEqual(r.status, "policy_denied")


if __name__ == "__main__":
    unittest.main()
