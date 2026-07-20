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

    def test_cidr_scope_entry_matches_contained_ip_regression(self):
        # Before the fix, any allowed_targets entry containing "/" (CIDR
        # notation) never matched anything at all — a case scoped to a
        # whole authorised network denied every single IP inside it.
        with _isolated_storage():
            case_id = self._make_case("alice", ["10.0.0.0/24"])
            c = _StubConnector(_spec("passive-cidr", ACTION_PASSIVE))
            r = c.run(ConnectorContext(
                target="10.0.0.5", target_type="ip",
                actor="alice", case_id=case_id,
            ))
        self.assertEqual(r.status, "ok", r.error)

    def test_cidr_scope_entry_denies_ip_outside_the_network(self):
        with _isolated_storage():
            case_id = self._make_case("alice", ["10.0.0.0/24"])
            c = _StubConnector(_spec("passive-cidr2", ACTION_PASSIVE))
            r = c.run(ConnectorContext(
                target="10.0.1.5", target_type="ip",
                actor="alice", case_id=case_id,
            ))
        self.assertEqual(r.status, "policy_denied")

    def test_ipv6_cidr_scope_entry_matches(self):
        with _isolated_storage():
            case_id = self._make_case("alice", ["2001:db8::/32"])
            c = _StubConnector(_spec("passive-cidr6", ACTION_PASSIVE))
            r = c.run(ConnectorContext(
                target="2001:db8::1", target_type="ip",
                actor="alice", case_id=case_id,
            ))
        self.assertEqual(r.status, "ok", r.error)

    def test_wildcard_scope_entry_matches_subdomain_and_apex_regression(self):
        # Before the fix, "*.example.com" matched literally nothing: the
        # exact-match check needed the target to BE "*.example.com", and
        # the domain-tree check looked for a literal ".*.example.com"
        # suffix, which no real domain ever has.
        with _isolated_storage():
            case_id = self._make_case("alice", ["*.example.com"])
            for tgt in ("mail.example.com", "example.com"):
                c = _StubConnector(_spec(f"passive-wc-{tgt}", ACTION_PASSIVE))
                r = c.run(ConnectorContext(
                    target=tgt, target_type="domain",
                    actor="alice", case_id=case_id,
                ))
                self.assertEqual(r.status, "ok", r.error)

    def test_wildcard_scope_entry_denies_unrelated_domain(self):
        with _isolated_storage():
            case_id = self._make_case("alice", ["*.example.com"])
            c = _StubConnector(_spec("passive-wc-out", ACTION_PASSIVE))
            r = c.run(ConnectorContext(
                target="attacker.evil", target_type="domain",
                actor="alice", case_id=case_id,
            ))
        self.assertEqual(r.status, "policy_denied")


class DefaultCaseAutoScopeTests(unittest.TestCase):
    """Regression tests for the bug where ensure_default_case() never
    populated allowed_targets: every gated connector (contactout, lusha,
    hibp, hunter, emailrep, cloud_buckets, content_discovery, port_scan,
    darkweb_scan) was policy_denied on every search made through the
    standard UI, silently, regardless of the confirm_authorization
    checkbox — because the RoE was permissive but the scope list backing
    it was always []. See ensure_default_case's docstring in web.py."""

    def test_authorized_target_on_default_case_unlocks_gated_connector(self):
        from osint_bot.web import ensure_default_case
        with _isolated_storage():
            case_id = ensure_default_case(
                "alice", target="alice-target.example", authorized=True,
            )
            c = _StubConnector(_spec("pii2", ACTION_PII_GATED))
            r = c.run(ConnectorContext(
                target="alice-target.example", target_type="domain",
                actor="alice", case_id=case_id,
            ))
        self.assertEqual(r.status, "ok", r.error)
        self.assertEqual(c.calls, 1)

    def test_unauthorized_target_on_default_case_stays_denied(self):
        from osint_bot.web import ensure_default_case
        with _isolated_storage():
            # No target confirmed at all: default case keeps its empty scope.
            case_id = ensure_default_case("bob")
            c = _StubConnector(_spec("pii3", ACTION_PII_GATED))
            r = c.run(ConnectorContext(
                target="whatever.example", target_type="domain",
                actor="bob", case_id=case_id,
            ))
        self.assertEqual(r.status, "policy_denied")
        self.assertEqual(c.calls, 0)

    def test_authorized_target_does_not_widen_scope_to_other_targets(self):
        from osint_bot.web import ensure_default_case
        with _isolated_storage():
            case_id = ensure_default_case(
                "carol", target="confirmed.example", authorized=True,
            )
            c = _StubConnector(_spec("pii4", ACTION_PII_GATED))
            r = c.run(ConnectorContext(
                target="not-confirmed.example", target_type="domain",
                actor="carol", case_id=case_id,
            ))
        self.assertEqual(r.status, "policy_denied")
        self.assertEqual(c.calls, 0)

    def test_second_authorized_search_widens_scope_additively(self):
        from osint_bot.web import ensure_default_case
        with _isolated_storage():
            case_id_1 = ensure_default_case(
                "dave", target="first.example", authorized=True,
            )
            case_id_2 = ensure_default_case(
                "dave", target="second.example", authorized=True,
            )
            self.assertEqual(case_id_1, case_id_2)
            for tgt in ("first.example", "second.example"):
                c = _StubConnector(_spec(f"pii-{tgt}", ACTION_PII_GATED))
                r = c.run(ConnectorContext(
                    target=tgt, target_type="domain",
                    actor="dave", case_id=case_id_1,
                ))
                self.assertEqual(r.status, "ok", r.error)


class RoeWindowAndFourEyesTests(unittest.TestCase):
    """Regression tests: check_policy (the gate every native connector goes
    through) previously never checked the RoE's time window or its
    four-eyes (requires_second_signature) requirement — both are enforced
    correctly for external tools via safety.authorize_action, but were
    silently skipped for the 63+ native connectors. See policy.py's
    check_policy steps 5-6."""

    def _case_with_roe(self, actor, target, action_classes, **roe_extra):
        from osint_bot.web import create_case, sign_roe
        case = create_case(
            {"title": "T", "legal_basis": {"type": "mandate"}, "allowed_targets": [target]},
            actor=actor,
        )
        payload = {"allowed_classes": action_classes, "scope": {}}
        payload.update(roe_extra)
        sign_roe(case["id"], payload, actor)
        return case["id"]

    def test_expired_roe_denies_gated_connector(self):
        with _isolated_storage():
            case_id = self._case_with_roe(
                "alice", "example.com", ["pii-gated"],
                valid_to="2000-01-01T00:00:00+00:00",
            )
            c = _StubConnector(_spec("pii-expired", ACTION_PII_GATED))
            r = c.run(ConnectorContext(
                target="example.com", target_type="domain",
                actor="alice", case_id=case_id,
            ))
        self.assertEqual(r.status, "policy_denied")
        self.assertIn("time window", r.error)
        self.assertEqual(c.calls, 0)

    def test_not_yet_valid_roe_denies_gated_connector(self):
        with _isolated_storage():
            case_id = self._case_with_roe(
                "alice", "example.com", ["pii-gated"],
                valid_from="2999-01-01T00:00:00+00:00",
            )
            c = _StubConnector(_spec("pii-future", ACTION_PII_GATED))
            r = c.run(ConnectorContext(
                target="example.com", target_type="domain",
                actor="alice", case_id=case_id,
            ))
        self.assertEqual(r.status, "policy_denied")
        self.assertIn("time window", r.error)

    def test_roe_within_window_still_allows(self):
        with _isolated_storage():
            case_id = self._case_with_roe(
                "alice", "example.com", ["pii-gated"],
                valid_from="2000-01-01T00:00:00+00:00",
                valid_to="2999-01-01T00:00:00+00:00",
            )
            c = _StubConnector(_spec("pii-inwindow", ACTION_PII_GATED))
            r = c.run(ConnectorContext(
                target="example.com", target_type="domain",
                actor="alice", case_id=case_id,
            ))
        self.assertEqual(r.status, "ok", r.error)
        self.assertEqual(c.calls, 1)

    def test_four_eyes_required_but_missing_denies_active_gated(self):
        with _isolated_storage():
            case_id = self._case_with_roe(
                "alice", "example.com", ["active-gated"],
                requires_second_signature=True,
            )
            c = _StubConnector(_spec("act-4eyes", ACTION_ACTIVE_GATED))
            r = c.run(ConnectorContext(
                target="example.com", target_type="domain",
                actor="alice", case_id=case_id,
            ))
        self.assertEqual(r.status, "policy_denied")
        self.assertIn("4-eyes", r.error)
        self.assertEqual(c.calls, 0)

    def test_four_eyes_satisfied_allows_active_gated(self):
        from osint_bot.web import get_storage
        with _isolated_storage():
            case_id = self._case_with_roe(
                "alice", "example.com", ["active-gated"],
                requires_second_signature=True,
            )
            store = get_storage()
            roe = store.get_active_roe(case_id)
            roe["second_signed_at"] = "2020-06-01T00:00:00+00:00"
            store.put_roe(roe)
            c = _StubConnector(_spec("act-4eyes-ok", ACTION_ACTIVE_GATED))
            r = c.run(ConnectorContext(
                target="example.com", target_type="domain",
                actor="alice", case_id=case_id,
            ))
        self.assertEqual(r.status, "ok", r.error)

    def test_four_eyes_not_required_for_pii_gated(self):
        # requires_second_signature only gates active/darkweb-gated,
        # mirroring safety.authorize_action — pii-gated must stay unaffected.
        with _isolated_storage():
            case_id = self._case_with_roe(
                "alice", "example.com", ["pii-gated"],
                requires_second_signature=True,
            )
            c = _StubConnector(_spec("pii-4eyes-exempt", ACTION_PII_GATED))
            r = c.run(ConnectorContext(
                target="example.com", target_type="domain",
                actor="alice", case_id=case_id,
            ))
        self.assertEqual(r.status, "ok", r.error)


if __name__ == "__main__":
    unittest.main()
