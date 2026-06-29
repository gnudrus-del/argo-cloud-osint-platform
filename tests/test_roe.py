import contextlib
import tempfile
import unittest
import uuid
from http import HTTPStatus
from pathlib import Path

from osint_bot.safety import SafetyError, authorize_action
from osint_bot.storage import Storage


@contextlib.contextmanager
def _isolated_storage():
    import osint_bot.web as web

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


def _sign_real_roe(store, case_id: str, signer: str, **overrides) -> dict:
    roe = {
        "id": uuid.uuid4().hex,
        "case_id": case_id,
        "signed_by": signer,
        "mandate_reference": "TEST-001",
        "scope": {"domains": ["example.com"]},
        "valid_from": None,
        "valid_to": None,
        "allowed_classes": ["passive", "pii-gated"],
        "requires_second_signature": False,
    }
    roe.update(overrides)
    store.put_roe(roe)
    return roe


class StorageRoeTests(unittest.TestCase):
    def test_put_get_active_roe_roundtrip(self):
        with _isolated_storage() as (_, store):
            from osint_bot.web import create_case
            case = create_case({"title": "x"}, actor="alice")
            roe = _sign_real_roe(store, case["id"], "alice")
            active = store.get_active_roe(case["id"])
            self.assertIsNotNone(active)
            self.assertEqual(active["id"], roe["id"])

    def test_revoked_roe_is_not_active(self):
        with _isolated_storage() as (_, store):
            from osint_bot.web import create_case
            case = create_case({"title": "x"}, actor="alice")
            roe = _sign_real_roe(store, case["id"], "alice")
            store.revoke_roe(roe["id"])
            self.assertIsNone(store.get_active_roe(case["id"]))


class AuthorizeActionTests(unittest.TestCase):
    def test_no_case_id_is_permissive_legacy_path(self):
        # Legacy CLI flow: no case context, no RoE check.
        result = authorize_action(
            action_class="passive", target_type="domain", target="example.com",
            case_id=None, actor="alice", storage=None,
        )
        self.assertTrue(result.allowed)

    def test_case_without_active_roe_denies(self):
        with _isolated_storage() as (_, store):
            from osint_bot.web import create_case
            case = create_case({"title": "Op X"}, actor="alice")
            # No RoE signed → deny.
            with self.assertRaises(SafetyError):
                authorize_action(
                    action_class="passive", target_type="domain", target="example.com",
                    case_id=case["id"], actor="alice", storage=store,
                )

    def test_in_scope_passive_allowed(self):
        with _isolated_storage() as (_, store):
            from osint_bot.web import create_case
            case = create_case({"title": "Op X"}, actor="alice")
            _sign_real_roe(store, case["id"], "alice")
            r = authorize_action(
                action_class="passive", target_type="domain", target="example.com",
                case_id=case["id"], actor="alice", storage=store,
            )
            self.assertTrue(r.allowed)
            self.assertEqual(r.mandate_reference, "TEST-001")

    def test_out_of_scope_denied(self):
        with _isolated_storage() as (_, store):
            from osint_bot.web import create_case
            case = create_case({"title": "Op X"}, actor="alice")
            _sign_real_roe(store, case["id"], "alice")
            with self.assertRaises(SafetyError) as ctx:
                authorize_action(
                    action_class="passive", target_type="domain", target="evil.com",
                    case_id=case["id"], actor="alice", storage=store,
                )
            self.assertIn("scope", str(ctx.exception).casefold())

    def test_disallowed_class_denied(self):
        with _isolated_storage() as (_, store):
            from osint_bot.web import create_case
            case = create_case({"title": "Op X"}, actor="alice")
            # RoE only allows passive — request active-gated.
            _sign_real_roe(store, case["id"], "alice", allowed_classes=["passive"])
            with self.assertRaises(SafetyError):
                authorize_action(
                    action_class="active-gated", target_type="domain", target="example.com",
                    case_id=case["id"], actor="alice", storage=store,
                )

    def test_outside_window_denied(self):
        with _isolated_storage() as (_, store):
            from osint_bot.web import create_case
            case = create_case({"title": "Op X"}, actor="alice")
            _sign_real_roe(store, case["id"], "alice",
                           valid_from="2030-01-01T00:00:00+00:00",
                           valid_to="2030-12-31T00:00:00+00:00")
            with self.assertRaises(SafetyError):
                authorize_action(
                    action_class="passive", target_type="domain", target="example.com",
                    case_id=case["id"], actor="alice", storage=store,
                    now_iso="2025-01-01T00:00:00+00:00",
                )

    def test_4eyes_required_blocks_active_without_second_signature(self):
        with _isolated_storage() as (_, store):
            from osint_bot.web import create_case
            case = create_case({"title": "Op X"}, actor="alice")
            _sign_real_roe(store, case["id"], "alice",
                           allowed_classes=["active-gated"],
                           requires_second_signature=True)
            with self.assertRaises(SafetyError) as ctx:
                authorize_action(
                    action_class="active-gated", target_type="domain", target="example.com",
                    case_id=case["id"], actor="alice", storage=store,
                )
            self.assertIn("seconda firma", str(ctx.exception).casefold())

    def test_4eyes_passes_when_second_signature_present(self):
        with _isolated_storage() as (_, store):
            from osint_bot.web import create_case
            case = create_case({"title": "Op X"}, actor="alice")
            _sign_real_roe(store, case["id"], "alice",
                           allowed_classes=["active-gated"],
                           requires_second_signature=True,
                           second_signed_by="bob",
                           second_signed_at="2026-06-26T00:00:00+00:00")
            r = authorize_action(
                action_class="active-gated", target_type="domain", target="example.com",
                case_id=case["id"], actor="alice", storage=store,
            )
            self.assertTrue(r.allowed)

    def test_cidr_scope_for_ip(self):
        with _isolated_storage() as (_, store):
            from osint_bot.web import create_case
            case = create_case({"title": "Op X"}, actor="alice")
            _sign_real_roe(store, case["id"], "alice",
                           scope={"cidrs": ["10.0.0.0/8"]})
            # In CIDR
            r = authorize_action(
                action_class="passive", target_type="ip", target="10.1.2.3",
                case_id=case["id"], actor="alice", storage=store,
            )
            self.assertTrue(r.allowed)
            # Out of CIDR
            with self.assertRaises(SafetyError):
                authorize_action(
                    action_class="passive", target_type="ip", target="8.8.8.8",
                    case_id=case["id"], actor="alice", storage=store,
                )

    def test_email_in_scope_via_domain(self):
        with _isolated_storage() as (_, store):
            from osint_bot.web import create_case
            case = create_case({"title": "Op X"}, actor="alice")
            _sign_real_roe(store, case["id"], "alice",
                           scope={"domains": ["example.com"]},
                           allowed_classes=["pii-gated"])
            r = authorize_action(
                action_class="pii-gated", target_type="email", target="bob@example.com",
                case_id=case["id"], actor="alice", storage=store,
            )
            self.assertTrue(r.allowed)


class AuditOnDenialTests(unittest.TestCase):
    def test_denial_writes_roe_denied_event(self):
        with _isolated_storage() as (_, store):
            from osint_bot.web import create_case
            case = create_case({"title": "Op X"}, actor="alice")
            with self.assertRaises(SafetyError):
                authorize_action(
                    action_class="passive", target_type="domain", target="example.com",
                    case_id=case["id"], actor="alice", storage=store,
                )
            events = [e["action"] for e in store.all_audit_events()]
            self.assertIn("roe_denied", events)

    def test_authorisation_writes_roe_authorized_event(self):
        with _isolated_storage() as (_, store):
            from osint_bot.web import create_case
            case = create_case({"title": "Op X"}, actor="alice")
            _sign_real_roe(store, case["id"], "alice")
            authorize_action(
                action_class="passive", target_type="domain", target="example.com",
                case_id=case["id"], actor="alice", storage=store,
            )
            events = [e["action"] for e in store.all_audit_events()]
            self.assertIn("roe_authorized", events)


class WebEndpointRoeTests(unittest.TestCase):
    def test_sign_roe_revokes_previous_one(self):
        with _isolated_storage() as (_, store):
            from osint_bot.web import create_case, sign_roe
            case = create_case({"title": "Op X"}, actor="alice")
            first = sign_roe(case["id"], {
                "mandate_reference": "M-1",
                "scope": {"domains": ["example.com"]},
                "allowed_classes": ["passive"],
            }, actor="alice")
            second = sign_roe(case["id"], {
                "mandate_reference": "M-2",
                "scope": {"domains": ["example.org"]},
                "allowed_classes": ["passive", "pii-gated"],
            }, actor="alice")
            active = store.get_active_roe(case["id"])
            self.assertEqual(active["id"], second["id"])
            self.assertEqual(active["mandate_reference"], "M-2")
            roes = store.list_roes(case["id"])
            # First one is revoked, second is active.
            revoked = next(r for r in roes if r["id"] == first["id"])
            self.assertIsNotNone(revoked["revoked_at"])

    def test_sign_roe_validates_class_names(self):
        from osint_bot.web import WebError, create_case, sign_roe
        with _isolated_storage():
            case = create_case({"title": "X"}, actor="alice")
            with self.assertRaises(WebError) as ctx:
                sign_roe(case["id"], {"allowed_classes": ["not-a-class"]}, actor="alice")
            self.assertEqual(ctx.exception.status, HTTPStatus.BAD_REQUEST)

    def test_only_owner_can_sign_roe(self):
        from osint_bot.web import WebError, create_case, sign_roe
        with _isolated_storage():
            case = create_case({"title": "X", "collaborators": ["bob"]}, actor="alice")
            with self.assertRaises(WebError) as ctx:
                sign_roe(case["id"], {"allowed_classes": ["passive"]}, actor="bob")
            self.assertEqual(ctx.exception.status, HTTPStatus.FORBIDDEN)


class DefaultCaseAutoRoeTests(unittest.TestCase):
    def test_default_case_has_permissive_roe(self):
        from osint_bot.web import ensure_default_case
        with _isolated_storage() as (_, store):
            case_id = ensure_default_case("alice")
            roe = store.get_active_roe(case_id)
            self.assertIsNotNone(roe)
            self.assertTrue(roe["scope"].get("any"))
            # Smoke-test: a passive action against an arbitrary domain works.
            r = authorize_action(
                action_class="passive", target_type="domain", target="anything.example",
                case_id=case_id, actor="alice", storage=store,
            )
            self.assertTrue(r.allowed)


if __name__ == "__main__":
    unittest.main()
