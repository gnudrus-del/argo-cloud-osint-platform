"""Tests for RBAC: the persistent 'role' column and session_is_admin()'s
two admission doors (legacy per-session unlock vs. persistent admin role).
"""
import contextlib
import tempfile
import unittest
from pathlib import Path

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


def _make_user(store, username, role="analyst"):
    store.put_user({
        "username": username, "password": "x", "plan": "free",
        "created_at": "2026-01-01T00:00:00+00:00", "disabled": False,
        "email": f"{username}@example.com", "verified": True,
        "verified_at": "2026-01-01T00:00:00+00:00", "role": role,
    })


class RoleStorageRoundTripTests(unittest.TestCase):
    def test_default_role_is_analyst(self):
        with _isolated_storage() as (_tmp, store):
            _make_user(store, "alice")
            self.assertEqual(store.get_user("alice")["role"], "analyst")
            self.assertEqual(store.all_users()["alice"]["role"], "analyst")

    def test_admin_role_persists_across_put_and_get(self):
        with _isolated_storage() as (_tmp, store):
            _make_user(store, "bob", role="admin")
            self.assertEqual(store.get_user("bob")["role"], "admin")

    def test_role_update_via_put_user_overwrites(self):
        with _isolated_storage() as (_tmp, store):
            _make_user(store, "carol", role="analyst")
            user = store.get_user("carol")
            user["role"] = "admin"
            store.put_user(user)
            self.assertEqual(store.get_user("carol")["role"], "admin")
            # Demote back.
            user["role"] = "analyst"
            store.put_user(user)
            self.assertEqual(store.get_user("carol")["role"], "analyst")


class SessionIsAdminTests(unittest.TestCase):
    def test_no_session_is_never_admin(self):
        from osint_bot.web import session_is_admin
        with _isolated_storage():
            self.assertFalse(session_is_admin(None))
            self.assertFalse(session_is_admin({}))

    def test_analyst_role_without_unlock_is_not_admin(self):
        from osint_bot.web import session_is_admin
        with _isolated_storage() as (_tmp, store):
            _make_user(store, "dave", role="analyst")
            self.assertFalse(session_is_admin({"username": "dave"}))

    def test_admin_role_without_legacy_unlock_flag_is_admin(self):
        from osint_bot.web import session_is_admin
        with _isolated_storage() as (_tmp, store):
            _make_user(store, "erin", role="admin")
            self.assertTrue(session_is_admin({"username": "erin"}))

    def test_legacy_admin_unlocked_flag_grants_admin_regardless_of_role(self):
        from osint_bot.web import session_is_admin
        with _isolated_storage() as (_tmp, store):
            _make_user(store, "frank", role="analyst")
            self.assertTrue(session_is_admin({"username": "frank", "admin_unlocked": True}))

    def test_unknown_username_in_session_is_not_admin(self):
        from osint_bot.web import session_is_admin
        with _isolated_storage():
            self.assertFalse(session_is_admin({"username": "ghost"}))

    def test_role_change_takes_effect_immediately_no_session_caching(self):
        """The whole point of a DB lookup per-request instead of caching the
        role in the session: a demotion applies on the very next check."""
        from osint_bot.web import session_is_admin
        with _isolated_storage() as (_tmp, store):
            _make_user(store, "grace", role="admin")
            sess = {"username": "grace"}
            self.assertTrue(session_is_admin(sess))
            # Demote — same session dict, no re-login.
            user = store.get_user("grace")
            user["role"] = "analyst"
            store.put_user(user)
            self.assertFalse(session_is_admin(sess))


class PublicUserExposesRoleTests(unittest.TestCase):
    def test_public_user_includes_role(self):
        from osint_bot.web import public_user
        result = public_user({"username": "hank", "plan": "free", "created_at": "", "role": "admin"})
        self.assertEqual(result["role"], "admin")

    def test_public_user_defaults_role_to_analyst(self):
        from osint_bot.web import public_user
        result = public_user({"username": "iris", "plan": "free", "created_at": ""})
        self.assertEqual(result["role"], "analyst")


if __name__ == "__main__":
    unittest.main()
