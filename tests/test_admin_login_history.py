"""Tests for admin_stats()'s per-user login history breakdown (Google login
feature): who logged in, when (last), how many times, via which method."""
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


def _make_user(store, username, email, auth_provider="password"):
    store.put_user({
        "username": username, "email": email, "password": "x",
        "plan": "free", "created_at": "2026-01-01T00:00:00+00:00",
        "disabled": False, "verified": True, "verified_at": "2026-01-01T00:00:00+00:00",
        "auth_provider": auth_provider,
    })


class AdminStatsLoginHistoryTests(unittest.TestCase):
    def test_user_with_no_logins_has_zero_count_and_empty_last_login(self):
        from osint_bot.web import admin_stats

        with _isolated_storage() as (_tmp, store):
            _make_user(store, "alice", "alice@example.com")
            data = admin_stats()

        row = next(r for r in data["logins"] if r["username"] == "alice")
        self.assertEqual(row["login_count"], 0)
        self.assertEqual(row["last_login"], "")
        self.assertEqual(row["email"], "alice@example.com")
        self.assertEqual(row["provider"], "password")

    def test_login_count_and_last_login_track_multiple_events(self):
        from osint_bot.web import admin_stats

        with _isolated_storage() as (_tmp, store):
            _make_user(store, "bob", "bob@example.com")
            store.append_audit_event("bob", "login_success", {"method": "password", "remote_ip": "1.1.1.1"})
            store.append_audit_event("bob", "login_success", {"method": "google", "remote_ip": "2.2.2.2"})
            data = admin_stats()

        row = next(r for r in data["logins"] if r["username"] == "bob")
        self.assertEqual(row["login_count"], 2)
        self.assertNotEqual(row["last_login"], "")
        # Last event (google) wins for last_method — chronologically 2nd.
        self.assertEqual(row["last_method"], "google")

    def test_google_provisioned_user_shows_google_provider(self):
        from osint_bot.web import admin_stats

        with _isolated_storage() as (_tmp, store):
            _make_user(store, "carol", "carol@gmail.com", auth_provider="google")
            store.append_audit_event("carol", "user_signup", {"email": "carol@gmail.com", "method": "google"})
            store.append_audit_event("carol", "login_success", {"method": "google", "remote_ip": "3.3.3.3"})
            data = admin_stats()

        row = next(r for r in data["logins"] if r["username"] == "carol")
        self.assertEqual(row["provider"], "google")
        self.assertEqual(row["login_count"], 1)

    def test_logins_sorted_by_last_login_descending(self):
        from osint_bot.web import admin_stats

        with _isolated_storage() as (_tmp, store):
            _make_user(store, "old_user", "old@example.com")
            _make_user(store, "new_user", "new@example.com")
            store.append_audit_event("old_user", "login_success", {"method": "password"})
            store.append_audit_event("new_user", "login_success", {"method": "password"})
            data = admin_stats()

        usernames_with_logins = [r["username"] for r in data["logins"] if r["login_count"] > 0]
        # new_user logged in after old_user -> comes first in the sorted list.
        self.assertEqual(usernames_with_logins[0], "new_user")

    def test_login_events_do_not_double_count_across_users(self):
        from osint_bot.web import admin_stats

        with _isolated_storage() as (_tmp, store):
            _make_user(store, "dave", "dave@example.com")
            _make_user(store, "erin", "erin@example.com")
            store.append_audit_event("dave", "login_success", {"method": "password"})
            data = admin_stats()

        dave_row = next(r for r in data["logins"] if r["username"] == "dave")
        erin_row = next(r for r in data["logins"] if r["username"] == "erin")
        self.assertEqual(dave_row["login_count"], 1)
        self.assertEqual(erin_row["login_count"], 0)


if __name__ == "__main__":
    unittest.main()
