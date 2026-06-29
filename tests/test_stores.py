import time
import unittest

from osint_bot.stores import InMemoryRateLimiter, InMemorySessionStore


class SessionStoreTests(unittest.TestCase):
    def test_put_get_delete_touch(self):
        store = InMemorySessionStore()
        store.put("sid", {"username": "alice", "last_seen": 100.0})
        self.assertEqual(store.get("sid")["username"], "alice")
        store.touch("sid", 200.0)
        self.assertEqual(store.get("sid")["last_seen"], 200.0)
        store.delete("sid")
        self.assertIsNone(store.get("sid"))


class RateLimiterTests(unittest.TestCase):
    def test_blocks_after_limit(self):
        limiter = InMemoryRateLimiter()
        for _ in range(3):
            self.assertTrue(limiter.hit("alice", window_seconds=60, limit=3))
        self.assertFalse(limiter.hit("alice", window_seconds=60, limit=3))

    def test_windows_are_per_key(self):
        limiter = InMemoryRateLimiter()
        limiter.hit("alice", window_seconds=60, limit=1)
        # Bob has his own window.
        self.assertTrue(limiter.hit("bob", window_seconds=60, limit=1))
        # Alice already used hers up.
        self.assertFalse(limiter.hit("alice", window_seconds=60, limit=1))

    def test_window_slides(self):
        limiter = InMemoryRateLimiter()
        self.assertTrue(limiter.hit("alice", window_seconds=0, limit=1))
        # window_seconds=0 → every hit expires immediately, never blocked.
        time.sleep(0.001)
        self.assertTrue(limiter.hit("alice", window_seconds=0, limit=1))


if __name__ == "__main__":
    unittest.main()
