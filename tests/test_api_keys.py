import tempfile
import unittest
from pathlib import Path

from osint_bot.storage import Storage


def _make_storage(tmp: str) -> Storage:
    return Storage(Path(tmp) / "gufo.sqlite3")


class ApiKeyStorageTests(unittest.TestCase):
    def test_put_get_list_delete_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = _make_storage(tmp)
            store.put_user({"username": "alice", "password": "p", "plan": "free", "created_at": "x", "disabled": False})
            store.put_api_key("alice", "shodan", "SHODANSECRET123")
            store.put_api_key("alice", "hibp", "HIBPSECRET456")
            self.assertEqual(store.get_api_key("alice", "shodan"), "SHODANSECRET123")

            keys = store.list_api_keys("alice")
            services = [k["service"] for k in keys]
            self.assertEqual(services, ["hibp", "shodan"])  # alphabetical
            mask_by_service = {k["service"]: k["masked"] for k in keys}
            # The masked preview never exposes the full key; only the last 4 chars.
            self.assertNotIn("SECRET", mask_by_service["shodan"])
            self.assertTrue(mask_by_service["shodan"].endswith("T123"))
            self.assertTrue(mask_by_service["hibp"].endswith("T456"))

            store.delete_api_key("alice", "shodan")
            self.assertIsNone(store.get_api_key("alice", "shodan"))
            store.close()

    def test_put_empty_value_deletes(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = _make_storage(tmp)
            store.put_user({"username": "alice", "password": "p", "plan": "free", "created_at": "x", "disabled": False})
            store.put_api_key("alice", "shodan", "SECRET")
            store.put_api_key("alice", "shodan", "")
            self.assertIsNone(store.get_api_key("alice", "shodan"))
            store.close()

    def test_keys_isolated_per_user(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = _make_storage(tmp)
            for name in ("alice", "bob"):
                store.put_user({"username": name, "password": "p", "plan": "free", "created_at": "x", "disabled": False})
            store.put_api_key("alice", "shodan", "ALICE-KEY")
            store.put_api_key("bob", "shodan", "BOB-KEY")
            self.assertEqual(store.get_api_key("alice", "shodan"), "ALICE-KEY")
            self.assertEqual(store.get_api_key("bob", "shodan"), "BOB-KEY")
            store.close()


if __name__ == "__main__":
    unittest.main()
