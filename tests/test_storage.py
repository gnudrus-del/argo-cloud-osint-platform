import json
import tempfile
import threading
import unittest
from pathlib import Path

from osint_bot.storage import Storage


def _make_storage(tmp: str) -> Storage:
    return Storage(Path(tmp) / "gufo.sqlite3")


class StorageUsersTests(unittest.TestCase):
    def test_put_and_get_user_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = _make_storage(tmp)
            store.put_user(
                {
                    "username": "alice",
                    "password": "hashed-pwd",
                    "plan": "pro",
                    "created_at": "2026-01-01T00:00:00+00:00",
                    "disabled": False,
                }
            )
            user = store.get_user("alice")
            self.assertEqual(user["username"], "alice")
            self.assertEqual(user["plan"], "pro")
            self.assertFalse(user["disabled"])
            store.close()

    def test_get_user_missing_returns_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = _make_storage(tmp)
            self.assertIsNone(store.get_user("nobody"))
            store.close()


class StorageJobsTests(unittest.TestCase):
    def _job(self, job_id: str, owner: str, status: str = "queued") -> dict:
        return {
            "id": job_id,
            "owner": owner,
            "status": status,
            "created_at": "2026-01-01T00:00:00+00:00",
            "updated_at": "2026-01-01T00:00:00+00:00",
            "profile": {"target": "example.com"},
        }

    def test_put_and_get_job_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = _make_storage(tmp)
            job = self._job("a" * 32, "alice")
            store.put_job(job["id"], job)
            loaded = store.get_job(job["id"])
            self.assertEqual(loaded["owner"], "alice")
            self.assertEqual(loaded["profile"]["target"], "example.com")
            store.close()

    def test_list_jobs_filters_by_owner(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = _make_storage(tmp)
            store.put_job("a" * 32, self._job("a" * 32, "alice"))
            store.put_job("b" * 32, self._job("b" * 32, "bob"))
            alice = store.list_jobs(owner="alice")
            bob = store.list_jobs(owner="bob")
            all_ = store.list_jobs()
            self.assertEqual([j["owner"] for j in alice], ["alice"])
            self.assertEqual([j["owner"] for j in bob], ["bob"])
            self.assertEqual(len(all_), 2)
            store.close()

    def test_put_job_upserts(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = _make_storage(tmp)
            job = self._job("a" * 32, "alice", status="queued")
            store.put_job(job["id"], job)
            job["status"] = "complete"
            store.put_job(job["id"], job)
            self.assertEqual(store.get_job(job["id"])["status"], "complete")
            self.assertEqual(len(store.list_jobs()), 1)
            store.close()


class StorageAuditTests(unittest.TestCase):
    def test_audit_chain_verifies(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = _make_storage(tmp)
            store.append_audit_event("alice", "job_created", {"job_id": "1"})
            store.append_audit_event("alice", "job_completed", {"job_id": "1"})
            self.assertTrue(store.verify_audit_chain())
            events = store.all_audit_events()
            self.assertEqual(len(events), 2)
            self.assertEqual(events[0]["previous_hash"], "")
            self.assertEqual(events[1]["previous_hash"], events[0]["hash"])
            store.close()

    def test_concurrent_appends_preserve_chain(self):
        thread_count = 16
        with tempfile.TemporaryDirectory() as tmp:
            store = _make_storage(tmp)
            barrier = threading.Barrier(thread_count)

            def worker(idx: int) -> None:
                barrier.wait()
                store.append_audit_event(f"worker-{idx}", "concurrent_event", {"idx": idx})

            threads = [threading.Thread(target=worker, args=(i,)) for i in range(thread_count)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            self.assertTrue(store.verify_audit_chain())
            self.assertEqual(len(store.all_audit_events()), thread_count)
            store.close()


class StorageMigrationTests(unittest.TestCase):
    def test_migrate_from_files_imports_users_jobs_and_audit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "users.json").write_text(
                json.dumps(
                    {
                        "alice": {
                            "username": "alice",
                            "password": "h",
                            "plan": "free",
                            "created_at": "2026-01-01T00:00:00+00:00",
                            "disabled": False,
                        }
                    }
                ),
                encoding="utf-8",
            )
            (root / "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json").write_text(
                json.dumps(
                    {
                        "id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "owner": "alice",
                        "status": "complete",
                        "created_at": "2026-01-01T00:00:00+00:00",
                        "updated_at": "2026-01-01T00:00:00+00:00",
                        "profile": {},
                    }
                ),
                encoding="utf-8",
            )
            # Build an audit.log via the file-based primitive so hashes line up.
            from osint_bot.audit import append_audit_event

            append_audit_event(root, "alice", "job_created", {"job_id": "1"})
            append_audit_event(root, "alice", "job_completed", {"job_id": "1"})

            store = Storage(root / "gufo.sqlite3")
            counts = store.migrate_from_files(root)
            self.assertEqual(counts["users"], 1)
            self.assertEqual(counts["jobs"], 1)
            self.assertEqual(counts["audit"], 2)
            self.assertTrue(store.verify_audit_chain())
            self.assertIsNotNone(store.get_user("alice"))
            self.assertIsNotNone(store.get_job("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
            store.close()

    def test_migrate_audit_is_skipped_when_table_not_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            from osint_bot.audit import append_audit_event

            append_audit_event(root, "alice", "old", {})
            store = Storage(root / "gufo.sqlite3")
            store.append_audit_event("bob", "new", {})
            counts = store.migrate_from_files(root)
            self.assertEqual(counts["audit"], 0)
            store.close()


if __name__ == "__main__":
    unittest.main()
