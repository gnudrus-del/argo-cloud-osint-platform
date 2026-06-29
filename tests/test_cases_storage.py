import sqlite3
import tempfile
import unittest
import uuid
from pathlib import Path

from osint_bot.storage import Storage


def _store(tmp: str) -> Storage:
    return Storage(Path(tmp) / "gufo.sqlite3")


def _case(owner: str = "alice", title: str = "Caso uno", **extra) -> dict:
    base = {
        "id": uuid.uuid4().hex,
        "owner": owner,
        "tenant_id": owner,
        "title": title,
        "legal_basis": {"type": "legitimate_interest", "reference": "mandato 2026/01"},
        "purpose": "Recon su perimetro autorizzato",
    }
    base.update(extra)
    return base


class CaseStorageTests(unittest.TestCase):
    def test_put_get_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = _store(tmp)
            c = _case(collaborators=["bob"])
            store.put_case(c)
            loaded = store.get_case(c["id"])
            self.assertEqual(loaded["title"], "Caso uno")
            self.assertEqual(loaded["collaborators"], ["bob"])
            self.assertEqual(loaded["legal_basis"]["type"], "legitimate_interest")
            store.close()

    def test_list_cases_includes_owner_and_collaborator(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = _store(tmp)
            store.put_case(_case(owner="alice", title="Alice case"))
            store.put_case(_case(owner="bob", title="Bob case", collaborators=["alice"]))
            store.put_case(_case(owner="carol", title="Carol case"))

            alice = store.list_cases(owner="alice")
            titles = {c["title"] for c in alice}
            self.assertEqual(titles, {"Alice case", "Bob case"})
            self.assertNotIn("Carol case", titles)
            store.close()

    def test_jobs_can_be_linked_to_case_and_listed(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = _store(tmp)
            c = _case()
            store.put_case(c)
            for i in range(3):
                store.put_job(f"{'a'*30}{i:02d}", {
                    "id": f"{'a'*30}{i:02d}",
                    "owner": "alice",
                    "status": "complete",
                    "created_at": "x", "updated_at": "x",
                    "profile": {},
                    "case_id": c["id"],
                })
            jobs = store.list_jobs_by_case(c["id"])
            self.assertEqual(len(jobs), 3)
            self.assertTrue(all(j["case_id"] == c["id"] for j in jobs))
            store.close()

    def test_list_jobs_without_case_finds_legacy_jobs(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = _store(tmp)
            for i in range(2):
                store.put_job(f"{'b'*30}{i:02d}", {
                    "id": f"{'b'*30}{i:02d}",
                    "owner": "alice",
                    "status": "complete",
                    "created_at": "x", "updated_at": "x",
                    "profile": {},
                })  # no case_id
            orphans = store.list_jobs_without_case()
            self.assertEqual(len(orphans), 2)
            store.close()

    def test_set_job_case_backfills(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = _store(tmp)
            c = _case()
            store.put_case(c)
            store.put_job("c" * 32, {
                "id": "c" * 32, "owner": "alice", "status": "queued",
                "created_at": "x", "updated_at": "x", "profile": {},
            })
            store.set_job_case("c" * 32, c["id"])
            jobs = store.list_jobs_by_case(c["id"])
            self.assertEqual(len(jobs), 1)
            store.close()

    def test_idempotent_column_migration_on_pre_existing_db(self):
        """A DB created before 0.1 (no case_id column) must migrate cleanly."""
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "gufo.sqlite3"
            # Build a minimal pre-0.1 schema: jobs without case_id.
            old = sqlite3.connect(str(db))
            old.executescript(
                """
                CREATE TABLE jobs (
                    id TEXT PRIMARY KEY,
                    owner TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                """
            )
            old.execute(
                "INSERT INTO jobs VALUES (?,?,?,?,?,?)",
                ("a" * 32, "alice", "complete", "x", "x", '{"id":"' + "a" * 32 + '"}'),
            )
            old.commit()
            old.close()

            # Open via Storage — must add case_id without errors.
            store = Storage(db)
            self.assertEqual(len(store.list_jobs_without_case()), 1)
            store.close()


if __name__ == "__main__":
    unittest.main()
