"""Tests for Pillar 0.4 — GDPR by-design."""
import json
import tempfile
import unittest
from pathlib import Path

from osint_bot.gdpr import (
    apply_retention_policy,
    dsar_erase,
    dsar_export,
    generate_ropa,
    tombstone_case,
)
from osint_bot.storage import Storage


def _store(tmp: str) -> Storage:
    return Storage(Path(tmp) / "gufo.sqlite3")


def _make_case(store: Storage, case_id: str, owner: str = "alice",
               retention_until: str | None = None, status: str = "open") -> dict:
    case = {
        "id": case_id,
        "owner": owner,
        "title": f"Caso {case_id[:4]}",
        "status": status,
        "legal_basis": {"type": "legitimate_interest", "reference": "mandato 2026/01"},
        "purpose": "OSINT investigation",
        "retention_until": retention_until,
    }
    store.put_case(case)
    return case


def _make_job(store: Storage, job_id: str, case_id: str,
              target: str = "bob@example.com") -> None:
    store.put_job(job_id, {
        "id": job_id,
        "owner": "alice",
        "status": "complete",
        "created_at": "2026-06-01T00:00:00+00:00",
        "updated_at": "2026-06-01T00:00:00+00:00",
        "profile": {"target": target, "target_type": "email"},
        "case_id": case_id,
    })


class TombstoneTests(unittest.TestCase):
    def test_tombstone_removes_email_from_job_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = _store(tmp)
            _make_case(store, "case-1")
            _make_job(store, "a" * 32, "case-1", target="victim@example.com")

            result = tombstone_case("case-1", "admin", store)

            job = store.get_job("a" * 32)
            self.assertNotIn("victim@example.com", json.dumps(job))
            self.assertIn("[ERASED", json.dumps(job))
            self.assertEqual(result["jobs_scrubbed"], 1)
            store.close()

    def test_tombstone_leaves_case_status_expired(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = _store(tmp)
            _make_case(store, "case-2")
            tombstone_case("case-2", "admin", store)
            case = store.get_case("case-2")
            self.assertEqual(case["status"], "expired")
            store.close()

    def test_tombstone_audit_chain_stays_valid(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = _store(tmp)
            _make_case(store, "case-3")
            _make_job(store, "b" * 32, "case-3", target="info@example.org")
            tombstone_case("case-3", "admin", store)
            self.assertTrue(store.verify_audit_chain())
            store.close()

    def test_tombstone_writes_case_tombstoned_audit_event(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = _store(tmp)
            _make_case(store, "case-4")
            tombstone_case("case-4", "admin", store)
            actions = [e["action"] for e in store.all_audit_events()]
            self.assertIn("case_tombstoned", actions)
            store.close()


class RetentionPolicyTests(unittest.TestCase):
    def test_expired_case_is_tombstoned_by_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = _store(tmp)
            # Past date → should be tombstoned.
            _make_case(store, "case-exp", retention_until="2020-01-01T00:00:00+00:00")
            _make_job(store, "c" * 32, "case-exp", target="pii@test.com")
            # Future date → must be skipped.
            _make_case(store, "case-ok", retention_until="2099-01-01T00:00:00+00:00")

            results = apply_retention_policy(store, actor="scheduler")

            tombstoned_ids = [r["case_id"] for r in results]
            self.assertIn("case-exp", tombstoned_ids)
            self.assertNotIn("case-ok", tombstoned_ids)
            job = store.get_job("c" * 32)
            self.assertNotIn("pii@test.com", json.dumps(job))
            store.close()

    def test_already_expired_case_is_not_re_tombstoned(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = _store(tmp)
            _make_case(store, "case-done", retention_until="2020-01-01T00:00:00+00:00",
                       status="expired")
            results = apply_retention_policy(store, actor="scheduler")
            self.assertEqual(results, [])
            store.close()


class DSARTests(unittest.TestCase):
    def test_dsar_export_finds_matching_jobs(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = _store(tmp)
            _make_job(store, "d" * 32, "", target="alice@corp.com")
            _make_job(store, "e" * 32, "", target="bob@corp.com")

            result = dsar_export("alice@corp.com", store)
            self.assertIn("d" * 32, result["jobs"])
            self.assertNotIn("e" * 32, result["jobs"])
            self.assertEqual(result["total"], 1)
            store.close()

    def test_dsar_erase_scrubs_target_from_job(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = _store(tmp)
            _make_job(store, "f" * 32, "", target="victim@evil.com")
            result = dsar_erase("victim@evil.com", "dpo", store)
            job = store.get_job("f" * 32)
            self.assertNotIn("victim@evil.com", json.dumps(job))
            self.assertEqual(result["jobs_scrubbed"], 1)
            self.assertIn("audit_hash", result)
            store.close()

    def test_dsar_erase_writes_audit_event_with_hash_not_plaintext(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = _store(tmp)
            _make_job(store, "g" * 32, "", target="secret@corp.com")
            dsar_erase("secret@corp.com", "dpo", store)
            events = store.all_audit_events()
            dsar_events = [e for e in events if e["action"] == "dsar_erased"]
            self.assertEqual(len(dsar_events), 1)
            raw = json.dumps(dsar_events[0]["details"])
            self.assertNotIn("secret@corp.com", raw, "plaintext selector must not appear in audit")
            self.assertIn("selector_sha256", dsar_events[0]["details"])
            store.close()

    def test_dsar_erase_audit_chain_remains_valid(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = _store(tmp)
            _make_job(store, "h" * 32, "", target="test@test.com")
            dsar_erase("test@test.com", "dpo", store)
            self.assertTrue(store.verify_audit_chain())
            store.close()


class RoPATests(unittest.TestCase):
    def test_ropa_lists_all_owner_cases(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = _store(tmp)
            _make_case(store, "case-A", owner="alice", retention_until="2027-01-01T00:00:00+00:00")
            _make_case(store, "case-B", owner="alice")
            _make_case(store, "case-C", owner="bob")
            _make_job(store, "i" * 32, "case-A", target="someone@example.com")

            ropa = generate_ropa("alice", store)
            ids = {r["case_id"] for r in ropa}
            self.assertIn("case-A", ids)
            self.assertIn("case-B", ids)
            self.assertNotIn("case-C", ids)
            store.close()

    def test_ropa_infers_data_categories_from_target_type(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = _store(tmp)
            _make_case(store, "case-D", owner="alice")
            store.put_job("j" * 32, {
                "id": "j" * 32, "owner": "alice", "status": "complete",
                "created_at": "x", "updated_at": "x",
                "profile": {"target": "alice@example.com", "target_type": "email"},
                "case_id": "case-D",
            })
            ropa = generate_ropa("alice", store)
            entry = next(r for r in ropa if r["case_id"] == "case-D")
            self.assertIn("contact_data", entry["data_categories"])
            self.assertIn("identifiers", entry["data_categories"])
            store.close()

    def test_ropa_entry_includes_required_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = _store(tmp)
            _make_case(store, "case-E", owner="alice")
            ropa = generate_ropa("alice", store)
            entry = ropa[0]
            for field in ("case_id", "title", "status", "purpose", "legal_basis",
                          "data_categories", "retention_until", "job_count",
                          "created_at", "updated_at"):
                self.assertIn(field, entry, f"RoPA entry missing: {field}")
            store.close()


if __name__ == "__main__":
    unittest.main()
