"""Integrazione Privacy Center/DSAR contro un vero PostgresStorage.

Gated da TEST_DATABASE_URL: skippato ovunque non ci sia un Postgres
raggiungibile (nessun ambiente di sviluppo locale in questa sessione lo ha —
gira solo nel job CI 'postgres-integration' con un container Postgres
reale). Rispecchia gli stessi scenari di tests/test_dsar_erasure.py e
tests/test_privacy_endpoints.py (SQLite) per provare che erase_actor_data,
verify_audit_chain e select_owned_columns si comportano allo stesso modo su
entrambi i backend — non solo che il codice Postgres "sembra giusto"."""
from __future__ import annotations

import hashlib
import os
import unittest
import uuid

TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL", "")


def _fresh_storage():
    """Una PostgresStorage su un DSN con schema pulito per il singolo test
    (drop + ricrea non è necessario: le tabelle sono CREATE TABLE IF NOT
    EXISTS e ogni test usa attori/id univoci per non intersecarsi)."""
    from osint_bot.storage_postgres import PostgresStorage
    return PostgresStorage(TEST_DATABASE_URL)


def _unique_actor(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


@unittest.skipUnless(TEST_DATABASE_URL, "richiede TEST_DATABASE_URL (Postgres live) — gira solo in CI")
class PostgresPrivacyRegressionTests(unittest.TestCase):
    """Stessi 3 comportamenti verificati su SQLite in test_dsar_erasure.py:
    la catena resta valida dopo una cancellazione legittima, una
    manomissione vera resta rilevata, l'export delle chiavi API funziona."""

    def test_erase_preserves_audit_chain_integrity(self):
        store = _fresh_storage()
        try:
            actor = _unique_actor("alice")
            store.put_user({"username": actor, "password": "x", "created_at": "now"})
            store.append_audit_event(actor, "login_success", {"note": f"{actor} logged in"})
            self.assertTrue(store.verify_audit_chain())

            req_id = uuid.uuid4().hex[:16]
            store.log_privacy_request({
                "id": req_id, "owner": actor, "type": "erase",
                "status": "pending", "reason": "test", "created_at": "now",
            })
            result = store.erase_actor_data(actor, request_id=req_id, redacted_placeholder="[REDACTED]")
            self.assertTrue(result["tombstone_id"].startswith("TOMB-"))
            self.assertTrue(store.verify_audit_chain())
        finally:
            store.close()

    def test_verify_audit_chain_still_detects_real_tampering(self):
        store = _fresh_storage()
        try:
            bystander = _unique_actor("bob")
            store.append_audit_event(bystander, "login_success", {"note": "bob logged in"})
            self.assertTrue(store.verify_audit_chain())

            store._exec(
                "UPDATE audit_events SET actor = 'mallory' WHERE actor = %s", (bystander,)
            )
            self.assertFalse(store.verify_audit_chain())
        finally:
            store.close()

    def test_select_owned_columns_finds_api_keys_by_username(self):
        store = _fresh_storage()
        try:
            actor = _unique_actor("alice")
            store.put_user({"username": actor, "password": "x", "created_at": "now"})
            store.put_api_key(actor, "shodan", "sk-test-123")
            rows = store.select_owned_columns("api_keys", "username", actor, ["service", "created_at"])
            self.assertEqual([r["service"] for r in rows], ["shodan"])
        finally:
            store.close()

    def test_erase_actor_data_deletes_business_rows_and_privacy_requests(self):
        store = _fresh_storage()
        try:
            actor = _unique_actor("alice")
            case_id = hashlib.sha256(actor.encode()).hexdigest()
            store.put_user({"username": actor, "password": "x", "created_at": "now"})
            store.put_case({"id": case_id, "owner": actor, "title": "T"})
            req_id = uuid.uuid4().hex[:16]
            store.log_privacy_request({
                "id": req_id, "owner": actor, "type": "erase",
                "status": "pending", "reason": "test", "created_at": "now",
            })
            result = store.erase_actor_data(actor, request_id=req_id, redacted_placeholder="[REDACTED]")
            self.assertEqual(result["deleted_counts"]["cases"], 1)
            self.assertEqual(result["deleted_counts"]["users"], 1)
            self.assertIsNone(store.get_user(actor))
            self.assertEqual(store.list_privacy_requests(actor), [])
        finally:
            store.close()


if __name__ == "__main__":
    unittest.main()
