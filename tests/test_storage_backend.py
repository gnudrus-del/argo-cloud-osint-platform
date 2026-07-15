"""Test dell'astrazione storage: factory, fallback graceful, conformità Protocol.

I test Postgres end-to-end richiederebbero un'istanza reale; qui verifichiamo
che (a) il default sia SQLite, (b) il factory degradi su SQLite quando Postgres
è richiesto ma psycopg manca, (c) il modulo Postgres si importi senza psycopg,
(d) il backend SQLite soddisfi il Protocol StorageBackend a runtime, (e) con
OSINT_STORAGE_STRICT=1 il fallback silenzioso diventa un errore fatale.
"""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from osint_bot.storage import Storage
from osint_bot.storage_base import StorageBackend, StoragePostgresRequiredError, create_storage


class StorageBackendTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def test_default_is_sqlite(self):
        backend = create_storage(Path(self.tmp))
        try:
            self.assertIsInstance(backend, Storage)
        finally:
            backend.close()

    def test_sqlite_satisfies_protocol(self):
        backend = create_storage(Path(self.tmp))
        try:
            self.assertIsInstance(backend, StorageBackend)
        finally:
            backend.close()

    def test_postgres_request_falls_back_when_psycopg_missing(self):
        # Se psycopg non è installato in questo ambiente, il factory deve
        # degradare su SQLite invece di sollevare.
        try:
            import psycopg  # noqa: F401
            has_pg = True
        except Exception:
            has_pg = False
        backend = create_storage(
            Path(self.tmp), database_url="postgresql://invalid:5432/none")
        try:
            if not has_pg:
                self.assertIsInstance(backend, Storage)
            else:
                # psycopg presente ma DSN invalido -> connessione fallisce -> fallback SQLite
                self.assertIsInstance(backend, Storage)
        finally:
            backend.close()

    def test_override_sqlite_forces_sqlite(self):
        backend = create_storage(
            Path(self.tmp), database_url="postgresql://x/y", override="sqlite")
        try:
            self.assertIsInstance(backend, Storage)
        finally:
            backend.close()

    def test_postgres_module_imports_without_psycopg(self):
        # Importare il modulo NON deve richiedere psycopg (import ritardato in __init__).
        import osint_bot.storage_postgres as sp
        self.assertTrue(hasattr(sp, "PostgresStorage"))

    def test_strict_mode_raises_instead_of_falling_back(self):
        """OSINT_STORAGE_STRICT=1: Postgres richiesto ma irraggiungibile deve
        far fallire l'avvio invece di degradare silenziosamente su SQLite."""
        with patch.dict(os.environ, {"OSINT_STORAGE_STRICT": "1"}):
            with self.assertRaises(StoragePostgresRequiredError):
                create_storage(Path(self.tmp), database_url="postgresql://invalid:5432/none")

    def test_strict_mode_does_not_affect_default_sqlite_usage(self):
        """OSINT_STORAGE_STRICT=1 senza DATABASE_URL non deve mai far
        fallire chi non ha mai chiesto Postgres — resta SQLite normalmente."""
        with patch.dict(os.environ, {"OSINT_STORAGE_STRICT": "1"}):
            backend = create_storage(Path(self.tmp))
            try:
                self.assertIsInstance(backend, Storage)
            finally:
                backend.close()

    def test_strict_mode_off_by_default_still_falls_back(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("OSINT_STORAGE_STRICT", None)
            backend = create_storage(Path(self.tmp), database_url="postgresql://invalid:5432/none")
        try:
            self.assertIsInstance(backend, Storage)
        finally:
            backend.close()

    def test_sqlite_roundtrip_through_factory(self):
        backend = create_storage(Path(self.tmp))
        try:
            backend.put_user({"username": "alice", "password": "x", "plan": "pro"})
            got = backend.get_user("alice")
            self.assertEqual(got["username"], "alice")
            self.assertEqual(got["plan"], "pro")
            ev = backend.append_audit_event("alice", "login", {"ip": "127.0.0.1"})
            self.assertIn("hash", ev)
            self.assertTrue(backend.verify_audit_chain())
        finally:
            backend.close()


if __name__ == "__main__":
    unittest.main()
