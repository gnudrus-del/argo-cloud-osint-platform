"""Contratto di storage: l'interfaccia che web.py usa, indipendente dal backend.

``Storage`` (SQLite, storage.py) e ``PostgresStorage`` (storage_postgres.py)
implementano entrambi questo Protocol. Il resto dell'app dipende SOLO da questa
interfaccia, così swappare SQLite -> Postgres non tocca nessun call-site.

Il factory ``create_storage`` sceglie il backend a runtime dalla env
``DATABASE_URL`` (postgres://... -> Postgres se psycopg è installato, altrimenti
SQLite). Nessuna dipendenza obbligatoria: senza psycopg la piattaforma gira
identica su SQLite.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class StorageBackend(Protocol):
    # users
    def get_user(self, username: str) -> dict | None: ...
    def all_users(self) -> dict[str, dict]: ...
    def put_user(self, user: dict) -> None: ...
    # jobs
    def put_job(self, job_id: str, job: dict) -> None: ...
    def get_job(self, job_id: str) -> dict | None: ...
    def list_jobs(self, owner: str = "", limit: int = 50) -> list[dict]: ...
    def list_jobs_by_case(self, case_id: str, limit: int = 200) -> list[dict]: ...
    def list_jobs_without_case(self) -> list[dict]: ...
    def set_job_case(self, job_id: str, case_id: str) -> None: ...
    def delete_job(self, job_id: str) -> int: ...
    # cases
    def put_case(self, case: dict) -> None: ...
    def get_case(self, case_id: str) -> dict | None: ...
    def list_cases(self, owner: str = "", tenant_id: str = "", limit: int = 100) -> list[dict]: ...
    def delete_case(self, case_id: str) -> None: ...
    # roes
    def put_roe(self, roe: dict) -> None: ...
    def get_active_roe(self, case_id: str) -> dict | None: ...
    def list_roes(self, case_id: str) -> list[dict]: ...
    def revoke_roe(self, roe_id: str) -> None: ...
    # artifacts
    def put_artifact(self, artifact: dict) -> None: ...
    def list_artifacts(self, case_id: str = "", job_id: str = "") -> list[dict]: ...
    def get_artifact(self, artifact_id: str) -> dict | None: ...
    # api keys (encrypted at rest — see secrets_crypto.py)
    def put_api_key(self, username: str, service: str, value: str) -> None: ...
    def get_api_key(self, username: str, service: str) -> str | None: ...
    def list_api_keys(self, username: str) -> list[dict]: ...
    def delete_api_key(self, username: str, service: str) -> None: ...
    def all_api_keys(self) -> list[dict]: ...  # rotation-only, every user
    def set_api_key_encrypted(self, username: str, service: str, encrypted_value: str) -> None: ...
    # audit
    def append_audit_event(self, actor: str, action: str,
                           details: dict[str, Any] | None = None) -> dict[str, Any]: ...
    def all_audit_events(self) -> list[dict[str, Any]]: ...
    def verify_audit_chain(self) -> bool: ...
    # lifecycle
    def close(self) -> None: ...


class StoragePostgresRequiredError(RuntimeError):
    """Postgres è stato richiesto esplicitamente (OSINT_STORAGE_STRICT=1) ma
    non è raggiungibile. Sollevata invece di degradare silenziosamente."""


def create_storage(job_root: Path, *, database_url: str = "", override: str = "") -> StorageBackend:
    """Istanzia il backend di storage giusto.

    Precedenza:
      1. ``override`` esplicito ("sqlite" | "postgres") — usato nei test.
      2. ``database_url`` (o env ``DATABASE_URL``) postgres:// + psycopg presente.
      3. fallback: SQLite in ``job_root/gufo.sqlite3``.

    Di default, se Postgres è richiesto ma non raggiungibile (psycopg assente,
    DSN sbagliato, server irraggiungibile), degrada silenziosamente su SQLite
    con un log — un operatore può credere di essere su Postgres e non esserlo
    mai, senza accorgersene. Con ``OSINT_STORAGE_STRICT=1`` questo fallback
    diventa un errore fatale invece di un log facile da perdere: chi vuole la
    garanzia "o Postgres o niente" la ottiene esplicitamente, senza cambiare
    il comportamento di default per chi non l'ha mai richiesta.
    """
    import logging
    import os

    from .storage import Storage  # SQLite backend (sempre disponibile)

    url = database_url or os.getenv("DATABASE_URL", "")
    want_pg = override == "postgres" or (
        override != "sqlite" and url.startswith(("postgres://", "postgresql://"))
    )
    strict = os.getenv("OSINT_STORAGE_STRICT", "0").strip() == "1"

    if want_pg:
        try:
            from .storage_postgres import PostgresStorage
            return PostgresStorage(url, job_root=Path(job_root))
        except Exception as exc:  # psycopg assente o connessione fallita
            if strict:
                raise StoragePostgresRequiredError(
                    f"OSINT_STORAGE_STRICT=1: Postgres richiesto ma non disponibile ({exc}). "
                    "Avvio interrotto invece di degradare silenziosamente su SQLite."
                ) from exc
            logging.getLogger("osint_bot.storage").error(
                "Postgres richiesto ma non disponibile (%s); fallback su SQLite. "
                "Imposta OSINT_STORAGE_STRICT=1 per rendere questo un errore fatale.",
                exc,
            )

    return Storage(Path(job_root) / "gufo.sqlite3")
