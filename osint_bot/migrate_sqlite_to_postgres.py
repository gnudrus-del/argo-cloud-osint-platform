"""Migrazione one-shot dei dati da SQLite a Postgres (Fase 4).

Copia utenti, casi, job (con case_id), RoE, artefatti, chiavi API e la catena
audit (verbatim, preservando hash/timestamp) dal DB SQLite al backend Postgres.
Idempotente sugli upsert; l'audit viene importato solo se la tabella PG è vuota.

Uso:
    python -m osint_bot.migrate_sqlite_to_postgres \
        --sqlite web_jobs/gufo.sqlite3 \
        --dsn postgresql://argo:PW@127.0.0.1:5433/argo

Oppure senza argomenti: legge OSINT_JOB_DIR/gufo.sqlite3 e DATABASE_URL dall'env.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


def migrate(sqlite_path: str, dsn: str) -> dict[str, int]:
    from .storage import Storage
    from .storage_postgres import PostgresStorage

    src = Storage(Path(sqlite_path))
    dst = PostgresStorage(dsn)
    counts = {"users": 0, "cases": 0, "jobs": 0, "roes": 0,
              "artifacts": 0, "api_keys": 0, "audit": 0}
    try:
        # Users
        for user in src.all_users().values():
            dst.put_user(user)
            counts["users"] += 1

        # Cases (limite alto = tutti)
        cases = src.list_cases("", "", limit=1_000_000)
        for case in cases:
            dst.put_case(case)
            counts["cases"] += 1
            # RoE del caso
            for roe in src.list_roes(case["id"]):
                dst.put_roe(roe)
                counts["roes"] += 1
            # Job del caso (preserva case_id)
            for job in src.list_jobs_by_case(case["id"], limit=1_000_000):
                job["case_id"] = case["id"]
                dst.put_job(job["id"], job)
                counts["jobs"] += 1

        # Job orfani (senza caso)
        for job in src.list_jobs_without_case():
            dst.put_job(job["id"], job)
            counts["jobs"] += 1

        # Artefatti (tutti)
        for art in src.list_artifacts():
            dst.put_artifact(art)
            counts["artifacts"] += 1

        # Chiavi API (valore reale via get_api_key, non il mascherato)
        for username in src.all_users():
            for entry in src.list_api_keys(username):
                svc = entry["service"]
                val = src.get_api_key(username, svc)
                if val:
                    dst.put_api_key(username, svc, val)
                    counts["api_keys"] += 1

        # Audit verbatim (solo se PG vuoto)
        counts["audit"] = dst.import_audit_verbatim(src.all_audit_events())

        ok = dst.verify_audit_chain()
        counts["audit_chain_valid"] = 1 if ok else 0
    finally:
        src.close()
        dst.close()
    return counts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Migra Argo da SQLite a Postgres.")
    parser.add_argument("--sqlite", default=os.path.join(
        os.getenv("OSINT_JOB_DIR", "web_jobs"), "gufo.sqlite3"))
    parser.add_argument("--dsn", default=os.getenv("DATABASE_URL", ""))
    args = parser.parse_args(argv)

    if not args.dsn:
        print("ERR: nessun DSN Postgres. Passa --dsn o imposta DATABASE_URL.", file=sys.stderr)
        return 2
    if not Path(args.sqlite).exists():
        print(f"ERR: SQLite non trovato: {args.sqlite}", file=sys.stderr)
        return 2

    print(f"Migrazione {args.sqlite} -> {args.dsn.split('@')[-1]} ...")
    counts = migrate(args.sqlite, args.dsn)
    for k, v in counts.items():
        print(f"  {k}: {v}")
    if counts.get("audit_chain_valid") == 0:
        print("⚠ Catena audit NON valida dopo la migrazione: verifica manuale.", file=sys.stderr)
        return 1
    print("OK migrazione completata, catena audit verificata.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
