# Configuration

Argo is configured entirely via environment variables. See `.env.example` at the repo root for the full list — this document explains the categories.

## Web server

| Variable | Default | Purpose |
| --- | --- | --- |
| `OSINT_WEB_HOST` | `127.0.0.1` | Bind address. |
| `OSINT_WEB_PORT` | `7655` | Bind port. |
| `OSINT_WEB_TOKEN` | (empty) | Bearer for health checks (not user auth). |
| `OSINT_JOB_DIR` | `web_jobs` | Where case/job files live. |
| `OSINT_SIGNUPS_ENABLED` | `1` | Set `0` after your users are created to freeze signups. |
| `OSINT_SECURE_COOKIE` | `1` | Set to `1` when serving via HTTPS. |
| `OSINT_HSTS` | `1` | Emits `Strict-Transport-Security`. |
| `OSINT_MAX_JSON_BYTES` | `65536` | Request body limit for JSON endpoints. |
| `OSINT_MAX_UPLOAD_BYTES` | `26214400` | 25 MiB upload cap. |

## Admin account (hidden-tool unlock)

The admin password is not stored in code. Generate a hash and place it in `ARGO_ADMIN_PASSWORD_HASH`:

```bash
python -c "import os,hashlib; s=os.urandom(16); h=hashlib.pbkdf2_hmac('sha256',b'YOUR_PASSWORD',s,200000); print(f'pbkdf2_sha256\$200000\${s.hex()}\${h.hex()}')"
```

Set `ARGO_ADMIN_USER` alongside it. Both are required to unlock admin-only tools.

## Storage

Default: SQLite under `$OSINT_JOB_DIR`. For multi-user or higher load:

```bash
DATABASE_URL=postgresql://argo:password@host:port/argo
```

Requires the `postgres` extra: `pip install -e ".[postgres]"`.

## Job queue

Default: in-process. For multi-worker:

```bash
QUEUE_BACKEND=celery
CELERY_BROKER_URL=redis://host:port/0
```

Requires the `queue` extra.

## Graph and search (optional)

- `NEO4J_HTTP_URL` + `NEO4J_PASSWORD` — enables graph sync.
- `OPENSEARCH_URL` — enables full-text index of findings.

Both use their REST APIs directly (no Python driver needed).

## BYOK API keys

Each connector reads one env var. Missing key = the connector reports `missing_key` cleanly and is skipped. Fill only what you have. Full list in `.env.example`.

## Local tools

Some connectors wrap installed CLIs (holehe, maigret, theHarvester, etc.). Their paths are configured via env vars — see the `# ─── Tool locali installati` block in `.env.example`.

## Production checklist

- [ ] `OSINT_WEB_TOKEN` is set to a long random value.
- [ ] `OSINT_SIGNUPS_ENABLED=0` once your users exist.
- [ ] `OSINT_SECURE_COOKIE=1`, `OSINT_HSTS=1`.
- [ ] Reverse proxy terminates TLS with valid certificates.
- [ ] `.env` is `chmod 600` and owned by the service user.
- [ ] OS-level disk encryption on the datastore volume.
