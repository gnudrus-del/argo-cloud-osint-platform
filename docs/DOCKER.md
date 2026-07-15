# Docker

Argo ships a `Dockerfile` and `docker-compose.yml` that build a lean Python 3.12-slim image.

## Build locally

```bash
docker build -t argo-cloud-osint-platform:local .
```

## Run with docker compose

`docker-compose.yml` ships **Postgres as the recommended storage backend** — it's included as a service and wired up automatically. Requires `OSINT_WEB_TOKEN` and `POSTGRES_PASSWORD` to be set:

```bash
export OSINT_WEB_TOKEN="pick-a-long-random-token"
export POSTGRES_PASSWORD="pick-another-long-random-value"
docker compose up --build
```

`argo-osint` waits for Postgres's healthcheck before starting (`depends_on: condition: service_healthy`), and the image always has `psycopg[binary]` installed (via the `[postgres]` extra in the `Dockerfile`) so this works with zero extra setup.

**Want SQLite instead** (zero-config, fine for a single analyst or evaluation — see `docs/CONFIGURATION.md`)? Comment out the `postgres` service and the `DATABASE_URL` line under `argo-osint` in `docker-compose.yml`, and drop `depends_on`. The app falls back to a SQLite file under the `argo_jobs` volume with no other change needed.

Optional env vars (all read from your shell, all default to safe values):

- `OSINT_SIGNUPS_ENABLED` (default `0` in compose)
- `OSINT_SECURE_COOKIE`, `OSINT_HSTS` (default `0` locally; set `1` in production behind HTTPS)
- `POSTGRES_USER`, `POSTGRES_DB` (default `argo`/`argo`)
- `OSINT_STORAGE_STRICT=1` — makes a broken/unreachable Postgres connection a **fatal** startup error instead of a silent fallback to SQLite (see `docs/CONFIGURATION.md`). Recommended once you've committed to Postgres in production, so a misconfiguration never goes unnoticed.
- BYOK API keys (`SHODAN_API_KEY`, `VIRUSTOTAL_API_KEY`, ...)

## Volumes

- `argo_jobs` → `/app/web_jobs` (case data, cache; SQLite file lives here if you're not using Postgres)
- `argo_reports` → `/app/reports` (generated reports)
- `argo_postgres_data` → Postgres's own data directory (only relevant if you kept the `postgres` service)

These are Docker-managed volumes. For a production self-hosted install, prefer bind mounts on an OS-encrypted disk.

## Healthcheck

The image includes a healthcheck that hits `/api/dashboard`. Response `200` or `401` is considered healthy (401 means "backend up, auth required" — as designed).

## Pulling the published image

A prebuilt image is published to GHCR automatically on every tagged GitHub release (`.github/workflows/docker-publish.yml`), with Sigstore build provenance attested:

```bash
docker pull ghcr.io/gnudrus-del/argo-cloud-osint-platform:latest
# pinned releases: :0.2.0, :0.1.0
```

Verify the attestation:

```bash
gh attestation verify oci://ghcr.io/gnudrus-del/argo-cloud-osint-platform:0.2.0 \
    --repo gnudrus-del/argo-cloud-osint-platform
```

See [`RELEASE_PROCESS.md`](RELEASE_PROCESS.md) for how a maintainer cuts a new tagged image.

## Behind a reverse proxy

Argo listens on `0.0.0.0:8000` inside the container. Terminate TLS in your reverse proxy (Caddy, Traefik, nginx). Set `OSINT_SECURE_COOKIE=1` and `OSINT_HSTS=1` when serving over HTTPS.
