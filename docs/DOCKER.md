# Docker

Argo ships a `Dockerfile` and `docker-compose.yml` that build a lean Python 3.12-slim image.

## Build locally

```bash
docker build -t argo-cloud-osint-platform:local .
```

## Run with docker compose

`docker-compose.yml` requires `OSINT_WEB_TOKEN` to be set:

```bash
export OSINT_WEB_TOKEN="pick-a-long-random-token"
docker compose up --build
```

Optional env vars (all read from your shell, all default to safe values):

- `OSINT_SIGNUPS_ENABLED` (default `0` in compose)
- `OSINT_SECURE_COOKIE`, `OSINT_HSTS` (default `0` locally; set `1` in production behind HTTPS)
- BYOK API keys (`SHODAN_API_KEY`, `VIRUSTOTAL_API_KEY`, ...)

## Volumes

- `argo_jobs` → `/app/web_jobs` (case data, cache)
- `argo_reports` → `/app/reports` (generated reports)

These are Docker-managed volumes. For a production self-hosted install, prefer bind mounts on an OS-encrypted disk.

## Healthcheck

The image includes a healthcheck that hits `/api/dashboard`. Response `200` or `401` is considered healthy (401 means "backend up, auth required" — as designed).

## Publishing to GHCR

Publishing is planned via GitHub Actions on tagged releases. See [`RELEASE_PROCESS.md`](RELEASE_PROCESS.md).

Manual push (advanced):

```bash
echo $GITHUB_TOKEN | docker login ghcr.io -u <your-user> --password-stdin
docker tag argo-cloud-osint-platform:local ghcr.io/<your-user>/argo-cloud-osint-platform:0.1.0
docker push ghcr.io/<your-user>/argo-cloud-osint-platform:0.1.0
```

## Behind a reverse proxy

Argo listens on `0.0.0.0:8000` inside the container. Terminate TLS in your reverse proxy (Caddy, Traefik, nginx). Set `OSINT_SECURE_COOKIE=1` and `OSINT_HSTS=1` when serving over HTTPS.
