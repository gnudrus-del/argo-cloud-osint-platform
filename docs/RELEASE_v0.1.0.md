# v0.1.0 — Argo Cloud OSINT Platform: first public release

Argo is a self-hosted defensive OSINT platform for analysts who need sourced, auditable and privacy-aware investigations. This is the first public release.

## Highlights

- **58 native connectors** (43 key-free + 15 BYOK) — crt.sh, RDAP, DNS, TLS certs, Wayback, holehe, maigret, theHarvester, Shodan, VirusTotal, HIBP, SecurityTrails, MISP, and 45 more.
- **CLI + web UI** for case-based investigations. Everything runs on your machine or VM.
- **SHA-256 audit chain** — every event is hash-linked, tampering is detectable with one command.
- **STIX 2.1 + MISP exports** for TIP integration, alongside Markdown / JSON / PDF.
- **Privacy-by-design**: personal targets require legal basis; contacts are redacted by default; GDPR DSAR endpoints included.
- **Deploy anywhere**: Docker, Docker Compose, systemd + Caddy on a VM. `Dockerfile` + `docker-compose.yml` in the repo.

## Installation

### From source

```bash
git clone https://github.com/gnudrus-del/argo-cloud-osint-platform.git
cd argo-cloud-osint-platform
python -m venv .venv
source .venv/bin/activate   # Windows: .\.venv\Scripts\Activate.ps1
pip install -e .
```

### Docker

```bash
git clone https://github.com/gnudrus-del/argo-cloud-osint-platform.git
cd argo-cloud-osint-platform
export OSINT_WEB_TOKEN="pick-a-long-random-token"
docker compose up --build
```

Full guide: [`docs/QUICKSTART.md`](https://github.com/gnudrus-del/argo-cloud-osint-platform/blob/main/docs/QUICKSTART.md).

## First investigation

```bash
argo-osint example.com --type domain --provider none \
    --output-dir reports/smoke --format both
```

More recipes: [`docs/EXAMPLES.md`](https://github.com/gnudrus-del/argo-cloud-osint-platform/blob/main/docs/EXAMPLES.md).

## Responsible use

Argo is a **defensive** tool. Please read [`docs/RESPONSIBLE_USE.md`](https://github.com/gnudrus-del/argo-cloud-osint-platform/blob/main/docs/RESPONSIBLE_USE.md) before running personal-target investigations. Argo refuses to be a stalking, doxxing, or unauthorized-scanning tool.

## Known limitations

- **BYOK provider keys are stored plaintext** in `.env`. Encryption-at-rest is planned for v0.2.0.
- **Datastore encryption-at-rest** is not applied — use OS-level disk encryption in production. Planned.
- **No PyPI package yet** — install from source. Package name `argo-cloud-osint` reserved.
- **No GHCR image yet** — workflow is in place, first publish will follow this release.
- **Screenshots** are placeholders in `docs/assets/`. Real screenshots to be added shortly.
- **Web UI test coverage** is manual; end-to-end tests are on the v0.2.0 roadmap.

## Upgrade notes

This is the first release, so no upgrade notes. Future releases will document breaking changes here.

## Documentation

- [Quickstart](https://github.com/gnudrus-del/argo-cloud-osint-platform/blob/main/docs/QUICKSTART.md)
- [Installation](https://github.com/gnudrus-del/argo-cloud-osint-platform/blob/main/docs/INSTALLATION.md)
- [Configuration](https://github.com/gnudrus-del/argo-cloud-osint-platform/blob/main/docs/CONFIGURATION.md)
- [Connectors](https://github.com/gnudrus-del/argo-cloud-osint-platform/blob/main/docs/CONNECTORS.md)
- [Threat model](https://github.com/gnudrus-del/argo-cloud-osint-platform/blob/main/docs/THREAT_MODEL.md)
- [Roadmap](https://github.com/gnudrus-del/argo-cloud-osint-platform/blob/main/docs/ROADMAP.md)
- Italian: [`docs/README.it.md`](https://github.com/gnudrus-del/argo-cloud-osint-platform/blob/main/docs/README.it.md)

## Feedback

Open a [Discussion](https://github.com/gnudrus-del/argo-cloud-osint-platform/discussions), a [bug report](https://github.com/gnudrus-del/argo-cloud-osint-platform/issues/new?template=bug_report.yml), or a [feature request](https://github.com/gnudrus-del/argo-cloud-osint-platform/issues/new?template=feature_request.yml).

If Argo helps your OSINT workflow, ⭐ the repo so other analysts can find it.

— Argo Cloud OSINT Platform contributors
