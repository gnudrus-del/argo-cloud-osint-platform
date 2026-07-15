# Changelog

All notable changes to Argo Cloud OSINT Platform are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- Report sealing: Ed25519 signature on every completed job (always on) + optional on-demand RFC3161 trusted timestamping (`report_signing.py`, `tsa_client.py`), CLI `argo-verify-report`.
- Privacy Center / DSAR made backend-portable: erasure, export and audit-redaction logic moved off raw SQLite SQL onto the shared `Storage`/`PostgresStorage` interface, so it now works correctly (not silently as a zero-column no-op) on Postgres.
- Postgres positioned as the recommended backend for production/multi-analyst deployments: wired into `docker-compose.yml`, `OSINT_STORAGE_STRICT` flag for a loud failure instead of a silent SQLite fallback, exercised in CI against a real `postgres:16` container. SQLite remains the zero-config default.
- `docs/AUDIT_READINESS.md` — preparatory material (suggested scope, dependencies, active CI gates) for a paid third-party security review. Not itself an audit.
- `pip-audit` dependency-scan CI job; `Pillow` bumped to `>=12.3.0` (5 known CVEs fixed).
- AI agent integration (opt-in, `ai` extra): narrative report synthesis, entity-resolution suggestions, finding triage via a BYOK LLM provider (Anthropic / OpenAI / local OpenAI-compatible endpoint), gated by a server kill switch + per-case consent + per-analyst key.
- **BYOK API key encryption at rest** (`osint_bot/secrets_crypto.py`): envelope encryption (AES-256-GCM, a random per-secret data key wrapped by an instance master key), the master key held outside the database (env var, systemd-credential file, or an auto-generated local file — never a DB row, never in `.env`), transparent upgrade of pre-existing plaintext rows on next write, per-access audit events (`api_key_stored` / `api_key_accessed` / `api_key_deleted`), and a `argo-rotate-master-key` CLI for rotation. Values are never written to logs, backups, or DSAR exports (the export path already selected only `service`/`created_at`, never `value`).
- Documentation fact-check pass across `README.md`, `SECURITY.md`, `docs/*` correcting stale/aspirational claims (connector counts, "tamper-evident" scope, encryption-at-rest status).

## [0.2.0] — 2026-07-14

### Added

- **Bilingual UI and connector output (Italian / English)** end-to-end — frontend, 59-connector-surface backend messages, per-request `ConnectorContext.lang`.
- **Centralised policy gate** — Rules of Engagement + case-scope enforcement consolidated in `BaseConnector.run` (hardening H1).
- **SSRF hardening completed** — every connector *and* the CLI/job-queue seed-URL fetcher (including its `robots.txt` lookup) route through `_safe_http`; zero direct HTTP calls left outside the gateway; CI-enforced (hardening H2 + follow-up).
- **Real DSAR (GDPR Art. 17)** — erasure endpoint became an atomic transaction: redact audit events, append a hash-chained `dsar_tombstoned` proof, delete business rows, all in one commit (hardening H3).
- **Docker image published to GHCR** on tagged release (`ghcr.io/gnudrus-del/argo-cloud-osint-platform:0.2.0`, `:latest`) — confirmed live via the `docker-publish.yml` workflow run for this tag.
- **Sigstore build provenance** (SLSA v1) attested and pushed to the registry alongside the image.
- **PyPI publish workflow** scaffolded (Trusted Publisher via OIDC) — not yet triggered; the package is not live on PyPI as of this release.
- Architecture diagram replaced with a full connector map; UI screenshots and a sample forensic report added to the repo.
- `web-next/` dependency and CI maintenance (Next.js upgraded past known CVEs); marked frozen/experimental, superseded by the production Python-served UI.

### Known limitations (carried forward)

- BYOK provider keys still stored plaintext in `.env` — encryption-at-rest remains planned, not yet built. *(Resolved in Unreleased above.)*
- No PyPI package published yet (workflow exists, unused).
- Datastore not encrypted at rest — relies on OS-level disk encryption.

## [0.1.0] — 2026-07-05

First public release.

### Added

- **CLI (`argo-osint`)** — defensive OSINT investigations from the terminal, Markdown / JSON output.
- **Web UI** — case-based investigations, findings viewer, report download.
- **58 native connectors** — 43 key-free (crt.sh, RDAP, DNS, TLS certs, Wayback, Gravatar, GDELT, Nominatim, PhishTank, OpenPhish, holehe, maigret, subdomain enumeration, port scan, content discovery, DNStwist, secret scan, URL harvest, theHarvester, ASN lookup, Shodan InternetDB, Overpass, ThreatFox, phone_meta, phone_footprint, GHunt, Toutatis, socid-extractor, LinkedIn2Username, Telegram checker, darkweb Ahmia, legit_scorer, and more) + 15 BYOK (Shodan, VirusTotal, HIBP, Hunter.io, SecurityTrails, GreyNoise, OTX, EmailRep, IPinfo, Etherscan, OpenCorporates, Companies House, Brave Search, Google PSE, Influencers Club, MISP).
- **Case model** with Rules of Engagement, scope, and legal-basis gating for personal-target investigations.
- **SHA-256 audit chain** — every login / search / finding / deletion is a hash-linked event; chain verification is a single command.
- **GDPR DSAR endpoints** — data export and deletion for subject requests.
- **Exports**: Markdown, JSON, PDF (via `reportlab`), **STIX 2.1** bundle, **MISP** core-format 2.4 event.
- **Security hardening**: PBKDF2-SHA256 (200k) admin auth, CSP, HSTS, X-Frame-Options DENY, COOP/CORP, CSRF token, `_safe_http` outbound wrapper (SSRF guard blocking cloud metadata / RFC1918), rate limits per connector.
- **Deploy artifacts**: `Dockerfile`, `docker-compose.yml`, systemd unit, Caddy reverse-proxy recipe (`deploy_artifacts/`), `deploy.ps1` / `deploy.sh` for VM sync.
- **Landing page** describing the platform (privacy-first, honest disclosure of demo data vs personas ipotetiche vs measured VM specs).
- **Docs**: `README.md`, `docs/QUICKSTART.md`, `docs/INSTALLATION.md`, `docs/DOCKER.md`, `docs/CONFIGURATION.md`, `docs/CONNECTORS.md`, `docs/EXAMPLES.md`, `docs/RESPONSIBLE_USE.md`, `docs/FAQ.md`, `docs/ROADMAP.md`, `docs/THREAT_MODEL.md`, `docs/RELEASE_PROCESS.md`, `docs/COMPARISON.md`, Italian mirror `docs/README.it.md`.
- **Community health**: issue templates (bug / feature / security-question), PR template, `SUPPORT.md`, `CITATION.cff`, `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`.
- **CI**: `.github/workflows/ci.yml` (matrix Python 3.10-3.12 on Ubuntu + Windows, ruff, compileall, unittest, package build, Docker image smoke build, Next.js advisory).
- **Dependabot** for pip / npm / docker / actions.
- **Release automation**: `.github/workflows/docker-publish.yml` for GHCR on tagged release, `.github/release.yml` for categorized release notes.

### Known limitations

- **BYOK provider keys are stored plaintext** in `.env`. *(Resolved in `[Unreleased]` above: envelope encryption at rest, see `osint_bot/secrets_crypto.py`.)*
- **Datastore is not encrypted at rest** — use OS-level disk encryption. Still planned.
- **No PyPI package published yet** — install from source until `argo-cloud-osint` is validated on PyPI. *(Still open in 0.2.0 — the publish workflow was added but has not been triggered.)*
- **No Docker image on GHCR yet** at the time of this release — the workflow was present but had not yet been publish-triggered. *(Resolved in 0.2.0: the image is published and Sigstore-attested.)*
- **Screenshots** in `docs/assets/` are placeholders. Real screenshots to be added post-v0.1.0. *(Resolved in 0.2.0.)*
- **Web UI test coverage** is manual; end-to-end tests are on the roadmap.

[Unreleased]: https://github.com/gnudrus-del/argo-cloud-osint-platform/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/gnudrus-del/argo-cloud-osint-platform/releases/tag/v0.2.0
[0.1.0]: https://github.com/gnudrus-del/argo-cloud-osint-platform/releases/tag/v0.1.0
