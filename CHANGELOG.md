# Changelog

All notable changes to Argo Cloud OSINT Platform are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- Placeholder for changes on `main` since the last tagged release.

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

- **BYOK provider keys are stored plaintext** in `.env`. Encryption-at-rest is planned for v0.2.0.
- **Datastore is not encrypted at rest** — use OS-level disk encryption. Planned.
- **No PyPI package published yet** — install from source until `argo-cloud-osint` is validated on PyPI.
- **No Docker image on GHCR yet** — the workflow is present but publish requires a maintainer-triggered release.
- **Screenshots** in `docs/assets/` are placeholders. Real screenshots to be added post-v0.1.0.
- **Web UI test coverage** is manual; end-to-end tests are on the v0.2.0 roadmap.

[Unreleased]: https://github.com/gnudrus-del/argo-cloud-osint-platform/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/gnudrus-del/argo-cloud-osint-platform/releases/tag/v0.1.0
