# Roadmap

Public planning. Priorities can change; nothing here is a promise.

## v0.1.0 — 2026-07-05

- 58 native connectors (43 key-free + 15 BYOK).
- CLI + web UI + Docker.
- SHA-256 audit chain, DSAR endpoints, RoE + case-scope gating.
- STIX 2.1 bundle + MISP event exports.
- Deployment recipes: systemd + Caddy, Docker Compose.

## v0.2.0 — 2026-07-14 — hardening + distribution

- Bilingual UI and connector output (Italian / English), end to end.
- Centralised policy gate (RoE + case-scope) in `BaseConnector.run`.
- SSRF hardening completed across every connector and the seed-URL fetcher; CI-enforced.
- Real DSAR (GDPR Art. 17) — atomic erasure transaction with hash-chained tombstone proof.
- **Docker image published to GHCR** on tagged release, Sigstore build provenance attested. Done — confirmed via a live workflow run against this tag.
- **PyPI publication** as `argo-cloud-osint` — workflow scaffolded (Trusted Publisher / OIDC), not yet triggered. Still not on PyPI.
- **Encryption-at-rest for connector keys** — did **not** ship in 0.2.0 despite earlier plans; keys were still plaintext in `.env`. Shipped in "Unreleased" below.

## Unreleased (on `main`, not yet tagged)

- **RBAC** — persistent per-account `role` (`analyst`/`admin`), alongside the existing shared-secret session unlock (unchanged, still works). Role assignment is a local CLI command (`argo-set-role`), not a web endpoint — no "admin promotes other admins over the web" surface by design.
- `docs/METHODOLOGY.md` — the confidence/source-reliability/severity discipline the `Finding` model already carried in code, written down as one citable convention.
- **`web-next/` CSRF + Docker wiring** (issue `#H4`, partial) — the experimental Next.js console gained CSRF protection and an opt-in Docker Compose profile. Still frozen, still not the production frontend; the complete-vs-delete decision on `#H4` stays open.
- **Google Sign-In** (`GOOGLE_OAUTH_CLIENT_ID`, optional `[auth]` extra) — additional login door alongside email+password, not a replacement. First-time Google sign-in auto-provisions a user. Admin metrics gained a per-user login history table (who, when, how many times, which method).
- Two new BYOK connectors: `contactout` and `lusha` (LinkedIn profile URL / email → personal or professional contact details, PII-gated). 61 → 63 native connectors, 15 → 17 BYOK.
- Three new key-free connectors: `cloud_buckets` (cloud storage exposure), `email_security` (SPF/DMARC/MTA-STS/DNSSEC posture), `hudsonrock` (infostealer breach corpus). 58 → 61 native connectors.
- Signed report seals (Ed25519, always on) + optional RFC3161 trusted timestamping, `argo-verify-report` CLI.
- Privacy Center / DSAR made backend-portable (works correctly on Postgres, not just SQLite).
- Postgres recommended for production/multi-analyst deployments, wired into `docker-compose.yml`, exercised in CI against a real container. SQLite stays the zero-config default.
- `docs/AUDIT_READINESS.md` for anyone commissioning a paid external security review.
- `pip-audit` CI gate; dependency bumps for known CVEs.
- Opt-in AI agent capabilities (narrative synthesis, entity-resolution suggestions, triage) via BYOK LLM, 3-gate fail-closed.
- **Connector-key encryption at rest** — envelope encryption (`osint_bot/secrets_crypto.py`), row-bound via AES-GCM associated data, a master key held outside the database (env var / systemd-credential file / auto-generated local file), `argo-rotate-master-key` for rotation, per-access audit events, keys excluded from logs/backups/exports.
- **Ed25519 report-signing key rotation** (`argo-rotate-signing-key`) — retires and archives the current key, past signatures stay verifiable unchanged.
- **Internal adversarial security review** of the new cryptographic code above, performed independently of the code that was reviewed — found and fixed a rotation-ordering bug, a false "no restart needed" claim, a rotation race condition, and missing row-binding on stored ciphertext. Not a substitute for an external audit; see `docs/AUDIT_READINESS.md`.

## v0.3.0 — analyst UX

- **Next.js web frontend** (`web-next/`, in progress) — richer entity/relationship graph.
- Case templates for common investigation types.
- Batch export (multi-case PDF).
- Localized UI (English default, Italian available).

## Experimental / research

- **AI enrichment** (`ai` extra, experimental): OCR + NER + language detect + translation for extracted content.
- **Judge panel connectors** — cross-verify findings across independent sources.
- **Diff-based monitoring** for authorized long-running cases.

## Community-driven

Feature requests via [Discussions](https://github.com/gnudrus-del/argo-cloud-osint-platform/discussions) or the [feature-request issue template](https://github.com/gnudrus-del/argo-cloud-osint-platform/issues/new?template=feature_request.yml). Please keep them within the [defensive-use scope](RESPONSIBLE_USE.md).
