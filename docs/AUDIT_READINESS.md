# Audit readiness

**This document is preparatory material for a third-party security reviewer — it is not a certification, and Argo has not been independently audited as of this writing.** It exists to make commissioning a paid external review faster and cheaper: everything a reviewer would otherwise have to reconstruct by reading the whole codebase is collected here instead. Nothing in this file should be read or quoted as "Argo has been audited" or "Argo is audit-certified" — those claims would be false. See [`docs/THREAT_MODEL.md`](THREAT_MODEL.md) for the full, authoritative threat model; this file summarizes and points at it rather than duplicating it.

## What Argo is

Self-hosted, single-tenant OSINT investigation platform (CLI + web UI). Apache-2.0, Python 3.10+, first tagged release `0.1.0` (2026-07-05). No SaaS offering, no telemetry to the maintainers, no managed hosting by the project itself.

## Suggested scope for an external review

- **Web application security** — auth (`osint_bot/web.py`: session cookies, CSRF, PBKDF2 admin auth), input handling, the DSAR/Privacy Center endpoints (`/api/privacy/*` — legally load-bearing, GDPR Art. 15/17/20).
- **SSRF surface** — `osint_bot/_safe_http.py` is the single sanctioned egress gateway; `scripts/enforce_safe_http.py` enforces its use in CI. A reviewer should specifically try to find a connector or code path that bypasses it.
- **The audit hash-chain** (`osint_bot/storage.py::verify_audit_chain`, mirrored in `storage_postgres.py`) — tamper-evidence claim, including the GDPR-redaction interaction (a tombstoned redaction is deliberately excluded from the self-hash check; an undocumented modification is not — see the docstring on `verify_audit_chain` for the exact mechanism).
- **Report sealing** (`osint_bot/report_signing.py`, `osint_bot/tsa_client.py`) — Ed25519 signing + optional RFC3161 timestamping. Scope note: Argo does not verify the TSA's own certificate chain by design (documented non-goal, see `THREAT_MODEL.md`) — a reviewer evaluating "is the timestamp trustworthy" should evaluate the *chosen TSA*, not just Argo's client code.
- **The AI agent (LLM) integration** (`osint_bot/llm_client.py` + capability modules) — opt-in, 3-gate fail-closed model; a reviewer should verify the gates are actually independent (kill switch off ⇒ 404 regardless of the other two, etc.) rather than trusting the docstrings.
- **Storage backend parity** — SQLite (`storage.py`) and Postgres (`storage_postgres.py`) implement the same interface (`storage_base.py`) independently, not through a shared query layer. A reviewer should specifically check for dialect drift, not just SQL-injection-style issues in either one alone.
- **API key envelope encryption** (`osint_bot/secrets_crypto.py`, `osint_bot/cli_rotate_key.py`) — AES-256-GCM per-secret DEK wrapped by an instance master key held outside the database, row-bound via AES-GCM associated data (`api_key_aad`). A reviewer should check: the master key never appears in a DB row, log line, backup, or DSAR export; the legacy-plaintext passthrough (rows written before this feature existed, `enc:v1:` rows with no AAD) does not create a downgrade path an attacker can force; and that rotation genuinely re-wraps every stored key rather than silently leaving old ones under the retired key — a rotation-ordering bug of exactly that shape was found and fixed by an internal adversarial review this session (see `docs/THREAT_MODEL.md`).
- **Ed25519 signing-key rotation** (`osint_bot/report_signing.py::rotate_signing_key`, `osint_bot/cli_rotate_signing_key.py`) — retires and archives the current key, generates a new one. A reviewer should check the archive-filename collision handling under concurrent rotation, and that the "restart required" caveat is actually surfaced everywhere it matters (an earlier draft of the CLI message claimed no restart was needed — wrong, and fixed).

## Known limitations (already disclosed)

Reproduced from `docs/THREAT_MODEL.md` — the authoritative, maintained copy is there; treat this list as a pointer, not a substitute:

- Connector API keys are envelope-encrypted at rest (`osint_bot/secrets_crypto.py`), row-bound via AES-GCM associated data — protects against a database-only leak, not against compromise of the host holding the master key. Rotation is available for both the API-key master key (`argo-rotate-master-key`) and the separate Ed25519 report-signing key (`argo-rotate-signing-key`); both require a service restart afterward (no cross-process cache invalidation).
- Datastore not encrypted at rest (SQLite file or Postgres database) — relies on OS-level disk encryption.
- Single-user admin model; no RBAC beyond admin/analyst. Not on the near-term roadmap (see multi-tenancy discussion below).
- `argo-verify-report` checks a seal's signature, not a full re-derived manifest from a bundled evidence set (would require exporting the complete artifact list — tracked, not yet built).
- **No independent external security audit has been performed.** An internal adversarial review of this session's new cryptographic code (envelope encryption, both rotation CLIs) was done by an independent context and found real, now-fixed issues (see `docs/THREAT_MODEL.md`'s "Known limitations" for the list). That is due diligence, not a substitute for a paid, professional, external review — the whole point of this document is to make commissioning one easier, not to claim one already happened.
- No live-Postgres CI coverage until the `postgres-integration` GitHub Actions job (added alongside this document) has actually run — the SQLite-vs-Postgres parity claim rests on careful code mirroring + the shared test suite in `tests/test_privacy_postgres.py`, not yet on a completed real run at the time this file was written.
- No locking between a master-key/signing-key rotation and a concurrently-running web service writing to the same keys — rotation must be run with the service stopped; this is an operational constraint documented in the rotation CLIs' own output, not enforced by the tooling.

## Out of scope (by design, not oversight)

Reproduced from `docs/THREAT_MODEL.md`'s "Out of scope" section: host OS compromise, analyst-account compromise, a malicious BYOK provider, compromise of a wrapped local tool (holehe/maigret/ghunt/...), legal-basis fabrication by the analyst, and — new in this pass — verification of a chosen RFC3161 TSA's own certificate chain (Argo requests and stores the token faithfully; trusting the TSA is the operator's decision, not Argo's).

## Dependencies

Core (`pyproject.toml`, always installed): `reportlab`, `phonenumbers`, `cryptography`, `asn1crypto`.

Optional extras: `ai` (`pytesseract`, `Pillow`, `spacy`, `langdetect`, `deep-translator`), `postgres` (`psycopg[binary]`), `queue` (`celery`, `redis`), `dev` (`pytest`, `ruff`, `build`, `twine`).

No vendored/bundled third-party source beyond what's declared above — connectors talk to external APIs over HTTP, they don't embed third-party client libraries beyond the ones listed.

## CI security gates already in place

All in `.github/workflows/ci.yml`:

| Job | What it checks |
| --- | --- |
| `python` | Lint (ruff, blocking), unit tests (600+ at time of writing), JS syntax |
| `ssrf-guard` | No connector imports a raw HTTP client (`urllib.request`/`httpx`/`requests`/`aiohttp`) instead of `_safe_http` |
| `dependency-scan` | `pip-audit` against the full dependency closure — blocks `build-package` |
| `postgres-integration` | Privacy Center/DSAR tests against a real `postgres:16` service container |
| `docker-build` | Image builds and imports cleanly |

Dependabot (`.github/dependabot.yml`) tracks pip/npm/docker/GitHub-Actions updates weekly.

## What this document does NOT cover

Business/legal review (data processing agreements, jurisdiction-specific admissibility of the audit chain as evidence — see `docs/FAQ.md`), penetration testing of a specific live deployment (this describes the software, not any one operator's configuration/network), and code outside `osint_bot/` (the frozen `web-next/` prototype is explicitly out of scope — see `web-next/STATUS.md`).
