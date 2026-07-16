# Architecture

This is the detailed, module-level companion to the [Architecture at a glance](../README.md#architecture-at-a-glance) diagram in the README. Read that first for the five-layer overview; this document walks each layer's actual source files, explains why the boundaries are drawn where they are, and lists the technical debt honestly instead of as a marketing pitch.

Argo is a single-process, self-hosted application: one Python codebase (`osint_bot/`), served either via the CLI (`argo-osint`) or the stdlib-based web server (`osint_bot/web.py`). There is no microservice split, no message broker requirement, and no cloud dependency — the entire pipeline runs on one machine or VM. That is a deliberate design constraint, not a limitation to "fix": it is what makes Argo installable on a Raspberry Pi or an air-gapped analyst workstation, and it is why the threat model in [`THREAT_MODEL.md`](THREAT_MODEL.md) assumes a trusted single-tenant operator rather than a multi-tenant SaaS.

## Layers

### 1. Input — CLI, web UI, REST API

- `osint_bot/cli.py` (`argo-osint` entry point) — scriptable, one-shot investigations; the same connector pipeline the web UI uses.
- `osint_bot/web.py` — a single stdlib `http.server`-based process. No web framework: routing, session cookies (`HttpOnly` + `SameSite=Strict`, `Secure` behind `OSINT_SECURE_COOKIE=1`), CSRF tokens, security headers (CSP, HSTS, X-Frame-Options, COOP), rate limiting, and every `/api/*` handler live here. This is the largest file in the codebase by design — it is the trust boundary, and keeping request handling in one auditable place beats spreading it across a framework's middleware stack.
- `osint_bot/web_static/` (`index.html`, `app.js`, `app.css`, `i18n.js`) — the browser-side UI. No build step, no bundler: plain JS served as static files. `i18n.js` + a shared message catalog drive the bilingual (IT/EN) UI and connector output.

### 2. Orchestrator, policy, and audit

- `osint_bot/orchestrator.py` — dispatches a target (domain / ip / email / handle / phone / wallet / company) to every connector whose `input_types` match, applies per-connector rate limits, and normalizes results into `Finding` objects.
- `osint_bot/policy.py`, `osint_bot/scope.py`, `osint_bot/safety.py` — the **centralized policy gate**: Rules of Engagement, case scope, and legal-basis checks run once, inside `BaseConnector.run`, not duplicated per connector. A connector cannot bypass this by construction — it never receives a target until the gate has cleared it.
- `osint_bot/audit.py` — the SHA-256 hash-chained audit log. Every login, search, finding, deletion, and (as of this version) AI-agent invocation and report seal is appended as a hash-linked event. `verify_audit_chain()` (mirrored in both storage backends, see below) walks the chain and flags a broken `previous_hash` link as tampering — except for events whose `seq` is listed in a `dsar_tombstones` record's `scope.redacted_seqs`, which are documented GDPR redactions, not tampering. This tombstone-aware distinction is the mechanism that lets "tamper-evident" and "GDPR-compliant erasure" coexist without contradicting each other.
- `osint_bot/_safe_http.py` — the single sanctioned egress gateway. Every connector, plus the CLI/job-queue seed-URL fetcher (`osint_bot/fetch.py`), routes outbound HTTP through it. It blocks cloud metadata (`169.254.169.254`), loopback, RFC1918 ranges, non-HTTP schemes, and revalidates redirect targets instead of trusting the first hop. `scripts/enforce_safe_http.py` runs in CI and fails the build if any connector imports `urllib.request` / `httpx` / `requests` / `aiohttp` directly — the guarantee is structural, not a code-review convention.

### 3. Connector registry — 63 native sources

- `osint_bot/connectors/` — one small module per source (`connector.py` defines the `BaseConnector` interface: `input_types`, `action_class` (`passive` / `active` / `intrusive`), rate limit, `required_key`, `legal_note`, and a `run()` returning `Finding` objects with evidence URLs and confidence). Adding a source is implementing this interface in ~50 lines; nothing else in the codebase needs to change.
- 46 connectors declare no `required_key` (work out of the box); 17 declare one and report `missing_key` cleanly when it is unset — this split is read directly from the registry (`build_default_registry().catalog()`), not hand-counted, so it cannot drift from what the code actually ships. See the README's connector tables for the full list grouped by capability.
- `osint_bot/external_tools.py`, `osint_bot/tool_adapter.py` — subprocess wrappers (with timeouts) around installed CLIs (holehe, maigret, theHarvester, GHunt, Toutatis, LinkedIn2Username, the Telegram checker) that are exposed to the orchestrator as ordinary connectors.

### 4. Storage — SQLite (default) or Postgres (recommended in production)

- `osint_bot/storage_base.py` defines the interface; `osint_bot/storage.py` (SQLite) and `osint_bot/storage_postgres.py` (Postgres) each implement every method independently, in their own SQL dialect — there is no shared query layer to drift silently. This includes the Privacy Center / DSAR methods (`table_columns`, `select_owned_columns`, `erase_actor_data`, `log_privacy_request`, ...), which used to bypass this abstraction with hand-written SQLite-only SQL; that path is now backend-portable, exercised in CI against a real `postgres:16` container (`postgres-integration` job, `tests/test_privacy_postgres.py`).
- `create_storage()` picks the backend from `DATABASE_URL`: unset → SQLite under `OSINT_JOB_DIR`, zero configuration. Set → Postgres, requiring the `postgres` extra (`psycopg[binary]`, installed by default in the Docker image). If Postgres is requested but unreachable, the default behavior is a logged fallback to SQLite; `OSINT_STORAGE_STRICT=1` makes that fallback a fatal startup error instead, for operators who need to know immediately if they are not actually running the backend they think they are.
- `osint_bot/neo4j_sync.py`, `osint_bot/opensearch_index.py` — optional, off unless `NEO4J_HTTP_URL` / `OPENSEARCH_URL` are set. Graph and full-text mirrors of the same finding data, not sources of truth.
- **BYOK API key encryption at rest** (`osint_bot/secrets_crypto.py`) — `Storage.put_api_key`/`get_api_key` on both backends transparently envelope-encrypt every value: a random per-secret AES-256-GCM data key encrypts the value, wrapped by the instance's master key. The master key itself lives outside the database by construction — resolved from `OSINT_MASTER_KEY` (env), `OSINT_MASTER_KEY_FILE` (a systemd-credential-friendly file path), or an auto-generated local file (`<job_root>/.master_key`, `chmod 600`) sibling to the SQLite/Postgres connection info, never a row inside either. Legacy plaintext rows (written before this existed) are read transparently and upgraded on next write — there is no blocking migration step. `argo-rotate-master-key` re-wraps every stored key under a fresh master key; every store/access/delete is a separate audit-chain event (`api_key_stored` / `api_key_accessed` / `api_key_deleted`), never including the value itself.

### 5. Report sealing — Ed25519 (always on) + RFC3161 (opt-in)

- `osint_bot/custody.py` builds a manifest hashing the case's collected evidence and generated report files; `osint_bot/report_signing.py` signs that manifest hash with the instance's Ed25519 key (auto-generated on first use, persisted at `OSINT_REPORT_SIGNING_KEY_PATH`). This runs automatically on every completed job — no configuration, no network call.
- `osint_bot/tsa_client.py` optionally requests an RFC3161 trusted timestamp from an external Time-Stamping Authority, on demand per report (never automatic). Only the 32-byte SHA-256 digest of the manifest is sent — never case content. The feature is invisible (`404`) until an operator sets `TSA_URL`; there is no default TSA baked into the code, since trusting one is the operator's decision.
- `argo-verify-report` (`osint_bot/cli_verify.py`) checks a seal's signature offline, independent of the running instance. It verifies the signature on the declared manifest hash; it does not re-hash the individual evidence/report files against that manifest (that would require exporting the complete artifact list — tracked, not yet built, and disclosed as such in [`docs/AUDIT_READINESS.md`](AUDIT_READINESS.md)).

### 6. AI agent (opt-in, 3-gate, off by default)

- `osint_bot/llm_client.py` — a thin multi-provider transport (Anthropic, OpenAI, or a local OpenAI-compatible endpoint such as Ollama/llama.cpp).
- `osint_bot/narrative_synthesis.py`, `osint_bot/entity_resolution_ai.py`, `osint_bot/triage_ai.py` — the three capabilities: narrative report synthesis, entity-resolution suggestions, and finding triage. Each is invoked only through `osint_bot/ai_context.py`, which enforces three independent, fail-closed gates before a single byte leaves the process: a server-wide kill switch (`OSINT_AI_AGENTS_ENABLED`, default off — the three LLM key slots and every `/api/ai/*` route are invisible, not merely disabled, when this is off), a per-case consent flag the case owner must explicitly set, and a per-analyst BYOK key. Every invocation — success or failure — is written to the audit chain with provider/model/byte-counts, never the prompt or response text.
- The `local` provider is the zero-data-leaves-your-infrastructure option: `_safe_http` allows a private/internal `LOCAL_LLM_BASE_URL` explicitly for this one provider, since it is an operator-configured target rather than a third party.

### 7. Export layer

- `osint_bot/report.py`, `osint_bot/pdf_report.py`, `osint_bot/forensic_report.py` — Markdown, JSON, and PDF (via `reportlab`) analyst reports.
- `osint_bot/stix_export.py` — STIX 2.1 bundle; the MISP core-format 2.4 event export lives alongside it for TIP integration.
- `redact_report_json()` (`osint_bot/web.py`) — when a report is served (not the on-disk copy) with `include_contact=False`, email/phone PII across `target`, `entities`, `findings`, `agent_results`, and `pages.emails` is redacted before the response leaves the process. The primary analyst web UI always requests the unredacted view (`include_contact: true` in `app.js`, a deliberate UX choice: the analyst doing the investigation needs the contact data to act on it) — the redaction path exists for the served-report case where a stricter default is warranted.

## Privacy Center / DSAR

`osint_bot/gdpr.py` plus the storage-backend methods above implement GDPR Art. 15 (access), Art. 17 (erasure), and Art. 20 (portability):

- `privacy_requests` — the operational log of subject requests (id, owner, type, status, reason, timestamps).
- `dsar_tombstones` — the durable cryptographic proof of erasure: a selector hash, actor, timestamp, and a `scope` recording which audit-chain sequence numbers were redacted as part of that erasure. This is intentionally a separate table from `privacy_requests` — the tombstone is the evidence that survives even if the request log itself is later pruned.
- Erasure (`erase_actor_data`) is one atomic transaction: redact matching audit events, append an `account_erased_dsar` audit event, write the tombstone, and delete the actor's rows across every schema-tolerant table (cases, jobs, artifacts, RoEs, API keys, users) — all in the same commit, so a failure partway through rolls back the whole thing rather than leaving a half-erased actor.

## Known limitations (as of this version)

Reproduced in more detail, with suggested external-review scope, in [`docs/AUDIT_READINESS.md`](AUDIT_READINESS.md) and [`docs/THREAT_MODEL.md`](THREAT_MODEL.md):

- **No key-rotation tooling** for the Ed25519 report-signing key (the BYOK API-key master key does have rotation — `argo-rotate-master-key` — the two are separate keys with separate lifecycles).
- **In-process job queue by default** (`osint_bot/job_queue.py`) — reliable for a single instance, does not survive a process crash mid-job the way a persistent broker (Celery/Redis, available via the `queue` extra) would.
- **`argo-verify-report` verifies the seal's signature, not a full re-derived manifest** against a bundled evidence export (see above).
- **Single-tenant admin model** — one admin credential, analyst/admin distinction, no per-tenant isolation or RBAC. Not currently on the roadmap; would be a prerequisite for selling to teams rather than individual analysts, and is an open, not-yet-decided direction for the project.
- **Datastore itself is not encrypted at rest** by the application (SQLite file or Postgres database) — this is deliberately delegated to OS/disk-level encryption rather than reimplemented in-app.

## Where this is going

See [`docs/ROADMAP.md`](ROADMAP.md) for the maintained, dated plan — this document intentionally does not duplicate a roadmap that would drift out of sync with it.
