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

**Default (zero-config): SQLite** under `$OSINT_JOB_DIR` — nothing to set up, fine for a single analyst or evaluation (this is what runs if `DATABASE_URL` is unset).

**Recommended for production / multi-analyst deployments: Postgres.** `docker-compose.yml` ships it as a service, wired up automatically — see `docs/DOCKER.md`. Outside Docker:

```bash
pip install -e ".[postgres]"
DATABASE_URL=postgresql://argo:password@host:port/argo
```

| Variable | Default | Purpose |
| --- | --- | --- |
| `DATABASE_URL` | (empty → SQLite) | `postgresql://...` switches to Postgres. Requires the `postgres` extra (`psycopg[binary]`) — installed automatically in the Docker image. |
| `OSINT_STORAGE_STRICT` | `0` | `0`: if Postgres is requested but unreachable (missing `psycopg`, bad DSN, server down), Argo silently falls back to SQLite with a log line — easy to miss. `1`: the same failure is **fatal** — the process refuses to start rather than run somewhere you didn't intend. Recommended once you've committed to Postgres in production. |

Both backends implement the identical `Storage`/`PostgresStorage` interface (`osint_bot/storage_base.py`) — every feature, including the Privacy Center/DSAR (GDPR Art. 15/17/20) endpoints, behaves the same on either. The Postgres backend is exercised in CI against a real Postgres container (`postgres-integration` job, `tests/test_privacy_postgres.py`).

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

Every key saved through the "Chiavi API" UI is encrypted at rest before it reaches the database — see the next section.

## API key encryption at rest

`osint_bot/secrets_crypto.py` envelope-encrypts every BYOK key `Storage`/`PostgresStorage` stores: a random per-secret AES-256-GCM data key encrypts the value, itself wrapped by the instance's master key. Always on, no opt-in required.

| Variable | Default | Purpose |
| --- | --- | --- |
| `OSINT_MASTER_KEY` | (empty) | Master key, base64, 32 bytes. For deployments where a secret manager injects it directly into the process environment. |
| `OSINT_MASTER_KEY_FILE` | (empty) | Path to a file holding the base64 key. The systemd-credentials-friendly option: `LoadCredential=argo_master_key:/path/to/encrypted-credential` exposes the decrypted value at `${CREDENTIALS_DIRECTORY}/argo_master_key`, readable only by the service's own user — set `OSINT_MASTER_KEY_FILE=${CREDENTIALS_DIRECTORY}/argo_master_key`. |

Neither set: Argo auto-generates a key on first use and persists it to `<OSINT_JOB_DIR>/.master_key` (`chmod 600`), sibling to the database file, never a row inside it — zero-config, same UX as the Ed25519 report-signing key.

API keys written before this feature existed are read transparently (no `enc:v1:` prefix means legacy plaintext) and silently upgraded to encrypted on the next write — no blocking migration.

**What this protects against:** a database-only leak (a stolen SQLite file, a Postgres dump, a leaked Postgres credential). **What it does not protect against:** compromise of the host the master key file lives on — same `chmod 600` / OS-disk-encryption reasoning as everything else in this file.

**Rotation:**

```bash
argo-rotate-master-key              # dry run — shows key source and how many keys would be re-wrapped
argo-rotate-master-key --yes        # rotates in place, if the key source is a local file Argo can rewrite
```

If the master key comes from `OSINT_MASTER_KEY` or a read-only systemd-credential mount, Argo cannot rewrite its own environment or an externally managed credential — rotation then requires `--new-key-output <path>`, after which you update your secret manager / systemd credential / `OSINT_MASTER_KEY` with the new value yourself. **Restart the Argo service after any rotation** — a running process caches its master key in memory and fails to decrypt keys re-wrapped under a new one until restarted.

Every store, access, and delete of an API key is a separate audit-chain event (`api_key_stored` / `api_key_accessed` / `api_key_deleted`), never including the value itself. Keys are excluded from the DSAR export (`GET /api/privacy/export` returns only `service`/`created_at` per key, never `value`).

## Local tools

Some connectors wrap installed CLIs (holehe, maigret, theHarvester, etc.). Their paths are configured via env vars — see the `# ─── Tool locali installati` block in `.env.example`.

## AI agent (LLM, opt-in)

Three opt-in capabilities — narrative report synthesis, entity-resolution suggestions, finding triage — send case data to an LLM provider **you choose and configure**. Disabled by default at three independent, fail-closed layers: a server-wide kill switch, a per-case consent flag, and per-analyst BYOK key presence. See `docs/THREAT_MODEL.md` for the full data-flow writeup.

| Variable | Default | Purpose |
| --- | --- | --- |
| `OSINT_AI_AGENTS_ENABLED` | `0` | Server-wide kill switch. `0`: the 3 LLM key slots are hidden from the API-key catalog and every `/api/ai/*` route returns 404 — the feature is invisible, not just "off". |
| `ANTHROPIC_API_KEY` | (empty) | Fallback for the `llm_anthropic` BYOK slot (per-analyst key in the UI takes precedence). |
| `OPENAI_API_KEY` | (empty) | Fallback for the `llm_openai` BYOK slot. |
| `LOCAL_LLM_BASE_URL` | (empty) | Fallback for the `llm_local` BYOK slot — an OpenAI-compatible endpoint (Ollama, llama.cpp) you run yourself. Stored/entered as `base_url` or `base_url\|bearer_token`. |
| `ANTHROPIC_MODEL` / `OPENAI_MODEL` / `LOCAL_LLM_MODEL` | provider default / provider default / (required) | Model id override. `LOCAL_LLM_MODEL` has no safe default — a `local` request with none set returns 400. |

Even with the kill switch on, **nothing is sent anywhere** until a case owner explicitly ticks "AI enrichment" for that specific case (`POST /api/cases/<id>/ai-settings`) and an analyst has a BYOK key configured. Every call — success or failure — is written to the SHA-256 audit chain (`ai_narrative_generated`, `ai_entity_suggestions_generated`, `ai_triage_generated`) with provider/model/byte-counts, never the key or the raw prompt/response text.

The `local` provider is the way to use these 3 capabilities with **zero data leaving your infrastructure**: point `LOCAL_LLM_BASE_URL` at an Ollama/llama.cpp instance on your own network — the endpoint is treated as an operator-configured private target (`_safe_http` allows it explicitly for this one provider only), never sent to a third party.

## Report signing & timestamping

Every completed job is **automatically sealed**: `custody.py` builds a manifest over the case's collected evidence and generated report files, and `report_signing.py` signs the manifest hash with the instance's Ed25519 key. This is always on, needs no configuration, and never makes a network call — see `docs/THREAT_MODEL.md` for exactly what a valid signature does and does not prove.

An optional RFC3161 trusted timestamp against an external Time-Stamping Authority (TSA) can be requested per report, on demand (never automatic), from the "Sigillo" panel in the report viewer or via `POST /api/jobs/<id>/seal/tsa-timestamp`.

| Variable | Default | Purpose |
| --- | --- | --- |
| `OSINT_REPORT_SIGNING_KEY_PATH` | `<OSINT_JOB_DIR>/.report_signing_key` | Where the instance's Ed25519 signing key (base64 seed) is generated on first use and persisted. Back this up — losing it makes past signatures unverifiable against a *new* key (the seals themselves remain unchanged, but you lose the ability to prove continuity of "the same instance signed all of these"). `chmod 600` it, same as `.env`. |
| `TSA_URL` | (empty) | RFC3161 Time-Stamping Authority endpoint. Empty: the timestamp feature is invisible — `POST /api/jobs/<id>/seal/tsa-timestamp` returns 404, same "absent unless configured" pattern as every other third-party integration. No default is shipped in code; pick one **you** are authorized to use under its terms of service. Commonly used public RFC3161 TSAs (verify current terms before production use): `http://timestamp.digicert.com`, `https://freetsa.org/tsr`, `http://timestamp.sectigo.com`. |

Only a 32-byte SHA-256 digest of the manifest is ever sent to the TSA — never case content, never finding text. This is why the timestamp feature has a single, light gate (is a TSA configured) rather than the AI agent's 3-gate model: the privacy exposure of a one-way hash is categorically different from sending case prose to an LLM.

Verify a sealed report independently, offline, with `argo-verify-report <seal.json>` (the seal export downloaded from `GET /api/jobs/<id>/seal`) — it checks the Ed25519 signature and, if present, prints the RFC3161 token's claimed timestamp with instructions to verify it yourself (`openssl ts -reply -in token.der -text`). Argo does not verify the TSA's own certificate chain — that trust decision belongs to whoever relies on the proof, not to the tool that requested it.

## Production checklist

- [ ] `OSINT_WEB_TOKEN` is set to a long random value.
- [ ] `OSINT_SIGNUPS_ENABLED=0` once your users exist.
- [ ] `OSINT_SECURE_COOKIE=1`, `OSINT_HSTS=1`.
- [ ] Reverse proxy terminates TLS with valid certificates.
- [ ] `.env` is `chmod 600` and owned by the service user.
- [ ] OS-level disk encryption on the datastore volume.
- [ ] The API-key master key (`<OSINT_JOB_DIR>/.master_key` by default) is backed up somewhere other than the datastore volume itself — losing it makes every stored BYOK key permanently unrecoverable, not just unencryptable-going-forward.
