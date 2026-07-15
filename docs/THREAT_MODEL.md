# Threat model

This is a public, high-level threat model. It describes what Argo defends against, what it does not, and where the security boundaries are.

## Deployment assumption

Argo is designed for **single-tenant, self-hosted** deployment:

- One or a small team of trusted analysts.
- Runs on a machine or VM whose OS-level access controls are correct (SSH key auth, minimal open ports, disk encryption).
- Not intended as a multi-tenant SaaS. Multi-tenant isolation of case data is **not** engineered.

## In scope

Argo defends against the following classes of threats:

### 1. Data leak to third parties

- **No telemetry.** No outbound connections except explicitly-configured connectors.
- **BYOK model.** Third-party API calls go directly from your machine to the provider; Argo never sees your case data pass through a shared cloud.
- **CSP / CORS / CORP / COOP** on the web UI to limit browser-side exfiltration.

**Deliberate, opt-in exception: the AI agent (LLM) capabilities.** Narrative
synthesis, entity-resolution suggestions, and finding triage
(`osint_bot/llm_client.py`, `narrative_synthesis.py`, `entity_resolution_ai.py`,
`triage_ai.py`) send case findings to an LLM provider of the analyst's
choice — this is the one place in the codebase where case data leaves the
perimeter by design, and it is fenced by three independent, fail-closed
gates, none of which is sufficient alone:

1. **Server kill switch** (`OSINT_AI_AGENTS_ENABLED=0` by default) — the 3
   LLM key slots don't exist in the API-key catalog and every `/api/ai/*`
   route 404s. An operator who never opts in has the same "zero data
   leaves" guarantee as before this feature existed.
2. **Per-case consent** — a case owner must explicitly enable AI enrichment
   for *that* case (`cases.ai_enrichment_enabled`, off by default). Cases
   created before this feature, or any case the owner hasn't opted in,
   never trigger an LLM call regardless of the kill switch.
3. **Per-analyst BYOK key** — no key configured, no call. One analyst
   enabling AI does not silently enable it for teammates without a key.

Every call, success or failure, is written to the audit chain
(`ai_narrative_generated`, `ai_entity_suggestions_generated`,
`ai_triage_generated`) with provider, model, byte counts and duration —
never the API key or the raw prompt/response text. Choosing `provider=local`
(an operator-run Ollama/llama.cpp endpoint) keeps this fully inside your own
network — `_safe_http`'s SSRF guard allows a private/loopback target only
for this one provider, exactly like the existing MISP/FlowSINT exception.

### 2. Tampering with past findings

- **SHA-256 audit chain.** Each event carries the hash of the previous event. Modifying a past event invalidates every subsequent hash.
- Chain verification is a single command.

**Signed report seals.** The audit chain above proves DB *events* weren't
tampered with — it says nothing about the exported report FILES
(`report.md/json/pdf`, forensic/red-team variants) on their own. To close
that gap: every completed job is **automatically sealed**
(`osint_bot/custody.py` + `osint_bot/report_signing.py`, zero configuration,
zero network egress). The evidence collected for the case plus that job's
report files are hashed into one manifest, and the manifest hash is signed
with the Argo instance's Ed25519 key (generated on first use, persisted at
`OSINT_REPORT_SIGNING_KEY_PATH`).

What a valid signature **proves**: this exact byte sequence (the manifest —
and transitively every file it hashes) is unchanged since an Argo instance
holding this specific key signed it. What it does **not** prove: that the
investigation methodology was sound, that the analyst who ran it is who they
claim to be, or that the signing key itself wasn't extracted by someone with
host-level access (see "Out of scope" below — key theft requires host
compromise, the same prerequisite as reading everything else).

**Optional RFC3161 timestamping.** An analyst can additionally request a
trusted timestamp from an external Time-Stamping Authority (TSA) the
operator configures (`TSA_URL`, empty by default — the feature is invisible
until set, same pattern as every other opt-in integration). Only the 32-byte
SHA-256 digest of the manifest is sent — never case content — via
`osint_bot/tsa_client.py`, always through `_safe_http`. Argo requests the
token and stores it verbatim; it does **not** verify the TSA's own
certificate chain — that verification, and the decision to trust a
particular TSA at all, belongs to whoever relies on the proof later
(`argo-verify-report`, or standard tools like `openssl ts -verify`), not to
the tool that requested it. This is a deliberate scope boundary, not an
oversight: a bug in Argo's own CMS/certificate-chain verification would be a
worse outcome than not attempting it.

### 3. Injection / SSRF

- **Every** connector's outbound HTTP goes through the **`_safe_http`** gateway.
  This is enforced in CI by `scripts/enforce_safe_http.py`, which fails the
  build if any connector imports `urllib.request` / `httpx` / `requests` /
  `aiohttp` directly (the grandfathered-exceptions set is empty — the
  migration is complete).
- `_safe_http` blocks, on the initial URL **and on every redirect hop**:
  - link-local `169.254.0.0/16` + `fe80::/10` (cloud instance metadata) —
    blocked unconditionally, never reachable even with `allow_private`;
  - loopback + RFC1918 private ranges — blocked unless the caller passes
    `allow_private=True` (used only for operator-configured internal
    endpoints such as a private MISP or a local FlowSINT bridge);
  - non-`http`/`https` schemes;
  - responses larger than 25 MiB (memory-exhaustion guard).
- Redirect-based SSRF (a public endpoint answering `302 Location:
  http://169.254.169.254/`) is defeated: the redirect handler re-validates
  each target before following it.

### 4. Auth abuse

- Admin password is stored as **PBKDF2-SHA256 (200k iterations)**. Never in code, never in logs.
- Admin actions unlock a distinct set of tools; the normal analyst role cannot escalate without the hash.
- Session cookies are `HttpOnly` and `Secure` when `OSINT_SECURE_COOKIE=1`.
- CSRF token on state-changing endpoints.

### 5. Rate-limit / ToS violation of upstream providers

- Every connector declares a per-minute, per-day and burst limit.
- Argo enforces client-side. Not a substitute for provider-side quota — a defense-in-depth.

## Out of scope

Argo does **not** defend against:

- **Compromise of the host OS.** If someone has root, they read everything.
- **Compromise of the analyst account.** Same.
- **Malicious BYOK provider.** If you configure Shodan/VirusTotal/HIBP with a compromised key, the provider sees your queries. Nothing Argo can do about it.
- **Compromise of a local tool wrapped by a connector** (holehe, maigret, ghunt, etc.). We assume these tools are what they claim to be. Pin versions, verify signatures.
- **Legal-basis fabrication.** Argo records what you tell it about the legal basis of a case. It cannot know if you are lying.

## Known limitations (tracked)

- **Connector API keys are encrypted at rest** (envelope encryption, `osint_bot/secrets_crypto.py`): a random per-secret data key encrypts the value (AES-256-GCM), wrapped by an instance master key that lives outside the database (env var, systemd-credential file, or an auto-generated local file, never a DB row, never `.env`). This protects against a database-only leak — a stolen SQLite file or Postgres dump. It does **not** protect against a compromise of the host the master key file lives on (see "Compromise of the host OS" above — that remains out of scope by design, same as everything else here). Rotate with `argo-rotate-master-key`.
- **Datastore itself is not encrypted at rest** by the application (the SQLite file or the Postgres database) — deliberately delegated to OS-level disk encryption rather than reimplemented in-app.
- **Single-user admin.** No role-based access control beyond admin/analyst. Not on the near-term roadmap.
- **`argo-verify-report` checks the seal's signature, not the full evidence file list.** V1 verifies that the manifest hash embedded in a seal export is authentically signed — it does not re-derive that hash from a bundled copy of every evidence/report file (which would require exporting the full artifact list, not just the seal summary). A tampered *seal export* is caught; re-deriving the manifest from scratch against a full artifact bundle is a tracked roadmap item.
- **No key-rotation tooling.** The Ed25519 signing key is generated once and persisted; there is no built-in rotate/re-key flow. Back it up (`OSINT_REPORT_SIGNING_KEY_PATH`) — losing it doesn't invalidate past signatures, but a new key can no longer be tied to the same "instance identity" as older seals.

## Attack surface summary

| Surface | Controls |
| --- | --- |
| Web UI (public port) | CSP, HSTS, HttpOnly cookies, CSRF, rate-limit, PBKDF2 admin auth |
| Outbound HTTP (connectors) | `_safe_http` (SSRF guard), scheme allow-list, cloud-metadata block, RFC1918 block |
| Outbound HTTP (AI agent, opt-in) | Kill switch + per-case consent + per-analyst BYOK key (all three required); `_safe_http`; audit-logged every call |
| Outbound HTTP (RFC3161 timestamp, opt-in) | `TSA_URL` must be configured (single light gate — only a 32-byte hash ever leaves); `_safe_http`; audit-logged every call |
| Report file integrity | Ed25519 signature over a manifest of evidence + report files, always on, zero egress; optional RFC3161 timestamp |
| CLI | Local file access; assumes local trust |
| Storage | SQLite/Postgres via parameterized queries; no dynamic SQL |
| Reports | Content sanitization for HTML embedding; PDF via `reportlab` (no HTML rendering) |

## Reporting a security issue

Do **not** open a public issue. Use [GitHub Security Advisories](https://github.com/gnudrus-del/argo-cloud-osint-platform/security/advisories/new). See [`SECURITY.md`](../SECURITY.md).
