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

### 2. Tampering with past findings

- **SHA-256 audit chain.** Each event carries the hash of the previous event. Modifying a past event invalidates every subsequent hash.
- Chain verification is a single command.

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

- **Encryption-at-rest is not applied to connector keys.** They live in `.env` as plaintext. Roadmap item.
- **Datastore is not encrypted at rest.** Use OS-level disk encryption. Roadmap item.
- **Single-user admin.** No role-based access control beyond admin/analyst. Not on the near-term roadmap.

## Attack surface summary

| Surface | Controls |
| --- | --- |
| Web UI (public port) | CSP, HSTS, HttpOnly cookies, CSRF, rate-limit, PBKDF2 admin auth |
| Outbound HTTP (connectors) | `_safe_http` (SSRF guard), scheme allow-list, cloud-metadata block, RFC1918 block |
| CLI | Local file access; assumes local trust |
| Storage | SQLite/Postgres via parameterized queries; no dynamic SQL |
| Reports | Content sanitization for HTML embedding; PDF via `reportlab` (no HTML rendering) |

## Reporting a security issue

Do **not** open a public issue. Use [GitHub Security Advisories](https://github.com/gnudrus-del/argo-cloud-osint-platform/security/advisories/new). See [`SECURITY.md`](../SECURITY.md).
