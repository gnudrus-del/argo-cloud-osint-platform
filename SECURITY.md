> 🇮🇹 [Leggi in italiano](docs/SECURITY.it.md)

# Security Policy

## Threat model

Argo OSINT is an **investigative** platform: it handles third parties'
personal data (investigation targets) and the analyst's credentials (API
keys, tool session cookies). The two most relevant attack surfaces are:

1. **Compromise of the analyst's credentials** stored in the DB
   (API keys, tool session cookies). An attacker who obtains a copy of the
   DB must find the credentials encrypted or unusable.
2. **Exfiltration or tampering of the audit chain** (forensic integrity):
   modifying/inserting audit events would invalidate the evidentiary value
   of the reports.

## Baseline hardening implemented

- **Auth**: server-side sessions with `HttpOnly + SameSite=Strict` cookies.
  `Secure` cookie via `OSINT_SECURE_COOKIE=1`. HSTS via `OSINT_HSTS=1`.
- **CSRF**: per-session token required on all POST/DELETE.
- **CSP**: `default-src 'self'`, `frame-ancestors 'none'`, no inline script.
- **Extra headers**: `X-Frame-Options DENY`, `X-Content-Type-Options nosniff`,
  `Referrer-Policy no-referrer`, restrictive `Permissions-Policy`,
  `Cross-Origin-Opener-Policy same-origin`.
- **Admin password**: PBKDF2-SHA256 with a 16-byte salt and 200k iterations;
  constant-time comparison (`hmac.compare_digest`); no password ever in code
  or in the repo.
- **In-process rate limiting** (`InMemoryRateLimiter`) + constant delay on
  admin failures to prevent enumeration.
- **SHA-256 audit chain** (hash of the previous event chained together).
- **Tool/connector obfuscation** for non-admin users (Phase 22): the list
  of search tools is visible only after unlocking with the admin password.

## What is NOT done (declared limits)

- API keys are encrypted at rest with application-level envelope encryption
  (`osint_bot/secrets_crypto.py`: AES-256-GCM, instance master key kept
  separate from the DB — env var, systemd credential file, or an
  auto-generated local file, never a table row). This protects against a
  leak of the database alone (stolen SQLite file, Postgres dump); it does
  not protect against a compromise of the machine hosting the master key —
  in that case, chmod 600 on the key file, VM-level filesystem encryption,
  and system access control remain relevant. Rotation via
  `argo-rotate-master-key`.
- External tool sessions (GHunt, Toutatis) are stored in env/dir on the VM:
  protecting them is the analyst's responsibility.
- Argo is NOT a WAF: behind a public reverse proxy, use Caddy/nginx with
  modern TLS and fail2ban (units included in `deploy_artifacts/`).

## Complete threat model and materials for an external audit

This file is a summary. The complete threat model (what is in scope, what
is explicitly out of scope, known limits) is in
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md). Anyone considering
commissioning a paid external security review will find preparatory
materials (suggested scope, dependencies, already-active CI gates) in
[`docs/AUDIT_READINESS.md`](docs/AUDIT_READINESS.md) — this is **not** an
attestation that Argo has already been reviewed: it has not been, as of
today.

## Reporting a vulnerability

- **Do not open a public issue.**
- Use the GitHub **Security Advisories** flow: `Security → Report a
  vulnerability`.
- In the report, include: reproduction steps, version (git SHA), potential
  impact, and — if you have one — a minimal PoC.

We respond within **7 business days** and agree on a coordinated disclosure
timeline (typically 90 days). Contributors who report verified
vulnerabilities are credited in the CHANGELOG (if they wish) and in the
fix releases.

## Responsible use

Argo is distributed for: (1) **authorized** investigations, (2) security
audits on assets you own, (3) documented investigative journalism, (4)
training/CTF. **It is not permitted** to use it for stalking, doxxing,
unauthorized surveillance, or violation of target platforms' ToS. The
Rules of Engagement (RoE) + authorized scope layer is designed precisely
to track what has been authorized on a case-by-case basis.
