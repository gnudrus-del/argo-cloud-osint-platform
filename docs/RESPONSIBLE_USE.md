# Responsible use

Argo is a **defensive** OSINT platform. It is not a weapon. Its guardrails exist to make the right thing the easy thing.

## What Argo assumes about you

You have a **legitimate reason** to investigate a target:

- The target is your own asset (own domain, own accounts, own infrastructure).
- The target belongs to an organization that has hired or authorized you.
- The target is a public figure or organization in the context of journalism or public-interest research and applicable law protects that use.
- The target is a threat actor in the context of authorized threat intelligence.
- The target is in scope for a legal proceeding, and you have the legal basis to gather evidence.

If none of the above applies, **do not use Argo on that target.**

## Legal-basis gating

For personal targets (email, phone, individual name), Argo requires a **case** with:

- A case ID.
- A recorded **legal basis** (contract, court order, journalistic public interest, own-account verification, other with description).
- A **Rules of Engagement** block that scopes what is in and out of bounds.

Findings tagged as personal are **redacted by default** in reports. Disclosure requires explicit override and the override is written to the audit chain.

## Rate limiting and Terms of Service

All connectors respect per-minute / per-day rate limits and target `robots.txt` where applicable. Do not patch this to be more aggressive. If you need faster throughput, upgrade your BYOK tier — do not violate ToS.

## Active recon

Content discovery, port scan, and subdomain enumeration are **active** — they touch the target. They require:

- An in-scope case.
- A user-visible confirmation.
- An audit-chain event with timestamp and hash.

Do not run active recon on infrastructure you do not own or have not been authorized to test. This is not merely policy — it is **the law** in most jurisdictions (Computer Fraud and Abuse Act, EU NIS2, Italian art. 615-ter c.p., etc.).

## Data retention

Case data lives in your local SQLite/Postgres. Argo does not phone home. Retention is your call:

- Set an expiry policy for closed cases.
- Wipe on request via the DSAR endpoint (GDPR art. 17).
- The datastore is **not** encrypted at rest by default — use OS-level disk encryption. Encryption-at-rest is a roadmap item.

## Disclosure

If you find a vulnerability **using Argo** on an authorized target, disclose it responsibly to that target's security contact. Argo maintainers do not intermediate disclosures.

If you find a vulnerability **in Argo itself**, see [`SECURITY.md`](../SECURITY.md).

## When in doubt

Ask a lawyer. This document is not legal advice.
