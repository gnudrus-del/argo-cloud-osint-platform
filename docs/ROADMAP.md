# Roadmap

Public planning. Priorities can change; nothing here is a promise.

## v0.1.0 (current)

- 58 native connectors (43 key-free + 15 BYOK).
- CLI + web UI + Docker.
- SHA-256 audit chain, DSAR endpoints, RoE + case-scope gating.
- STIX 2.1 bundle + MISP event exports.
- Deployment recipes: systemd + Caddy, Docker Compose.

## v0.2.0 — hardening + distribution

- **Encryption-at-rest for connector keys** (planned). Currently keys are plaintext in `.env`. Roadmap: OS keychain integration + envelope-encrypted `.env` file.
- **Publish Docker image to GHCR** on tagged releases (planned).
- **PyPI publication** as `argo-cloud-osint` (planned).
- **Signed releases** (Sigstore / cosign) (planned).
- Broader test coverage of connector edge cases.
- Ruff clean pass across the codebase.

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
