# GitHub publication checklist

Manual steps for the maintainer to run **on the GitHub UI**. Nothing in this list can be automated from a PR.

## 1. Repository → Settings → General

- [ ] **Description**: `Self-hosted defensive OSINT platform with CLI + web UI, BYOK connectors, audit chain, PDF/JSON/STIX/MISP exports, and privacy-by-design guardrails.`
- [ ] **Website**: (leave empty for now, or point to your demo URL if you run one publicly).
- [ ] **Topics** (add all):
      `osint`, `threat-intelligence`, `cyber-security`, `security-tools`, `digital-forensics`, `investigation`, `socmint`, `recon`, `stix`, `misp`, `python`, `self-hosted`, `privacy-by-design`, `gdpr`, `docker`, `cli`, `web-ui`

## 2. Repository → Settings → General → Features

- [ ] **Issues** — enabled
- [ ] **Discussions** — enabled (this is the community front door)
- [ ] **Wiki** — disabled (docs live in `docs/`)
- [ ] **Projects** — optional; enable if you plan to use them

## 3. Repository → Settings → Code security and analysis

- [ ] **Dependency graph** — enabled
- [ ] **Dependabot alerts** — enabled
- [ ] **Dependabot security updates** — enabled
- [ ] **Dependabot version updates** — enabled (already configured via `.github/dependabot.yml`)
- [ ] **Secret scanning** — enabled
- [ ] **Push protection** for secrets — enabled
- [ ] **CodeQL analysis** — enable if available on public repos in your plan

## 4. Repository → Settings → Branches

- [ ] Branch protection rule on `main`:
  - [ ] Require pull request before merging
  - [ ] Require status checks to pass (once CI is stable, add `ci` as required)
  - [ ] Require conversation resolution before merging
  - [ ] Do not allow bypassing settings

## 5. Repository → Insights → Community Standards

Verify these are all green (files that already exist in the repo satisfy them):

- [ ] Description ✔
- [ ] README ✔
- [ ] Code of Conduct ✔ (`CODE_OF_CONDUCT.md`)
- [ ] Contributing ✔ (`CONTRIBUTING.md`)
- [ ] License ✔ (`LICENSE`)
- [ ] Security policy ✔ (`SECURITY.md`)
- [ ] Issue templates ✔ (`.github/ISSUE_TEMPLATE/*.yml`)
- [ ] Pull request template ✔ (`.github/pull_request_template.md`)

## 6. Social preview image

- [ ] Open **Settings → General → Social preview** → **Edit** → upload a 1280×640 PNG.
- Suggested content: Argo logo + one-liner + Apache-2.0 badge.
- If you do not have one yet, this is the single biggest visual conversion lever on GitHub search.

## 7. Pin the repo on your profile

- [ ] Profile → **Customize your pins** → add `argo-cloud-osint-platform`.

## 8. First release

Follow [`RELEASE_PROCESS.md`](RELEASE_PROCESS.md):

- [ ] Tag `v0.1.0`.
- [ ] Draft a **GitHub Release** with the message from `RELEASE_PROCESS.md`.
- [ ] Attach source archives (auto).
- [ ] (Optional) Publish Docker image to GHCR — enable **Settings → Packages** first.

## 9. Discussions kickoff

Once Discussions is enabled, seed the categories:

- [ ] Category: **Announcements** — post the v0.1.0 release note (locked, maintainers only).
- [ ] Category: **Q&A** — pin a "How to ask for help" thread linking `SUPPORT.md`.
- [ ] Category: **Show and tell** — invite analysts to share sanitized workflows.
- [ ] Category: **Ideas** — link the feature-request issue template.

## 10. Screenshots

- [ ] Populate `docs/assets/` with real screenshots per [`docs/assets/README.md`](assets/README.md).
- [ ] Reference them in `README.md` under a **Screenshots** section (add the section once assets exist).

## 11. External signals (optional)

Ethical growth only. Do **not** buy stars, do not spam, do not cross-post to unrelated communities.

- [ ] Add to [awesome-osint](https://github.com/jivoi/awesome-osint) via PR — only after v0.1.0 is tagged and README is stable.
- [ ] Announce in relevant, on-topic communities (e.g. `r/OSINT`, IntelTechniques forum, defensive-security mailing lists) with a **factual** description and a link. Follow each community's promotion rules.
