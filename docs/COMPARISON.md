# Comparison

Honest, non-denigratory comparison with a few alternatives. Every tool listed has its use — Argo occupies a specific niche.

## When to use Argo

- You need **self-hosted** OSINT with **case data that never leaves your perimeter by default** (the only exception is the optional, opt-in AI agent capabilities — see `docs/THREAT_MODEL.md`).
- You need **audit-chained findings** for evidentiary or compliance reasons.
- You are OK writing Python for custom connectors.
- Your investigations are **defensive, authorized, or public-interest**.

## When *not* to use Argo

- You want a fully managed SaaS with 24/7 support and SLAs → look at commercial platforms (Maltego, ShadowDragon, Intel471, DomainTools Iris).
- You want visual link analysis as the primary interface → Maltego's UX is more mature; you can also use Argo's STIX/MISP exports as an ingestion source for it.
- You need a very large ecosystem of pre-built transforms → Maltego / SpiderFoot / OSINT Framework have broader out-of-the-box catalogs.
- You want an entirely CLI-first, single-purpose tool → holehe, maigret, theHarvester, or ghunt used directly may be lighter than Argo.

## What Argo brings that others do not (as far as we know)

- **SHA-256 audit chain** natively integrated with the analyst workflow.
- **BYOK-only** for commercial providers — Argo does not intermediate.
- **Legal-basis gating** and **DSAR endpoints** built in.
- **STIX 2.1 + MISP** exports without a paid tier.
- Apache-2.0, no telemetry, no vendor lock-in.

## Nearby projects (mentioned for context, not compared feature-by-feature)

- **SpiderFoot** — long-standing open-source recon, broader catalog, less privacy-tuned.
- **Maltego (CE / commercial)** — graph-first analyst UX, extensive transform ecosystem.
- **theHarvester / holehe / maigret** — single-purpose CLIs; Argo wraps some of these as connectors.
- **OpenCTI / MISP** — threat-intel platforms; Argo can export to them, not replace them.
- **Recon-ng** — modular recon framework; Argo shares the modular ethos but adds case management and audit chain.

If we missed a project you think fits the comparison, open a PR against this document with a factual entry.
