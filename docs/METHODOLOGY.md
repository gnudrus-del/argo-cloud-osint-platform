# Analyst Methodology

This document makes explicit a discipline Argo's data model already
half-enforces in code but never wrote down: how confidence, source
reliability, and severity are assigned to a `Finding`, and how an analyst
should read them. It exists so the convention is citable — for new connector
authors (see [`CONTRIBUTING_MODULES.md`](CONTRIBUTING_MODULES.md)) and for
analysts reading a report — rather than living only as scattered judgment
calls inside 63 connector modules.

Scope note: this is **not** an external red-team recon playbook. Argo
operates inside a case with Rules of Engagement, scope, and (for personal
targets) an explicit legal basis — see [`RESPONSIBLE_USE.md`](RESPONSIBLE_USE.md).
The confidence/severity/evidence discipline below is methodology-agnostic and
applies equally to an authorized-case investigation; the guardrails around
*when* you're allowed to look are a separate, stricter layer enforced by
`osint_bot/policy.py`/`scope.py`/`safety.py`, not by this document.

## 1. Confidence

Every `Finding` carries `confidence: float` (0.0–1.0), set by the connector
that produced it. There is no single formula — a connector author's
judgment call — but the three qualitative tiers below anchor what the
number should mean, and appear as the connector docstrings' informal
vocabulary throughout the codebase:

| Tier | Range (guideline) | Meaning |
| --- | --- | --- |
| **Tentative** | roughly < 0.5 | Plausible from indirect evidence, unverified. A single passive source, an inferred pattern, a snippet-only match. |
| **Firm** | roughly 0.5–0.85 | Directly observed, not yet independently corroborated. A DNS record that resolves, an API that returned a positive match, a banner read live. |
| **Confirmed** | roughly > 0.85 | Independently corroborated by ≥2 sources, or verified by direct, unambiguous interaction (a listable bucket, a live-validated key via a read-only check). |

**Rule of three for attribution**: don't assert an identity link (this
account belongs to this person, this asset belongs to this org) from a
single weak signal. Two independent weak signals, or one strong + one weak,
before treating a link as Firm rather than Tentative. `Finding.why_linked`
exists precisely to make this auditable — write down *which* signals, not
just the conclusion.

**`Finding.gaps`** is the confidence-upgrade mechanism: what's missing to
move a Tentative finding to Firm, or Firm to Confirmed. A connector (or an
analyst reading the report) should be able to answer "what would it take to
trust this more" by reading this field, not by re-deriving it from scratch.

## 2. Source reliability — Admiralty/NATO grade (STANAG 2511)

`Finding.source_reliability` (`"A"`–`"F"`) and `Finding.info_credibility`
(`1`–`6`) together form the Admiralty grade shown on every report (see
`docs/samples/example-report/example.com.md`, "Affidabilità delle evidenze"):

- **Reliability** (the source itself): `A` completely reliable → `F` cannot
  be judged.
- **Credibility** (this specific piece of information): `1` confirmed by
  other sources → `6` cannot be judged.

Legacy/default is `"F"` / `6` ("cannot be judged") so old call-sites keep
working — connector authors should set both explicitly rather than leaving
the default, since an unset grade is indistinguishable from "I didn't
think about it."

Rough mapping to confidence tiers: `A1`–`B2` ≈ Confirmed-grade evidence,
`B3`–`C2` ≈ Firm, `C3`–`D4` ≈ Tentative/needs verification, `D5`–`F6` ≈ weak
or unevaluable. The report's evidence-quality summary already buckets
findings this way — this document just names the buckets.

## 3. Severity

`Finding.severity` (`info | low | medium | high | critical`) is set only
where a finding represents an *exposure*, not for ordinary identity/footprint
data. Anchors, consistent across active-recon connectors
(`cloud_buckets`, `port_scan`, `secret_scan`, `email_security`, ...):

| Severity | Anchor |
| --- | --- |
| **critical** | Listable public storage with data, a live-validated credential, an infostealer breach hit with ≥10 employee accounts (`hudsonrock`). |
| **high** | A confirmed secret in a public repo, an exposed admin/service panel, ≥1–9 employee breach accounts. |
| **medium** | A hardening gap with no direct exposure yet (missing SPF/DMARC, a private-but-guessable bucket). |
| **low** | Cosmetic or marginal (missing security header, outdated-but-unexploited software). |
| **info** | Worth recording, no action implied. |

`Finding.attck_ttps` optionally maps a finding to a MITRE ATT&CK technique
ID (e.g. `T1589.002` for email-address collection) when one applies —
useful for feeding findings into a SIEM/TIP alongside the STIX/MISP export.

## 4. Evidence hygiene

Every `Evidence` on a `Finding` should carry a `url` and, where the
connector captured one, a `quote`. The audit chain (`osint_bot/audit.py`)
independently timestamps *when* a finding was produced and hash-chains it —
so "when was this collected" is already answered at the platform level and
does not need to be duplicated inside every `Finding.notes` string.

## 5. Asset graph, not a flat list

`Entity` and `Relationship` (`osint_bot/models.py`) exist so findings about
the same underlying thing (a domain, a person, a wallet) converge on one
node instead of staying N disconnected strings. When a connector or the
link-analysis layer (`osint_bot/link_analysis.py`) creates an `Entity`, dedup
by a stable key first, then attach findings — don't create a second `Entity`
for a value you've already seen under a different casing/format.

## 6. What this document deliberately does not cover

- Active-recon technique detail (wordlists, probe paths, payloads) — that's
  operational reference material for authorized external assessments, kept
  in the offensive-security tooling used to *build* connectors like
  `cloud_buckets`, not in Argo's own docs, since Argo's default posture is
  passive-first (see `docs/RESPONSIBLE_USE.md`).
- OpSec/sock-puppet guidance for the analyst's own investigative footprint —
  out of scope for a self-hosted defensive tool whose target is, by
  definition, a case with a documented legal basis.
