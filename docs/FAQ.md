# FAQ

## Is Argo free?

Yes. Apache-2.0. Self-host it. There is no paid tier and no telemetry.

## Is there a hosted / SaaS version?

Not currently. A public demo instance exists for evaluation but should not be used for real cases — it has no SLA and no confidentiality guarantees.

## Which connectors work without any API key?

43 out of 58 — see [`CONNECTORS.md`](CONNECTORS.md).

## What about the BYOK providers?

You bring your key, Argo uses it directly against the provider's API. Argo does **not** intermediate. Your rate quota, your invoice, your data.

## Does Argo store my API keys in clear text?

Currently **yes**, in your local `.env`. Encryption-at-rest for connector keys is a tracked roadmap item. In the meantime: `chmod 600 .env`, run on OS-encrypted disk, use a service-account for BYOK where possible so you can rotate.

## Does Argo phone home?

No. Zero telemetry — Argo's own servers (there are none) never see your data. By default there are also no non-connector outbound calls at all; verify with `strace` or by inspecting the source. The one deliberate, opt-in exception is the AI agent (LLM) capability: if you explicitly enable it (server kill switch + per-case consent + your own BYOK key, all three required), case findings are sent to the LLM provider *you* choose — see [`THREAT_MODEL.md`](THREAT_MODEL.md#1-data-leak-to-third-parties). Leave it disabled and the guarantee is unconditional.

## Can I run it on a Raspberry Pi?

Yes for the base install (46 key-free connectors). The `ai` extra needs more memory and CPU.

## Does it work on Windows?

Yes — CLI and web UI. Some optional integrations (holehe, maigret, ghunt) are Linux/macOS-friendly and used via WSL on Windows.

## Can I add my own connector?

Yes. About 50 lines of Python. See [`CONNECTORS.md`](CONNECTORS.md) and [`CONTRIBUTING.md`](../CONTRIBUTING.md).

## Is the audit chain court-ready?

The chain is tamper-evident (any modification of a past event invalidates every subsequent hash). Every completed report is also independently signed (Ed25519, automatic, zero config) and can be optionally timestamped against an RFC3161 authority you choose — verifiable offline with `argo-verify-report` or standard tools, without trusting Argo's own database. See `docs/CONFIGURATION.md` and `docs/THREAT_MODEL.md` for exactly what this proves. Whether it is admissible as evidence in your jurisdiction still depends on chain-of-custody procedure and expert testimony — that is a legal question, not a code question.

## Why "Argo"?

The Argo of Greek mythology carried a crew across unknown seas to find something specific. The tool carries an analyst across public sources to find something specific. And "Argo" is short.

## Where does it *not* fit?

- **Illegal or unauthorized investigations.** Refuses to be that tool.
- **Mass surveillance.** Not a monitoring platform.
- **Full-text web crawling.** Argo aggregates existing sources; it does not run a general web crawler.
- **Automated exploitation.** Argo is passive-first with narrow, opt-in active recon.
