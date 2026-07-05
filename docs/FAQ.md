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

No. Zero telemetry. Verify with `strace` or by inspecting the source — there are no non-connector outbound calls.

## Can I run it on a Raspberry Pi?

Yes for the base install (43 key-free connectors). The `ai` extra needs more memory and CPU.

## Does it work on Windows?

Yes — CLI and web UI. Some optional integrations (holehe, maigret, ghunt) are Linux/macOS-friendly and used via WSL on Windows.

## Can I add my own connector?

Yes. About 50 lines of Python. See [`CONNECTORS.md`](CONNECTORS.md) and [`CONTRIBUTING.md`](../CONTRIBUTING.md).

## Is the audit chain court-ready?

The chain is tamper-evident (any modification of a past event invalidates every subsequent hash). Whether it is admissible as evidence in your jurisdiction depends on chain-of-custody, timestamping and expert testimony — that is a legal question, not a code question.

## Why "Argo"?

The Argo of Greek mythology carried a crew across unknown seas to find something specific. The tool carries an analyst across public sources to find something specific. And "Argo" is short.

## Where does it *not* fit?

- **Illegal or unauthorized investigations.** Refuses to be that tool.
- **Mass surveillance.** Not a monitoring platform.
- **Full-text web crawling.** Argo aggregates existing sources; it does not run a general web crawler.
- **Automated exploitation.** Argo is passive-first with narrow, opt-in active recon.
