# Sample reports

Reports produced by Argo Cloud OSINT Platform, committed as reference
material so reviewers can inspect the output *without* installing the
tool first.

Every sample in this directory targets a **safe, public, non-sensitive
domain** (`example.com`, defined by IANA specifically for use in
documentation and examples — see [RFC 2606](https://www.rfc-editor.org/rfc/rfc2606)).
No real subject, no real API key, no real infrastructure was queried
during generation.

## Files

| File | Format | Size | Purpose |
| --- | --- | ---: | --- |
| [`example-report/example.com.md`](example-report/example.com.md) | Markdown | ~19 KB | Analyst-readable narrative report |
| [`example-report/example.com.json`](example-report/example.com.json) | JSON | ~82 KB | Machine-readable structured findings |
| [`example-report/example.com.pdf`](example-report/example.com.pdf) | PDF | ~15 KB | Print/court-ready rendering of the Markdown |

## How each file was generated

```bash
argo-osint example.com \
    --type domain \
    --provider none \
    --max-pages 1 \
    --output-dir docs/samples/example-report \
    --format both

python -c "
from pathlib import Path
from osint_bot.pdf_report import write_pdf_from_markdown
write_pdf_from_markdown(
    Path('docs/samples/example-report/example.com.md'),
    Path('docs/samples/example-report/example.com.pdf'),
)
"
```

The report was produced with **`--provider none`**: only the 43 key-free
connectors were involved. No BYOK provider was contacted, no API key was
used. Re-running the command against `example.com` will produce
substantially identical output.

## What the sample demonstrates

- The structure of an Argo report (narrative sections, evidence
  grouping by category, Admiralty-code reliability grading).
- The JSON schema that downstream tooling can integrate.
- The PDF rendering used for archival / evidentiary purposes.
- The typical size and shape of an output on a low-signal target.
- The dork catalogue that is generated for further manual verification.

## What the sample does **not** demonstrate

- BYOK-enriched findings (Shodan, VirusTotal, HIBP, ...) — those require
  a live key and produce target-specific data that is not appropriate
  to commit.
- Active-recon output (port scan, content discovery) — those are gated
  to in-scope cases and not applicable to `example.com`.
- STIX 2.1 and MISP exports — these are generated on demand from the
  same JSON via `stix_export.py`; sample bundles will be added in a
  follow-up when the CI stubs are stable.

If you want a richer sample, run the same command with your own BYOK
providers configured; do **not** open a PR to add key-enriched output.
