# docs/assets/

Screenshots and images for the README and docs.

## Files to add

| File | Purpose | Suggested size |
| --- | --- | --- |
| `dashboard.png` | Web UI dashboard, one active case | 1440×900 |
| `case-detail.png` | Case detail with findings list | 1440×900 |
| `report-preview.png` | PDF/Markdown report side by side | 1440×900 |
| `graph.png` | Entity-relationship graph view | 1440×900 |
| `cli-demo.gif` | 20-30 sec CLI recording | ≤ 5 MB |
| `social-preview.png` | GitHub social preview image | 1280×640 |
| `logo.svg` | Vector logo | any |
| `logo-mono.svg` | Monochrome variant for dark backgrounds | any |

## Redaction rules

Every screenshot **must** be redacted before commit:

- No real email addresses, names, phone numbers, IPs, domains, wallets.
- Use `example.com`, `alice@example.com`, `10.0.0.42`, `bc1qexample...` as safe placeholders.
- Blur or overlay solid boxes on any real content.
- Verify with `git diff --stat` that no unexpected binary blob is being added.

## Adding a screenshot

1. Record on a case that only uses `example.com` and synthetic data (or redact).
2. Save as PNG (or SVG where possible) at the recommended size.
3. Optimize with a tool like `oxipng` or `pngquant` (target ≤ 200 KB per asset).
4. Commit under this directory.
5. Reference from README:

```markdown
![Argo dashboard](docs/assets/dashboard.png)
```

## Placeholder status

At the time of `v0.1.0`, this directory is intentionally empty. The README references screenshots that do not yet exist — this is a **TODO for the maintainer**, tracked in the roadmap. Do not fake screenshots.
