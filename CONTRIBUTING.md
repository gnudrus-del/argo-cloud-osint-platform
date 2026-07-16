> 🇮🇹 [Leggi in italiano](docs/CONTRIBUTING.it.md)

# Contributing to Argo OSINT

Welcome. Argo is an **Italian OSINT platform**, privacy-by-design,
GDPR-oriented, with a tamper-proof SHA-256 audit chain. Every contribution
helps make it a reference point.

## How to get involved

### Reporting a bug
- Check that a similar issue doesn't already exist.
- Open an issue with: operating system, version (`git rev-parse HEAD`),
  reproduction steps, expected vs. observed output, relevant logs.
- **Secrets**: never in the logs/screenshots you attach. Redact API keys.

### Proposing a feature
- Discuss it first in a **Discussion** or "proposal" issue: find out whether
  it fits the roadmap before writing code.
- Argo has a strong stance: **privacy-by-design + native-first**. PRs that
  add heavy dependencies or mandatory SaaS services need to be justified.

### Adding an OSINT connector
- See `osint_bot/connectors/` for the pattern (subclass `BaseConnector`).
- Golden rules:
  1. **Passive by default** (`ACTION_PASSIVE`); active only if it makes
     sense, and it must be marked `ACTION_ACTIVE_GATED`.
  2. **Graceful degrade**: if the tool/key is missing → `status="missing_key"`
     with a clear message. Never exceptions.
  3. **Rate limit and cache TTL** declared in the spec.
  4. **Deterministic offline tests** (in `tests/`).
  5. **Legal note** in Italian in the spec: what it sends over the network
     and to whom.

### Security
See [SECURITY.md](SECURITY.md). If you discover a vulnerability, **do not
open a public issue**: use GitHub Security Advisories.

## Dev setup

```bash
git clone https://github.com/gnudrus-del/argo-cloud-osint-platform.git
cd argo-cloud-osint-platform
python -m venv .venv && . .venv/bin/activate   # or .venv\Scripts\activate
pip install -e '.[ai,postgres,queue]'          # optional extras
cp .env.example .env                           # configure at least OSINT_WEB_TOKEN
python -m pytest tests/ -q                     # must pass fully
python -m osint_bot.web --port 7655            # start the backend
```

Optional Next.js frontend in `web-next/` (see `web-next/README.md`).

## Code style

- **Python 3.10+**, type hints where they help readability.
- Comments only where the WHY isn't obvious; no "this is function X"
  comments.
- Italian naming in user-facing messages/documents, English in code.
- **Tests**: every connector has an offline `tests/test_connector_<name>.py`.

## PR process

1. Fork + branch from `main` (`feat/<name>`, `fix/<name>`).
2. One commit = one logical change; imperative commit message in English.
3. `pre-push`: `python -m pytest tests/ -q` must pass.
4. In the PR: describe what changes, why, and how you tested it.
5. A maintainer will review; be open to discussion.

## Code of conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). In short: be respectful,
don't publish third parties' personal data in examples, no personal attacks.

Thank you for your time. 💛
