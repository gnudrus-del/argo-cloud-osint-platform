# Quickstart

Get Argo running in 5 minutes.

## 1. Prerequisites

- Python 3.10+ (3.12 recommended)
- Git

Optional: Docker + Docker Compose (if you prefer containers).

## 2. Install

```bash
git clone https://github.com/gnudrus-del/argo-cloud-osint-platform.git
cd argo-cloud-osint-platform
python -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows PowerShell:
# .\.venv\Scripts\Activate.ps1
pip install -e .
```

## 3. First CLI run (no keys needed)

```bash
argo-osint example.com --type domain --provider none \
    --max-pages 1 --output-dir reports/smoke --format both
```

Output: `reports/smoke/` contains both Markdown and JSON.

## 4. Start the web UI

```bash
export OSINT_WEB_TOKEN="pick-a-long-random-token"
python -m osint_bot.web --host 127.0.0.1 --port 8000
```

Open <http://127.0.0.1:8000>. Sign up, open a case, run a query.

## 5. (Optional) Add BYOK providers

Copy `.env.example` to `.env`, fill only the keys you have:

```bash
cp .env.example .env
$EDITOR .env
```

Restart the web UI. Provider-backed connectors will pick up their keys.

## Next steps

- [`docs/CONFIGURATION.md`](CONFIGURATION.md) — all environment variables.
- [`docs/CONNECTORS.md`](CONNECTORS.md) — the 58 connectors, key-free vs BYOK.
- [`docs/EXAMPLES.md`](EXAMPLES.md) — copy-paste investigation recipes.
- [`docs/DOCKER.md`](DOCKER.md) — containerized deployment.
- [`docs/RESPONSIBLE_USE.md`](RESPONSIBLE_USE.md) — legal-basis gating.
