# Installation

Three supported paths: local Python, Docker, and self-hosted systemd on a VM.

## A. Local Python (dev / analyst laptop)

### A.1 Minimal install

```bash
git clone https://github.com/gnudrus-del/argo-cloud-osint-platform.git
cd argo-cloud-osint-platform
python -m venv .venv
source .venv/bin/activate  # Windows: .\.venv\Scripts\Activate.ps1
pip install -e .
```

### A.2 With optional extras

Argo ships lean; heavy dependencies are opt-in.

| Extra | Provides | Install |
| --- | --- | --- |
| `web` | Web UI (bundled, no extra deps) | `pip install -e ".[web]"` |
| `ai` | OCR + NER + language detect + translation | `pip install -e ".[ai]"` |
| `postgres` | Postgres storage backend | `pip install -e ".[postgres]"` |
| `queue` | Celery + Redis job queue | `pip install -e ".[queue]"` |
| `dev` | pytest, ruff, build, twine | `pip install -e ".[dev]"` |

Combine: `pip install -e ".[web,ai,dev]"`.

### A.3 Verify

```bash
python -m compileall osint_bot
python -m unittest discover -s tests
argo-osint --help
```

## B. Docker

See [`docs/DOCKER.md`](DOCKER.md).

## C. Self-hosted VM (systemd + Caddy)

Recipe: see `deploy_artifacts/` and `scripts/bootstrap-vm-fresh.sh`. High-level:

1. Provision Ubuntu 24.04 (1 vCPU / ≥2 GB RAM works for a single analyst).
2. `sudo ./scripts/bootstrap-vm-fresh.sh` — installs Python, creates `argo` user, sets up systemd unit and Caddy reverse-proxy.
3. `./deploy.sh` (or `./deploy.ps1` on Windows) — rsync of `osint_bot/` to the VM, restart the service.
4. Point your DNS at the VM. Argo lands on HTTPS via Caddy's automatic Let's Encrypt.

Full VM guide: [`docs/DEPLOY.md`](DEPLOY.md).
