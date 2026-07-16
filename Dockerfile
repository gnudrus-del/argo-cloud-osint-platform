FROM python:3.12-slim

LABEL org.opencontainers.image.title="Argo Cloud OSINT Platform"
LABEL org.opencontainers.image.description="Self-hosted defensive OSINT platform with CLI + web UI, BYOK connectors, audit chain, and STIX/MISP/PDF/JSON/Markdown exports."
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.source="https://github.com/gnudrus-del/argo-cloud-osint-platform"

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV OSINT_WEB_HOST=0.0.0.0
ENV OSINT_WEB_PORT=8000

WORKDIR /app

RUN useradd --create-home --shell /usr/sbin/nologin argo

COPY pyproject.toml README.md LICENSE ./
COPY osint_bot ./osint_bot
COPY config ./config
COPY scripts ./scripts
COPY docs/DEPLOY.md ./docs/DEPLOY.md

# [postgres] installa psycopg[binary] (wheel precompilata, nessuna libreria
# di sistema extra necessaria) — Postgres è il backend raccomandato in
# produzione (vedi docker-compose.yml); l'immagine lo supporta sempre, resta
# comunque inerte finché DATABASE_URL non è impostata (default: SQLite).
RUN pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir -e ".[postgres]"

RUN mkdir -p /app/web_jobs /app/reports && chown -R argo:argo /app
USER argo

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/dashboard', timeout=3).status in (200,401) else 1)" || exit 1

CMD ["python", "-m", "osint_bot.web", "--host", "0.0.0.0", "--port", "8000"]
