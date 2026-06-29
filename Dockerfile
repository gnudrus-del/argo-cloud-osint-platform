FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV OSINT_WEB_HOST=0.0.0.0
ENV OSINT_WEB_PORT=8000

WORKDIR /app

RUN useradd --create-home --shell /usr/sbin/nologin gufo

COPY pyproject.toml README.md ./
COPY osint_bot ./osint_bot
COPY config ./config
COPY scripts ./scripts
COPY DEPLOYMENT.md ./

RUN pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir -e .

RUN mkdir -p /app/web_jobs /app/reports && chown -R gufo:gufo /app
USER gufo

EXPOSE 8000

CMD ["python", "-m", "osint_bot.web", "--host", "0.0.0.0", "--port", "8000"]
