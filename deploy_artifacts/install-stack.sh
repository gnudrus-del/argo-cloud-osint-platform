#!/usr/bin/env bash
# Argo — installer dello stack avanzato (Fasi 4/6/7) su Ubuntu 24.04.
#
# Attiva SOLO i profili che gli passi. Ogni profilo è indipendente:
#   sudo bash install-stack.sh queue                 # solo Celery/Redis
#   sudo bash install-stack.sh graph search          # Neo4j + OpenSearch
#   sudo bash install-stack.sh db queue graph search # tutto
#   sudo bash install-stack.sh web                   # (extra) frontend Next.js
#
# Le password dei servizi vanno messe in /opt/argo-osint/stack.env (consigliato),
# oppure esportate e passate con sudo -E:
#   echo 'ARGO_PG_PASSWORD=...'    >> /opt/argo-osint/stack.env   (profilo db)
#   echo 'ARGO_NEO4J_PASSWORD=...' >> /opt/argo-osint/stack.env   (profilo graph)
#   sudo bash install-stack.sh db graph          # legge stack.env
#   # -- oppure --
#   export ARGO_PG_PASSWORD=...; sudo -E bash install-stack.sh db
#
# Lo script è idempotente: rilanciarlo aggiorna soltanto ciò che è cambiato.
set -euo pipefail

ARGO_HOME="/opt/argo-osint"
ARGO_USER="ubuntu"
COMPOSE="${ARGO_HOME}/deploy_artifacts/stack-compose.yml"
VENV_PIP="${ARGO_HOME}/.venv/bin/pip"

if [[ $# -eq 0 ]]; then
  echo "Uso: sudo bash install-stack.sh [db] [queue] [graph] [search] [web]" >&2
  exit 2
fi

# Carica eventuali password da stack.env (non versionato).
[[ -f "${ARGO_HOME}/stack.env" ]] && source "${ARGO_HOME}/stack.env"

PROFILES=()
WANT_WEB=0
EXTRAS=()
for p in "$@"; do
  case "$p" in
    db)     PROFILES+=(--profile db);     EXTRAS+=("postgres") ;;
    queue)  PROFILES+=(--profile queue);  EXTRAS+=("queue") ;;
    graph)  PROFILES+=(--profile graph) ;;   # Neo4j: nessuna dep Python (HTTP)
    search) PROFILES+=(--profile search) ;;  # OpenSearch: nessuna dep Python (REST)
    web)    WANT_WEB=1 ;;
    *) echo "Profilo sconosciuto: $p" >&2; exit 2 ;;
  esac
done

echo "[1/6] Docker + compose plugin..."
if ! command -v docker >/dev/null 2>&1; then
  curl -fsSL https://get.docker.com | sh
fi
if ! docker compose version >/dev/null 2>&1; then
  apt-get update -qq
  apt-get install -y -qq docker-compose-plugin
fi

echo "[2/6] Validazione password richieste..."
for p in "$@"; do
  [[ "$p" == "db"    && -z "${ARGO_PG_PASSWORD:-}"    ]] && { echo "ERR export ARGO_PG_PASSWORD prima (profilo db)." >&2; exit 1; }
  [[ "$p" == "graph" && -z "${ARGO_NEO4J_PASSWORD:-}" ]] && { echo "ERR export ARGO_NEO4J_PASSWORD prima (profilo graph)." >&2; exit 1; }
done

if [[ ${#PROFILES[@]} -gt 0 ]]; then
  echo "[3/6] Avvio servizi Docker: ${PROFILES[*]}"
  docker compose -f "$COMPOSE" "${PROFILES[@]}" up -d
else
  echo "[3/6] Nessun servizio Docker richiesto (solo web?)."
fi

echo "[4/6] Dipendenze Python opzionali nel venv..."
if [[ ${#EXTRAS[@]} -gt 0 ]]; then
  joined=$(IFS=, ; echo "${EXTRAS[*]}")
  sudo -u "$ARGO_USER" "$VENV_PIP" install -e "${ARGO_HOME}[${joined}]"
else
  echo "    (Neo4j/OpenSearch non richiedono deps Python — skip)"
fi

echo "[5/6] Servizi systemd..."
if printf '%s\n' "$@" | grep -qx queue; then
  cp "${ARGO_HOME}/deploy_artifacts/argo-celery.service" /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable --now argo-celery.service
  echo "    argo-celery attivo."
fi

if [[ "$WANT_WEB" -eq 1 ]]; then
  echo "    Frontend Next.js: build + servizio..."
  if ! command -v npm >/dev/null 2>&1; then
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
    apt-get install -y -qq nodejs
  fi
  pushd "${ARGO_HOME}/web-next" >/dev/null
  sudo -u "$ARGO_USER" npm ci
  sudo -u "$ARGO_USER" npm run build
  popd >/dev/null
  cp "${ARGO_HOME}/deploy_artifacts/argo-web-next.service" /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable --now argo-web-next.service
  echo "    argo-web-next attivo su :3000 (proxya /api verso :7655)."
fi

echo "[6/6] Ricorda di aggiornare ${ARGO_HOME}/.env con le righe di dotenv.stack.template,"
echo "      poi: sudo systemctl restart argo-osint  (e argo-celery se attivo)."
echo "Done."
