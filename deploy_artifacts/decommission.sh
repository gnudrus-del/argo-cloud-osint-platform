#!/usr/bin/env bash
# Argo — decommissiona i componenti resi ridondanti dallo stack nativo.
# BACKUP-FIRST: non cancella dati irreversibilmente. I volumi Docker restano
# (niente -v), i file vengono archiviati, l'.env viene salvato prima di editarlo.
#
# Uso (item multipli):
#   sudo bash decommission.sh flowsint          # spegne FlowSINT (6 container)
#   sudo bash decommission.sh sqlite            # archivia gufo.sqlite3 (dopo migrazione a PG)
#   sudo bash decommission.sh tools             # disabilita nell'.env i *_CMD ora nativi
#   sudo bash decommission.sh flowsint sqlite tools
#
# ⚠ Esegui SOLO dopo aver verificato che lo stack nativo risponda (vedi REPLACEMENTS.md §Ordine).
set -euo pipefail

ARGO_HOME="/opt/argo-osint"
ARGO_USER="ubuntu"
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="${ARGO_HOME}/decommission-backup-${STAMP}"
FLOWSINT_DIR="${FLOWSINT_DIR:-/home/${ARGO_USER}/flowsint}"

# *_CMD resi ridondanti dai connettori nativi (sola disabilitazione .env).
REPLACED_CMDS=(
  PHONEINFOGA_CMD PHUNTER_CMD DNSTWIST_CMD DNSX_CMD FFUF_CMD DIRSEARCH_CMD
  FEROXBUSTER_CMD ARJUN_CMD SUBFINDER_CMD AMASS_CMD FIERCE_CMD DNSENUM_CMD
  NAABU_CMD SECRETFINDER_CMD WAYBACKURLS_CMD GAU_CMD HAKRAWLER_CMD LINKFINDER_CMD
  WHATWEB_CMD WAFW00F_CMD TESTSSL_CMD EXIFTOOL_CMD
)

if [[ $# -eq 0 ]]; then
  echo "Uso: sudo bash decommission.sh [flowsint] [sqlite] [tools]" >&2
  exit 2
fi

mkdir -p "$BACKUP_DIR"
echo "Backup in: $BACKUP_DIR"

for item in "$@"; do
  case "$item" in
    flowsint)
      echo "[flowsint] Spengo lo stack Docker (volumi preservati)..."
      if [[ -f "${FLOWSINT_DIR}/docker-compose.yml" ]]; then
        (cd "$FLOWSINT_DIR" && docker compose down) || echo "  (compose down non riuscito, controlla manualmente)"
        tar -czf "${BACKUP_DIR}/flowsint-config.tgz" -C "$FLOWSINT_DIR" . 2>/dev/null || true
        echo "  FlowSINT fermo. Config archiviata. Per rimuovere anche i volumi (IRREVERSIBILE):"
        echo "     cd $FLOWSINT_DIR && docker compose down -v"
      else
        echo "  compose FlowSINT non trovato in $FLOWSINT_DIR (FLOWSINT_DIR=... per override)."
      fi
      echo "  Suggerito: rimuovi il connettore-bridge disabilitandolo o togliendolo dal registry."
      ;;
    sqlite)
      DB="${ARGO_HOME}/web_jobs/gufo.sqlite3"
      if grep -q '^DATABASE_URL=postgres' "${ARGO_HOME}/.env" 2>/dev/null; then
        if [[ -f "$DB" ]]; then
          cp "$DB" "${BACKUP_DIR}/gufo.sqlite3"
          mv "$DB" "${DB}.archived-${STAMP}"
          echo "[sqlite] Archiviato $DB (Postgres attivo). Backup in $BACKUP_DIR."
        else
          echo "[sqlite] Nessun gufo.sqlite3 da archiviare."
        fi
      else
        echo "[sqlite] SALTATO: DATABASE_URL Postgres non impostata nell'.env."
        echo "         Migra prima: python -m osint_bot.migrate_sqlite_to_postgres"
      fi
      ;;
    tools)
      ENV="${ARGO_HOME}/.env"
      if [[ -f "$ENV" ]]; then
        cp "$ENV" "${BACKUP_DIR}/.env"
        for cmd in "${REPLACED_CMDS[@]}"; do
          # commenta la riga <CMD>=... se valorizzata (idempotente)
          sed -i -E "s|^(${cmd}=.+)$|# [nativo] \1|" "$ENV" || true
        done
        echo "[tools] Disabilitati nell'.env i *_CMD ora nativi (backup in $BACKUP_DIR)."
        echo "        I binari restano su disco: rimuovili a mano se vuoi liberare spazio."
      else
        echo "[tools] .env non trovato in $ARGO_HOME."
      fi
      ;;
    *)
      echo "Item sconosciuto: $item (usa: flowsint | sqlite | tools)" >&2
      ;;
  esac
done

echo "Fatto. Riavvia i servizi: sudo systemctl restart argo-osint argo-celery 2>/dev/null || true"
