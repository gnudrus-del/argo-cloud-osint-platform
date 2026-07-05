#!/usr/bin/env bash
# Wrapper Bash di deploy.ps1: serve a far lanciare il deploy direttamente
# dall'assistente (tool Bash) usando la chiave SSH gia' configurata sul PC,
# senza che l'utente debba aprire una PowerShell.
#
# Default host: argo-cloud.duckdns.org. Override con: HOST=<altro> ./deploy.sh
# Flag passa-through: ./deploy.sh --dry-run   ./deploy.sh --force
#
# Niente credenziali/IP hardcoded: l'host arriva da $HOST o dal default
# pubblico documentato nello spec.

set -u
HOST="${HOST:-argo-cloud.duckdns.org}"
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

ARGS=( -ExecutionPolicy Bypass -File "${SCRIPT_DIR}/deploy.ps1" -Host "$HOST" )
for a in "$@"; do
  case "$a" in
    --dry-run|-DryRun|-dryrun) ARGS+=( -DryRun ) ;;
    *) ARGS+=( "$a" ) ;;
  esac
done

# Su Windows-git-bash 'powershell' e' nel PATH; su Linux/macOS lo script non
# si applica (il deploy reale di Argo e' progettato da Win).
if ! command -v powershell >/dev/null 2>&1; then
  echo "ERR powershell non trovato nel PATH. Sei su Windows / Git Bash?" >&2
  exit 127
fi

echo "==> wrapper: powershell ${ARGS[*]}"
exec powershell "${ARGS[@]}"
