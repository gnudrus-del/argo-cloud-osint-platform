#!/usr/bin/env bash
# Wrapper Bash di verify-live.ps1.
set -u
HOST="${HOST:-argo.example.com}"
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
ARGS=( -ExecutionPolicy Bypass -File "${SCRIPT_DIR}/verify-live.ps1" -Host "$HOST" "$@" )
exec powershell "${ARGS[@]}"
