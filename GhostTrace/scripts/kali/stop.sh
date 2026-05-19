#!/usr/bin/env bash
# GhostTrace — parar serviços (Kali)
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_lib.sh"

stop_pid_file() {
  local name=$1 file=$2
  if [[ -f "$file" ]]; then
    local pid
    pid=$(cat "$file")
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      sleep 1
      kill -9 "$pid" 2>/dev/null || true
      log "$name parado (PID $pid)"
    fi
    rm -f "$file"
  fi
}

stop_pid_file "API" "$RUN_DIR/api.pid"
stop_pid_file "Web" "$RUN_DIR/web.pid"

# filhos órfãos (next / uvicorn)
pkill -f "uvicorn app.main:app" 2>/dev/null || true
pkill -f "next dev" 2>/dev/null || true

log "Serviços encerrados."
