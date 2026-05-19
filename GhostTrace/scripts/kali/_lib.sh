#!/usr/bin/env bash
# Funções partilhadas — scripts Kali/Linux

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
RUN_DIR="$ROOT/.ghosttrace/run"
LOG_DIR="$ROOT/.ghosttrace/logs"
API_PORT="${GHOSTTRACE_API_PORT:-8787}"
WEB_PORT="${GHOSTTRACE_WEB_PORT:-3000}"
API_HOST="${GHOSTTRACE_API_HOST:-0.0.0.0}"
WEB_HOST="${GHOSTTRACE_WEB_HOST:-0.0.0.0}"
API_URL="http://127.0.0.1:${API_PORT}"
VENV="$ROOT/backend/.venv"

mkdir -p "$RUN_DIR" "$LOG_DIR"

log() { echo -e "\033[1;32m[ghosttrace]\033[0m $*"; }
warn() { echo -e "\033[1;33m[ghosttrace]\033[0m $*"; }
err() { echo -e "\033[1;31m[ghosttrace]\033[0m $*" >&2; }

ensure_env() {
  local env_file="$ROOT/.env.local"
  if [[ ! -f "$env_file" ]]; then
    if [[ -f "$ROOT/.env.example" ]]; then
      cp "$ROOT/.env.example" "$env_file"
    else
      cat >"$env_file" <<EOF
NEXT_PUBLIC_APP_NAME=GhostTrace
NEXT_PUBLIC_APP_VERSION=0.1.0
NEXT_PUBLIC_API_URL=http://127.0.0.1:${API_PORT}
EOF
    fi
    warn ".env.local criado"
  fi
  if grep -q "NEXT_PUBLIC_API_URL=http://localhost:8000" "$env_file" 2>/dev/null; then
    sed -i "s|http://localhost:8000|http://127.0.0.1:${API_PORT}|g" "$env_file"
  fi
}

activate_venv() {
  if [[ ! -d "$VENV" ]]; then
    err "Venv não encontrado. Rode: ./scripts/kali/install.sh"
    exit 1
  fi
  # shellcheck disable=SC1091
  source "$VENV/bin/activate"
}

port_pid() {
  local port=$1
  ss -tlnp 2>/dev/null | grep ":${port} " | sed -n 's/.*pid=\([0-9]*\).*/\1/p' | head -1
}

wait_api() {
  local i
  for i in $(seq 1 40); do
    if curl -sf "${API_URL}/health" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.5
  done
  return 1
}

lan_ip() {
  hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1"
}
