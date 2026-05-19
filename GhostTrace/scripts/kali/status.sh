#!/usr/bin/env bash
# GhostTrace — status dos serviços (Kali)
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_lib.sh"

check() {
  local name=$1 file=$2 url=$3
  if [[ -f "$file" ]] && kill -0 "$(cat "$file")" 2>/dev/null; then
    echo "  $name: RODANDO (PID $(cat "$file"))"
    if [[ -n "$url" ]] && curl -sf "$url" >/dev/null 2>&1; then
      echo "         HTTP OK — $url"
    fi
  else
    echo "  $name: PARADO"
  fi
}

echo ""
echo "  ghosttrace — status"
check "API" "$RUN_DIR/api.pid" "${API_URL}/health"
check "Web" "$RUN_DIR/web.pid" "http://127.0.0.1:${WEB_PORT}"
echo ""
