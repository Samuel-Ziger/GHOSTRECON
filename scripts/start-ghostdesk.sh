#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT/GhostDesk/frontend"
export GHOSTDESK_PORT="${GHOSTDESK_PORT:-5173}"

if [ ! -d node_modules ]; then
  echo "[GhostDesk] node_modules em falta — a correr npm install..."
  npm install
fi

exec npx vite --host 127.0.0.1 --port "$GHOSTDESK_PORT"
