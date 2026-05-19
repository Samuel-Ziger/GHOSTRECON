#!/usr/bin/env bash
# GhostTrace — arranque em background (Kali) — fica rodando após fechar o terminal
# Uso: ./scripts/kali/start.sh

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_lib.sh
source "$SCRIPT_DIR/_lib.sh"

cd "$ROOT"
ensure_env

API_PID_FILE="$RUN_DIR/api.pid"
WEB_PID_FILE="$RUN_DIR/web.pid"

if [[ -f "$API_PID_FILE" ]] && kill -0 "$(cat "$API_PID_FILE")" 2>/dev/null; then
  warn "API já está rodando (PID $(cat "$API_PID_FILE")). Use ./scripts/kali/stop.sh primeiro."
  exit 1
fi

if [[ ! -d "$VENV" ]]; then
  err "Rode o instalador: ./scripts/kali/install.sh"
  exit 1
fi

existing_api=$(port_pid "$API_PORT" || true)
if [[ -n "${existing_api:-}" ]]; then
  warn "Porta $API_PORT ocupada (PID $existing_api). Liberando..."
  kill "$existing_api" 2>/dev/null || true
  sleep 1
fi

log "Iniciando API em ${API_HOST}:${API_PORT}..."
(
  cd "$ROOT/backend"
  # shellcheck disable=SC1091
  source "$VENV/bin/activate"
  nohup python -m uvicorn app.main:app --host "$API_HOST" --port "$API_PORT" \
    >>"$LOG_DIR/api.log" 2>&1 &
  echo $! >"$API_PID_FILE"
)

log "Aguardando API..."
if ! wait_api; then
  err "API não subiu. Ver: $LOG_DIR/api.log"
  exit 1
fi
log "API online"

log "Iniciando frontend em ${WEB_HOST}:${WEB_PORT}..."
(
  cd "$ROOT"
  nohup npm run dev -- --hostname "$WEB_HOST" --port "$WEB_PORT" \
    >>"$LOG_DIR/web.log" 2>&1 &
  echo $! >"$WEB_PID_FILE"
)

sleep 4
LAN=$(lan_ip)

echo ""
log "GhostTrace rodando em background"
echo "  Web (local):  http://127.0.0.1:${WEB_PORT}"
echo "  Web (LAN):    http://${LAN}:${WEB_PORT}"
echo "  API:          http://127.0.0.1:${API_PORT}/health"
echo "  Logs:         $LOG_DIR/"
echo "  Parar:        ./scripts/kali/stop.sh"
echo "  Status:       ./scripts/kali/status.sh"
echo ""
