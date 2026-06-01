#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GHOST_START_SCRIPT="$ROOT_DIR/ghost-local-v5/ghost-local/start.sh"
GHOST_PORT="${GHOST_PORT:-8000}"
GHOST_HEALTH_URL="${GHOST_HEALTH_URL:-http://127.0.0.1:${GHOST_PORT}/health}"
GHOST_LOG_FILE="$ROOT_DIR/ghost-local-v5/ghost-local/ghost.log"

GHOSTMAP_START_SCRIPT="$ROOT_DIR/scripts/start-ghostmap.sh"
GHOSTMAP_PORT="${GHOSTMAP_PORT:-3020}"
GHOSTMAP_HEALTH_URL="${GHOSTMAP_HEALTH_URL:-http://127.0.0.1:${GHOSTMAP_PORT}/ghostmap}"
GHOSTMAP_LOG_FILE="$ROOT_DIR/ghostmap/frontend/ghostmap.log"

GHOSTDESK_START_SCRIPT="$ROOT_DIR/scripts/start-ghostdesk.sh"
GHOSTDESK_PORT="${GHOSTDESK_PORT:-5173}"
GHOSTDESK_HEALTH_URL="${GHOSTDESK_HEALTH_URL:-http://127.0.0.1:${GHOSTDESK_PORT}/}"
GHOSTDESK_LOG_FILE="$ROOT_DIR/GhostDesk/frontend/ghostdesk.log"

log() { printf '[STACK] %s\n' "$*"; }
warn() { printf '[STACK][WARN] %s\n' "$*" >&2; }

port_in_use() {
  local port="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -tln 2>/dev/null | grep -q ":${port} "
  else
    return 1
  fi
}

start_ghost_if_needed() {
  if [ ! -f "$GHOST_START_SCRIPT" ]; then
    warn "script do GHOST nao encontrado em $GHOST_START_SCRIPT"
    return 0
  fi

  if port_in_use "$GHOST_PORT"; then
    log "GHOST ja esta em execucao na porta ${GHOST_PORT}"
    return 0
  fi

  log "A iniciar GHOST IA local na porta ${GHOST_PORT}..."
  mkdir -p "$(dirname "$GHOST_LOG_FILE")"
  (
    cd "$ROOT_DIR/ghost-local-v5/ghost-local"
    GHOST_START_HEXSTRIKE="${GHOST_START_HEXSTRIKE:-0}" PORT="$GHOST_PORT" \
      nohup bash "$GHOST_START_SCRIPT" >>"$GHOST_LOG_FILE" 2>&1 &
  )

  for _ in $(seq 1 25); do
    if curl -fsS "$GHOST_HEALTH_URL" >/dev/null 2>&1; then
      log "GHOST online em $GHOST_HEALTH_URL"
      return 0
    fi
    sleep 1
  done
  warn "GHOST nao respondeu no tempo esperado; verifica $GHOST_LOG_FILE"
}

start_ghostmap_if_needed() {
  if [ ! -f "$GHOSTMAP_START_SCRIPT" ]; then
    warn "script do GhostMap nao encontrado em $GHOSTMAP_START_SCRIPT"
    return 0
  fi

  if port_in_use "$GHOSTMAP_PORT"; then
    log "GhostMap ja esta em execucao na porta ${GHOSTMAP_PORT}"
    return 0
  fi

  log "A iniciar GhostMap (Next.js) na porta ${GHOSTMAP_PORT}..."
  mkdir -p "$(dirname "$GHOSTMAP_LOG_FILE")"
  (
    nohup bash "$GHOSTMAP_START_SCRIPT" >>"$GHOSTMAP_LOG_FILE" 2>&1 &
  )

  for _ in $(seq 1 45); do
    if curl -fsS "$GHOSTMAP_HEALTH_URL" >/dev/null 2>&1; then
      log "GhostMap online em $GHOSTMAP_HEALTH_URL (proxy /ghostmap na API)"
      return 0
    fi
    sleep 1
  done
  warn "GhostMap nao respondeu no tempo esperado; verifica $GHOSTMAP_LOG_FILE"
}

start_ghostdesk_if_needed() {
  if [ ! -f "$GHOSTDESK_START_SCRIPT" ]; then
    warn "script do GhostDesk nao encontrado em $GHOSTDESK_START_SCRIPT"
    return 0
  fi

  if port_in_use "$GHOSTDESK_PORT"; then
    log "GhostDesk ja esta em execucao na porta ${GHOSTDESK_PORT}"
    return 0
  fi

  log "A iniciar GhostDesk (Vite) na porta ${GHOSTDESK_PORT}..."
  mkdir -p "$(dirname "$GHOSTDESK_LOG_FILE")"
  (
    nohup bash "$GHOSTDESK_START_SCRIPT" >>"$GHOSTDESK_LOG_FILE" 2>&1 &
  )

  for _ in $(seq 1 30); do
    if curl -fsS "$GHOSTDESK_HEALTH_URL" >/dev/null 2>&1; then
      log "GhostDesk online em $GHOSTDESK_HEALTH_URL (proxy /api -> :3847)"
      return 0
    fi
    sleep 1
  done
  warn "GhostDesk nao respondeu no tempo esperado; verifica $GHOSTDESK_LOG_FILE"
}

start_ghost_if_needed
start_ghostmap_if_needed
start_ghostdesk_if_needed
log "A iniciar API GHOSTRECON (Node)..."
exec node "$ROOT_DIR/server/index.js"
