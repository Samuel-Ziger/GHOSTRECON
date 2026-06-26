#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NODE_BIN="${NODE_BIN:-$(command -v node || true)}"
ENV_FILE="$ROOT/.env"
STATE_DIR="${GHOSTCOMMAND_STATE_DIR:-$ROOT/.ghostcommand}"
UNIT_PREFIX="${GHOSTCOMMAND_UNIT_PREFIX:-ghostcommand}"
TIMER_TZ="${GHOSTCOMMAND_TIMER_TZ:-America/Sao_Paulo}"
OPEN_TIME="${GHOSTCOMMAND_OPEN_TIME:-08:00:00}"
ALLOWED_IP="${GHOSTCOMMAND_ALLOWED_IP:-162.243.54.185}"

usage() {
  cat <<EOF
setup-ghostcommand-vps.sh

Configura o gate do GhostCommand para abrir automaticamente as $OPEN_TIME ($TIMER_TZ).

Env principais:
  GHOSTCOMMAND_ALLOWED_IP       Default: 162.243.54.185
  GHOSTCOMMAND_OPEN_TIME        Default: 08:00:00
  GHOSTCOMMAND_TIMER_TZ         Default: America/Sao_Paulo
  GHOSTCOMMAND_STATE_DIR        Default: <repo>/.ghostcommand

Uso:
  bash scripts/setup-ghostcommand-vps.sh
EOF
}

for arg in "$@"; do
  case "$arg" in
    -h|--help)
      usage
      exit 0
      ;;
  esac
done

if [[ -z "$NODE_BIN" ]]; then
  echo "[ghostcommand-setup] node nao encontrado no PATH" >&2
  exit 2
fi

if [[ "$(id -u)" -eq 0 ]]; then
  SUDO=()
else
  SUDO=(sudo)
fi

env_value() {
  local key="$1"
  if [[ ! -f "$ENV_FILE" ]]; then
    return 0
  fi
  grep -E "^${key}=" "$ENV_FILE" 2>/dev/null | tail -n1 | cut -d= -f2-
}

append_env_if_missing() {
  local key="$1"
  local value="$2"
  touch "$ENV_FILE"
  if ! grep -Eq "^${key}=" "$ENV_FILE"; then
    printf '%s=%s\n' "$key" "$value" >>"$ENV_FILE"
  fi
}

generate_key() {
  "$NODE_BIN" -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
}

mkdir -p "$STATE_DIR"
if [[ ! -f "$ENV_FILE" ]]; then
  touch "$ENV_FILE"
  chmod 600 "$ENV_FILE" || true
  echo "[ghostcommand-setup] .env criado em $ENV_FILE"
fi

if [[ -z "$(env_value GHOSTCOMMAND_API_KEY)" ]]; then
  append_env_if_missing "GHOSTCOMMAND_API_KEY" "$(generate_key)"
  echo "[ghostcommand-setup] GHOSTCOMMAND_API_KEY gerado no .env"
fi
append_env_if_missing "GHOSTCOMMAND_ALLOWED_IP" "$ALLOWED_IP"
append_env_if_missing "GHOSTCOMMAND_STATE_DIR" "$STATE_DIR"
append_env_if_missing "GHOSTCOMMAND_TIMER_TZ" "$TIMER_TZ"
append_env_if_missing "GHOSTCOMMAND_OPEN_TIME" "$OPEN_TIME"

OPEN_SERVICE="/etc/systemd/system/${UNIT_PREFIX}-open.service"
OPEN_TIMER="/etc/systemd/system/${UNIT_PREFIX}-open.timer"

"${SUDO[@]}" tee "$OPEN_SERVICE" >/dev/null <<EOF
[Unit]
Description=Open GhostCommand mobile gate
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
WorkingDirectory=$ROOT
EnvironmentFile=-$ENV_FILE
ExecStart=$NODE_BIN server/scripts/ghostcommand-gate.mjs open timer
EOF

"${SUDO[@]}" tee "$OPEN_TIMER" >/dev/null <<EOF
[Unit]
Description=Open GhostCommand mobile gate daily

[Timer]
OnCalendar=*-*-* $OPEN_TIME $TIMER_TZ
Persistent=true
Unit=${UNIT_PREFIX}-open.service

[Install]
WantedBy=timers.target
EOF

"${SUDO[@]}" systemctl daemon-reload
"${SUDO[@]}" systemctl enable --now "${UNIT_PREFIX}-open.timer"

echo "[ghostcommand-setup] pronto"
echo "  Gate:      $NODE_BIN server/scripts/ghostcommand-gate.mjs status"
echo "  Abrir:     $NODE_BIN server/scripts/ghostcommand-gate.mjs open manual"
echo "  Fechar:    $NODE_BIN server/scripts/ghostcommand-gate.mjs close manual"
echo "  Timer:     systemctl list-timers | grep ${UNIT_PREFIX}-open"
echo "  Horario:   $OPEN_TIME ($TIMER_TZ)"
echo "  IP:        $ALLOWED_IP"
echo "  Token:     grep '^GHOSTCOMMAND_API_KEY=' $ENV_FILE"
