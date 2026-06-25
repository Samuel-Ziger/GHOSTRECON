#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NODE_BIN="${NODE_BIN:-$(command -v node || true)}"
NPM_BIN="${NPM_BIN:-$(command -v npm || true)}"
SERVER_URL="${GHOSTRECON_SERVER:-http://127.0.0.1:3847}"
STATE_DIR="${GHOSTWATCH_STATE_DIR:-$ROOT/.ghostrecon-ghostwatch}"
UNIT_PREFIX="${GHOSTWATCH_UNIT_PREFIX:-ghostrecon}"
TIMER_TZ="${GHOSTWATCH_TIMER_TZ:-America/Sao_Paulo}"

usage() {
  cat <<EOF
setup-ghostwatch-vps.sh

Configura GhostWatch em uma VPS com systemd timer as 06:00 e 18:00.

Env/args principais:
  O script reaproveita o .env da raiz do GHOSTRECON.
  Use GHOSTRECON_WEBHOOK_URL no .env para o Discord.
  GHOSTRECON_SERVER                      Default: http://127.0.0.1:3847.
  GHOSTWATCH_TIMER_TZ                    Default: America/Sao_Paulo.
  NODE_BIN / NPM_BIN                     Overrides de binarios.

Uso:
  bash scripts/setup-ghostwatch-vps.sh
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
  if command -v apt-get >/dev/null 2>&1; then
    echo "[ghostwatch-setup] node nao encontrado; instalando nodejs npm via apt-get..."
    if [[ "$(id -u)" -eq 0 ]]; then
      apt-get update
      apt-get install -y nodejs npm
    else
      sudo apt-get update
      sudo apt-get install -y nodejs npm
    fi
    NODE_BIN="$(command -v node || true)"
    NPM_BIN="$(command -v npm || true)"
  fi
fi

if [[ -z "$NODE_BIN" ]]; then
  echo "[ghostwatch-setup] node nao encontrado no PATH" >&2
  exit 2
fi

if [[ -z "$NPM_BIN" ]]; then
  if command -v apt-get >/dev/null 2>&1; then
    echo "[ghostwatch-setup] npm nao encontrado; instalando npm via apt-get..."
    if [[ "$(id -u)" -eq 0 ]]; then
      apt-get update
      apt-get install -y npm
    else
      sudo apt-get update
      sudo apt-get install -y npm
    fi
    NPM_BIN="$(command -v npm || true)"
  fi
fi

if [[ -z "$NPM_BIN" ]]; then
  echo "[ghostwatch-setup] npm nao encontrado no PATH" >&2
  exit 2
fi

if [[ "$(id -u)" -eq 0 ]]; then
  SUDO=()
else
  SUDO=(sudo)
fi

mkdir -p "$STATE_DIR"

if [[ ! -d "$ROOT/node_modules" ]]; then
  echo "[ghostwatch-setup] instalando dependencias Node..."
  (cd "$ROOT" && "$NPM_BIN" ci)
fi

if [[ -d /usr/local/bin ]]; then
  "${SUDO[@]}" ln -sf "$ROOT/bin/ghostrecon.mjs" /usr/local/bin/ghostrecon
  "${SUDO[@]}" chmod +x "$ROOT/bin/ghostrecon.mjs"
  echo "[ghostwatch-setup] comando global: /usr/local/bin/ghostrecon"
fi

ENV_FILE="$ROOT/.env"
echo "[ghostwatch-setup] usando env do GHOSTRECON: $ENV_FILE"

API_SERVICE="/etc/systemd/system/${UNIT_PREFIX}-api.service"
RUN_SERVICE="/etc/systemd/system/${UNIT_PREFIX}-ghostwatch.service"
TIMER_UNIT="/etc/systemd/system/${UNIT_PREFIX}-ghostwatch.timer"

"${SUDO[@]}" tee "$API_SERVICE" >/dev/null <<EOF
[Unit]
Description=GHOSTRECON API
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$ROOT
EnvironmentFile=-$ENV_FILE
Environment=GHOSTRECON_NAVIGATOR_MODE=0
Environment=GHOSTRECON_TOR_REQUIRED=0
Environment=GHOSTRECON_TOR_STRICT=0
ExecStart=$NODE_BIN server/index.js
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

"${SUDO[@]}" tee "$RUN_SERVICE" >/dev/null <<EOF
[Unit]
Description=GhostWatch sweep
After=${UNIT_PREFIX}-api.service network-online.target
Wants=${UNIT_PREFIX}-api.service network-online.target

[Service]
Type=oneshot
WorkingDirectory=$ROOT
EnvironmentFile=-$ENV_FILE
Environment=GHOSTRECON_NAVIGATOR_MODE=0
Environment=GHOSTRECON_TOR_REQUIRED=0
Environment=GHOSTRECON_TOR_STRICT=0
Environment=GHOSTWATCH_STATE_DIR=$STATE_DIR
ExecStart=/usr/bin/env bash -lc '"$NODE_BIN" bin/ghostrecon.mjs ghostwatch run --once --server "\${GHOSTRECON_SERVER:-$SERVER_URL}" --state-dir "\${GHOSTWATCH_STATE_DIR:-$STATE_DIR}" --start-server'
EOF

"${SUDO[@]}" tee "$TIMER_UNIT" >/dev/null <<EOF
[Unit]
Description=Run GhostWatch at 06:00 and 18:00

[Timer]
OnCalendar=*-*-* 06,18:00:00 $TIMER_TZ
Persistent=true
Unit=${UNIT_PREFIX}-ghostwatch.service

[Install]
WantedBy=timers.target
EOF

"${SUDO[@]}" systemctl daemon-reload
"${SUDO[@]}" systemctl enable --now "${UNIT_PREFIX}-api.service"
"${SUDO[@]}" systemctl enable --now "${UNIT_PREFIX}-ghostwatch.timer"

echo "[ghostwatch-setup] pronto"
echo "  API:       systemctl status ${UNIT_PREFIX}-api.service"
echo "  Timer:     systemctl list-timers | grep ${UNIT_PREFIX}-ghostwatch"
echo "  Horario:   06:00 e 18:00 ($TIMER_TZ)"
echo "  Run agora: sudo systemctl start ${UNIT_PREFIX}-ghostwatch.service"
echo "  Logs:      journalctl -xeu ${UNIT_PREFIX}-ghostwatch.service --no-pager -n 120"
echo "  Env:       $ENV_FILE"
