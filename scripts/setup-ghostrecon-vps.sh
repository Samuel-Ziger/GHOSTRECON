#!/usr/bin/env bash
# setup-ghostrecon-vps.sh — bootstrap completo da sentinela VPS (GhostWatch).
#
# Configura .env VPS, domains.txt, deps, checks de bins e systemd:
#   API loopback + timer 01:00 / 10:00 (America/Sao_Paulo) + flock.
#
# Uso:
#   bash scripts/setup-ghostrecon-vps.sh
#   bash scripts/setup-ghostrecon-vps.sh --dry-run
#   bash scripts/setup-ghostrecon-vps.sh --skip-deps --skip-systemd
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NODE_BIN="${NODE_BIN:-$(command -v node || true)}"
NPM_BIN="${NPM_BIN:-$(command -v npm || true)}"
SERVER_URL="${GHOSTRECON_SERVER:-http://127.0.0.1:3847}"
STATE_DIR="${GHOSTWATCH_STATE_DIR:-$ROOT/.ghostrecon-ghostwatch}"
DOMAINS_FILE="${GHOSTWATCH_DOMAINS_FILE:-$ROOT/domains.txt}"
UNIT_PREFIX="${GHOSTWATCH_UNIT_PREFIX:-ghostrecon}"
TIMER_TZ="${GHOSTWATCH_TIMER_TZ:-America/Sao_Paulo}"
LOCK_FILE="${GHOSTWATCH_LOCK_FILE:-/run/ghostrecon-ghostwatch.lock}"
ENV_FILE="$ROOT/.env"
DRY_RUN=0
SKIP_DEPS=0
SKIP_SYSTEMD=0
SKIP_NPM_CI=0

usage() {
  cat <<EOF
setup-ghostrecon-vps.sh

Bootstrap da sentinela VPS GHOSTRECON / GhostWatch.

  - patch idempotente do .env (preserva secrets)
  - chmod 600 .env
  - domains.txt template
  - npm ci (se necessario)
  - symlink /usr/local/bin/ghostrecon
  - systemd: API + timer 01:00 e 10:00 ($TIMER_TZ) + flock
  - validacao final (webhook, trusted, CVE, engines)

Flags:
  --dry-run         Mostra o que faria no .env / units sem gravar systemd
  --skip-deps       Nao instala node_modules / nao cria symlink
  --skip-systemd    So prepara .env + domains (sem units)
  --skip-npm-ci     Nao roda npm ci mesmo sem node_modules
  -h|--help         Esta ajuda

Env:
  GHOSTWATCH_DOMAINS_FILE   Default: \$ROOT/domains.txt
  GHOSTWATCH_STATE_DIR      Default: \$ROOT/.ghostrecon-ghostwatch
  GHOSTWATCH_TIMER_TZ       Default: America/Sao_Paulo
  GHOSTWATCH_LOCK_FILE      Default: /run/ghostrecon-ghostwatch.lock
EOF
}

for arg in "$@"; do
  case "$arg" in
    -h|--help) usage; exit 0 ;;
    --dry-run) DRY_RUN=1 ;;
    --skip-deps) SKIP_DEPS=1 ;;
    --skip-systemd) SKIP_SYSTEMD=1 ;;
    --skip-npm-ci) SKIP_NPM_CI=1 ;;
    *)
      echo "[vps-setup] flag desconhecida: $arg" >&2
      usage >&2
      exit 2
      ;;
  esac
done

log() { echo "[vps-setup] $*"; }
warn() { echo "[vps-setup][WARN] $*" >&2; }

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
  if [[ "$DRY_RUN" -eq 1 ]]; then
    if ! grep -Eq "^${key}=" "$ENV_FILE" 2>/dev/null; then
      log "dry-run: append ${key}=${value}"
    fi
    return 0
  fi
  touch "$ENV_FILE"
  if ! grep -Eq "^${key}=" "$ENV_FILE"; then
    printf '%s=%s\n' "$key" "$value" >>"$ENV_FILE"
    log "env + ${key}"
  fi
}

set_env_value() {
  local key="$1"
  local value="$2"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    local cur
    cur="$(env_value "$key")"
    if [[ "$cur" != "$value" ]]; then
      log "dry-run: set ${key}=${value} (antes=${cur:-<ausente>})"
    fi
    return 0
  fi
  local tmp
  touch "$ENV_FILE"
  tmp="$(mktemp)"
  grep -Ev "^${key}=" "$ENV_FILE" >"$tmp" || true
  printf '%s=%s\n' "$key" "$value" >>"$tmp"
  mv "$tmp" "$ENV_FILE"
  log "env = ${key}"
}

generate_api_key() {
  "$NODE_BIN" -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
}

first_auth_api_key() {
  local preferred
  preferred="$(env_value AUTH_API_KEYS | tr '|' '\n' | awk -F: '$2 == "red" || $2 == "admin" { print $1; exit }')"
  if [[ -n "$preferred" ]]; then
    printf '%s' "$preferred"
    return 0
  fi
  env_value AUTH_API_KEYS | tr '|' '\n' | awk -F: 'NF >= 2 { print $1; exit }'
}

auth_api_keys_contains() {
  local key="$1"
  env_value AUTH_API_KEYS | tr '|' '\n' | awk -F: -v k="$key" '$1 == k { found=1 } END { exit found ? 0 : 1 }'
}

check_node_major() {
  local major
  major="$("$NODE_BIN" -p "process.versions.node.split('.')[0]" 2>/dev/null || echo 0)"
  if [[ "${major:-0}" -lt 20 ]]; then
    echo "[vps-setup] Node >=20 necessario (atual: $("$NODE_BIN" -v 2>/dev/null || echo ?))" >&2
    exit 2
  fi
}

if [[ -z "$NODE_BIN" ]]; then
  if command -v apt-get >/dev/null 2>&1; then
    log "node nao encontrado; instalando nodejs npm via apt-get..."
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
  echo "[vps-setup] node nao encontrado no PATH" >&2
  exit 2
fi
check_node_major

if [[ -z "$NPM_BIN" ]]; then
  if command -v apt-get >/dev/null 2>&1; then
    log "npm nao encontrado; instalando npm via apt-get..."
    if [[ "$(id -u)" -eq 0 ]]; then
      apt-get install -y npm
    else
      sudo apt-get install -y npm
    fi
    NPM_BIN="$(command -v npm || true)"
  fi
fi

if [[ -z "$NPM_BIN" ]]; then
  echo "[vps-setup] npm nao encontrado no PATH" >&2
  exit 2
fi

if ! command -v python3 >/dev/null 2>&1; then
  warn "python3 ausente — coletor CVE (cve:collect) nao vai funcionar ate instalar"
fi

if [[ "$(id -u)" -eq 0 ]]; then
  SUDO=()
else
  SUDO=(sudo)
fi

mkdir -p "$STATE_DIR"

if [[ "$SKIP_DEPS" -eq 0 ]]; then
  if [[ ! -d "$ROOT/node_modules" && "$SKIP_NPM_CI" -eq 0 ]]; then
    log "instalando dependencias Node (npm ci)..."
    if [[ "$DRY_RUN" -eq 0 ]]; then
      (cd "$ROOT" && "$NPM_BIN" ci)
    else
      log "dry-run: npm ci"
    fi
  fi
  if [[ -d /usr/local/bin && "$DRY_RUN" -eq 0 ]]; then
    "${SUDO[@]}" ln -sf "$ROOT/bin/ghostrecon.mjs" /usr/local/bin/ghostrecon
    "${SUDO[@]}" chmod +x "$ROOT/bin/ghostrecon.mjs"
    log "comando global: /usr/local/bin/ghostrecon"
  fi
fi

if [[ ! -f "$ENV_FILE" ]]; then
  if [[ "$DRY_RUN" -eq 0 ]]; then
    touch "$ENV_FILE"
    chmod 600 "$ENV_FILE" || true
  fi
  log ".env criado em $ENV_FILE"
fi

# Auth bootstrap (preserva chave existente)
GHOSTWATCH_API_KEY="$(env_value GHOSTRECON_API_KEY)"
if [[ -z "$GHOSTWATCH_API_KEY" ]]; then
  GHOSTWATCH_API_KEY="$(first_auth_api_key)"
fi
if [[ -z "$GHOSTWATCH_API_KEY" ]]; then
  GHOSTWATCH_API_KEY="$(generate_api_key)"
  log "chave API local gerada para GhostWatch"
fi
append_env_if_missing "GHOSTRECON_API_KEY" "$GHOSTWATCH_API_KEY"
if ! auth_api_keys_contains "$GHOSTWATCH_API_KEY"; then
  if [[ -n "$(env_value AUTH_API_KEYS)" ]]; then
    set_env_value "AUTH_API_KEYS" "$(env_value AUTH_API_KEYS)|${GHOSTWATCH_API_KEY}:red:vps-ghostwatch"
  else
    append_env_if_missing "AUTH_API_KEYS" "${GHOSTWATCH_API_KEY}:red:vps-ghostwatch"
  fi
fi
append_env_if_missing "AUTH_MODE" "apikey"

# Bloco VPS sentinela (idempotente: set força valores operacionais)
set_env_value "HOST" "127.0.0.1"
set_env_value "GHOSTWATCH_TRUSTED_OPERATOR" "1"
set_env_value "GHOSTWATCH_CONFIRM_ACTIVE" "1"
set_env_value "GHOSTWATCH_PLAYBOOK" "full-recon"
set_env_value "GHOSTWATCH_OPSEC_PROFILE" "aggressive"
set_env_value "GHOSTWATCH_INCLUDE_FRAMESEVEN" "1"
set_env_value "GHOSTWATCH_CVE_UPDATE" "1"
set_env_value "GHOSTWATCH_SYNC_DOMAINS" "1"
set_env_value "GHOSTWATCH_DOMAINS_FILE" "$DOMAINS_FILE"
set_env_value "GHOSTWATCH_STATE_DIR" "$STATE_DIR"
set_env_value "GHOSTRECON_ENGINE" "both"
set_env_value "GHOSTRECON_VIGOLIUM_STRATEGY" "deep"
set_env_value "GHOSTRECON_VIGOLIUM_USE_CODEX" "1"
set_env_value "GHOSTRECON_VIGOLIUM_VPS_PROFILE" "1"
set_env_value "GHOSTRECON_CVE_AUTO_UPDATE" "1"
set_env_value "GHOSTRECON_CVE_AUTO_UPDATE_TTL_HOURS" "24"
set_env_value "GHOSTRECON_NAVIGATOR_MODE" "0"
set_env_value "GHOSTRECON_TOR_REQUIRED" "0"
set_env_value "GHOSTRECON_TOR_STRICT" "0"
append_env_if_missing "GHOSTRECON_SERVER" "$SERVER_URL"
append_env_if_missing "PORT" "3847"
append_env_if_missing "GHOSTRECON_CODEX_APP_SERVER" "1"

if [[ "$DRY_RUN" -eq 0 ]]; then
  chmod 600 "$ENV_FILE" || true
  log ".env perms -> 600"
fi

if [[ ! -f "$DOMAINS_FILE" ]]; then
  if [[ "$DRY_RUN" -eq 0 ]]; then
    cat >"$DOMAINS_FILE" <<'EOF'
# domains.txt — um apex/host por linha (comentarios com #)
# exemplo.com
# alvo2.com
EOF
  fi
  log "domains.txt template em $DOMAINS_FILE — edite antes do primeiro sweep"
else
  log "domains.txt OK: $DOMAINS_FILE"
fi

# Checks de engines / tools
VIG_BIN=""
for cand in \
  "${GHOSTRECON_VIGOLIUM_BIN:-}" \
  "$ROOT/engines/vigolium" \
  "$ROOT/vigolium/bin/vigolium" \
  "$(command -v vigolium || true)"; do
  if [[ -n "$cand" && -x "$cand" ]]; then
    VIG_BIN="$cand"
    break
  fi
done
FS_BIN="$ROOT/FrameSeven/bin/frameseven/cli/v1"
if [[ -n "$VIG_BIN" ]]; then
  log "Vigolium: $VIG_BIN"
else
  warn "binario Vigolium nao encontrado (engines/vigolium ou PATH)"
fi
if [[ -x "$FS_BIN" ]]; then
  log "FrameSeven: $FS_BIN"
else
  warn "FrameSeven CLI ausente em $FS_BIN"
fi
if command -v codex >/dev/null 2>&1; then
  log "Codex CLI: $(command -v codex)"
else
  warn "codex nao esta no PATH — GHOSTRECON_VIGOLIUM_USE_CODEX=1 pode degradar"
fi

for tool in nmap nuclei ffuf subfinder; do
  if command -v "$tool" >/dev/null 2>&1; then
    log "tool OK: $tool"
  else
    warn "tool ausente no PATH: $tool (modulos Kali podem pular)"
  fi
done

WEBHOOK="$(env_value GHOSTRECON_WEBHOOK_URL)"
if [[ -z "$WEBHOOK" ]]; then
  WEBHOOK="$(env_value GHOSTWATCH_WEBHOOK)"
fi
if [[ -z "$WEBHOOK" ]]; then
  WEBHOOK="$(env_value DISCORD_WEBHOOK)"
fi
if [[ -z "$WEBHOOK" ]]; then
  warn "webhook Discord ausente — defina GHOSTRECON_WEBHOOK_URL no .env"
else
  log "webhook Discord: presente (${#WEBHOOK} chars)"
fi

if [[ "$SKIP_SYSTEMD" -eq 1 ]]; then
  log "skip-systemd: units nao instaladas"
  log "pronto (parcial)"
  exit 0
fi

API_SERVICE="/etc/systemd/system/${UNIT_PREFIX}-api.service"
RUN_SERVICE="/etc/systemd/system/${UNIT_PREFIX}-ghostwatch.service"
TIMER_UNIT="/etc/systemd/system/${UNIT_PREFIX}-ghostwatch.timer"

if [[ "$DRY_RUN" -eq 1 ]]; then
  log "dry-run: escreveria $API_SERVICE"
  log "dry-run: escreveria $RUN_SERVICE (flock $LOCK_FILE)"
  log "dry-run: escreveria $TIMER_UNIT (01:00 e 10:00 $TIMER_TZ)"
  log "pronto (dry-run)"
  exit 0
fi

"${SUDO[@]}" tee "$API_SERVICE" >/dev/null <<EOF
[Unit]
Description=GHOSTRECON API (loopback)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$ROOT
EnvironmentFile=-$ENV_FILE
Environment=HOST=127.0.0.1
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
Description=GhostWatch full-stack sweep (CVE + recon + Discord new-only)
After=${UNIT_PREFIX}-api.service network-online.target
Wants=${UNIT_PREFIX}-api.service network-online.target

[Service]
Type=oneshot
WorkingDirectory=$ROOT
EnvironmentFile=-$ENV_FILE
Environment=HOST=127.0.0.1
Environment=GHOSTRECON_NAVIGATOR_MODE=0
Environment=GHOSTRECON_TOR_REQUIRED=0
Environment=GHOSTRECON_TOR_STRICT=0
Environment=GHOSTWATCH_STATE_DIR=$STATE_DIR
Environment=GHOSTWATCH_DOMAINS_FILE=$DOMAINS_FILE
# Timeout alto: full-recon + Vigolium + FrameSeven por alvo
TimeoutStartSec=0
ExecStart=/usr/bin/flock -n $LOCK_FILE /usr/bin/env bash -lc 'exec "$NODE_BIN" bin/ghostrecon.mjs ghostwatch run --once --confirm-active --server "\${GHOSTRECON_SERVER:-$SERVER_URL}" --state-dir "\${GHOSTWATCH_STATE_DIR:-$STATE_DIR}" --domains-file "\${GHOSTWATCH_DOMAINS_FILE:-$DOMAINS_FILE}" --start-server'
EOF

"${SUDO[@]}" tee "$TIMER_UNIT" >/dev/null <<EOF
[Unit]
Description=Run GhostWatch at 01:00 and 10:00 ($TIMER_TZ)

[Timer]
OnCalendar=*-*-* 01:00:00
OnCalendar=*-*-* 10:00:00
Timezone=$TIMER_TZ
Persistent=true
Unit=${UNIT_PREFIX}-ghostwatch.service

[Install]
WantedBy=timers.target
EOF

"${SUDO[@]}" systemctl daemon-reload
"${SUDO[@]}" systemctl enable "${UNIT_PREFIX}-api.service"
"${SUDO[@]}" systemctl restart "${UNIT_PREFIX}-api.service"
"${SUDO[@]}" systemctl enable --now "${UNIT_PREFIX}-ghostwatch.timer"

# health check curto
sleep 1
if curl -fsS -o /dev/null -m 3 "${SERVER_URL}/api/health" 2>/dev/null \
  || curl -fsS -o /dev/null -m 3 "${SERVER_URL}/health" 2>/dev/null \
  || curl -fsS -o /dev/null -m 3 "${SERVER_URL}/" 2>/dev/null; then
  log "API responde em $SERVER_URL"
else
  warn "API ainda nao respondeu em $SERVER_URL — verifique: systemctl status ${UNIT_PREFIX}-api.service"
fi

log "pronto"
echo "  API:         systemctl status ${UNIT_PREFIX}-api.service"
echo "  Timer:       systemctl list-timers | grep ${UNIT_PREFIX}-ghostwatch"
echo "  Horario:     01:00 e 10:00 ($TIMER_TZ)"
echo "  Lock:        $LOCK_FILE"
echo "  domains.txt: $DOMAINS_FILE"
echo "  Run agora:   sudo systemctl start ${UNIT_PREFIX}-ghostwatch.service"
echo "  Sync alvos:  npm run cli -- ghostwatch sync-domains --file $DOMAINS_FILE --bootstrap --confirm-active --start-server"
echo "  Logs:        journalctl -xeu ${UNIT_PREFIX}-ghostwatch.service --no-pager -n 120"
echo "  Env:         $ENV_FILE"
echo "  Doc:         docs/GHOSTWATCH-VPS.md"
