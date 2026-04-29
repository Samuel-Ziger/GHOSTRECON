#!/usr/bin/env bash
set -euo pipefail

# Navegation setup/control (Tor + OpenVPN) com idempotência.
# Uso:
#   bash navegation.sh status
#   bash navegation.sh up --dry-run
#   sudo bash navegation.sh up
#   sudo bash navegation.sh down

DRY_RUN=0
ACTION="${1:-up}"
if [[ "${2:-}" == "--dry-run" || "${1:-}" == "--dry-run" ]]; then
  DRY_RUN=1
fi

TORRC="/etc/tor/torrc"
OVPN_CONF="/etc/openvpn/server.conf"

log() { printf '[nav] %s\n' "$*"; }

run() {
  log "cmd: $*"
  if [[ "$DRY_RUN" -eq 0 ]]; then
    "$@"
  fi
}

backup_file() {
  local file="$1"
  local ts
  ts="$(date +%Y%m%d-%H%M%S)"
  local out="${file}.bak.${ts}"
  log "backup: ${file} -> ${out}"
  if [[ "$DRY_RUN" -eq 0 ]]; then
    cp -a "$file" "$out"
  fi
}

ensure_line() {
  local file="$1"
  local line="$2"
  if grep -Fqx "$line" "$file"; then
    return 0
  fi
  log "append torrc: $line"
  if [[ "$DRY_RUN" -eq 0 ]]; then
    printf '%s\n' "$line" >>"$file"
  fi
}

status_services() {
  local tor_state ovpn_state
  tor_state="$(systemctl is-active tor 2>/dev/null || true)"
  ovpn_state="$(systemctl is-active openvpn@server 2>/dev/null || true)"
  echo "tor=${tor_state:-unknown}"
  echo "openvpn=${ovpn_state:-unknown}"
  if [[ "$tor_state" == "active" || "$ovpn_state" == "active" ]]; then
    return 0
  fi
  return 3
}

if [[ "$ACTION" == "status" ]]; then
  status_services
  exit $?
fi

if [[ "$DRY_RUN" -eq 0 && "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "Executa como root (sudo) ou usa --dry-run." >&2
  exit 1
fi

if [[ "$ACTION" == "down" ]]; then
  run systemctl disable --now openvpn@server
  run systemctl stop tor
  log "tunelamento desativado."
  exit 0
fi

if [[ "$ACTION" != "up" ]]; then
  echo "Ação inválida: $ACTION (use: up | down | status)" >&2
  exit 2
fi

run apt-get update
run apt-get install -y tor openvpn

if [[ ! -f "$TORRC" ]]; then
  echo "Arquivo não encontrado: $TORRC" >&2
  exit 1
fi

backup_file "$TORRC"
ensure_line "$TORRC" "VirtualAddrNetwork 10.192.0.0/10"
ensure_line "$TORRC" "AutomapHostsOnResolve 1"
ensure_line "$TORRC" "TransPort 9050"
ensure_line "$TORRC" "DNSPort 53"

if [[ -f "$OVPN_CONF" ]]; then
  backup_file "$OVPN_CONF"
fi

log "write: $OVPN_CONF"
if [[ "$DRY_RUN" -eq 0 ]]; then
  cat >"$OVPN_CONF" <<'EOF'
server 10.8.0.0 255.255.255.0
dev tun
proto udp
topology subnet
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 10.8.0.1"
keepalive 10 120
cipher AES-256-CBC
auth SHA256
persist-key
persist-tun
verb 3
EOF
fi

run systemctl restart tor
run systemctl enable --now openvpn@server
log "concluído."
