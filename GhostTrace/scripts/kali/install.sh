#!/usr/bin/env bash
# GhostTrace — instalador Kali / Debian / Ubuntu
# Uso: ./scripts/kali/install.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"

echo ""
echo "  ghosttrace — instalador (Kali/Linux)"
echo ""

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "  [!!] '$1' não encontrado."
    echo "       Instale com: sudo apt update && sudo apt install -y $2"
    exit 1
  fi
}

need_cmd nodejs "nodejs npm"
need_cmd npm "npm"
need_cmd python3 "python3 python3-pip python3-venv"
need_cmd curl "curl"

# Node 18+ recomendado
NODE_MAJOR=$(node -v | sed 's/v//' | cut -d. -f1)
if [[ "$NODE_MAJOR" -lt 18 ]]; then
  echo "  [!!] Node.js 18+ recomendado (atual: $(node -v))"
  echo "       https://nodejs.org/ ou: curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -"
fi

echo "  [..] npm install..."
npm install

echo "  [..] venv Python em backend/.venv..."
python3 -m venv backend/.venv
# shellcheck disable=SC1091
source backend/.venv/bin/activate
pip install --upgrade pip -q
pip install -r backend/requirements.txt -q

ENV_FILE="$ROOT/.env.local"
if [[ ! -f "$ENV_FILE" ]]; then
  cp .env.example "$ENV_FILE" 2>/dev/null || cat >"$ENV_FILE" <<EOF
NEXT_PUBLIC_APP_NAME=GhostTrace
NEXT_PUBLIC_APP_VERSION=0.1.0
NEXT_PUBLIC_API_URL=http://127.0.0.1:8787
EOF
fi

chmod +x scripts/kali/*.sh 2>/dev/null || true

echo ""
echo "  [ok] Instalação concluída."
echo "  Subir em background: ./scripts/kali/start.sh"
echo "  Parar:               ./scripts/kali/stop.sh"
echo ""
