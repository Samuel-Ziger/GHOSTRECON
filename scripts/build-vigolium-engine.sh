#!/usr/bin/env bash
# Compila vigolium/ (fonte temporária) → engines/vigolium
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC_DIR="$ROOT/vigolium"
DEST="$ROOT/engines/vigolium"

if [[ ! -d "$SRC_DIR" ]]; then
  echo "build-vigolium-engine: pasta vigolium/ ausente." >&2
  echo "  git clone https://github.com/vigolium/vigolium.git \"$SRC_DIR\"" >&2
  exit 1
fi

echo "A compilar Vigolium (pode demorar vários minutos)…"
make -C "$SRC_DIR" build
BIN="$SRC_DIR/bin/vigolium"
if [[ ! -x "$BIN" ]]; then
  if command -v vigolium >/dev/null 2>&1; then
    BIN="$(command -v vigolium)"
  else
    echo "build-vigolium-engine: binário não encontrado após make build" >&2
    exit 1
  fi
fi

mkdir -p "$ROOT/engines"
cp -f "$BIN" "$DEST"
chmod +x "$DEST"
echo "OK: $DEST"
"$DEST" version | head -3
