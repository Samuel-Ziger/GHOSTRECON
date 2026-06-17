#!/usr/bin/env bash
# Copia vigolium para engines/vigolium (runtime GHOSTRECON).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$ROOT/engines/vigolium"
mkdir -p "$ROOT/engines"

resolve_src() {
  if [[ -n "${GHOSTRECON_VIGOLIUM_SRC:-}" && -x "${GHOSTRECON_VIGOLIUM_SRC}" ]]; then
    echo "$GHOSTRECON_VIGOLIUM_SRC"
    return
  fi
  if [[ -x "$ROOT/vigolium/bin/vigolium" ]]; then
    echo "$ROOT/vigolium/bin/vigolium"
    return
  fi
  if command -v vigolium >/dev/null 2>&1; then
    command -v vigolium
    return
  fi
  echo ""
}

SRC="$(resolve_src)"
if [[ -z "$SRC" ]]; then
  echo "install-vigolium-engine: binário não encontrado." >&2
  echo "  Instale: curl -fsSL https://vigolium.com/install.sh | bash" >&2
  echo "  Ou compile: bash scripts/build-vigolium-engine.sh" >&2
  exit 1
fi

cp -f "$SRC" "$DEST"
chmod +x "$DEST"
echo "OK: $DEST ← $SRC"
"$DEST" version 2>/dev/null | head -3 || true
