#!/usr/bin/env bash
# Stack completo — preferir: npm start (start-stack.mjs)
set -Eeuo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec node "$ROOT_DIR/scripts/start-stack.mjs"
