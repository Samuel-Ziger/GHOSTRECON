#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

bash "$ROOT/scripts/start-anotacao.sh" &
ANOT_PID=$!

cleanup() { kill "$ANOT_PID" 2>/dev/null || true; }
trap cleanup EXIT INT TERM

sleep 2
exec bash "$ROOT/scripts/start-stack.sh"
