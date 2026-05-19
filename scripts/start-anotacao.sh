#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT/GhostTrace"
export NEXT_PUBLIC_BASE_PATH=/anotacao
export PORT="${GHOSTTRACE_PORT:-3010}"
exec npx next dev -p "$PORT"
