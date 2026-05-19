#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT/ghostmap/frontend"
export NEXT_PUBLIC_BASE_PATH=/ghostmap
export PORT="${GHOSTMAP_PORT:-3012}"
exec npx next dev -p "$PORT"
