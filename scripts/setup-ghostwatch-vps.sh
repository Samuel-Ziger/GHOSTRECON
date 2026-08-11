#!/usr/bin/env bash
# Compat: redireciona para o bootstrap completo da sentinela VPS.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec bash "$ROOT/scripts/setup-ghostrecon-vps.sh" "$@"
