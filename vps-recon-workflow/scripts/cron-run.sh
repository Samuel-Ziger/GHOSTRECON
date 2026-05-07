#!/usr/bin/env bash
# Executado pelo crontab: cd no pacote, .env pai se preciso, depois ciclo VPS (sync Supabase → pipeline).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

if [[ -z "${GHOSTRECON_ENV_FILE:-}" ]] && [[ ! -f "${ROOT}/.env" ]] && [[ -f "${ROOT}/../.env" ]]; then
  export GHOSTRECON_ENV_FILE="$(cd "${ROOT}/.." && pwd)/.env"
fi

NODE="$(command -v node)"
exec "${NODE}" "${ROOT}/scripts/run-cycle.mjs" "$@"
