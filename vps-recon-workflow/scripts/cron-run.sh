#!/usr/bin/env bash
# Executado pelo crontab: cd no repo GHOSTRECON (raiz, p/ Xss/, playbooks/, tokens/, evidence/),
# .env pai se preciso, depois ciclo VPS (sync Supabase → pipeline).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PARENT_ROOT="$(cd "${ROOT}/.." && pwd)"

# cwd no repo raiz para que módulos do server/ que usam process.cwd() (xss_vibes, evidence-capture,
# curl-probe, engagement, github-clone, projects, etc.) achem os assets relativos correctos.
if [[ -d "${PARENT_ROOT}/Xss" ]] || [[ -d "${PARENT_ROOT}/server" ]]; then
  cd "${PARENT_ROOT}"
else
  cd "${ROOT}"
fi

if [[ -z "${GHOSTRECON_ENV_FILE:-}" ]] && [[ ! -f "${ROOT}/.env" ]] && [[ -f "${PARENT_ROOT}/.env" ]]; then
  export GHOSTRECON_ENV_FILE="${PARENT_ROOT}/.env"
fi

NODE="$(command -v node)"
exec "${NODE}" "${ROOT}/scripts/run-cycle.mjs" "$@"
