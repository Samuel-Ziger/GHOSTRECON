#!/usr/bin/env bash
# Atalho legado — delega em cron-install.sh (comportamento idêntico ao antigo: a cada 6 h).
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "${DIR}/cron-install.sh" "$@"
