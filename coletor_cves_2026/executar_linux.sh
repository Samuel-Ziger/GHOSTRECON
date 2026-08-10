#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
python3 coletar_cves_2026.py --fonte nvd --anos 2018-2026 --somente-web --excluir-rejeitadas --saida cves_web_saida
