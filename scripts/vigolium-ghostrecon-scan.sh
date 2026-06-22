#!/usr/bin/env bash
# GhostRecon — scan Vigolium isolado (perfil VPS / scripts/vigolium/vigolium.sh sem Discord nem IA).
#
# Uso:
#   ./scripts/vigolium-ghostrecon-scan.sh https://alvo.com /caminho/saida-base
#
# Variáveis:
#   VIGOLIUM                  binário (default: vigolium)
#   VIGOLIUM_STRATEGY         lite|balanced|deep (default: deep)
#   SKIP_EXTERNAL_HARVEST     1 = --skip external-harvest (default: 1)
#   GHOSTRECON_VIGOLIUM_USE_CODEX=1  repassa provider Codex ao processo filho
#
# Saídas: ${OUT_BASE}.html, ${OUT_BASE}.sqlite, ${OUT_BASE}.jsonl

set -euo pipefail

TARGET="${1:-}"
OUT_BASE="${2:-}"
VIGOLIUM="${VIGOLIUM:-vigolium}"
STRATEGY="${VIGOLIUM_STRATEGY:-deep}"
SKIP_EXTERNAL_HARVEST="${SKIP_EXTERNAL_HARVEST:-1}"

if [[ -z "$TARGET" || -z "$OUT_BASE" ]]; then
  echo "Uso: $0 <url-alvo> <caminho-base-saida-sem-extensao>" >&2
  exit 2
fi

if ! command -v "$VIGOLIUM" >/dev/null 2>&1; then
  echo "Erro: vigolium não encontrado ($VIGOLIUM)" >&2
  exit 1
fi

mkdir -p "$(dirname "$OUT_BASE")"

scan_args=(
  scan -t "$TARGET"
  -S
  --format html,sqlite,jsonl
  -o "$OUT_BASE"
  --strategy "$STRATEGY"
  --scope-origin strict
  -F
  --soft-fail
)

if [[ "$SKIP_EXTERNAL_HARVEST" == "1" ]]; then
  scan_args+=(--skip external-harvest)
fi

exec "$VIGOLIUM" "${scan_args[@]}"
