#!/usr/bin/env bash
#
# Instala no crontab do utilizador atual o ciclo completo do modo VPS GhostRecon:
#   sync Supabase → ../subdomains.txt (por defeito) → recon → SQLite → IA → webhook
#
# Uso:
#   bash cron-install.sh                       # a cada 6 horas (igual ao README)
#   bash cron-install.sh --hours 3             # a cada 3 horas
#   bash cron-install.sh --at "06:00,18:00"    # horários fixos diários (06h e 18h)
#   bash cron-install.sh --at "02:30"          # único horário fixo (02:30 todo dia)
#   bash cron-install.sh --dry-run             # só mostra o que seria instalado
#

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG="${ROOT}/logs/cycle.log"
WRAPPER="${ROOT}/scripts/cron-run.sh"
MARK_BEGIN='# BEGIN ghostrecon-vps-workflow'
MARK_END='# END ghostrecon-vps-workflow'

HOURS=6
DRY_RUN=0
AT_TIMES=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --hours)
      HOURS="${2:?}"
      shift 2
      ;;
    --at)
      AT_TIMES="${2:?}"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    -h|--help)
      grep '^#' "$0" | grep -v '^#!/' | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "Argumento desconhecido: $1 (use --help)" >&2
      exit 1
      ;;
  esac
done

need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "[cron-install] Erro: necessário \"$1\""; exit 1; }; }
need_cmd node

if [[ ! -f "${WRAPPER}" ]]; then
  echo "[cron-install] Em falta: ${WRAPPER}" >&2
  exit 1
fi

chmod +x "${WRAPPER}" 2>/dev/null || true
mkdir -p "${ROOT}/logs" "${ROOT}/data"

JOB="\"${WRAPPER}\" >> \"${LOG}\" 2>&1"

if [[ -n "${AT_TIMES}" ]]; then
  # Modo horário fixo: --at "HH:MM,HH:MM,..."
  HOURS_LIST=""
  MIN_FIXED=""
  IFS=',' read -ra TIMES_ARR <<< "${AT_TIMES}"
  for t in "${TIMES_ARR[@]}"; do
    t="${t// /}"
    if [[ ! "${t}" =~ ^([0-1]?[0-9]|2[0-3]):([0-5][0-9])$ ]]; then
      echo "[cron-install] Erro: --at espera HH:MM (recebi: '${t}')" >&2
      exit 1
    fi
    h="${BASH_REMATCH[1]}"; m="${BASH_REMATCH[2]}"
    h=$((10#${h})); m=$((10#${m}))
    if [[ -z "${MIN_FIXED}" ]]; then
      MIN_FIXED="${m}"
    elif [[ "${MIN_FIXED}" != "${m}" ]]; then
      echo "[cron-install] Erro: --at exige o mesmo minuto em todos os horários (ex: 06:00,18:00)." >&2
      echo "[cron-install]        Para minutos diferentes use entradas crontab manuais ou várias --at." >&2
      exit 1
    fi
    if [[ -z "${HOURS_LIST}" ]]; then
      HOURS_LIST="${h}"
    else
      HOURS_LIST="${HOURS_LIST},${h}"
    fi
  done
  SPEC="${MIN_FIXED} ${HOURS_LIST} * * * ${JOB}"
  SCHEDULE_DESC="diariamente em ${AT_TIMES} (cron: ${MIN_FIXED} ${HOURS_LIST} * * *)"
else
  # Modo periódico: --hours N
  if [[ ! "${HOURS}" =~ ^[0-9]+$ ]] || [[ "${HOURS}" -lt 1 ]] || [[ "${HOURS}" -gt 168 ]]; then
    echo "[cron-install] Erro: --hours deve ser inteiro entre 1 e 168 (recebi: ${HOURS})" >&2
    exit 1
  fi
  # Minuto inicial aleatório (0–59) para não alinhar todos os VPS ao mesmo segundo
  MINUTE=$((RANDOM % 60))
  SPEC="${MINUTE} */${HOURS} * * * ${JOB}"
  SCHEDULE_DESC="a cada ${HOURS} h (minuto ${MINUTE} de cada janela)"
fi

BLOCK="$(printf '%s\n%s\n%s\n' "$MARK_BEGIN" "$SPEC" "$MARK_END")"

FILTERED="$(crontab -l 2>/dev/null | awk -v beg="$MARK_BEGIN" -v end="$MARK_END" '
  $0 == beg { skip=1; next }
  $0 == end { skip=0; next }
  !skip { print }
' || true)"

echo "[cron-install] Pacote: ${ROOT}"
echo "[cron-install] Agendamento: ${SCHEDULE_DESC}"
echo "[cron-install] Comando: ${WRAPPER}"
echo "[cron-install] Log: ${LOG}"
if [[ -f "${ROOT}/../.env" ]] && [[ ! -f "${ROOT}/.env" ]]; then
  echo "[cron-install] Nota: sem .env local — cron-run.sh exporta GHOSTRECON_ENV_FILE para $(cd "${ROOT}/.." && pwd)/.env"
fi

if [[ "${DRY_RUN}" -eq 1 ]]; then
  echo ""
  echo "--- bloco crontab (dry-run) ---"
  printf '%s\n' "$BLOCK"
  echo "--- fim ---"
  exit 0
fi

{
  printf '%s\n' "$FILTERED"
  printf '%s\n' "$BLOCK"
} | crontab -

echo "[cron-install] Crontab actualizado."
echo "[cron-install] Ver: crontab -l"
