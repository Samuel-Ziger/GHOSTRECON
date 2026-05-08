#!/usr/bin/env bash
# Um comando na VPS: dependências sistema + npm + opcional cron + lista de alvos.
#
# Flags:
#   --cron        configurar crontab (cada 6 h) ao final
#   --kali        instalar ferramentas Kali (nmap, subfinder, amass, ffuf, nuclei,
#                 wpscan, sqlmap, dalfox, katana, etc.) + Playwright Chromium +
#                 Python deps (xss_vibes). Auto-ativado se /etc/os-release indicar Kali.
#   --no-kali     desativa explicitamente a fase Kali (sobrescreve auto-detect)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${ROOT}"

WITH_CRON=0
WITH_KALI=auto
for arg in "$@"; do
  case "$arg" in
    --cron) WITH_CRON=1 ;;
    --kali) WITH_KALI=1 ;;
    --no-kali) WITH_KALI=0 ;;
  esac
done

if [[ "${WITH_KALI}" == "auto" ]]; then
  if grep -qiE 'kali' /etc/os-release 2>/dev/null; then
    WITH_KALI=1
    echo "[install] Distro Kali detectada → fase --kali será executada (use --no-kali para pular)"
  else
    WITH_KALI=0
  fi
fi

need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "Erro: necessário \"$1\""; exit 1; }; }

echo "[install] Pacote em: ${ROOT}"

if command -v apt-get >/dev/null 2>&1; then
  echo "[install] apt: tools de compilação (better-sqlite3, etc.)"
  sudo DEBIAN_FRONTEND=noninteractive apt-get update -y
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
    curl ca-certificates build-essential python3 python3-pip make g++ sqlite3 openssl ca-certificates git
fi

echo "[install] Node.js (mínimo 20 recomendado)"
if command -v node >/dev/null 2>&1; then
  major="$(node -e "console.log(process.versions.node.split('.')[0])")"
  if [[ "${major}" -lt 20 ]]; then
    echo "[install] Aviso: Node ${major} pode falhar — use Node 20 LTS ou 22."
  fi
else
  if command -v apt-get >/dev/null 2>&1; then
    curl -fsSL https://deb.nodesource.com/setup_22.x | sudo bash -
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y nodejs
  else
    echo "Instale Node 20+ manualmente e volte a correr este script.";
    exit 1
  fi
fi

need_cmd node
need_cmd npm

npm_install_in() {
  local dir="$1"
  echo "[install] npm install em ${dir}"
  (
    cd "${dir}"
    if ! npm ci --omit=dev 2>/dev/null; then
      if ! npm install --omit=dev; then
        echo "[install] npm install falhou em ${dir} — tentando --legacy-peer-deps"
        npm install --omit=dev --legacy-peer-deps
      fi
    fi
  )
}

PARENT_ROOT="$(cd "${ROOT}/.." && pwd)"

if [[ -f "${PARENT_ROOT}/package.json" ]] && [[ "${PARENT_ROOT}" != "${ROOT}" ]]; then
  echo "[install] Detectado mono-repo GHOSTRECON em ${PARENT_ROOT} — instalando deps do motor (server/, playbooks/)"
  npm_install_in "${PARENT_ROOT}"
fi

npm_install_in "${ROOT}"

# ─── Fase Kali: ferramentas ofensivas (opt-in via --kali ou auto-detect Kali) ───
if [[ "${WITH_KALI}" == "1" ]]; then
  echo ""
  echo "[install] === FASE KALI: ferramentas ofensivas ==="

  if command -v apt-get >/dev/null 2>&1; then
    echo "[install] apt: nmap, subfinder, amass, ffuf, nuclei, wpscan, sqlmap, etc."
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
      nmap masscan \
      subfinder amass assetfinder \
      ffuf gobuster dirb dirsearch \
      nuclei httpx-toolkit \
      whatweb wpscan \
      sqlmap nikto \
      whois bind9-dnsutils dnsrecon \
      exploitdb \
      golang-go \
      python3-requests python3-colorama \
      || echo "[install] aviso: alguns pacotes podem ter falhado — checa manualmente"
  fi

  # Go bins: katana + dalfox (alguns metapacotes Kali já põem em /usr/local/bin/, mas garantimos)
  export GOPATH="${GOPATH:-/root/go}"
  export PATH="${PATH}:${GOPATH}/bin:/usr/local/go/bin"
  for rcfile in /root/.bashrc /root/.zshrc; do
    if [[ -w "${rcfile}" ]] || [[ ! -e "${rcfile}" ]]; then
      grep -q 'GOPATH=/root/go' "${rcfile}" 2>/dev/null || echo 'export GOPATH=/root/go' >> "${rcfile}"
      grep -q 'go/bin' "${rcfile}" 2>/dev/null || echo 'export PATH="$PATH:$GOPATH/bin:/usr/local/go/bin"' >> "${rcfile}"
    fi
  done

  if command -v go >/dev/null 2>&1; then
    if ! command -v katana >/dev/null 2>&1; then
      echo "[install] go install katana"
      go install github.com/projectdiscovery/katana/cmd/katana@latest || echo "[install] aviso: katana falhou"
    fi
    if ! command -v dalfox >/dev/null 2>&1; then
      echo "[install] go install dalfox"
      go install github.com/hahwul/dalfox/v2@latest || echo "[install] aviso: dalfox falhou"
    fi
  fi

  # Python deps do xss_vibes (na pasta Xss/xss_vibes do repo raiz)
  XSS_VIBES_DIR=""
  if [[ -d "${ROOT}/../Xss/xss_vibes" ]]; then
    XSS_VIBES_DIR="${ROOT}/../Xss/xss_vibes"
  elif [[ -d "${ROOT}/Xss/xss_vibes" ]]; then
    XSS_VIBES_DIR="${ROOT}/Xss/xss_vibes"
  fi
  if [[ -n "${XSS_VIBES_DIR}" ]]; then
    echo "[install] xss_vibes em ${XSS_VIBES_DIR}"
    sudo pip3 install --break-system-packages wafw00f 2>/dev/null \
      || pip3 install --user --break-system-packages wafw00f \
      || echo "[install] aviso: pip wafw00f falhou — xss_vibes pode pular WAF detection"
  fi

  # Templates do nuclei
  if command -v nuclei >/dev/null 2>&1; then
    echo "[install] nuclei -update-templates"
    nuclei -update-templates 2>/dev/null || true
  fi

  # Playwright Chromium (módulo Navegation)
  if [[ -d "${ROOT}/../node_modules/playwright" ]] || [[ -d "${ROOT}/node_modules/playwright" ]]; then
    echo "[install] Playwright Chromium"
    (
      cd "${ROOT}/.."
      npx playwright install chromium 2>/dev/null \
        || (sudo npx playwright install-deps chromium 2>/dev/null && npx playwright install chromium) \
        || echo "[install] aviso: Playwright chromium falhou — Navegation rodará sem browser headless"
    )
  fi

  echo "[install] === FASE KALI concluída ==="
  echo ""
fi

if [[ ! -f "${ROOT}/.env" ]]; then
  if [[ -f "${ROOT}/.env.example" ]]; then
    cp "${ROOT}/.env.example" "${ROOT}/.env"
    echo "[install] Copiado .env.example → .env (edite ou substitua pelo .env do GHOSTRECON)"
  elif [[ -f "${ROOT}/../.env" ]]; then
    ln -snf "${ROOT}/../.env" "${ROOT}/.env"
    echo "[install] Ligado symlink .env ao diretório pai (GHOSTRECON)"
  fi
fi

PARENT_SD="${ROOT}/../subdomains.txt"
if [[ -f "${PARENT_SD}" ]]; then
  echo "[install] Lista de alvos: ${PARENT_SD} — ficheiro partilhado com o mono-repo por defeito (WORKFLOW_DOMAINS_FILE=../subdomains.txt)."
elif [[ ! -f "${ROOT}/subdomains.txt" ]]; then
  if [[ -f "${ROOT}/subdomains.txt.example" ]]; then
    cp "${ROOT}/subdomains.txt.example" "${ROOT}/subdomains.txt"
    echo "[install] Criado ${ROOT}/subdomains.txt inicial (VPC isolada; em mono-repo usa ../subdomains.txt)."
  elif [[ -f "${ROOT}/domains.txt.example" ]]; then
    cp "${ROOT}/domains.txt.example" "${ROOT}/subdomains.txt"
    echo "[install] Criado ${ROOT}/subdomains.txt a partir de domains.txt.example."
  fi
fi

chmod +x "${ROOT}/cron-install.sh" "${ROOT}/setup-cron.sh" "${ROOT}/scripts/cron-run.sh" 2>/dev/null || true

if [[ "${WITH_CRON}" -eq 1 ]]; then
  bash "${ROOT}/cron-install.sh"
else
  echo ""
  echo "[install] Cron NÃO configurado. Para instalar no crontab (cada 6 h):"
  echo "         bash ${ROOT}/cron-install.sh"
  echo "         ou: bash ${ROOT}/setup-cron.sh"
  echo "         ou: bash ${ROOT}/install.sh --cron"
fi

echo ""
echo "[install] Teste rápido (opcional):"
echo "         cd \"${ROOT}\" && node scripts/sync-domains.mjs && node scripts/run-pipeline.mjs"
echo ""
echo "[install] Status das ferramentas:"
for t in node npm nmap subfinder amass ffuf nuclei httpx katana dalfox wpscan sqlmap nikto whatweb dnsrecon searchsploit; do
  if command -v "$t" >/dev/null 2>&1; then
    printf "    \xe2\x9c\x93 %-14s %s\n" "$t" "$(command -v $t)"
  else
    printf "    \xe2\x9c\x97 %-14s (faltando — Kali Mode pode pular este módulo)\n" "$t"
  fi
done
echo ""
echo "[install] Pronto."
