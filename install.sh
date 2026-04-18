#!/usr/bin/env bash

set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IAS_DIR="$ROOT_DIR/IAs"
XSS_DIR="$ROOT_DIR/Xss/xss_vibes"
PROFILE="full"
INSTALL_IAS=1
INSTALL_PLAYWRIGHT=1
INSTALL_DOCKER=1
INSTALL_SUPABASE=1

log() { printf '[GHOSTRECON] %s\n' "$*"; }
warn() { printf '[GHOSTRECON][WARN] %s\n' "$*" >&2; }
die() { printf '[GHOSTRECON][ERRO] %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Uso:
  ./install.sh [opcoes]

Perfis:
  --profile minimal   Instala Node, deps npm e base do projeto
  --profile passive   Minimal + ferramentas passivas/auxiliares
  --profile full      Passive + modo Kali + Playwright + IAs opcionais

Opcoes:
  --skip-ias          Nao clona/prepara Shannon e PentestGPT
  --skip-playwright   Nao instala Chromium do Playwright
  --skip-docker       Nao instala Docker
  --skip-supabase     Nao instala Supabase CLI global
  -h, --help          Mostra esta ajuda
EOF
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

append_line_if_missing() {
  local file="$1"
  local line="$2"
  touch "$file"
  if ! grep -Fqx "$line" "$file"; then
    printf '%s\n' "$line" >>"$file"
  fi
}

run_sudo() {
  if [ "${EUID:-$(id -u)}" -eq 0 ]; then
    "$@"
  elif need_cmd sudo; then
    sudo "$@"
  else
    die "sudo nao encontrado. Rode como root ou instale sudo."
  fi
}

apt_install_if_available() {
  local pkg
  local install_list=()
  for pkg in "$@"; do
    if apt-cache show "$pkg" >/dev/null 2>&1; then
      install_list+=("$pkg")
    else
      warn "Pacote nao encontrado no APT: $pkg"
    fi
  done
  if [ "${#install_list[@]}" -gt 0 ]; then
    run_sudo apt-get install -y "${install_list[@]}"
  fi
}

ensure_shell_path() {
  local rc
  local marker_start="# >>> GHOSTRECON PATH >>>"
  local marker_end="# <<< GHOSTRECON PATH <<<"
  local export_line='export PATH="$HOME/.local/bin:$HOME/go/bin:$HOME/bin:/usr/local/go/bin:$PATH"'

  for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
    touch "$rc"
    if ! grep -Fq "$marker_start" "$rc"; then
      {
        printf '\n%s\n' "$marker_start"
        printf '%s\n' "$export_line"
        printf '%s\n' "$marker_end"
      } >>"$rc"
    fi
  done

  export PATH="$HOME/.local/bin:$HOME/go/bin:$HOME/bin:/usr/local/go/bin:$PATH"
}

detect_debian_like() {
  [ -f /etc/os-release ] || return 1
  grep -Eiq '(^ID=debian$|^ID=kali$|^ID_LIKE=.*debian)' /etc/os-release
}

install_base_apt_packages() {
  log "Atualizando indice APT"
  run_sudo apt-get update

  log "Instalando pacotes base"
  apt_install_if_available \
    ca-certificates curl git jq unzip xz-utils gnupg lsb-release software-properties-common \
    build-essential pkg-config make gcc g++ python3 python3-pip python3-venv python3-dev \
    whois wafw00f ffuf nmap sqlmap dirb seclists
}

install_node_22() {
  local major=""
  if need_cmd node; then
    major="$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || true)"
  fi
  if [ -n "$major" ] && [ "$major" -ge 18 ]; then
    log "Node.js ja atende o requisito (>=18)"
    return
  fi

  log "Instalando Node.js 22"
  curl -fsSL https://deb.nodesource.com/setup_22.x | run_sudo bash
  run_sudo apt-get install -y nodejs
}

install_go() {
  if need_cmd go; then
    log "Go ja instalado: $(go version)"
    return
  fi
  log "Instalando Go pelo APT"
  apt_install_if_available golang-go
}

install_pnpm() {
  if need_cmd pnpm; then
    log "pnpm ja instalado"
    return
  fi
  log "Instalando pnpm"
  if need_cmd corepack; then
    run_sudo corepack enable
    run_sudo corepack prepare pnpm@latest --activate
  else
    run_sudo npm install -g pnpm
  fi
}

install_uv() {
  if need_cmd uv; then
    log "uv ja instalado"
    return
  fi
  log "Instalando uv"
  curl -LsSf https://astral.sh/uv/install.sh | sh
  export PATH="$HOME/.local/bin:$PATH"
}

install_docker() {
  if [ "$INSTALL_DOCKER" -ne 1 ]; then
    return
  fi
  if need_cmd docker; then
    log "Docker ja instalado"
  else
    log "Instalando Docker"
    apt_install_if_available docker.io docker-compose-plugin
  fi
  if getent group docker >/dev/null 2>&1; then
    run_sudo usermod -aG docker "$USER" || true
  fi
}

install_go_tool() {
  local binary="$1"
  local module="$2"
  if need_cmd "$binary"; then
    log "$binary ja esta no PATH"
    return
  fi
  log "Instalando $binary via go install"
  GO111MODULE=on go install "$module"
}

install_apt_security_tools() {
  log "Instalando ferramentas de seguranca via APT"
  apt_install_if_available exploitdb amass wpscan
}

install_go_security_tools() {
  install_go_tool subfinder github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  install_go_tool nuclei github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
  install_go_tool katana github.com/projectdiscovery/katana/cmd/katana@latest
  install_go_tool gau github.com/lc/gau/v2/cmd/gau@latest
  install_go_tool waybackurls github.com/tomnomnom/waybackurls@latest
  install_go_tool dalfox github.com/hahwul/dalfox/v2@latest
}

install_project_npm() {
  log "Instalando dependencias npm do projeto"
  cd "$ROOT_DIR"
  npm install
}

setup_env_file() {
  if [ ! -f "$ROOT_DIR/.env" ] && [ -f "$ROOT_DIR/.env.example" ]; then
    log "Criando .env a partir do exemplo"
    cp "$ROOT_DIR/.env.example" "$ROOT_DIR/.env"
  fi
}

install_xss_vibes_python() {
  [ -d "$XSS_DIR" ] || return
  log "Instalando dependencias Python do xss_vibes"
  python3 -m pip install --user -r "$XSS_DIR/requirements" || \
    python3 -m pip install --user --break-system-packages -r "$XSS_DIR/requirements"
}

install_playwright() {
  if [ "$INSTALL_PLAYWRIGHT" -ne 1 ]; then
    return
  fi
  log "Instalando Playwright no projeto"
  cd "$ROOT_DIR"
  npm install playwright
  npx playwright install chromium
}

clone_if_missing() {
  local repo_url="$1"
  local target_dir="$2"
  if [ -d "$target_dir/.git" ] || [ -d "$target_dir" ]; then
    log "Diretorio ja existe: $target_dir"
    return
  fi
  mkdir -p "$(dirname "$target_dir")"
  git clone --recurse-submodules "$repo_url" "$target_dir"
}

prepare_shannon() {
  local shannon_dir="$IAS_DIR/shannon"
  clone_if_missing "https://github.com/keygraph/shannon.git" "$shannon_dir"
  if [ -d "$shannon_dir" ]; then
    log "Preparando Shannon"
    (
      cd "$shannon_dir"
      pnpm install
      pnpm build
      ./shannon build || warn "Falhou ./shannon build; revise Docker/credenciais depois"
    )
  fi
}

prepare_pentestgpt() {
  local pentest_dir="$IAS_DIR/PentestGPT"
  clone_if_missing "https://github.com/GreyDGL/PentestGPT.git" "$pentest_dir"
  if [ -d "$pentest_dir" ]; then
    log "Preparando PentestGPT"
    (
      cd "$pentest_dir"
      make install || warn "Falhou make install em PentestGPT"
    )
  fi
}

install_supabase_cli() {
  if [ "$INSTALL_SUPABASE" -ne 1 ]; then
    return
  fi
  if need_cmd supabase; then
    log "Supabase CLI ja esta no PATH"
    return
  fi
  log "Instalando Supabase CLI global"
  run_sudo npm install -g supabase
}

verify_install() {
  log "Resumo de verificacao"
  local cmds=(
    node npm python3 pip3 git go pnpm uv docker
    nmap ffuf nuclei subfinder amass gau waybackurls katana dalfox
    whois wpscan wafw00f searchsploit sqlmap supabase
  )
  local c
  for c in "${cmds[@]}"; do
    if need_cmd "$c"; then
      printf '  [ok] %s -> %s\n' "$c" "$(command -v "$c")"
    else
      printf '  [--] %s\n' "$c"
    fi
  done
}

while [ $# -gt 0 ]; do
  case "$1" in
    --profile)
      shift
      PROFILE="${1:-}"
      [ -n "$PROFILE" ] || die "Faltou valor para --profile"
      ;;
    --skip-ias)
      INSTALL_IAS=0
      ;;
    --skip-playwright)
      INSTALL_PLAYWRIGHT=0
      ;;
    --skip-docker)
      INSTALL_DOCKER=0
      ;;
    --skip-supabase)
      INSTALL_SUPABASE=0
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "Opcao invalida: $1"
      ;;
  esac
  shift
done

case "$PROFILE" in
  minimal|passive|full) ;;
  *) die "Perfil invalido: $PROFILE" ;;
esac

detect_debian_like || die "Este instalador foi feito para Debian/Kali."
need_cmd apt-get || die "apt-get nao encontrado."

ensure_shell_path
install_base_apt_packages
install_node_22
install_go
install_pnpm
install_uv
install_docker
install_project_npm
setup_env_file
install_xss_vibes_python
install_supabase_cli

if [ "$PROFILE" = "passive" ] || [ "$PROFILE" = "full" ]; then
  install_go_security_tools
fi

if [ "$PROFILE" = "full" ]; then
  install_apt_security_tools
  install_playwright
  if [ "$INSTALL_IAS" -eq 1 ]; then
    prepare_shannon
    prepare_pentestgpt
  fi
fi

verify_install

cat <<'EOF'

Instalacao concluida.

Notas:
  - Abra um novo terminal para garantir o PATH atualizado no bash/zsh.
  - Se o Docker foi instalado agora, talvez precise relogar para o grupo docker surtir efeito.
  - O arquivo .env foi copiado do exemplo se nao existia; preencha as chaves/API keys antes de usar tudo.
  - PentestGPT e Shannon podem exigir configuracoes adicionais e credenciais proprias.

Comandos uteis:
  npm start
  npm test
  npm run db:link
  npm run db:push
EOF
