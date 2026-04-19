#!/usr/bin/env bash

set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IAS_DIR="$ROOT_DIR/IAs"
XSS_DIR="$ROOT_DIR/Xss/xss_vibes"
PROFILE="full"
INSTALL_SHANNON=1
INSTALL_PENTESTGPT=1
INSTALL_PLAYWRIGHT=1
INSTALL_DOCKER=1
INSTALL_SUPABASE=1
INSTALL_GHOST_LOCAL=1
# 1 = valor definido na linha de comando; nao perguntar no modo interativo
CLI_DOCKER=0
CLI_SHANNON=0
CLI_PENTESTGPT=0
ASSUME_DEFAULTS=0

log() { printf '[GHOSTRECON] %s\n' "$*"; }
warn() { printf '[GHOSTRECON][WARN] %s\n' "$*" >&2; }
die() { printf '[GHOSTRECON][ERRO] %s\n' "$*" >&2; exit 1; }

# Retorna 0 = sim, 1 = nao. default: y ou n
prompt_yes_no() {
  local question="$1"
  local default="${2:-y}"
  local reply lower
  while true; do
    if [ "$default" = "y" ]; then
      printf '[GHOSTRECON] %s [Y/n] ' "$question"
    else
      printf '[GHOSTRECON] %s [y/N] ' "$question"
    fi
    if ! read -r reply </dev/tty 2>/dev/null; then
      reply=""
    fi
    lower="$(printf '%s' "$reply" | tr '[:upper:]' '[:lower:]')"
    case "$lower" in
      y|yes|s|sim) return 0 ;;
      n|no|nao) return 1 ;;
      "")
        [ "$default" = "y" ] && return 0 || return 1
        ;;
      *) printf '[GHOSTRECON] Responda y ou n.\n' ;;
    esac
  done
}

# Ajusta INSTALL_* conforme respostas (so em TTY e sem -y, e sem --skip-* daquele item).
prompt_optional_installs() {
  [ "${ASSUME_DEFAULTS:-0}" -eq 1 ] && return 0
  [ -t 0 ] || return 0

  if [ "${CLI_DOCKER:-0}" -eq 0 ]; then
    if prompt_yes_no "Instalar Docker (docker.io, compose plugin e usuario no grupo docker)?" y; then
      INSTALL_DOCKER=1
    else
      INSTALL_DOCKER=0
      log "Docker: pulado por escolha."
    fi
  fi

  local sh_def="y" pt_def="y"
  case "$PROFILE" in minimal|passive) sh_def="n"; pt_def="n" ;; esac

  if [ "${CLI_SHANNON:-0}" -eq 0 ]; then
    if prompt_yes_no "Clonar e preparar Shannon (IAs/shannon)? (perfil: ${PROFILE})" "$sh_def"; then
      INSTALL_SHANNON=1
    else
      INSTALL_SHANNON=0
      log "Shannon: pulado por escolha."
    fi
  fi
  if [ "${CLI_PENTESTGPT:-0}" -eq 0 ]; then
    if prompt_yes_no "Clonar e preparar PentestGPT (IAs/PentestGPT)? (perfil: ${PROFILE})" "$pt_def"; then
      INSTALL_PENTESTGPT=1
    else
      INSTALL_PENTESTGPT=0
      log "PentestGPT: pulado por escolha."
    fi
  fi
}

usage() {
  cat <<'EOF'
Uso:
  ./install.sh [opcoes]

Perfis:
  --profile minimal   Instala Node, deps npm e base do projeto
  --profile passive   Minimal + ferramentas passivas/auxiliares
  --profile full      Passive + modo Kali + Playwright + IAs opcionais

Opcoes:
  --skip-ias          Nao clona/prepara Shannon nem PentestGPT (sem perguntar)
  --skip-shannon      Nao prepara Shannon (sem perguntar)
  --skip-pentestgpt   Nao prepara PentestGPT (sem perguntar)
  --skip-playwright   Nao instala Chromium do Playwright
  --skip-docker       Nao instala Docker (sem perguntar)
  --skip-supabase     Nao instala Supabase CLI global
  --skip-ghost-local  Nao prepara a IA local GHOST (ghost-local-v5)
  -y, --yes           Nao pergunta; usa os padroes atuais / flags --skip-*
  -h, --help          Mostra esta ajuda

Interativo:
  Em terminal (stdin TTY), pergunta por Docker, Shannon e PentestGPT em qualquer
  perfil — salvo -y/--yes ou --skip-* correspondente. Sem TTY, perfis minimal/passive
  nao incluem Shannon/Pentest por padrao; perfil full mantem inclusao por padrao.
EOF
}

# Sem TTY: minimal/passive nao puxam IAs por padrao (comportamento classico).
apply_profile_ia_defaults() {
  case "$PROFILE" in
    minimal|passive)
      [ "${CLI_SHANNON:-0}" -eq 0 ] && INSTALL_SHANNON=0
      [ "${CLI_PENTESTGPT:-0}" -eq 0 ] && INSTALL_PENTESTGPT=0
      ;;
  esac
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

set_env_key_if_missing() {
  local file="$1"
  local key="$2"
  local value="$3"
  touch "$file"
  if ! grep -Eq "^${key}=" "$file"; then
    printf '%s=%s\n' "$key" "$value" >>"$file"
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
    ca-certificates curl git jq unzip xz-utils gnupg lsb-release \
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
  if [ -f "$ROOT_DIR/.env" ] && [ "$INSTALL_GHOST_LOCAL" -eq 1 ]; then
    set_env_key_if_missing "$ROOT_DIR/.env" "GHOSTRECON_LMSTUDIO_ENABLED" "1"
    set_env_key_if_missing "$ROOT_DIR/.env" "GHOSTRECON_LMSTUDIO_BASE_URL" "http://127.0.0.1:8000/v1"
    set_env_key_if_missing "$ROOT_DIR/.env" "GHOSTRECON_LMSTUDIO_MODEL" "ghost"
    set_env_key_if_missing "$ROOT_DIR/.env" "GHOSTRECON_LMSTUDIO_API_KEY" "lm-studio"
  fi
}

prepare_ghost_local() {
  if [ "$INSTALL_GHOST_LOCAL" -ne 1 ]; then
    return
  fi
  local setup_script="$ROOT_DIR/ghost-local-v5/ghost-local/setup.sh"
  if [ ! -f "$setup_script" ]; then
    warn "ghost-local-v5 nao encontrado; pulando preparo da IA local."
    return
  fi
  log "Preparando GHOST local (venv + dependencias Python)"
  bash "$setup_script" --deps-only --skip-start
}

# CORRIGIDO: evita o erro de "externally-managed-environment" tentando uv primeiro,
# depois vai direto pro --break-system-packages sem exibir erro desnecessario.
install_xss_vibes_python() {
  [ -d "$XSS_DIR" ] || return
  log "Instalando dependencias Python do xss_vibes"

  local req="$XSS_DIR/requirements"

  if need_cmd uv; then
    log "Usando uv para instalar dependencias Python"
    uv pip install --system -r "$req" 2>/dev/null && return
  fi

  log "Usando pip com --break-system-packages"
  python3 -m pip install --user --break-system-packages -r "$req"
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
  if [ "${INSTALL_SHANNON:-0}" -ne 1 ]; then
    return
  fi
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
  if [ "${INSTALL_PENTESTGPT:-0}" -ne 1 ]; then
    return
  fi
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

# CORRIGIDO: npm install -g supabase nao e suportado pela CLI do Supabase.
# Agora baixa o .deb diretamente do GitHub releases.
install_supabase_cli() {
  if [ "$INSTALL_SUPABASE" -ne 1 ]; then
    return
  fi
  if need_cmd supabase; then
    log "Supabase CLI ja esta no PATH"
    return
  fi

  log "Instalando Supabase CLI via GitHub releases"

  local latest_tag
  latest_tag="$(curl -fsSL https://api.github.com/repos/supabase/cli/releases/latest \
    | jq -r '.tag_name')"

  if [ -z "$latest_tag" ] || [ "$latest_tag" = "null" ]; then
    warn "Nao foi possivel obter a versao mais recente do Supabase CLI. Pulando."
    return
  fi

  local version="${latest_tag#v}"
  local tmp_deb
  tmp_deb="$(mktemp /tmp/supabase_XXXXXX.deb)"

  log "Baixando supabase ${latest_tag}"
  if curl -fsSL \
    "https://github.com/supabase/cli/releases/download/${latest_tag}/supabase_${version}_linux_amd64.deb" \
    -o "$tmp_deb"; then
    run_sudo dpkg -i "$tmp_deb"
    rm -f "$tmp_deb"
  else
    rm -f "$tmp_deb"
    warn "Falha ao baixar Supabase CLI. Instale manualmente: https://github.com/supabase/cli#install-the-cli"
  fi
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
      INSTALL_SHANNON=0
      INSTALL_PENTESTGPT=0
      CLI_SHANNON=1
      CLI_PENTESTGPT=1
      ;;
    --skip-shannon)
      INSTALL_SHANNON=0
      CLI_SHANNON=1
      ;;
    --skip-pentestgpt)
      INSTALL_PENTESTGPT=0
      CLI_PENTESTGPT=1
      ;;
    --skip-playwright)
      INSTALL_PLAYWRIGHT=0
      ;;
    --skip-docker)
      INSTALL_DOCKER=0
      CLI_DOCKER=1
      ;;
    --skip-supabase)
      INSTALL_SUPABASE=0
      ;;
    --skip-ghost-local)
      INSTALL_GHOST_LOCAL=0
      ;;
    -y|--yes)
      ASSUME_DEFAULTS=1
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

apply_profile_ia_defaults

detect_debian_like || die "Este instalador foi feito para Debian/Kali."
need_cmd apt-get || die "apt-get nao encontrado."

prompt_optional_installs

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

prepare_shannon
prepare_pentestgpt

if [ "$PROFILE" = "full" ]; then
  install_apt_security_tools
  install_playwright
  prepare_ghost_local
fi

verify_install

cat <<'EOF'

Instalacao concluida.

Notas:
  - Abra um novo terminal para garantir o PATH atualizado no bash/zsh.
  - Se o Docker foi instalado agora, talvez precise relogar para o grupo docker surtir efeito.
  - O arquivo .env foi copiado do exemplo se nao existia; preencha as chaves/API keys antes de usar tudo.
  - PentestGPT e Shannon podem exigir configuracoes adicionais e credenciais proprias.
  - Modo interativo: em TTY pergunta por Docker, Shannon e PentestGPT em qualquer perfil; use -y para pular perguntas.

Comandos uteis:
  npm start
  npm run start:api
  npm run start:ghost
  npm test
  npm run db:link
  npm run db:push
EOF
