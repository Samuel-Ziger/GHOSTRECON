#!/usr/bin/env bash
# Instala/verifica Vigolium para o runtime GHOSTRECON.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$ROOT/engines/vigolium"
CODEX_DESKTOP_DIR="${CODEX_DESKTOP_LINUX_DIR:-$ROOT/IAs/codex-desktop-linux}"
mkdir -p "$ROOT/engines" "$ROOT/IAs"

ask_yes_no() {
  local prompt="$1"
  local default="${2:-N}"
  if [[ ! -t 0 ]]; then
    [[ "$default" =~ ^[Yy]$ ]]
    return
  fi
  local answer
  read -r -p "$prompt " answer || answer=""
  answer="${answer:-$default}"
  [[ "$answer" =~ ^[Yy]$ ]]
}

resolve_src() {
  if [[ -n "${GHOSTRECON_VIGOLIUM_SRC:-}" && -x "${GHOSTRECON_VIGOLIUM_SRC}" ]]; then
    echo "$GHOSTRECON_VIGOLIUM_SRC"
    return
  fi
  if command -v vigolium >/dev/null 2>&1; then
    command -v vigolium
    return
  fi
  if [[ -x "$ROOT/vigolium/bin/vigolium" ]]; then
    echo "$ROOT/vigolium/bin/vigolium"
    return
  fi
  echo ""
}

install_vigolium_path() {
  echo "Instalando Vigolium no PATH com:"
  echo "  curl -fsSL https://vigolium.com/install.sh | bash"
  curl -fsSL https://vigolium.com/install.sh | bash
  hash -r 2>/dev/null || true
}

setup_codex_linux() {
  echo
  echo "Codex para Vigolium IA:"
  echo "  - requer Codex CLI/login funcional e plano/acesso habilitado pela OpenAI."
  echo "  - o wrapper ilysenko/codex-desktop-linux e nao oficial e nao libera acesso por conta propria."
  echo "  - depois valide com: codex login && codex exec 'hello'"
  echo

  if ! command -v git >/dev/null 2>&1; then
    echo "git nao encontrado; pulei clone do codex-desktop-linux." >&2
    return
  fi

  if [[ -d "$CODEX_DESKTOP_DIR/.git" ]]; then
    echo "Atualizando $CODEX_DESKTOP_DIR"
    git -C "$CODEX_DESKTOP_DIR" pull --ff-only || true
  else
    echo "Clonando codex-desktop-linux em $CODEX_DESKTOP_DIR"
    git clone https://github.com/ilysenko/codex-desktop-linux.git "$CODEX_DESKTOP_DIR"
  fi

  if [[ "$(uname -s 2>/dev/null || echo unknown)" != "Linux" ]]; then
    echo "Ambiente nao-Linux detectado; clone pronto, mas setup-native deve ser rodado no Linux/Kali."
    return
  fi

  if command -v make >/dev/null 2>&1; then
    echo "Setup sugerido do wrapper:"
    echo "  cd \"$CODEX_DESKTOP_DIR\" && make bootstrap-native"
    echo "  cd \"$CODEX_DESKTOP_DIR\" && make setup-native"
    if [[ "${GHOSTRECON_CODEX_DESKTOP_SETUP:-0}" == "1" ]] || ask_yes_no "Rodar make bootstrap-native agora? [y/N]" "N"; then
      make -C "$CODEX_DESKTOP_DIR" bootstrap-native
    fi
  else
    echo "make nao encontrado; clone pronto. Instale make/build deps antes de setup-native."
  fi

  echo
  echo "Para usar no GhostRecon/Vigolium:"
  echo "  export GHOSTRECON_VIGOLIUM_USE_CODEX=1"
  echo "  export VIGOLIUM_PROVIDER=openai-codex-oauth"
}

SRC="$(resolve_src)"
if [[ -z "$SRC" ]]; then
  echo "install-vigolium-engine: binario vigolium nao encontrado no PATH/fonte local." >&2
  if [[ "${GHOSTRECON_INSTALL_VIGOLIUM_PATH:-0}" == "1" ]] || ask_yes_no "Instalar Vigolium no PATH agora? curl -fsSL https://vigolium.com/install.sh | bash [y/N]" "N"; then
    install_vigolium_path
    SRC="$(resolve_src)"
  fi
fi

if [[ -z "$SRC" ]]; then
  echo "Nao foi possivel localizar vigolium apos a instalacao." >&2
  echo "Instale manualmente: curl -fsSL https://vigolium.com/install.sh | bash" >&2
  exit 1
fi

cp -f "$SRC" "$DEST"
chmod +x "$DEST"
echo "OK: $DEST <- $SRC"
"$DEST" version 2>/dev/null | head -3 || true

echo
echo "Modo Kali/PATH:"
echo "  Na UI marque 'Modo Vigolium PATH (Kali)' ou use GHOSTRECON_VIGOLIUM_PREFER_PATH=1."
echo "  Se vigolium estiver no PATH, o GhostRecon roda o binario instalado; se nao estiver, usa engines/vigolium."

if [[ "${GHOSTRECON_INSTALL_CODEX:-0}" == "1" ]] || ask_yes_no "Quer preparar Codex para agents IA do Vigolium? [y/N]" "N"; then
  setup_codex_linux
fi
