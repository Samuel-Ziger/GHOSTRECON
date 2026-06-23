#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║            MetaAutoRecon v2.0 — Automated Recon for Metasploit          ║
# ║                                                                          ║
# ║  Funções : Host discovery · Port scan · Service enum · Version detect   ║
# ║            Risk scoring · CVE lookup · MSF module suggestions           ║
# ║            Importação automática para workspace Metasploit              ║
# ║                                                                          ║
# ║  AVISO LEGAL: Use exclusivamente em ambientes autorizados.              ║
# ║  Lei 12.737/2012 · Marco Civil da Internet (12.965/2014) · LGPD        ║
# ╚══════════════════════════════════════════════════════════════════════════╝

set -euo pipefail
IFS=$'\n\t'

# ═══════════════════════════════════════════════════════════════════════════
#  SEÇÃO 1 — CONFIGURAÇÃO GLOBAL
# ═══════════════════════════════════════════════════════════════════════════

VERSION="2.0"
TOOL_NAME="MetaAutoRecon"

# Diretórios
BASE_DIR="${HOME}/.metaautorecon"
LOG_DIR="${BASE_DIR}/logs"
REPORT_DIR="${BASE_DIR}/reports"
SCAN_DIR="${BASE_DIR}/scans"
RC_DIR="${BASE_DIR}/resources"

# Variáveis de estado
TARGET=""
WORKSPACE="recon_$(date +%Y%m%d)"
LHOST=""
SCAN_XML=""
SCAN_LOG=""
VERBOSE=false
DRY_RUN=false
AUTHORIZED=false
TOTAL_RISK=0
declare -a HOSTS_FOUND=()
declare -a OPEN_PORTS=()
declare -a SERVICES_FOUND=()
declare -a CVES_FOUND=()
declare -a MODULES_SUGGESTED=()

# ═══════════════════════════════════════════════════════════════════════════
#  SEÇÃO 2 — CORES & UI
# ═══════════════════════════════════════════════════════════════════════════

R="\033[0m"
BOLD="\033[1m"
DIM="\033[2m"
BLINK="\033[5m"

BLACK="\033[0;30m";  BBLACK="\033[1;30m"
RED="\033[0;31m";    BRED="\033[1;31m"
GREEN="\033[0;32m";  BGREEN="\033[1;32m"
YELLOW="\033[0;33m"; BYELLOW="\033[1;33m"
BLUE="\033[0;34m";   BBLUE="\033[1;34m"
MAGENTA="\033[0;35m";BMAGENTA="\033[1;35m"
CYAN="\033[0;36m";   BCYAN="\033[1;36m"
WHITE="\033[0;37m";  BWHITE="\033[1;37m"

# Sem cor quando não for terminal
[[ ! -t 1 ]] && { R=""; BOLD=""; DIM=""; BLINK=""; BLACK=""; BBLACK=""
    RED=""; BRED=""; GREEN=""; BGREEN=""; YELLOW=""; BYELLOW=""
    BLUE=""; BBLUE=""; MAGENTA=""; BMAGENTA=""; CYAN=""; BCYAN=""
    WHITE=""; BWHITE=""; }

# ── Ícones & prefixos ─────────────────────────────────────────
OK()    { echo -e "  ${BGREEN}[✔]${R}  $*"; }
WARN()  { echo -e "  ${BYELLOW}[!]${R}  $*"; }
ERR()   { echo -e "  ${BRED}[✘]${R}  $*"; }
INFO()  { echo -e "  ${CYAN}[~]${R}  $*"; }
RUN()   { echo -e "  ${BBLUE}[▶]${R}  ${DIM}$*${R}"; }
FOUND() { echo -e "  ${BMAGENTA}[◆]${R}  $*"; }
CVE()   { echo -e "  ${BRED}[CVE]${R} $*"; }
MOD()   { echo -e "  ${BCYAN}[MSF]${R} $*"; }

sep()   { echo -e "  ${DIM}$(printf '─%.0s' {1..68})${R}"; }
nl()    { echo ""; }

# ═══════════════════════════════════════════════════════════════════════════
#  SEÇÃO 3 — BANNER & STATUS
# ═══════════════════════════════════════════════════════════════════════════

print_banner() {
    clear
    echo -e "${BRED}"
    cat << 'BANNER'
  ███╗   ███╗███████╗████████╗ █████╗      █████╗ ██╗   ██╗████████╗ ██████╗
  ████╗ ████║██╔════╝╚══██╔══╝██╔══██╗    ██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗
  ██╔████╔██║█████╗     ██║   ███████║    ███████║██║   ██║   ██║   ██║   ██║
  ██║╚██╔╝██║██╔══╝     ██║   ██╔══██║    ██╔══██║██║   ██║   ██║   ██║   ██║
  ██║ ╚═╝ ██║███████╗   ██║   ██║  ██║    ██║  ██║╚██████╔╝   ██║   ╚██████╔╝
  ╚═╝     ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝    ╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝
BANNER
    echo -e "${R}"
    echo -e "  ${DIM}██████████████████████████████████████████████████████████████████████${R}"
    echo -e "  ${BBLACK}  Automated Recon · Metasploit Workspace Import · Risk Scoring · v${VERSION}${R}"
    echo -e "  ${DIM}██████████████████████████████████████████████████████████████████████${R}"
    nl
}

print_status_bar() {
    local risk_color="${BGREEN}"
    (( TOTAL_RISK >= 40 )) && risk_color="${BYELLOW}"
    (( TOTAL_RISK >= 70 )) && risk_color="${BRED}"

    local db_status
    db_status=$(check_db_status)

    echo -e "  ${DIM}┌─ STATUS ─────────────────────────────────────────────────────────┐${R}"
    printf "  ${DIM}│${R}  %-14s ${BYELLOW}%-20s${R}  %-8s ${BCYAN}%-18s${R}  ${DIM}│${R}\n" \
        "Target:" "${TARGET:-não definido}" "LHOST:" "${LHOST:-auto}"
    printf "  ${DIM}│${R}  %-14s ${BWHITE}%-20s${R}  %-8s ${db_status}%-14s${R}  ${DIM}│${R}\n" \
        "Workspace:" "$WORKSPACE" "DB:" ""
    printf "  ${DIM}│${R}  %-14s ${risk_color}%-3s/100${R}  %-9s ${DIM}%s${R}  %-16s ${DIM}%s${R}    ${DIM}│${R}\n" \
        "Risk Score:" "$TOTAL_RISK" "Hosts:" "${#HOSTS_FOUND[@]}" "CVEs:" "${#CVES_FOUND[@]}"
    echo -e "  ${DIM}└──────────────────────────────────────────────────────────────────┘${R}"
    nl
}

print_main_menu() {
    print_banner
    print_status_bar
    echo -e "  ${BOLD}${BCYAN}╔══════════════════════════════════════════════════╗${R}"
    echo -e "  ${BCYAN}║           MENU PRINCIPAL — MetaAutoRecon          ║${R}"
    echo -e "  ${BCYAN}╠══════════════════════════════════════════════════╣${R}"
    echo -e "  ${BCYAN}║${R}  ${BYELLOW}[1]${R}  Configurar Alvo & Ambiente               ${BCYAN}║${R}"
    echo -e "  ${BCYAN}║${R}  ${BYELLOW}[2]${R}  Reconhecimento Completo (auto pipeline)  ${BCYAN}║${R}"
    echo -e "  ${BCYAN}║${R}  ${BYELLOW}[3]${R}  Scans Individuais                        ${BCYAN}║${R}"
    echo -e "  ${BCYAN}║${R}  ${BYELLOW}[4]${R}  Importar para Metasploit DB              ${BCYAN}║${R}"
    echo -e "  ${BCYAN}║${R}  ${BYELLOW}[5]${R}  Analisar Resultados & Risk Score         ${BCYAN}║${R}"
    echo -e "  ${BCYAN}║${R}  ${BYELLOW}[6]${R}  Dashboard Hacker                         ${BCYAN}║${R}"
    echo -e "  ${BCYAN}║${R}  ${BYELLOW}[7]${R}  Relatório Completo                       ${BCYAN}║${R}"
    echo -e "  ${BCYAN}║${R}  ${BYELLOW}[8]${R}  Verificar Dependências                   ${BCYAN}║${R}"
    echo -e "  ${BCYAN}║${R}  ${BRED}[0]${R}  Sair                                     ${BCYAN}║${R}"
    echo -e "  ${BOLD}${BCYAN}╚══════════════════════════════════════════════════╝${R}"
    nl
}

# ═══════════════════════════════════════════════════════════════════════════
#  SEÇÃO 4 — UTILITÁRIOS
# ═══════════════════════════════════════════════════════════════════════════

ts()         { date '+%Y%m%d_%H%M%S'; }
ts_human()   { date '+%d/%m/%Y %H:%M:%S'; }
press_enter(){ nl; read -rp "$(echo -e "  ${DIM}Pressione ENTER para continuar...${R}")" _; }

confirm() {
    read -rp "$(echo -e "  ${BYELLOW}${1:-Confirma?} [s/N]: ${R}")" r
    [[ "${r,,}" == "s" ]]
}

require_target() {
    if [[ -z "$TARGET" ]]; then
        WARN "Nenhum alvo definido. Configure em [1]."; press_enter; return 1
    fi
}

get_local_ip() {
    ip route get 1.1.1.1 2>/dev/null \
        | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' \
        || hostname -I 2>/dev/null | awk '{print $1}' \
        || echo "127.0.0.1"
}

check_db_status() {
    if command -v msfdb &>/dev/null 2>&1; then
        if msfdb status 2>/dev/null | grep -qi "connected\|running\|started"; then
            echo -e "${BGREEN}online   ${R}"
            return
        fi
    fi
    echo -e "${BRED}offline  ${R}"
}

log() {
    local level="$1"; shift
    echo "[$(ts_human)] [$level] $*" >> "$SCAN_LOG" 2>/dev/null || true
}

run_cmd() {
    local cmd="$*"
    RUN "$cmd"
    log "RUN" "$cmd"
    if [[ "$DRY_RUN" == "true" ]]; then
        WARN "[DRY-RUN] Comando não executado."
        return 0
    fi
    eval "$cmd"
}

# ═══════════════════════════════════════════════════════════════════════════
#  SEÇÃO 5 — VERIFICAÇÃO DE DEPENDÊNCIAS
# ═══════════════════════════════════════════════════════════════════════════

check_dependencies() {
    nl
    echo -e "  ${BOLD}${BCYAN}── Verificando Dependências ──────────────────────────────────${R}"
    nl

    local critical=(nmap msfconsole msfvenom)
    local optional=(msfdb jq curl python3 xmllint)
    local missing_critical=0

    echo -e "  ${BOLD}Críticas:${R}"
    for dep in "${critical[@]}"; do
        if command -v "$dep" &>/dev/null; then
            OK "${dep} $(command -v "$dep")"
        else
            ERR "${dep} — ${BRED}NÃO ENCONTRADO${R}"
            (( missing_critical++ ))
        fi
    done

    nl
    echo -e "  ${BOLD}Opcionais:${R}"
    for dep in "${optional[@]}"; do
        if command -v "$dep" &>/dev/null; then
            OK "${dep}"
        else
            WARN "${dep} — não encontrado ${DIM}(funcionalidades limitadas)${R}"
        fi
    done

    nl
    if command -v msfdb &>/dev/null; then
        echo -e "  ${BOLD}Banco de Dados MSF:${R}"
        msfdb status 2>&1 | while IFS= read -r line; do
            INFO "$line"
        done
    fi

    if (( missing_critical > 0 )); then
        nl
        ERR "Instale as dependências críticas antes de continuar:"
        INFO "  sudo apt update && sudo apt install -y metasploit-framework nmap"
    fi

    nl
    press_enter
}

# ═══════════════════════════════════════════════════════════════════════════
#  SEÇÃO 6 — CONFIGURAÇÃO DE ALVO
# ═══════════════════════════════════════════════════════════════════════════

menu_config() {
    clear
    echo -e "  ${BOLD}${BCYAN}── Configurar Alvo & Ambiente ────────────────────────────────${R}"
    nl

    # Aviso legal obrigatório
    if [[ "$AUTHORIZED" == "false" ]]; then
        echo -e "  ${BRED}╔═══════════════════════════════════════════════════════╗${R}"
        echo -e "  ${BRED}║           ⚠  AVISO LEGAL OBRIGATÓRIO  ⚠              ║${R}"
        echo -e "  ${BRED}╠═══════════════════════════════════════════════════════╣${R}"
        echo -e "  ${BRED}║${R}  Esta ferramenta é para uso em:                        ${BRED}║${R}"
        echo -e "  ${BRED}║${R}   • Redes e sistemas próprios                          ${BRED}║${R}"
        echo -e "  ${BRED}║${R}   • Ambientes com autorização formal e documentada     ${BRED}║${R}"
        echo -e "  ${BRED}║${R}   • Laboratórios: HackTheBox, TryHackMe, VMs locais    ${BRED}║${R}"
        echo -e "  ${BRED}║${R}                                                         ${BRED}║${R}"
        echo -e "  ${BRED}║${R}  Uso não autorizado é crime:                            ${BRED}║${R}"
        echo -e "  ${BRED}║${R}   • Lei 12.737/2012 — até 3 anos de reclusão           ${BRED}║${R}"
        echo -e "  ${BRED}║${R}   • Marco Civil da Internet — Lei 12.965/2014           ${BRED}║${R}"
        echo -e "  ${BRED}╚═══════════════════════════════════════════════════════╝${R}"
        nl
        read -rp "$(echo -e "  ${BYELLOW}Confirmo autorização para testar este alvo [s/N]: ${R}")" ack
        if [[ "${ack,,}" != "s" ]]; then
            WARN "Não confirmado. Retornando ao menu."; press_enter; return
        fi
        AUTHORIZED=true
    fi

    nl
    read -rp "$(echo -e "  Alvo IP/CIDR/hostname [${TARGET:-ex: 192.168.1.0/24}]: ")" t
    [[ -n "$t" ]] && TARGET="$t"

    read -rp "$(echo -e "  LHOST — seu IP [$(get_local_ip)]: ")" lh
    LHOST="${lh:-$(get_local_ip)}"

    read -rp "$(echo -e "  Workspace MSF [${WORKSPACE}]: ")" ws
    [[ -n "$ws" ]] && WORKSPACE="$ws"

    # Inicializa arquivos de saída
    SCAN_XML="${SCAN_DIR}/${TARGET//\//_}_$(ts).xml"
    SCAN_LOG="${LOG_DIR}/recon_$(ts).log"

    nl
    OK "Alvo     : ${BYELLOW}${TARGET}${R}"
    OK "LHOST    : ${BCYAN}${LHOST}${R}"
    OK "Workspace: ${BWHITE}${WORKSPACE}${R}"
    OK "Scan XML : ${DIM}${SCAN_XML}${R}"
    log "INFO" "Configuração: TARGET=$TARGET LHOST=$LHOST WS=$WORKSPACE"
    press_enter
}

# ═══════════════════════════════════════════════════════════════════════════
#  SEÇÃO 7 — FUNÇÕES DE SCAN
# ═══════════════════════════════════════════════════════════════════════════

# ── 7.1 Ping sweep — hosts ativos ────────────────────────────
scan_host_discovery() {
    require_target || return
    nl
    echo -e "  ${BOLD}${BCYAN}── Host Discovery ────────────────────────────────────────────${R}"
    INFO "Identificando hosts ativos em: ${BYELLOW}${TARGET}${R}"
    nl

    local out_file="${SCAN_DIR}/discovery_${TARGET//\//_}_$(ts)"
    local cmd="nmap -sn -T4 --open -oG ${out_file}.gnmap -oX ${out_file}.xml ${TARGET}"
    run_cmd "$cmd"

    # Parsear hosts encontrados
    HOSTS_FOUND=()
    if [[ -f "${out_file}.gnmap" ]]; then
        while IFS= read -r line; do
            if echo "$line" | grep -q "Status: Up"; then
                local ip
                ip=$(echo "$line" | awk '{print $2}')
                HOSTS_FOUND+=("$ip")
                FOUND "Host ativo: ${BGREEN}${ip}${R}"
            fi
        done < "${out_file}.gnmap"
    fi

    nl
    OK "${#HOSTS_FOUND[@]} host(s) encontrado(s)."
    log "INFO" "Host discovery: ${#HOSTS_FOUND[@]} hosts ativos"
    press_enter
}

# ── 7.2 Port scan ─────────────────────────────────────────────
scan_ports() {
    require_target || return
    nl
    echo -e "  ${BOLD}${BCYAN}── Port Scan ─────────────────────────────────────────────────${R}"
    nl
    echo -e "  ${BYELLOW}[1]${R}  Rápido (top 1000 portas TCP)"
    echo -e "  ${BYELLOW}[2]${R}  Completo (todas as 65535 portas TCP)"
    echo -e "  ${BYELLOW}[3]${R}  TCP + UDP principais"
    read -rp "$(echo -e "  Escolha [1]: ")" ps
    ps="${ps:-1}"

    local out_file="${SCAN_DIR}/ports_${TARGET//\//_}_$(ts)"
    local cmd

    case "$ps" in
        1) cmd="nmap -T4 --open -oX ${out_file}.xml -oN ${out_file}.txt ${TARGET}" ;;
        2) cmd="nmap -T4 -p- --open -oX ${out_file}.xml -oN ${out_file}.txt ${TARGET}" ;;
        3) cmd="nmap -T4 -p- -sU --top-ports 100 --open -oX ${out_file}.xml -oN ${out_file}.txt ${TARGET}" ;;
        *) WARN "Opção inválida."; press_enter; return ;;
    esac

    SCAN_XML="${out_file}.xml"
    run_cmd "$cmd"

    _parse_open_ports "${out_file}.xml"
    _display_port_table

    log "INFO" "Port scan: ${#OPEN_PORTS[@]} portas abertas"
    press_enter
}

# ── 7.3 Service & Version Detection ───────────────────────────
scan_services() {
    require_target || return
    nl
    echo -e "  ${BOLD}${BCYAN}── Detecção de Serviços & Versões ───────────────────────────${R}"
    nl

    read -rp "$(echo -e "  Portas específicas (ex: 22,80,443) ou ENTER para automático: ")" ports_in
    local port_arg=""
    [[ -n "$ports_in" ]] && port_arg="-p ${ports_in}"

    local out_file="${SCAN_DIR}/services_${TARGET//\//_}_$(ts)"
    SCAN_XML="${out_file}.xml"

    local cmd="nmap -sV -sC ${port_arg} --version-intensity 7 --open -oX ${out_file}.xml -oN ${out_file}.txt ${TARGET}"
    run_cmd "$cmd"

    _parse_services "${out_file}.xml"
    _display_service_table

    log "INFO" "Service scan completo: ${#SERVICES_FOUND[@]} serviços detectados"
    press_enter
}

# ── 7.4 NSE — Scripts de segurança ───────────────────────────
scan_nse() {
    require_target || return
    nl
    echo -e "  ${BOLD}${BCYAN}── NSE — Scripts de Segurança ───────────────────────────────${R}"
    nl
    echo -e "  ${BYELLOW}[1]${R}  default + safe (recomendado)"
    echo -e "  ${BYELLOW}[2]${R}  smb-security-mode · smb2-security-mode"
    echo -e "  ${BYELLOW}[3]${R}  http-title · http-headers · http-methods"
    echo -e "  ${BYELLOW}[4]${R}  ssh-hostkey · ssh-auth-methods"
    echo -e "  ${BYELLOW}[5]${R}  ftp-anon · ftp-syst"
    echo -e "  ${BYELLOW}[6]${R}  ssl-cert · ssl-enum-ciphers"
    read -rp "$(echo -e "  Escolha [1]: ")" nse_opt
    nse_opt="${nse_opt:-1}"

    local scripts
    case "$nse_opt" in
        1) scripts="default,safe" ;;
        2) scripts="smb-security-mode,smb2-security-mode,smb-os-discovery" ;;
        3) scripts="http-title,http-headers,http-methods,http-server-header" ;;
        4) scripts="ssh-hostkey,ssh-auth-methods" ;;
        5) scripts="ftp-anon,ftp-syst,ftp-bounce" ;;
        6) scripts="ssl-cert,ssl-enum-ciphers,ssl-date" ;;
        *) WARN "Opção inválida."; press_enter; return ;;
    esac

    local out_file="${SCAN_DIR}/nse_${TARGET//\//_}_$(ts)"
    local cmd="nmap -sV --script=${scripts} --open -oX ${out_file}.xml -oN ${out_file}.txt ${TARGET}"
    run_cmd "$cmd"

    _parse_services "${out_file}.xml"
    log "INFO" "NSE scan: scripts=${scripts}"
    press_enter
}

# ── 7.5 Pipeline Completo ─────────────────────────────────────
scan_full_pipeline() {
    require_target || return
    nl
    echo -e "  ${BOLD}${BCYAN}╔══════════════════════════════════════════════════╗${R}"
    echo -e "  ${BCYAN}║    PIPELINE COMPLETO DE RECONHECIMENTO           ║${R}"
    echo -e "  ${BCYAN}╠══════════════════════════════════════════════════╣${R}"
    echo -e "  ${BCYAN}║${R}  1. Host Discovery                               ${BCYAN}║${R}"
    echo -e "  ${BCYAN}║${R}  2. Port Scan (top 1000)                          ${BCYAN}║${R}"
    echo -e "  ${BCYAN}║${R}  3. Service & Version Detection                   ${BCYAN}║${R}"
    echo -e "  ${BCYAN}║${R}  4. NSE Scripts (default+safe)                    ${BCYAN}║${R}"
    echo -e "  ${BCYAN}║${R}  5. Importar para Metasploit DB                   ${BCYAN}║${R}"
    echo -e "  ${BCYAN}║${R}  6. Risk Scoring & CVE Lookup                     ${BCYAN}║${R}"
    echo -e "  ${BCYAN}║${R}  7. Sugestão de Módulos MSF                       ${BCYAN}║${R}"
    echo -e "  ${BOLD}${BCYAN}╚══════════════════════════════════════════════════╝${R}"
    nl

    if ! confirm "Iniciar pipeline completo para ${BYELLOW}${TARGET}${R}?"; then
        return
    fi

    local ts_run
    ts_run=$(ts)
    local out_base="${SCAN_DIR}/full_${TARGET//\//_}_${ts_run}"
    SCAN_XML="${out_base}.xml"

    # FASE 1 — Host Discovery
    nl
    echo -e "  ${BMAGENTA}[FASE 1/6]${R} Host Discovery..."
    sep
    if [[ "$DRY_RUN" == "true" ]]; then
        WARN "[DRY-RUN] nmap -sn -T4 ${TARGET}"
    else
        nmap -sn -T4 --open \
            -oG "${out_base}_discovery.gnmap" \
            -oX "${out_base}_discovery.xml" \
            "$TARGET" 2>&1 | _live_filter
        _parse_hosts_from_gnmap "${out_base}_discovery.gnmap"
    fi
    OK "${#HOSTS_FOUND[@]} host(s) ativo(s)"

    # FASE 2 — Port Scan
    nl
    echo -e "  ${BMAGENTA}[FASE 2/6]${R} Port Scan (top 1000)..."
    sep
    if [[ "$DRY_RUN" == "true" ]]; then
        WARN "[DRY-RUN] nmap -T4 --open ${TARGET}"
    else
        nmap -T4 --open \
            -oX "${out_base}_ports.xml" \
            -oN "${out_base}_ports.txt" \
            "$TARGET" 2>&1 | _live_filter
        _parse_open_ports "${out_base}_ports.xml"
    fi
    OK "${#OPEN_PORTS[@]} porta(s) aberta(s)"

    # FASE 3 — Service Detection
    nl
    echo -e "  ${BMAGENTA}[FASE 3/6]${R} Detecção de Versões..."
    sep
    if [[ "$DRY_RUN" == "true" ]]; then
        WARN "[DRY-RUN] nmap -sV -sC --open ${TARGET}"
    else
        nmap -sV -sC --version-intensity 5 --open \
            -oX "$SCAN_XML" \
            -oN "${out_base}.txt" \
            "$TARGET" 2>&1 | _live_filter
        _parse_services "$SCAN_XML"
    fi
    OK "${#SERVICES_FOUND[@]} serviço(s) detectado(s)"

    # FASE 4 — NSE
    nl
    echo -e "  ${BMAGENTA}[FASE 4/6]${R} NSE Scripts (safe)..."
    sep
    if [[ "$DRY_RUN" == "true" ]]; then
        WARN "[DRY-RUN] nmap --script=default,safe ${TARGET}"
    else
        nmap --script="default,safe" --open \
            -oX "${out_base}_nse.xml" \
            -oN "${out_base}_nse.txt" \
            "$TARGET" 2>&1 | _live_filter
    fi
    OK "NSE concluído"

    # FASE 5 — Import MSF
    nl
    echo -e "  ${BMAGENTA}[FASE 5/6]${R} Importando para Metasploit DB..."
    sep
    import_to_msf_silent

    # FASE 6 — Análise
    nl
    echo -e "  ${BMAGENTA}[FASE 6/6]${R} Calculando Risk Score & CVEs..."
    sep
    calculate_risk_score
    lookup_cves
    suggest_msf_modules

    nl
    echo -e "  ${BGREEN}╔══════════════════════════════════════════════════╗${R}"
    echo -e "  ${BGREEN}║         PIPELINE CONCLUÍDO COM SUCESSO!          ║${R}"
    echo -e "  ${BGREEN}╚══════════════════════════════════════════════════╝${R}"
    nl
    OK "Hosts encontrados : ${BGREEN}${#HOSTS_FOUND[@]}${R}"
    OK "Portas abertas    : ${BYELLOW}${#OPEN_PORTS[@]}${R}"
    OK "Serviços detectados: ${BCYAN}${#SERVICES_FOUND[@]}${R}"
    OK "Risk Score        : $(_risk_color "${TOTAL_RISK}")${TOTAL_RISK}/100${R}"
    OK "CVEs identificados: ${BRED}${#CVES_FOUND[@]}${R}"
    OK "Módulos sugeridos : ${BMAGENTA}${#MODULES_SUGGESTED[@]}${R}"
    nl
    INFO "Use [6] Dashboard para visualizar os resultados."
    press_enter
}

# ── Filtro live output ────────────────────────────────────────
_live_filter() {
    while IFS= read -r line; do
        [[ "$line" =~ ^# ]] && continue
        [[ -z "$line" ]] && continue
        echo -e "    ${DIM}${line}${R}"
    done
}

# ═══════════════════════════════════════════════════════════════════════════
#  SEÇÃO 8 — PARSERS DE RESULTADO
# ═══════════════════════════════════════════════════════════════════════════

# ── Parsear hosts do .gnmap ───────────────────────────────────
_parse_hosts_from_gnmap() {
    local gnmap_file="$1"
    HOSTS_FOUND=()
    [[ ! -f "$gnmap_file" ]] && return
    while IFS= read -r line; do
        if echo "$line" | grep -q "Status: Up"; then
            local ip
            ip=$(echo "$line" | awk '{print $2}')
            HOSTS_FOUND+=("$ip")
        fi
    done < "$gnmap_file"
}

# ── Parsear portas abertas do XML ─────────────────────────────
_parse_open_ports() {
    local xml_file="$1"
    OPEN_PORTS=()
    [[ ! -f "$xml_file" ]] && return
    while IFS= read -r line; do
        if echo "$line" | grep -q 'state="open"'; then
            local port
            port=$(echo "$line" | grep -oP 'portid="\K[0-9]+')
            local proto
            proto=$(echo "$line" | grep -oP 'protocol="\K[^"]+')
            [[ -n "$port" ]] && OPEN_PORTS+=("${proto}/${port}")
        fi
    done < "$xml_file"
}

# ── Parsear serviços do XML ───────────────────────────────────
_parse_services() {
    local xml_file="$1"
    SERVICES_FOUND=()
    [[ ! -f "$xml_file" ]] && return

    local current_host=""
    local current_port=""
    local current_proto=""

    while IFS= read -r line; do
        # Captura IP do host
        if echo "$line" | grep -q '<address addr='; then
            current_host=$(echo "$line" | grep -oP 'addr="\K[0-9.]+(?=")')
        fi
        # Captura porta aberta
        if echo "$line" | grep -q 'state="open"'; then
            current_port=$(echo "$line" | grep -oP 'portid="\K[0-9]+')
            current_proto=$(echo "$line" | grep -oP 'protocol="\K[^"]+')
        fi
        # Captura serviço/versão
        if echo "$line" | grep -q '<service '; then
            local name product version extra
            name=$(echo "$line"    | grep -oP 'name="\K[^"]+' || echo "")
            product=$(echo "$line" | grep -oP 'product="\K[^"]+' || echo "")
            version=$(echo "$line" | grep -oP 'version="\K[^"]+' || echo "")
            [[ -z "$name" ]] && continue
            local svc_entry="${current_host}:${current_port}/${current_proto} ${name} ${product} ${version}"
            SERVICES_FOUND+=("$svc_entry")
        fi
    done < "$xml_file"
}

# ── Tabela de portas abertas ──────────────────────────────────
_display_port_table() {
    [[ ${#OPEN_PORTS[@]} -eq 0 ]] && { WARN "Nenhuma porta aberta detectada."; return; }
    nl
    echo -e "  ${BOLD}Portas Abertas:${R}"
    sep
    printf "  ${DIM}%-12s  %-8s  %-20s${R}\n" "PROTOCOLO" "PORTA" "STATUS"
    sep
    for p in "${OPEN_PORTS[@]}"; do
        local proto="${p%%/*}"
        local port="${p##*/}"
        printf "  ${BCYAN}%-12s${R}  ${BGREEN}%-8s${R}  ${BGREEN}%-20s${R}\n" "$proto" "$port" "open"
    done
    sep
}

# ── Tabela de serviços ────────────────────────────────────────
_display_service_table() {
    [[ ${#SERVICES_FOUND[@]} -eq 0 ]] && { WARN "Nenhum serviço detectado."; return; }
    nl
    echo -e "  ${BOLD}Serviços Detectados:${R}"
    sep
    printf "  ${DIM}%-20s  %-7s  %-15s  %-20s${R}\n" "HOST" "PORTA" "SERVIÇO" "VERSÃO"
    sep
    for svc in "${SERVICES_FOUND[@]}"; do
        local host port_info service version
        host=$(echo "$svc" | awk '{print $1}' | cut -d: -f1)
        port_info=$(echo "$svc" | awk '{print $1}' | cut -d: -f2)
        service=$(echo "$svc" | awk '{print $2}')
        version=$(echo "$svc" | awk '{$1=$2=""; print $0}' | xargs)
        printf "  ${BCYAN}%-20s${R}  ${BYELLOW}%-7s${R}  ${BWHITE}%-15s${R}  ${DIM}%-20s${R}\n" \
            "$host" "$port_info" "$service" "${version:0:20}"
    done
    sep
}

# ═══════════════════════════════════════════════════════════════════════════
#  SEÇÃO 9 — IMPORTAÇÃO PARA METASPLOIT DB
# ═══════════════════════════════════════════════════════════════════════════

menu_import_msf() {
    require_target || return
    nl
    echo -e "  ${BOLD}${BCYAN}── Importar para Metasploit DB ──────────────────────────────${R}"
    nl
    echo -e "  ${BYELLOW}[1]${R}  db_nmap rápido (importa e cria workspace)"
    echo -e "  ${BYELLOW}[2]${R}  db_nmap completo com versões"
    echo -e "  ${BYELLOW}[3]${R}  Importar XML existente"
    echo -e "  ${BYELLOW}[4]${R}  Ver hosts no workspace"
    echo -e "  ${BYELLOW}[5]${R}  Ver serviços no workspace"
    echo -e "  ${BRED}[0]${R}  Voltar"
    nl
    read -rp "$(echo -e "  ${GREEN}import${R} » ")" opt
    case "$opt" in
        1) _import_db_nmap_quick ;;
        2) _import_db_nmap_full ;;
        3) _import_xml_file ;;
        4) _msf_show_hosts ;;
        5) _msf_show_services ;;
        0) return ;;
        *) WARN "Opção inválida." ;;
    esac
}

import_to_msf_silent() {
    if ! command -v msfconsole &>/dev/null; then
        WARN "msfconsole não encontrado. Pulando importação."; return
    fi
    local rc_file="${RC_DIR}/import_$(ts).rc"
    cat > "$rc_file" <<EOF
workspace -a ${WORKSPACE}
workspace ${WORKSPACE}
db_nmap -T4 -sV --open ${TARGET}
hosts
services
exit
EOF
    log "RUN" "db_nmap silencioso para workspace=${WORKSPACE}"
    if [[ "$DRY_RUN" == "false" ]]; then
        msfconsole -q -r "$rc_file" 2>&1 | tail -20
    else
        WARN "[DRY-RUN] msfconsole -q -r $rc_file"
    fi
    OK "Importação concluída → workspace: ${BWHITE}${WORKSPACE}${R}"
}

_import_db_nmap_quick() {
    local rc_file="${RC_DIR}/dbnmap_quick_$(ts).rc"
    cat > "$rc_file" <<EOF
workspace -a ${WORKSPACE}
workspace ${WORKSPACE}
db_nmap -T4 --open ${TARGET}
hosts
exit
EOF
    INFO "Executando db_nmap → workspace: ${WORKSPACE}"
    _run_rc "$rc_file"
    press_enter
}

_import_db_nmap_full() {
    local rc_file="${RC_DIR}/dbnmap_full_$(ts).rc"
    cat > "$rc_file" <<EOF
workspace -a ${WORKSPACE}
workspace ${WORKSPACE}
db_nmap -T4 -sV -sC --open ${TARGET}
hosts
services
exit
EOF
    INFO "Executando db_nmap completo → workspace: ${WORKSPACE}"
    _run_rc "$rc_file"
    press_enter
}

_import_xml_file() {
    nl
    read -rp "  Caminho do arquivo XML do nmap: " xml_path
    if [[ ! -f "$xml_path" ]]; then
        ERR "Arquivo não encontrado: $xml_path"; press_enter; return
    fi
    local rc_file="${RC_DIR}/import_xml_$(ts).rc"
    cat > "$rc_file" <<EOF
workspace -a ${WORKSPACE}
workspace ${WORKSPACE}
db_import ${xml_path}
hosts
services
exit
EOF
    INFO "Importando XML: $xml_path"
    _run_rc "$rc_file"
    press_enter
}

_msf_show_hosts() {
    local rc_file="${RC_DIR}/show_hosts_$(ts).rc"
    cat > "$rc_file" <<EOF
workspace ${WORKSPACE}
hosts
exit
EOF
    _run_rc "$rc_file"
    press_enter
}

_msf_show_services() {
    local rc_file="${RC_DIR}/show_services_$(ts).rc"
    cat > "$rc_file" <<EOF
workspace ${WORKSPACE}
services
exit
EOF
    _run_rc "$rc_file"
    press_enter
}

_run_rc() {
    local rc="$1"
    log "RUN" "msfconsole -q -r $rc"
    if [[ "$DRY_RUN" == "true" ]]; then
        WARN "[DRY-RUN] msfconsole -q -r $rc"
        nl
        cat "$rc"
        return
    fi
    msfconsole -q -r "$rc" 2>&1
}

# ═══════════════════════════════════════════════════════════════════════════
#  SEÇÃO 10 — RISK SCORING
# ═══════════════════════════════════════════════════════════════════════════

_risk_color() {
    local score=$1
    if   (( score >= 75 )); then echo -n "${BRED}"
    elif (( score >= 50 )); then echo -n "${BYELLOW}"
    elif (( score >= 25 )); then echo -n "${BCYAN}"
    else                         echo -n "${BGREEN}"
    fi
}

_risk_label() {
    local score=$1
    if   (( score >= 75 )); then echo "CRÍTICO"
    elif (( score >= 50 )); then echo "ALTO"
    elif (( score >= 25 )); then echo "MÉDIO"
    else                         echo "BAIXO"
    fi
}

calculate_risk_score() {
    TOTAL_RISK=0

    # Pontuação por portas de alto risco
    declare -A PORT_RISK=(
        [21]=10 [22]=5  [23]=20 [25]=8  [53]=5
        [80]=5  [110]=8 [135]=15 [139]=20 [443]=3
        [445]=25 [1433]=15 [1521]=15 [3306]=15
        [3389]=25 [5432]=10 [5900]=20 [6379]=15
        [8080]=5  [8443]=3  [27017]=15
    )

    for p in "${OPEN_PORTS[@]}"; do
        local port="${p##*/}"
        if [[ -n "${PORT_RISK[$port]:-}" ]]; then
            TOTAL_RISK=$(( TOTAL_RISK + PORT_RISK[$port] ))
        else
            TOTAL_RISK=$(( TOTAL_RISK + 1 ))
        fi
    done

    # Bônus por quantidade de portas
    local n_ports=${#OPEN_PORTS[@]}
    (( n_ports > 20 )) && TOTAL_RISK=$(( TOTAL_RISK + 15 ))
    (( n_ports > 50 )) && TOTAL_RISK=$(( TOTAL_RISK + 10 ))

    # Limite máximo
    (( TOTAL_RISK > 100 )) && TOTAL_RISK=100

    log "INFO" "Risk Score calculado: ${TOTAL_RISK}/100"
}

# ═══════════════════════════════════════════════════════════════════════════
#  SEÇÃO 11 — CVE LOOKUP (base local de versões conhecidas)
# ═══════════════════════════════════════════════════════════════════════════

lookup_cves() {
    CVES_FOUND=()

    # Base de mapeamento serviço/versão → CVE (exemplos educacionais conhecidos)
    declare -A CVE_DB=(
        # SSH
        ["openssh 7."]="CVE-2018-15473 (OpenSSH user enumeration < 7.7)"
        ["openssh 6."]="CVE-2016-6515 (OpenSSH DoS) | CVE-2015-5600"
        # FTP
        ["vsftpd 2.3.4"]="CVE-2011-2523 (vsftpd 2.3.4 backdoor)"
        ["proftpd 1.3.3"]="CVE-2010-4221 (ProFTPD buffer overflow)"
        # HTTP/Apache
        ["apache 2.4.49"]="CVE-2021-41773 (Path Traversal / RCE)"
        ["apache 2.4.50"]="CVE-2021-42013 (Path Traversal / RCE)"
        ["apache 2.2."]="CVE-2017-7679 | CVE-2017-7668 (múltiplas)"
        # Nginx
        ["nginx 1."]="CVE-2021-23017 (Nginx DNS resolver off-by-one)"
        # SMB / Samba
        ["samba 3."]="CVE-2007-2447 (Samba usermap_script RCE)"
        ["samba 4."]="CVE-2017-7494 (SambaCry RCE)"
        # Windows SMB
        ["microsoft-ds"]="MS17-010 (EternalBlue) — verificar versão SMB"
        # MySQL
        ["mysql 5.5"]="CVE-2012-2122 (MySQL auth bypass)"
        ["mysql 5.6"]="CVE-2016-6662 (MySQL privilege escalation)"
        # PostgreSQL
        ["postgresql 9."]="CVE-2019-10164 (Stack buffer overflow)"
        # Redis
        ["redis"]="CVE-2022-0543 (Lua sandbox escape) — sem auth?"
        # MongoDB
        ["mongodb"]="CWE-284 — verificar autenticação habilitada"
        # Telnet
        ["telnet"]="CWE-319 — Protocolo sem criptografia (plaintext)"
        # RDP
        ["ms-wbt-server"]="CVE-2019-0708 (BlueKeep) — verificar patch"
        # VNC
        ["rfb"]="CVE-2006-2369 (VNC auth bypass) | verificar NLA"
        # IIS
        ["microsoft iis 6"]="CVE-2017-7269 (IIS 6.0 WebDAV buffer overflow)"
        ["microsoft iis 7"]="CVE-2010-1256 | múltiplas — verificar patches"
        # Elasticsearch
        ["elasticsearch"]="CVE-2014-3120 | CVE-2015-1427 — acesso sem auth?"
        # Log4j (pela versão do Java)
        ["java"]="CVE-2021-44228 (Log4Shell) — verificar aplicações Java"
    )

    for svc in "${SERVICES_FOUND[@]}"; do
        local svc_lower
        svc_lower=$(echo "$svc" | tr '[:upper:]' '[:lower:]')
        for pattern in "${!CVE_DB[@]}"; do
            if echo "$svc_lower" | grep -q "$pattern"; then
                local cve_entry="${CVE_DB[$pattern]}"
                # Evitar duplicatas
                local found=0
                for existing in "${CVES_FOUND[@]:-}"; do
                    [[ "$existing" == "$cve_entry" ]] && found=1 && break
                done
                [[ $found -eq 0 ]] && CVES_FOUND+=("$cve_entry")
            fi
        done
    done

    log "INFO" "CVE lookup: ${#CVES_FOUND[@]} entradas encontradas"
}

# ═══════════════════════════════════════════════════════════════════════════
#  SEÇÃO 12 — SUGESTÃO DE MÓDULOS MSF
# ═══════════════════════════════════════════════════════════════════════════

suggest_msf_modules() {
    MODULES_SUGGESTED=()

    # Mapeamento porta/serviço → módulo MSF (apenas auxiliary/scanner)
    declare -A MODULE_MAP=(
        [21]="auxiliary/scanner/ftp/ftp_version  |  auxiliary/scanner/ftp/anonymous"
        [22]="auxiliary/scanner/ssh/ssh_version  |  auxiliary/scanner/ssh/ssh_identify_pubkeys"
        [23]="auxiliary/scanner/telnet/telnet_version"
        [25]="auxiliary/scanner/smtp/smtp_version  |  auxiliary/scanner/smtp/smtp_enum"
        [53]="auxiliary/scanner/dns/dns_amp  |  auxiliary/gather/dns_info"
        [80]="auxiliary/scanner/http/http_version  |  auxiliary/scanner/http/title"
        [110]="auxiliary/scanner/pop3/pop3_version"
        [135]="auxiliary/scanner/dcerpc/endpoint_mapper"
        [139]="auxiliary/scanner/smb/smb_version  |  auxiliary/scanner/smb/smb_enumshares"
        [443]="auxiliary/scanner/http/ssl_version  |  auxiliary/scanner/ssl/openssl_heartbleed"
        [445]="auxiliary/scanner/smb/smb_version  |  auxiliary/scanner/smb/smb2  |  auxiliary/scanner/smb/smb_enumusers"
        [1433]="auxiliary/scanner/mssql/mssql_ping  |  auxiliary/scanner/mssql/mssql_login"
        [1521]="auxiliary/scanner/oracle/tnslsnr_version"
        [3306]="auxiliary/scanner/mysql/mysql_version  |  auxiliary/scanner/mysql/mysql_authbypass_hashdump"
        [3389]="auxiliary/scanner/rdp/rdp_scanner  |  auxiliary/scanner/rdp/cve_2019_0708_bluekeep"
        [5432]="auxiliary/scanner/postgres/postgres_version"
        [5900]="auxiliary/scanner/vnc/vnc_none_auth"
        [6379]="auxiliary/scanner/redis/redis_server"
        [8080]="auxiliary/scanner/http/http_version  |  auxiliary/scanner/http/title"
        [27017]="auxiliary/gather/mongodb_db_info"
    )

    for p in "${OPEN_PORTS[@]}"; do
        local port="${p##*/}"
        if [[ -n "${MODULE_MAP[$port]:-}" ]]; then
            local mod_entry="${MODULE_MAP[$port]}"
            local found=0
            for existing in "${MODULES_SUGGESTED[@]:-}"; do
                [[ "$existing" == "$mod_entry" ]] && found=1 && break
            done
            [[ $found -eq 0 ]] && MODULES_SUGGESTED+=("port ${port}: ${mod_entry}")
        fi
    done

    log "INFO" "Módulos sugeridos: ${#MODULES_SUGGESTED[@]}"
}

menu_analysis() {
    require_target || return
    nl
    echo -e "  ${BOLD}${BCYAN}── Análise: Risk Score + CVEs + Módulos ─────────────────────${R}"
    nl
    calculate_risk_score
    lookup_cves
    suggest_msf_modules

    # Risk Score
    local color
    color=$(_risk_color "$TOTAL_RISK")
    local label
    label=$(_risk_label "$TOTAL_RISK")
    nl
    echo -e "  ${BOLD}Risk Score:${R}"
    sep
    _print_risk_bar "$TOTAL_RISK"
    echo -e "  Score: ${color}${BOLD}${TOTAL_RISK}/100 — ${label}${R}"
    nl

    # CVEs
    echo -e "  ${BOLD}CVEs Identificados (${#CVES_FOUND[@]}):${R}"
    sep
    if [[ ${#CVES_FOUND[@]} -eq 0 ]]; then
        OK "Nenhuma versão vulnerável conhecida detectada."
    else
        for cve in "${CVES_FOUND[@]}"; do
            CVE "$cve"
        done
    fi
    nl

    # Módulos
    echo -e "  ${BOLD}Módulos MSF Sugeridos (${#MODULES_SUGGESTED[@]}):${R}"
    sep
    if [[ ${#MODULES_SUGGESTED[@]} -eq 0 ]]; then
        INFO "Execute um scan primeiro para obter sugestões."
    else
        for mod in "${MODULES_SUGGESTED[@]}"; do
            MOD "$mod"
        done
    fi
    nl
    press_enter
}

_print_risk_bar() {
    local score=$1
    local bar_len=50
    local filled=$(( score * bar_len / 100 ))
    local empty=$(( bar_len - filled ))
    local color
    color=$(_risk_color "$score")

    printf "  ["
    printf "${color}"
    printf '%0.s█' $(seq 1 $filled)
    printf "${DIM}"
    printf '%0.s░' $(seq 1 $empty)
    printf "${R}] ${color}${score}%%%${R}\n"
}

# ═══════════════════════════════════════════════════════════════════════════
#  SEÇÃO 13 — DASHBOARD HACKER
# ═══════════════════════════════════════════════════════════════════════════

show_dashboard() {
    require_target || return
    calculate_risk_score
    lookup_cves
    suggest_msf_modules

    clear
    echo -e "${BRED}"
    cat << 'DASH'
  ┌─────────────────────────────────────────────────────────────────────┐
  │                    MetaAutoRecon :: DASHBOARD                        │
  └─────────────────────────────────────────────────────────────────────┘
DASH
    echo -e "${R}"

    local risk_color
    risk_color=$(_risk_color "$TOTAL_RISK")
    local risk_label
    risk_label=$(_risk_label "$TOTAL_RISK")

    # ── Painel topo ───────────────────────────────────────────
    printf "  ${BCYAN}%-20s${R}  ${BYELLOW}%-30s${R}  ${DIM}Scan: %s${R}\n" \
        "TARGET: ${TARGET}" "WORKSPACE: ${WORKSPACE}" "$(ts_human)"
    nl

    # ── Métricas ──────────────────────────────────────────────
    echo -e "  ${DIM}┌─────────────────┬──────────────────┬─────────────────┬────────────────┐${R}"
    printf "  ${DIM}│${R}  ${BOLD}%-13s${R}   ${DIM}│${R}  ${BOLD}%-13s${R}   ${DIM}│${R}  ${BOLD}%-12s${R}    ${DIM}│${R}  ${BOLD}%-11s${R}   ${DIM}│${R}\n" \
        "HOSTS ATIVOS" "PORTAS ABERTAS" "SERVIÇOS" "RISK SCORE"
    printf "  ${DIM}│${R}  ${BGREEN}%-15s${R}  ${DIM}│${R}  ${BYELLOW}%-15s${R}  ${DIM}│${R}  ${BCYAN}%-14s${R}  ${DIM}│${R}  ${risk_color}%-14s${R}  ${DIM}│${R}\n" \
        "${#HOSTS_FOUND[@]}" "${#OPEN_PORTS[@]}" "${#SERVICES_FOUND[@]}" "${TOTAL_RISK}/100 ${risk_label}"
    echo -e "  ${DIM}└─────────────────┴──────────────────┴─────────────────┴────────────────┘${R}"
    nl

    # ── Risk Bar ──────────────────────────────────────────────
    echo -e "  ${BOLD}RISK SCORE${R}"
    _print_risk_bar "$TOTAL_RISK"
    nl

    # ── Hosts ─────────────────────────────────────────────────
    if [[ ${#HOSTS_FOUND[@]} -gt 0 ]]; then
        echo -e "  ${BOLD}HOSTS ATIVOS${R}"
        sep
        local i=0
        for h in "${HOSTS_FOUND[@]}"; do
            printf "  ${BGREEN}  %-18s${R}" "$h"
            (( ++i % 4 == 0 )) && nl
        done
        [[ $(( i % 4 )) -ne 0 ]] && nl
        nl
    fi

    # ── Top Portas ────────────────────────────────────────────
    if [[ ${#OPEN_PORTS[@]} -gt 0 ]]; then
        echo -e "  ${BOLD}PORTAS ABERTAS${R}"
        sep
        local i=0
        for p in "${OPEN_PORTS[@]}"; do
            printf "  ${BYELLOW}  %-12s${R}" "$p"
            (( ++i % 6 == 0 )) && nl
        done
        [[ $(( i % 6 )) -ne 0 ]] && nl
        nl
    fi

    # ── Serviços detectados ───────────────────────────────────
    if [[ ${#SERVICES_FOUND[@]} -gt 0 ]]; then
        echo -e "  ${BOLD}SERVIÇOS DETECTADOS${R}"
        sep
        printf "  ${DIM}%-22s %-8s %-15s %-25s${R}\n" "HOST" "PORTA" "SERVIÇO" "VERSÃO"
        sep
        local count=0
        for svc in "${SERVICES_FOUND[@]}"; do
            (( count >= 15 )) && { INFO "... e mais $((${#SERVICES_FOUND[@]} - 15)) serviços. Ver relatório completo."; break; }
            local host port_info service version
            host=$(echo "$svc" | awk '{print $1}' | cut -d: -f1)
            port_info=$(echo "$svc" | awk '{print $1}' | cut -d: -f2)
            service=$(echo "$svc" | awk '{print $2}')
            version=$(echo "$svc" | awk '{$1=$2=""; print $0}' | xargs)
            printf "  ${BCYAN}%-22s${R} ${BYELLOW}%-8s${R} ${BWHITE}%-15s${R} ${DIM}%-25s${R}\n" \
                "$host" "$port_info" "$service" "${version:0:25}"
            (( count++ ))
        done
        nl
    fi

    # ── CVEs ──────────────────────────────────────────────────
    if [[ ${#CVES_FOUND[@]} -gt 0 ]]; then
        echo -e "  ${BOLD}${BRED}CVEs POTENCIAIS IDENTIFICADOS${R}"
        sep
        for cve in "${CVES_FOUND[@]}"; do
            CVE "$cve"
        done
        nl
        WARN "Confirme manualmente cada CVE antes de qualquer ação."
    else
        echo -e "  ${BOLD}CVEs${R}"
        sep
        OK "Nenhuma versão vulnerável conhecida detectada."
        nl
    fi

    # ── Módulos MSF ───────────────────────────────────────────
    if [[ ${#MODULES_SUGGESTED[@]} -gt 0 ]]; then
        echo -e "  ${BOLD}${BMAGENTA}MÓDULOS MSF SUGERIDOS (auxiliaries de scan)${R}"
        sep
        for mod in "${MODULES_SUGGESTED[@]}"; do
            MOD "$mod"
        done
        nl
        INFO "Use estes módulos em ${DIM}msfconsole${R} para validação."
    fi

    # ── Rodapé ────────────────────────────────────────────────
    echo -e "  ${DIM}═══════════════════════════════════════════════════════════════════${R}"
    echo -e "  ${DIM}  Gerado por MetaAutoRecon v${VERSION} | $(ts_human) | Apenas uso autorizado${R}"
    echo -e "  ${DIM}═══════════════════════════════════════════════════════════════════${R}"
    nl
    press_enter
}

# ═══════════════════════════════════════════════════════════════════════════
#  SEÇÃO 14 — RELATÓRIO
# ═══════════════════════════════════════════════════════════════════════════

generate_report() {
    require_target || return
    calculate_risk_score
    lookup_cves
    suggest_msf_modules

    local report_file="${REPORT_DIR}/report_${TARGET//\//_}_$(ts).txt"
    local ts_now
    ts_now=$(ts_human)

    INFO "Gerando relatório..."

    cat > "$report_file" <<REPORT
╔══════════════════════════════════════════════════════════════════════════╗
║               MetaAutoRecon v${VERSION} — Relatório de Reconhecimento            ║
╚══════════════════════════════════════════════════════════════════════════╝

Gerado em  : ${ts_now}
Alvo       : ${TARGET}
LHOST      : ${LHOST}
Workspace  : ${WORKSPACE}
Risk Score : ${TOTAL_RISK}/100 — $(_risk_label "$TOTAL_RISK")

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 1. HOSTS ATIVOS (${#HOSTS_FOUND[@]})
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
REPORT

    if [[ ${#HOSTS_FOUND[@]} -gt 0 ]]; then
        for h in "${HOSTS_FOUND[@]}"; do
            echo "  [ONLINE]  $h" >> "$report_file"
        done
    else
        echo "  Nenhum host encontrado." >> "$report_file"
    fi

    cat >> "$report_file" <<REPORT

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 2. PORTAS ABERTAS (${#OPEN_PORTS[@]})
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
REPORT

    for p in "${OPEN_PORTS[@]}"; do
        echo "  [OPEN]  $p" >> "$report_file"
    done

    cat >> "$report_file" <<REPORT

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 3. SERVIÇOS & VERSÕES (${#SERVICES_FOUND[@]})
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
REPORT

    for svc in "${SERVICES_FOUND[@]}"; do
        echo "  $svc" >> "$report_file"
    done

    cat >> "$report_file" <<REPORT

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 4. CVEs POTENCIAIS (${#CVES_FOUND[@]})
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

 ATENÇÃO: Estas são sugestões baseadas em versões detectadas.
 Confirme cada CVE manualmente antes de qualquer ação.

REPORT

    if [[ ${#CVES_FOUND[@]} -gt 0 ]]; then
        for cve in "${CVES_FOUND[@]}"; do
            echo "  [CVE]  $cve" >> "$report_file"
        done
    else
        echo "  Nenhuma versão vulnerável conhecida detectada." >> "$report_file"
    fi

    cat >> "$report_file" <<REPORT

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 5. MÓDULOS MSF SUGERIDOS (${#MODULES_SUGGESTED[@]})
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

 Módulos auxiliary/scanner recomendados para validação:

REPORT

    for mod in "${MODULES_SUGGESTED[@]}"; do
        echo "  [MSF]  $mod" >> "$report_file"
    done

    cat >> "$report_file" <<REPORT

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 6. AVISO LEGAL
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

 Este relatório foi gerado exclusivamente para fins de auditoria
 autorizada. O uso não autorizado destas informações é crime:
   • Lei 12.737/2012 (Crimes Cibernéticos)
   • Marco Civil da Internet — Lei 12.965/2014
   • LGPD — Lei 13.709/2018

═════════════════════════════════════════════════════════════════════════
 MetaAutoRecon v${VERSION} | ${ts_now}
═════════════════════════════════════════════════════════════════════════
REPORT

    OK "Relatório salvo: ${BYELLOW}${report_file}${R}"
    nl
    INFO "Abrir agora? (cat ${DIM}${report_file}${R})"
    if confirm "Visualizar relatório?"; then
        nl
        cat "$report_file" 2>&1 | head -100
        nl
        INFO "Arquivo completo: ${DIM}${report_file}${R}"
    fi
    press_enter
}

menu_report() {
    require_target || return
    nl
    echo -e "  ${BOLD}${BCYAN}── Relatórios ────────────────────────────────────────────────${R}"
    nl
    echo -e "  ${BYELLOW}[1]${R}  Gerar relatório completo"
    echo -e "  ${BYELLOW}[2]${R}  Listar relatórios anteriores"
    echo -e "  ${BYELLOW}[3]${R}  Abrir relatório existente"
    echo -e "  ${BRED}[0]${R}  Voltar"
    nl
    read -rp "$(echo -e "  ${GREEN}report${R} » ")" opt
    case "$opt" in
        1) generate_report ;;
        2) ls -lh "${REPORT_DIR}/"*.txt 2>/dev/null | awk '{print "  "$NF, $5}' \
            || WARN "Nenhum relatório encontrado."; press_enter ;;
        3) read -rp "  Arquivo: " rf; [[ -f "$rf" ]] && cat "$rf" || ERR "Não encontrado."; press_enter ;;
        0) return ;;
        *) WARN "Opção inválida." ;;
    esac
}

# ═══════════════════════════════════════════════════════════════════════════
#  SEÇÃO 15 — SCANS INDIVIDUAIS (submenu)
# ═══════════════════════════════════════════════════════════════════════════

menu_scans() {
    while true; do
        clear
        echo -e "  ${BOLD}${BCYAN}── Scans Individuais ─────────────────────────────────────────${R}"
        echo -e "  Alvo: ${BYELLOW}${TARGET:-não definido}${R}"
        nl
        echo -e "  ${BYELLOW}[1]${R}  Host Discovery (ping sweep)"
        echo -e "  ${BYELLOW}[2]${R}  Port Scan"
        echo -e "  ${BYELLOW}[3]${R}  Service & Version Detection"
        echo -e "  ${BYELLOW}[4]${R}  NSE Scripts"
        echo -e "  ${BRED}[0]${R}  Voltar"
        nl
        read -rp "$(echo -e "  ${GREEN}scan${R} » ")" opt
        case "$opt" in
            1) scan_host_discovery ;;
            2) scan_ports ;;
            3) scan_services ;;
            4) scan_nse ;;
            0) return ;;
            *) WARN "Opção inválida." ;;
        esac
    done
}

# ═══════════════════════════════════════════════════════════════════════════
#  SEÇÃO 16 — LOOP PRINCIPAL
# ═══════════════════════════════════════════════════════════════════════════

main_loop() {
    while true; do
        print_main_menu
        read -rp "$(echo -e "  ${BGREEN}metaautorecon${R}@${BYELLOW}${TARGET:-alvo}${R} » ")" choice
        case "$choice" in
            1) menu_config ;;
            2) scan_full_pipeline ;;
            3) menu_scans ;;
            4) menu_import_msf ;;
            5) menu_analysis ;;
            6) show_dashboard ;;
            7) menu_report ;;
            8) check_dependencies ;;
            0) _exit_clean ;;
            *) WARN "Opção inválida: ${choice}" ;;
        esac
    done
}

_exit_clean() {
    nl
    INFO "Encerrando MetaAutoRecon..."
    rm -f /tmp/mar_*.rc 2>/dev/null || true
    echo -e "  ${BGREEN}Até logo!${R}"
    nl
    exit 0
}

trap _exit_clean SIGINT SIGTERM

# ═══════════════════════════════════════════════════════════════════════════
#  SEÇÃO 17 — CLI & INICIALIZAÇÃO
# ═══════════════════════════════════════════════════════════════════════════

usage() {
    cat <<EOF
$(echo -e "${BCYAN}MetaAutoRecon v${VERSION}${R} — Automated Recon for Metasploit")

$(echo -e "${BOLD}Uso:${R}")  $0 [opções]

$(echo -e "${BOLD}Opções:${R}")
  -t <alvo>     Alvo (IP, CIDR, hostname)
  -w <ws>       Workspace Metasploit (padrão: recon_YYYYMMDD)
  -l <lhost>    LHOST — seu IP
  -d            Dry-run (simulação, sem execução real)
  -v            Verbose
  -h            Ajuda

$(echo -e "${BOLD}Exemplos:${R}")
  $0
  $0 -t 192.168.1.0/24
  $0 -t 10.0.0.5 -w lab_htb -v
  $0 -t 192.168.56.101 -d

$(echo -e "${BOLD}Legal:${R}") Apenas em ambientes com autorização.
  Lei 12.737/2012 · Marco Civil da Internet · LGPD
EOF
}

init() {
    # Criar diretórios de trabalho
    mkdir -p "$LOG_DIR" "$REPORT_DIR" "$SCAN_DIR" "$RC_DIR"

    # Arquivo de log padrão
    SCAN_LOG="${LOG_DIR}/metaautorecon_$(ts).log"
    echo "[$(ts_human)] [INIT] MetaAutoRecon v${VERSION} iniciado. PID=$$" >> "$SCAN_LOG"

    # Auto-detectar LHOST se não definido
    [[ -z "$LHOST" ]] && LHOST=$(get_local_ip)

    main_loop
}

# Parse de argumentos CLI
while getopts ":t:w:l:dvh" opt; do
    case $opt in
        t) TARGET="$OPTARG" ;;
        w) WORKSPACE="$OPTARG" ;;
        l) LHOST="$OPTARG" ;;
        d) DRY_RUN=true ;;
        v) VERBOSE=true ;;
        h) usage; exit 0 ;;
        :) echo "Erro: -$OPTARG requer argumento." >&2; exit 1 ;;
        \?) echo "Erro: opção inválida -$OPTARG" >&2; exit 1 ;;
    esac
done

[[ "$DRY_RUN" == "true" ]] && echo -e "  ${BYELLOW}[!]${R}  Modo Dry-Run ativado — nenhum comando real será executado."

init