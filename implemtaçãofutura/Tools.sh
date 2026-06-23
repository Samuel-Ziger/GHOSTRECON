#!/bin/bash
# =============================================================================
#  CTFMind AI - Assistente Hacker Offline para CTF & Pentest
#  Versão 2.0 "Cortex"
#  Autor: CTFMind Project
#  Uso: ./ctfmind.sh [comando] [opções]
#  Tudo em um único arquivo, sem dependências externas de APIs.
# =============================================================================

set -e  # Parar em erros (não críticos para UI, desabilitado adiante)

# ------------------------------------------------------------
# 0. Configuração inicial e diretórios
# ------------------------------------------------------------
CTFMIND_HOME="${HOME}/.ctfmind"
CONFIG_DIR="${CTFMIND_HOME}/config"
MEMORY_DIR="${CTFMIND_HOME}/memory"
KNOWLEDGE_DIR="${CTFMIND_HOME}/knowledge"
LOG_DIR="${CTFMIND_HOME}/logs"
REPORT_DIR="${CTFMIND_HOME}/reports"
PLUGIN_DIR="${CTFMIND_HOME}/plugins"
TEMP_DIR="${CTFMIND_HOME}/tmp"

mkdir -p "${CONFIG_DIR}" "${MEMORY_DIR}" "${KNOWLEDGE_DIR}" "${LOG_DIR}" "${REPORT_DIR}" "${PLUGIN_DIR}" "${TEMP_DIR}"

# ------------------------------------------------------------
# 1. Cores e estilos (cyberpunk)
# ------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BOLD='\033[1m'
DIM='\033[2m'
BLINK='\033[5m'
RESET='\033[0m'

# ------------------------------------------------------------
# 2. Funções de UI
# ------------------------------------------------------------
type_out() {
    local msg="$1"
    local delay="${2:-0.02}"
    for (( i=0; i<${#msg}; i++ )); do
        echo -n "${msg:$i:1}"
        sleep "$delay"
    done
    echo
}

spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while kill -0 "$pid" 2>/dev/null; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

ui_header() {
    clear
    echo -e "${BOLD}${CYAN}
   ▄████████  ▄████████ ████████▄     ▄████████ ███▄▄▄▄   ████████▄  
  ███    ███ ███    ███ ███   ▀███   ███    ███ ███▀▀▀██▄ ███   ▀███ 
  ███    █▀  ███    ███ ███    ███   ███    ███ ███   ███ ███    ███ 
  ███        ███    ███ ███    ███  ▄███▄▄▄▄██▀ ███   ███ ███    ███ 
  ███        ███    ███ ███    ███ ▀▀███▀▀▀▀▀   ███   ███ ███    ███ 
  ███    █▄  ███    ███ ███    ███ ▀███████████ ███   ███ ███    ███ 
  ███    ███ ███    ███ ███   ▄███   ███    ███ ███   ███ ███   ▄███ 
  ████████▀  ████████▀  ████████▀    ███    ███  ▀█   █▀  ████████▀  
                                     ███    ███                       
  ${RESET}${GREEN}v2.0 :: IA Offline para CTF :: ${RED}CTFMind AI${RESET}"
    echo ""
}

log_info()  { echo -e "${GREEN}[✔]${RESET} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${RESET} $1"; }
log_error() { echo -e "${RED}[✖]${RESET} $1"; }
log_ai()    { echo -ne "${MAGENTA}[AI]${RESET} "; type_out "$1" 0.01; }
debug_msg() { echo -e "${DIM}[DBG]${RESET} $1"; }

# Barra de progresso simples
progress_bar() {
    local current=$1
    local total=$2
    local width=40
    local percent=$((current * 100 / total))
    local filled=$((width * current / total))
    local empty=$((width - filled))
    printf "\r["
    printf "%${filled}s" | tr ' ' '▓'
    printf "%${empty}s" | tr ' ' '░'
    printf "] %3d%%" "$percent"
}

# ------------------------------------------------------------
# 3. Sistema de memória e aprendizado (SQLite)
# ------------------------------------------------------------
DB_FILE="${MEMORY_DIR}/ctfmind.db"
sqlite3 "$DB_FILE" "CREATE TABLE IF NOT EXISTS hosts (id INTEGER PRIMARY KEY, ip TEXT, services TEXT, vulns TEXT, scan_time DATETIME DEFAULT CURRENT_TIMESTAMP);" 2>/dev/null
sqlite3 "$DB_FILE" "CREATE TABLE IF NOT EXISTS payloads (id INTEGER PRIMARY KEY, name TEXT, type TEXT, payload TEXT, success INTEGER DEFAULT 0, score INTEGER DEFAULT 0);" 2>/dev/null
sqlite3 "$DB_FILE" "CREATE TABLE IF NOT EXISTS sessions (id INTEGER PRIMARY KEY, target TEXT, commands TEXT, output TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP);" 2>/dev/null
sqlite3 "$DB_FILE" "CREATE TABLE IF NOT EXISTS knowledge (id INTEGER PRIMARY KEY, tag TEXT, content TEXT, weight INTEGER DEFAULT 1);" 2>/dev/null

db_add_host() { sqlite3 "$DB_FILE" "INSERT INTO hosts (ip, services, vulns) VALUES ('$1', '$2', '$3');" 2>/dev/null; }
db_record_payload() { sqlite3 "$DB_FILE" "INSERT INTO payloads (name, type, payload, success, score) VALUES ('$1', '$2', '$3', $4, $5);" 2>/dev/null; }
db_add_knowledge() { sqlite3 "$DB_FILE" "INSERT INTO knowledge (tag, content) VALUES ('$1', '$2');" 2>/dev/null; }
db_get_top_exploits() { sqlite3 "$DB_FILE" "SELECT name, payload FROM payloads WHERE success=1 ORDER BY score DESC LIMIT 5;" 2>/dev/null; }
db_last_target() { sqlite3 "$DB_FILE" "SELECT ip FROM hosts ORDER BY scan_time DESC LIMIT 1;" 2>/dev/null; }
db_count_sessions() { sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM hosts;" 2>/dev/null; }

# ------------------------------------------------------------
# 4. Base de conhecimento interna (payloads, técnicas)
# ------------------------------------------------------------
# Pequenas coleções offline para fallback quando LLM não está disponível.
declare -A HEURISTIC_RULES
HEURISTIC_RULES["80/tcp.*Apache.*?page="]="Possível LFI: tente ../../../../etc/passwd ou filtro PHP."
HEURISTIC_RULES["445/tcp open"]="SMB detectado. Enumere com smbclient -L //TARGET -N e enum4linux."
HEURISTIC_RULES["21/tcp open.*ftp"]="FTP anônimo? Teste: ftp TARGET 21, user anonymous."
HEURISTIC_RULES["3306/tcp open.*mysql"]="MySQL rodando. Tente credenciais padrão ou brute-force com hydra."
HEURISTIC_RULES["wordpress"]="WordPress encontrado. Execute: wpscan --url TARGET --enumerate u,p."
HEURISTIC_RULES["joomla"]="Joomla detectado. Use joomscan e verifique componentes vulneráveis."
HEURISTIC_RULES["drupal"]="Drupal: cheque por Drupalgeddon (CVE-2018-7600)."
HEURISTIC_RULES["tomcat"]="Apache Tomcat: tente /manager/html com credenciais padrão."

# Função de busca heurística por palavras-chave
heuristic_search() {
    local data="$1"
    local hint=""
    for pattern in "${!HEURISTIC_RULES[@]}"; do
        if echo "$data" | grep -qi "$pattern"; then
            hint+="• ${HEURISTIC_RULES[$pattern]}\n"
        fi
    done
    if [[ -z "$hint" ]]; then
        hint="Nenhuma regra exata encontrada. Recomendo enumeração completa: nmap -sV -sC -p- TARGET, gobuster dir, etc."
    fi
    echo -e "$hint"
}

# ------------------------------------------------------------
# 5. Integração com LLM local (Ollama)
# ------------------------------------------------------------
AI_MODEL="${AI_MODEL:-phi3:mini}"
OLLAMA_AVAILABLE=false
if command -v ollama &> /dev/null; then
    OLLAMA_AVAILABLE=true
fi

ai_query() {
    local prompt="$1"
    local context="${2:-sem contexto adicional}"
    
    if $OLLAMA_AVAILABLE; then
        local full_prompt="Você é um assistente de segurança ofensiva especializado em CTF, testes de penetração e hacking ético. Responda de forma técnica, direta e útil. Considere o seguinte contexto: $context\n\nPergunta: $prompt\nResposta:"
        local response
        response=$(ollama run "$AI_MODEL" "$full_prompt" 2>/dev/null) || true
        if [[ -n "$response" ]]; then
            echo "$response"
            return
        fi
    fi
    
    # Fallback heurístico
    heuristic_response "$prompt" "$context"
}

heuristic_response() {
    local prompt="$1"
    local context="$2"
    
    # Regras específicas para comandos comuns
    if echo "$prompt" | grep -qi "analise\|recon\|escanear\|portas"; then
        echo -e "=== Análise heurística ===\n$(heuristic_search "$context")\n=== Ações sugeridas ==="
        echo "1. Enumere todos os serviços (nmap -A -p- TARGET)."
        echo "2. Busque por exploits públicos para cada serviço (searchsploit)."
        echo "3. Teste credenciais padrão ou listas de brute-force."
    elif echo "$prompt" | grep -qi "web\|http\|lfi\|sqli\|xss"; then
        echo "Teste parâmetros com payloads comuns: ' OR 1=1--, <script>alert(1)</script>, ../../etc/passwd."
        echo "Use ferramentas como sqlmap, burp, ou scripts customizados."
    else
        echo "Não foi possível processar com IA local. Execute '--install' para configurar Ollama."
    fi
}

# ------------------------------------------------------------
# 6. Módulos de ataque
# ------------------------------------------------------------

# ---- Recon ----
recon_run() {
    local target="$1"
    mkdir -p "${MEMORY_DIR}/scans/${target}"
    
    log_info "Iniciando reconhecimento em ${target}..."
    local scan_quick="${MEMORY_DIR}/scans/${target}/quick.nmap"
    local scan_full="${MEMORY_DIR}/scans/${target}/full.nmap"
    
    # Escaneamento rápido das 1000 portas comuns
    ( nmap -sS -T4 --top-ports 1000 -oN "$scan_quick" "$target" &> /dev/null ) &
    spinner $!
    log_info "Varredura rápida concluída."
    
    # Escaneamento completo de versões e scripts
    ( nmap -sV -sC -O -oN "$scan_full" "$target" &> /dev/null ) &
    spinner $!
    log_info "Varredura de versões e scripts concluída."
    
    # Interpretação
    local services
    services=$(grep -E "^[0-9]+/tcp" "$scan_full" | tr '\n' ' ')
    log_ai "Analisando serviços encontrados..."
    local analysis
    analysis=$(ai_query "Analise estes serviços e sugira próximos passos" "$services")
    echo -e "${CYAN}${analysis}${RESET}"
    
    # Salva no banco
    db_add_host "$target" "$services" "pendente"
    echo "$scan_full"
}

# ---- Web ----
web_run() {
    local target="$1"
    log_info "Analisando vulnerabilidades web em ${target}..."
    
    # Exemplo: executa gobuster se instalado
    if command -v gobuster &> /dev/null; then
        gobuster dir -u "http://${target}" -w "${KNOWLEDGE_DIR}/wordlists/common.txt" -o "${TEMP_DIR}/gobuster_${target}.txt" &>/dev/null &
        spinner $!
        log_info "Enumeração de diretórios concluída."
    else
        log_warn "gobuster não encontrado. Instale para enumeração de diretórios."
    fi
    
    # Heurísticas web básicas via curl
    local http_response
    http_response=$(curl -s -L -I "http://${target}" 2>/dev/null || true)
    local analysis
    analysis=$(ai_query "Analise cabeçalhos HTTP e sugira vulnerabilidades" "$http_response")
    echo -e "${CYAN}${analysis}${RESET}"
    
    # Regras comuns
    if echo "$http_response" | grep -qi "wordpress"; then
        log_warn "WordPress detectado. Use wpscan."
    fi
}

# ---- Crypto ----
crypto_run() {
    local file="$1"
    if [[ ! -f "$file" ]]; then
        log_error "Arquivo não encontrado: $file"
        return 1
    fi
    log_info "Analisando criptografia do arquivo ${file}..."
    
    local content
    content=$(cat "$file")
    local hint
    hint=$(ai_query "Identifique o tipo de cifra/codificação deste conteúdo e sugira como quebrar" "$content")
    echo -e "${CYAN}${hint}${RESET}"
    
    # Tentativa automática de base64
    if echo "$content" | base64 -d &>/dev/null; then
        log_info "Base64 decodificado com sucesso."
    fi
}

# ---- Forensics ----
forensics_run() {
    local file="$1"
    if [[ ! -f "$file" ]]; then
        log_error "Arquivo não encontrado: $file"
        return 1
    fi
    log_info "Análise forense de ${file}..."
    
    local filetype
    filetype=$(file "$file")
    log_info "Tipo de arquivo: $filetype"
    
    # Strings, exiftool, binwalk (se instalados)
    if command -v strings &> /dev/null; then
        strings "$file" > "${TEMP_DIR}/strings_${file##*/}.txt"
        log_info "Strings extraídas."
    fi
    if command -v exiftool &> /dev/null; then
        exiftool "$file" > "${TEMP_DIR}/exiftool_${file##*/}.txt"
        log_info "Metadados extraídos."
    fi
    
    local summary
    summary="Arquivo: $filetype\n"
    summary+=$(cat "${TEMP_DIR}/strings_${file##*/}.txt" 2>/dev/null | head -n 20)
    local analysis
    analysis=$(ai_query "Analise este arquivo forense e sugira investigação" "$summary")
    echo -e "${CYAN}${analysis}${RESET}"
}

# ---- PrivEsc ----
privesc_run() {
    log_info "Coletando informações para escalação de privilégios local..."
    
    local sysinfo
    sysinfo="Sistema: $(uname -a)\n"
    sysinfo+="Usuário: $(whoami)\n"
    sysinfo+="SUID: $(find / -perm -4000 -type f 2>/dev/null | head -n 10)\n"
    sysinfo+="Sudo: $(sudo -l 2>/dev/null || echo 'N/A')\n"
    sysinfo+="Cron: $(cat /etc/crontab 2>/dev/null || echo 'N/A')\n"
    
    local analysis
    analysis=$(ai_query "Analise estas informações e sugira vetores de escalação de privilégios" "$sysinfo")
    echo -e "${CYAN}${analysis}${RESET}"
}

# ------------------------------------------------------------
# 7. Modo Chat Interativo
# ------------------------------------------------------------
chat_mode() {
    ui_header
    log_ai "CTFMind AI iniciada. Digite 'sair' para encerrar."
    echo ""
    while true; do
        echo -ne "${BOLD}${GREEN}[CTFMind]${RESET} > "
        read -r input
        if [[ "$input" == "sair" || "$input" == "exit" ]]; then
            log_ai "Encerrando... Stay sharp."
            break
        elif [[ -z "$input" ]]; then
            continue
        fi
        local response
        response=$(ai_query "$input" "")
        echo -e "${CYAN}${response}${RESET}\n"
    done
}

# ------------------------------------------------------------
# 8. Modo Autônomo
# ------------------------------------------------------------
auto_mode() {
    local target="$1"
    if [[ -z "$target" ]]; then
        log_error "Alvo não especificado. Ex: --auto 10.10.10.5"
        exit 1
    fi
    ui_header
    log_ai "Iniciando modo autônomo contra ${target}..."
    
    # Recon
    recon_run "$target"
    
    # Web (se porta 80/443 aberta)
    if grep -qE "80/tcp|443/tcp" "${MEMORY_DIR}/scans/${target}/quick.nmap" 2>/dev/null; then
        web_run "$target"
    fi
    
    # Sugestão de próximos passos
    log_ai "Modo autônomo concluído. Revise os resultados e execute módulos específicos."
}

# ------------------------------------------------------------
# 9. Dashboard de status
# ------------------------------------------------------------
show_dashboard() {
    ui_header
    echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════╗${RESET}"
    echo -e "${BOLD}${GREEN}║        CTFMind AI - DASHBOARD            ║${RESET}"
    echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════╝${RESET}"
    echo ""
    echo -e "${CYAN}Status da IA:${RESET} Ativa"
    echo -e "${CYAN}Modelo LLM:${RESET} ${AI_MODEL} (local: $OLLAMA_AVAILABLE)"
    echo -e "${CYAN}Sessões registradas:${RESET} $(db_count_sessions)"
    echo -e "${CYAN}Último alvo:${RESET} $(db_last_target)"
    echo -e "${CYAN}Uso de CPU:${RESET} $(top -bn1 | grep "Cpu(s)" | awk '{print 100 - $8 "%"}')"
    echo -e "${CYAN}RAM livre:${RESET} $(free -h | awk '/^Mem:/ {print $4}')"
    echo ""
    echo -e "${YELLOW}Comandos rápidos:${RESET}"
    echo "  --chat   - Iniciar conversa com a IA"
    echo "  --auto   - Modo autônomo (target)"
    echo "  --recon  - Reconhecimento"
    echo "  --web    - Análise web"
    echo "  --report - Gerar relatório"
}

# ------------------------------------------------------------
# 10. Geração de relatórios
# ------------------------------------------------------------
generate_report() {
    local report_file="${REPORT_DIR}/ctfmind_report_$(date +%Y%m%d_%H%M%S).md"
    ui_header
    log_info "Gerando relatório..."
    
    {
        echo "# CTFMind AI - Relatório de Atividades"
        echo "Data: $(date)"
        echo ""
        echo "## Alvos escaneados"
        sqlite3 "$DB_FILE" "SELECT ip, services, vulns, scan_time FROM hosts ORDER BY scan_time DESC LIMIT 10;" | while IFS='|' read -r ip services vulns time; do
            echo "- **${ip}** (${time}): ${services} - Vulns: ${vulns}"
        done
        echo ""
        echo "## Payloads bem-sucedidos"
        sqlite3 "$DB_FILE" "SELECT name, type, payload, score FROM payloads WHERE success=1 ORDER BY score DESC LIMIT 10;" | while IFS='|' read -r name type payload score; do
            echo "- **${name}** (${type}): \`${payload}\` (score: ${score})"
        done
        echo ""
        echo "## Recomendações"
        echo "1. Sempre mantenha suas ferramentas atualizadas."
        echo "2. Explore manualmente os serviços identificados."
        echo "3. Consulte writeups de CTFs similares."
    } > "$report_file"
    
    log_info "Relatório salvo em: ${report_file}"
}

# ------------------------------------------------------------
# 11. Instalação
# ------------------------------------------------------------
install_deps() {
    ui_header
    log_info "Iniciando instalação do CTFMind AI..."
    
    # Dependências essenciais
    local packages=(nmap sqlite3 jq curl git python3 python3-pip)
    for pkg in "${packages[@]}"; do
        if ! dpkg -s "$pkg" &> /dev/null; then
            log_warn "Instalando ${pkg}..."
            sudo apt-get install -y "$pkg" > /dev/null 2>&1
        fi
    done
    
    # Ollama (LLM local)
    if ! command -v ollama &> /dev/null; then
        log_info "Instalando Ollama..."
        curl -fsSL https://ollama.com/install.sh | sh
        # Baixar modelo leve
        ollama pull phi3:mini
    fi
    
    # Pacotes Python auxiliares
    pip3 install -q rich textual 2>/dev/null || true
    
    # Criar wordlist básica
    mkdir -p "${KNOWLEDGE_DIR}/wordlists"
    cat <<EOF > "${KNOWLEDGE_DIR}/wordlists/common.txt"
admin
login
wp-admin
backup
test
dev
robots.txt
sitemap.xml
.git
.env
config
phpinfo.php
EOF

    # Configurações padrão
    cat <<EOF > "${CONFIG_DIR}/settings.conf"
AI_MODEL="phi3:mini"
OLLAMA_HOST="localhost:11434"
MAX_SCANS=10
LOG_LEVEL="INFO"
EOF

    log_info "Instalação concluída! Execute 'ctfmind --chat' para iniciar."
}

# ------------------------------------------------------------
# 12. Menu de ajuda
# ------------------------------------------------------------
show_help() {
    echo -e "${BOLD}CTFMind AI - Comandos disponíveis:${RESET}"
    echo ""
    echo "  --chat              Iniciar chat interativo com a IA"
    echo "  --auto <IP/DOMINIO> Executar modo autônomo contra alvo"
    echo "  --recon <IP/DOMINIO> Realizar reconhecimento"
    echo "  --web <IP/DOMINIO>  Analisar vulnerabilidades web"
    echo "  --crypto <ARQUIVO>  Analisar cifra/codificação"
    echo "  --forensics <ARQUIVO> Análise forense"
    echo "  --privesc           Coletar informações para escalação de privilégios"
    echo "  --report            Gerar relatório da sessão atual"
    echo "  --ai-status         Exibir dashboard da IA"
    echo "  --install           Instalar dependências (requer root)"
    echo "  --help              Mostrar esta ajuda"
    echo ""
    echo "Exemplo: ./ctfmind.sh --auto 10.10.10.5"
}

# ------------------------------------------------------------
# 13. Função principal
# ------------------------------------------------------------
main() {
    case "${1}" in
        --chat)            chat_mode ;;
        --auto)            auto_mode "${2}" ;;
        --recon)           recon_run "${2}" ;;
        --web)             web_run "${2}" ;;
        --crypto)          crypto_run "${2}" ;;
        --forensics)       forensics_run "${2}" ;;
        --privesc)         privesc_run ;;
        --report)          generate_report ;;
        --ai-status)       show_dashboard ;;
        --install)         install_deps ;;
        --help|-h)         show_help ;;
        *)                 show_help; exit 1 ;;
    esac
}

# Iniciar
main "$@"