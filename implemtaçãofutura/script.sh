#!/usr/bin/env bash

# ===================================================================
# OSINTool v4.0 - Ferramenta OSINT Profissional em Bash
# Descrição: Coleta avançada de informações com módulos expandidos:
#   - Domínios, E-mails, IPs, Usernames, Redes Sociais
#   - Metadados, Vulnerabilidades, Pessoas, Empresas
#   - TOR/Dark Web check, Crypto addresses, Certificates
#   - ASN, BGP, Threat Intelligence, CVE lookup
#   - Geofencing, Reverse Image, Phone OSINT
#   - Modo silencioso, exportação JSON/CSV/HTML
# ===================================================================

# ========================= CONFIGURAÇÕES ===========================
VERSION="4.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="osintool_${TIMESTAMP}.log"
HTML_REPORT="osint_report_${TIMESTAMP}.html"
JSON_REPORT="osint_report_${TIMESTAMP}.json"
CSV_REPORT="osint_report_${TIMESTAMP}.csv"
TEMP_DIR="/tmp/osintool_$$"
OUTPUT_DIR="./osint_results"
mkdir -p "$TEMP_DIR" "$OUTPUT_DIR"

# Mover relatórios para pasta de saída
LOG_FILE="$OUTPUT_DIR/$LOG_FILE"
HTML_REPORT="$OUTPUT_DIR/$HTML_REPORT"
JSON_REPORT="$OUTPUT_DIR/$JSON_REPORT"
CSV_REPORT="$OUTPUT_DIR/$CSV_REPORT"

# ========================= CORES ===================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
GRAY='\033[0;37m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ========================= APIs (configure aqui) ==================
SHODAN_API_KEY=""          # https://account.shodan.io/register
SECURITYTRAILS_API_KEY=""  # https://securitytrails.com
HIBP_API_KEY=""            # https://haveibeenpwned.com/API/Key
IPINFO_TOKEN=""            # https://ipinfo.io/signup
VIRUSTOTAL_API_KEY=""      # https://www.virustotal.com
ABUSEIPDB_API_KEY=""       # https://www.abuseipdb.com/api
CENSYS_API_ID=""           # https://censys.io/register
CENSYS_API_SECRET=""
HUNTER_API_KEY=""          # https://hunter.io/api
GREYNOISE_API_KEY=""       # https://greynoise.io
FULLCONTACT_API_KEY=""     # https://www.fullcontact.com
NUMVERIFY_API_KEY=""       # https://numverify.com

USER_AGENT="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
CURL_TIMEOUT=10
CURL_RETRIES=2

# ========================= MODO OPERAÇÃO ==========================
SILENT_MODE=false
VERBOSE_MODE=false
EXPORT_JSON=false
EXPORT_CSV=false
RATE_LIMIT=0.5  # segundos entre requests

# ========================= JSON GLOBAL ============================
JSON_DATA="{}"

# ========================= FUNÇÕES LOG ============================
log() {
    local timestamp="[$(date '+%H:%M:%S')]"
    if [[ "$SILENT_MODE" == false ]]; then
        echo -e "$timestamp $1" | tee -a "$LOG_FILE"
    else
        echo -e "$timestamp $1" >> "$LOG_FILE"
    fi
}

error() {
    echo -e "${RED}[ERRO]${NC} $1" | tee -a "$LOG_FILE"
}

success() {
    echo -e "${GREEN}[+]${NC} $1" | tee -a "$LOG_FILE"
}

info() {
    echo -e "${BLUE}[*]${NC} $1" | tee -a "$LOG_FILE"
}

warning() {
    echo -e "${YELLOW}[!]${NC} $1" | tee -a "$LOG_FILE"
}

found() {
    echo -e "${GREEN}${BOLD}[✓]${NC} $1" | tee -a "$LOG_FILE"
}

not_found() {
    echo -e "${RED}[✗]${NC} $1" | tee -a "$LOG_FILE"
}

section() {
    echo -e "\n${CYAN}${BOLD}══════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}${BOLD}  $1${NC}"
    echo -e "${CYAN}${BOLD}══════════════════════════════════════════════════${NC}"
}

subsection() {
    echo -e "\n${PURPLE}  ▶ $1${NC}"
}

# ========================= RATE LIMITING ==========================
rate_limit() {
    sleep "$RATE_LIMIT"
}

# ========================= CURL WRAPPER ===========================
safe_curl() {
    local url="$1"
    shift
    curl -s --max-time "$CURL_TIMEOUT" --retry "$CURL_RETRIES" \
         -A "$USER_AGENT" "$@" "$url" 2>/dev/null
}

# ========================= HTML GERADOR ===========================
generate_html_header() {
    cat > "$HTML_REPORT" << 'HTMLEOF'
<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OSINTool v4.0 - Relatório</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;700&family=Orbitron:wght@400;700;900&display=swap');
  :root {
    --bg: #050a0e; --bg2: #0a1520; --bg3: #0f1f30;
    --cyan: #00d4ff; --green: #00ff88; --red: #ff3366;
    --yellow: #ffcc00; --purple: #8b5cf6; --gray: #4a6080;
    --text: #c8e0f0; --dim: #4a6080;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'JetBrains Mono', monospace; background: var(--bg);
         color: var(--text); padding: 20px; line-height: 1.6; }
  .header { text-align: center; padding: 40px 20px; border-bottom: 1px solid var(--gray);
            margin-bottom: 30px; }
  .header h1 { font-family: 'Orbitron', monospace; font-size: 2.5rem;
               color: var(--cyan); text-shadow: 0 0 20px rgba(0,212,255,0.5); }
  .header .meta { color: var(--dim); font-size: 0.85rem; margin-top: 10px; }
  .section { background: var(--bg2); border: 1px solid var(--bg3);
             border-left: 3px solid var(--cyan); border-radius: 8px;
             padding: 20px; margin-bottom: 25px; }
  .section h2 { font-family: 'Orbitron', monospace; font-size: 1.1rem;
                color: var(--cyan); margin-bottom: 15px; display: flex;
                align-items: center; gap: 10px; }
  .section h2 .badge { background: rgba(0,212,255,0.1); border: 1px solid var(--cyan);
                       padding: 2px 8px; border-radius: 12px; font-size: 0.75rem; }
  .subsection { margin: 15px 0; }
  .subsection h3 { color: var(--purple); font-size: 0.9rem; margin-bottom: 8px;
                   padding-left: 10px; border-left: 2px solid var(--purple); }
  pre { background: var(--bg3); padding: 12px; border-radius: 5px; font-size: 0.82rem;
        overflow-x: auto; white-space: pre-wrap; word-break: break-all; color: var(--text); }
  .found { color: var(--green); } .notfound { color: var(--red); }
  .warning { color: var(--yellow); } .info { color: var(--cyan); }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 15px; }
  .card { background: var(--bg3); border-radius: 6px; padding: 12px;
          border: 1px solid rgba(0,212,255,0.15); }
  .card .label { color: var(--dim); font-size: 0.75rem; text-transform: uppercase;
                 letter-spacing: 1px; }
  .card .value { color: var(--green); font-size: 0.95rem; margin-top: 4px; }
  a { color: var(--cyan); text-decoration: none; }
  a:hover { text-decoration: underline; }
  .tag { display: inline-block; background: rgba(139,92,246,0.2); color: var(--purple);
         border: 1px solid rgba(139,92,246,0.4); border-radius: 12px; padding: 2px 8px;
         font-size: 0.75rem; margin: 2px; }
  .severity-high { color: var(--red); }
  .severity-medium { color: var(--yellow); }
  .severity-low { color: var(--green); }
  .toc { background: var(--bg2); border: 1px solid var(--bg3); border-radius: 8px;
         padding: 20px; margin-bottom: 30px; }
  .toc h2 { color: var(--cyan); margin-bottom: 12px; font-size: 0.95rem; }
  .toc a { display: block; color: var(--text); padding: 3px 0;
           padding-left: 15px; border-left: 2px solid transparent; }
  .toc a:hover { border-left-color: var(--cyan); color: var(--cyan); text-decoration: none; }
  footer { text-align: center; color: var(--dim); font-size: 0.8rem;
           margin-top: 40px; padding-top: 20px; border-top: 1px solid var(--bg3); }
</style>
</head>
<body>
<div class="header">
  <h1>🔍 OSINTool v4.0</h1>
HTMLEOF
    echo "  <div class='meta'>Gerado em: $(date '+%d/%m/%Y %H:%M:%S') | Relatório OSINT Profissional</div>" >> "$HTML_REPORT"
    echo "</div>" >> "$HTML_REPORT"
}

append_html() {
    echo "$1" >> "$HTML_REPORT"
}

close_html() {
    cat >> "$HTML_REPORT" << 'EOF'
<footer>OSINTool v4.0 — Use com responsabilidade e apenas para fins legais.</footer>
</body></html>
EOF
}

# ========================= CSV SETUP ==============================
init_csv() {
    echo "Timestamp,Categoria,Subcategoria,Campo,Valor" > "$CSV_REPORT"
}

append_csv() {
    local cat="$1" subcat="$2" field="$3" value="$4"
    echo "\"$(date '+%Y-%m-%d %H:%M:%S')\",\"$cat\",\"$subcat\",\"$field\",\"$(echo "$value" | tr '"' "'")\"" >> "$CSV_REPORT"
}

# ========================= DEPENDÊNCIAS ===========================
check_deps() {
    local required=("curl" "jq" "whois" "dig" "host" "nmap" "exiftool" "python3")
    local optional=("nslookup" "traceroute" "masscan" "amass" "dnsrecon" "whatweb" "nikto" "sslscan" "theHarvester" "sublist3r" "fierce" "dnsx" "httpx" "nuclei" "gau" "waybackurls")
    local missing_req=()
    local missing_opt=()

    section "VERIFICAÇÃO DE DEPENDÊNCIAS"

    for dep in "${required[@]}"; do
        if command -v "$dep" &>/dev/null; then
            found "$dep (obrigatório) — disponível"
        else
            missing_req+=("$dep")
            not_found "$dep (obrigatório) — FALTANDO"
        fi
    done

    for dep in "${optional[@]}"; do
        if command -v "$dep" &>/dev/null; then
            found "$dep (opcional) — disponível"
        else
            missing_opt+=("$dep")
            warning "$dep (opcional) — não instalado"
        fi
    done

    if [ ${#missing_req[@]} -ne 0 ]; then
        error "Ferramentas obrigatórias faltando: ${missing_req[*]}"
        read -rp "Instalar automaticamente? (s/n): " install_opt
        if [[ "$install_opt" =~ ^[Ss]$ ]]; then
            sudo apt-get update -qq
            sudo apt-get install -y "${missing_req[@]}" 2>/dev/null
        else
            error "Instale as dependências e execute novamente."
            exit 1
        fi
    fi

    if [ ${#missing_opt[@]} -gt 0 ] && [[ "$SILENT_MODE" == false ]]; then
        warning "Ferramentas opcionais não encontradas: ${missing_opt[*]}"
        warning "Algumas funcionalidades serão limitadas."
    fi
}

# ========================= BANNER =================================
banner() {
    clear
    echo -e "${CYAN}${BOLD}"
    cat << "BANNER"
  ██████╗ ███████╗██╗███╗   ██╗████████╗ ██████╗  ██████╗ ██╗     
 ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝██╔═══██╗██╔══██╗██║     
 ██║   ██║███████╗██║██╔██╗ ██║   ██║   ██║   ██║██║  ██║██║     
 ██║   ██║╚════██║██║██║╚██╗██║   ██║   ██║   ██║██║  ██║██║     
 ╚██████╔╝███████║██║██║ ╚████║   ██║   ╚██████╔╝██████╔╝███████╗
  ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═════╝ ╚══════╝
BANNER
    echo -e "${NC}"
    echo -e "  ${WHITE}${BOLD}OSINTool v4.0${NC}  ${DIM}— Coleta de Inteligência de Fontes Abertas${NC}"
    echo -e "  ${DIM}Log: $LOG_FILE${NC}"
    echo -e "  ${DIM}Saída: $OUTPUT_DIR/${NC}\n"
}

# ========================= MÓDULO 1: DOMÍNIO ======================
domain_recon() {
    local domain="$1"
    section "RECONHECIMENTO DE DOMÍNIO: $domain"
    append_html "<div class='section' id='domain'><h2>🌐 Domínio <span class='badge'>$domain</span></h2>"

    # --- WHOIS ---
    subsection "WHOIS Lookup"
    local whois_data
    whois_data=$(whois "$domain" 2>/dev/null)
    local registrar created expires status
    registrar=$(echo "$whois_data" | grep -iE "registrar:" | head -1 | cut -d: -f2- | xargs)
    created=$(echo "$whois_data" | grep -iE "creation date:|created:" | head -1 | cut -d: -f2- | xargs)
    expires=$(echo "$whois_data" | grep -iE "expiry date:|expires:" | head -1 | cut -d: -f2- | xargs)
    status=$(echo "$whois_data" | grep -iE "^status:" | head -3 | cut -d: -f2- | xargs)

    echo "  Registrar : $registrar"
    echo "  Criado em : $created"
    echo "  Expira em : $expires"
    echo "  Status    : $status"

    append_csv "Domínio" "WHOIS" "Registrar" "$registrar"
    append_csv "Domínio" "WHOIS" "Criado" "$created"
    append_csv "Domínio" "WHOIS" "Expira" "$expires"

    append_html "<div class='subsection'><h3>WHOIS</h3><div class='grid'>
      <div class='card'><div class='label'>Registrar</div><div class='value'>$registrar</div></div>
      <div class='card'><div class='label'>Criado</div><div class='value'>$created</div></div>
      <div class='card'><div class='label'>Expira</div><div class='value'>$expires</div></div>
      <div class='card'><div class='label'>Status</div><div class='value'>$status</div></div>
    </div></div>"

    # --- DNS ---
    subsection "Registros DNS"
    for record in A AAAA MX TXT NS SOA CNAME; do
        local rec_data
        rec_data=$(dig "$domain" "$record" +short 2>/dev/null)
        if [[ -n "$rec_data" ]]; then
            echo "  $record: $rec_data"
            append_csv "Domínio" "DNS" "$record" "$rec_data"
            append_html "<div class='subsection'><h3>DNS $record</h3><pre>$rec_data</pre></div>"
        fi
    done

    # SPF / DMARC / DKIM check
    subsection "Email Security Records"
    local spf dmarc
    spf=$(dig "$domain" TXT +short 2>/dev/null | grep -i "v=spf")
    dmarc=$(dig "_dmarc.$domain" TXT +short 2>/dev/null)
    [[ -n "$spf" ]] && found "SPF: $spf" || warning "SPF: não encontrado"
    [[ -n "$dmarc" ]] && found "DMARC: $dmarc" || warning "DMARC: não encontrado"
    append_html "<div class='subsection'><h3>Email Security</h3>
      <pre>SPF: ${spf:-NÃO ENCONTRADO}\nDMARC: ${dmarc:-NÃO ENCONTRADO}</pre></div>"

    # --- Subdomínios passivos (várias fontes) ---
    subsection "Enumeração de Subdomínios"
    local subs_file="$TEMP_DIR/subdomains_$domain.txt"
    touch "$subs_file"

    # crt.sh (Certificate Transparency)
    info "  → crt.sh (Certificate Transparency)..."
    safe_curl "https://crt.sh/?q=%25.$domain&output=json" | \
        jq -r '.[].name_value' 2>/dev/null | sort -u | grep -v '*' >> "$subs_file"

    # HackerTarget
    info "  → HackerTarget..."
    safe_curl "https://api.hackertarget.com/hostsearch/?q=$domain" | \
        cut -d',' -f1 >> "$subs_file" 2>/dev/null

    # RapidDNS
    info "  → RapidDNS..."
    safe_curl "https://rapiddns.io/subdomain/$domain?full=1" | \
        grep -oP '(?<=<td>)[a-zA-Z0-9._-]+\.'$domain'(?=</td>)' >> "$subs_file" 2>/dev/null

    # Amass (se disponível)
    if command -v amass &>/dev/null; then
        info "  → Amass (passivo)..."
        amass enum -passive -d "$domain" -o "$TEMP_DIR/amass_$domain.txt" 2>/dev/null &
        local amass_pid=$!
        sleep 15
        kill "$amass_pid" 2>/dev/null
        cat "$TEMP_DIR/amass_$domain.txt" >> "$subs_file" 2>/dev/null
    fi

    # Sublist3r
    if command -v sublist3r &>/dev/null; then
        info "  → Sublist3r..."
        sublist3r -d "$domain" -o "$TEMP_DIR/sublist3r_$domain.txt" -q 2>/dev/null
        cat "$TEMP_DIR/sublist3r_$domain.txt" >> "$subs_file" 2>/dev/null
    fi

    sort -u "$subs_file" -o "$subs_file"
    local sub_count
    sub_count=$(wc -l < "$subs_file")
    found "Total de subdomínios encontrados: $sub_count"

    # Verifica quais estão ativos
    subsection "Subdomínios Ativos"
    local active_subs=()
    while IFS= read -r sub; do
        [[ -z "$sub" ]] && continue
        local ip
        ip=$(dig "$sub" A +short 2>/dev/null | head -1)
        if [[ -n "$ip" ]]; then
            found "$sub → $ip"
            active_subs+=("$sub:$ip")
            append_csv "Domínio" "Subdomínios" "$sub" "$ip"
        fi
    done < "$subs_file"

    append_html "<div class='subsection'><h3>Subdomínios ($sub_count encontrados)</h3><pre>"
    while IFS= read -r sub; do append_html "$sub"; done < "$subs_file"
    append_html "</pre></div>"

    # --- Tecnologias (WhatWeb) ---
    if command -v whatweb &>/dev/null; then
        subsection "Tecnologias Detectadas"
        local tech
        tech=$(whatweb "https://$domain" 2>/dev/null)
        echo "$tech"
        append_html "<div class='subsection'><h3>Tecnologias (WhatWeb)</h3><pre>$tech</pre></div>"
    fi

    # --- Certificado SSL ---
    subsection "Certificado SSL/TLS"
    local cert_info
    cert_info=$(echo | openssl s_client -connect "$domain:443" -servername "$domain" 2>/dev/null | openssl x509 -noout -text 2>/dev/null | grep -E "Subject:|Issuer:|Not Before:|Not After:|DNS:")
    if [[ -n "$cert_info" ]]; then
        echo "$cert_info"
        append_html "<div class='subsection'><h3>Certificado SSL</h3><pre>$cert_info</pre></div>"
    fi

    # sslscan
    if command -v sslscan &>/dev/null; then
        subsection "SSL Scan (vulnerabilidades)"
        local ssl_vulns
        ssl_vulns=$(sslscan --no-colour "$domain" 2>/dev/null | grep -E "VULNERABLE|SSLv|TLSv|RC4|POODLE|HEARTBLEED|BEAST")
        [[ -n "$ssl_vulns" ]] && echo "$ssl_vulns" && append_html "<div class='subsection'><h3>SSL Vulnerabilidades</h3><pre class='severity-high'>$ssl_vulns</pre></div>"
    fi

    # --- Wayback Machine ---
    subsection "URLs Históricas (Wayback Machine)"
    local wayback
    wayback=$(safe_curl "http://web.archive.org/cdx/search/cdx?url=$domain/*&output=text&fl=original&limit=50&collapse=urlkey")
    if [[ -n "$wayback" ]]; then
        echo "$wayback" | head -20
        local wb_count; wb_count=$(echo "$wayback" | wc -l)
        found "Total de URLs encontradas: $wb_count"
        append_html "<div class='subsection'><h3>Wayback Machine ($wb_count URLs)</h3><pre>$wayback</pre></div>"
    fi

    # --- Google Cache check ---
    subsection "Robots.txt e Sitemap"
    local robots sitemap
    robots=$(safe_curl "https://$domain/robots.txt" | head -30)
    sitemap=$(safe_curl "https://$domain/sitemap.xml" | grep -oP '<loc>[^<]+</loc>' | sed 's/<[^>]*>//g' | head -20)
    [[ -n "$robots" ]] && append_html "<div class='subsection'><h3>Robots.txt</h3><pre>$robots</pre></div>"
    [[ -n "$sitemap" ]] && append_html "<div class='subsection'><h3>Sitemap</h3><pre>$sitemap</pre></div>"

    # --- SecurityTrails ---
    if [[ -n "$SECURITYTRAILS_API_KEY" ]]; then
        subsection "SecurityTrails (histórico DNS)"
        rate_limit
        local st_data
        st_data=$(safe_curl "https://api.securitytrails.com/v1/domain/$domain/dns/a" \
            -H "APIKEY: $SECURITYTRAILS_API_KEY")
        echo "$st_data" | jq '.records[].values[].ip' 2>/dev/null
        append_html "<div class='subsection'><h3>SecurityTrails DNS History</h3><pre>$(echo "$st_data" | jq '.' 2>/dev/null)</pre></div>"
    fi

    # --- Shodan ---
    if [[ -n "$SHODAN_API_KEY" ]]; then
        subsection "Shodan"
        rate_limit
        local shodan_data
        shodan_data=$(safe_curl "https://api.shodan.io/shodan/host/search?key=$SHODAN_API_KEY&query=hostname:$domain")
        echo "$shodan_data" | jq -r '.matches[] | "\(.ip_str) — \(.org) — Portas: \(.port)"' 2>/dev/null | head -15
        append_html "<div class='subsection'><h3>Shodan</h3><pre>$(echo "$shodan_data" | jq '.matches[] | {ip: .ip_str, org: .org, port: .port}' 2>/dev/null | head -20)</pre></div>"
    fi

    # --- Nikto (se disponível) ---
    if command -v nikto &>/dev/null; then
        subsection "Nikto (vulnerabilidades web)"
        warning "Executando Nikto (pode levar alguns minutos)..."
        local nikto_out
        nikto_out=$(nikto -h "https://$domain" -maxtime 60 2>/dev/null | grep -E "^\+")
        echo "$nikto_out" | head -20
        append_html "<div class='subsection'><h3>Nikto</h3><pre class='severity-medium'>$nikto_out</pre></div>"
    fi

    append_html "</div>"
}

# ========================= MÓDULO 2: EMAIL =======================
email_osint() {
    local email="$1"
    section "OSINT DE E-MAIL: $email"
    append_html "<div class='section' id='email'><h2>📧 E-mail <span class='badge'>$email</span></h2>"

    local domain_email
    domain_email=$(echo "$email" | cut -d'@' -f2)
    local username_email
    username_email=$(echo "$email" | cut -d'@' -f1)

    # --- Validação de formato ---
    subsection "Validação"
    if [[ "$email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        found "Formato de e-mail válido"
    else
        warning "Formato de e-mail suspeito"
    fi

    # --- MX Records ---
    subsection "Servidores MX do domínio"
    local mx
    mx=$(dig "$domain_email" MX +short | sort -n)
    echo "$mx"
    [[ -n "$mx" ]] && found "Servidores MX encontrados" || warning "Sem MX — domínio pode não receber emails"
    append_html "<div class='subsection'><h3>MX Records</h3><pre>$mx</pre></div>"

    # --- Provedor de email ---
    subsection "Identificação do Provedor"
    if echo "$mx" | grep -qi "google\|gmail"; then
        found "Provedor: Google (Gmail/Google Workspace)"
    elif echo "$mx" | grep -qi "outlook\|microsoft\|hotmail"; then
        found "Provedor: Microsoft (Outlook/Office365)"
    elif echo "$mx" | grep -qi "yahoo"; then
        found "Provedor: Yahoo Mail"
    elif echo "$mx" | grep -qi "protonmail\|proton.me"; then
        found "Provedor: ProtonMail (criptografado)"
    else
        info "Provedor: Personalizado/Desconhecido"
    fi

    # --- Gravatar ---
    subsection "Gravatar"
    local hash_md5
    hash_md5=$(echo -n "$email" | md5sum | awk '{print $1}')
    local gravatar_url="https://www.gravatar.com/avatar/$hash_md5?d=404"
    local gravatar_http
    gravatar_http=$(curl -s -o /dev/null -w "%{http_code}" "$gravatar_url")
    if [[ "$gravatar_http" == "200" ]]; then
        found "Perfil Gravatar encontrado: $gravatar_url"
        append_html "<div class='subsection'><h3>Gravatar</h3><p class='found'>✓ Encontrado: <a href='$gravatar_url'>$gravatar_url</a></p>
          <img src='https://www.gravatar.com/avatar/$hash_md5?s=150' style='border-radius:50%;border:2px solid #00d4ff;'/></div>"
    else
        not_found "Sem perfil Gravatar"
        append_html "<div class='subsection'><h3>Gravatar</h3><p class='notfound'>✗ Não encontrado</p></div>"
    fi

    # --- Have I Been Pwned ---
    subsection "Have I Been Pwned"
    if [[ -n "$HIBP_API_KEY" ]]; then
        rate_limit
        local hibp_result
        hibp_result=$(safe_curl "https://haveibeenpwned.com/api/v3/breachedaccount/$email?truncateResponse=false" \
            -H "hibp-api-key: $HIBP_API_KEY" -H "User-Agent: OSINTool/4.0")
        if [[ -n "$hibp_result" ]] && echo "$hibp_result" | jq -e '.[0]' &>/dev/null; then
            local breach_count
            breach_count=$(echo "$hibp_result" | jq '. | length')
            warning "ALERTA: $breach_count vazamentos encontrados!"
            echo "$hibp_result" | jq -r '.[] | "  [\(.BreachDate)] \(.Name) — \(.DataClasses | join(", "))"' 2>/dev/null
            append_html "<div class='subsection'><h3>Have I Been Pwned</h3>
              <p class='warning'>⚠ $breach_count vazamentos!</p>
              <pre>$(echo "$hibp_result" | jq -r '.[] | "[\(.BreachDate)] \(.Name) — \(.DataClasses | join(", "))"' 2>/dev/null)</pre></div>"
            append_csv "Email" "HIBP" "Vazamentos" "$breach_count"
        else
            found "Nenhum vazamento encontrado no HIBP"
            append_html "<div class='subsection'><h3>Have I Been Pwned</h3><p class='found'>✓ Sem vazamentos</p></div>"
        fi
    else
        warning "Chave HIBP não configurada — pulando verificação"
    fi

    # --- Paste sites (pastebin, etc.) ---
    subsection "Pastebins / Leaks"
    if [[ -n "$HIBP_API_KEY" ]]; then
        rate_limit
        local paste_result
        paste_result=$(safe_curl "https://haveibeenpwned.com/api/v3/pasteaccount/$email" \
            -H "hibp-api-key: $HIBP_API_KEY" -H "User-Agent: OSINTool/4.0")
        if [[ -n "$paste_result" ]] && echo "$paste_result" | jq -e '.[0]' &>/dev/null; then
            local paste_count
            paste_count=$(echo "$paste_result" | jq '. | length')
            warning "$paste_count pastes encontrados!"
            echo "$paste_result" | jq -r '.[] | "  \(.Source): \(.Title // "Sem título") (\(.Date // "?"))"' 2>/dev/null
        else
            found "Nenhum paste encontrado"
        fi
    fi

    # --- Hunter.io ---
    if [[ -n "$HUNTER_API_KEY" ]]; then
        subsection "Hunter.io (verificação e outros emails)"
        rate_limit
        local hunter_verify
        hunter_verify=$(safe_curl "https://api.hunter.io/v2/email-verifier?email=$email&api_key=$HUNTER_API_KEY")
        local deliverability confidence
        deliverability=$(echo "$hunter_verify" | jq -r '.data.result' 2>/dev/null)
        confidence=$(echo "$hunter_verify" | jq -r '.data.score' 2>/dev/null)
        echo "  Deliverability: $deliverability"
        echo "  Confiança: $confidence/100"
        append_html "<div class='subsection'><h3>Hunter.io</h3><div class='grid'>
          <div class='card'><div class='label'>Deliverability</div><div class='value'>$deliverability</div></div>
          <div class='card'><div class='label'>Score</div><div class='value'>$confidence/100</div></div>
        </div></div>"
    fi

    # --- theHarvester ---
    if command -v theHarvester &>/dev/null; then
        subsection "theHarvester (e-mails no mesmo domínio)"
        local harvester_out
        harvester_out=$(theHarvester -d "$domain_email" -b all -l 30 2>/dev/null | grep -E "@$domain_email" | sort -u)
        echo "$harvester_out"
        append_html "<div class='subsection'><h3>E-mails Relacionados (theHarvester)</h3><pre>$harvester_out</pre></div>"
    fi

    # --- Busca em redes sociais por username do email ---
    subsection "Username derivado: $username_email"
    local social_sites=(
        "github.com/$username_email"
        "twitter.com/$username_email"
        "instagram.com/$username_email"
        "linkedin.com/in/$username_email"
        "reddit.com/user/$username_email"
    )
    for site in "${social_sites[@]}"; do
        local status
        status=$(curl -s -o /dev/null -w "%{http_code}" -A "$USER_AGENT" "https://$site" --max-time 5)
        [[ "$status" == "200" ]] && found "https://$site" || not_found "https://$site"
    done

    append_html "</div>"
}

# ========================= MÓDULO 3: IP ==========================
ip_geo_intel() {
    local ip="$1"
    section "INTELIGÊNCIA DE IP: $ip"
    append_html "<div class='section' id='ip'><h2>🌍 IP <span class='badge'>$ip</span></h2>"

    # --- Geolocalização ---
    subsection "Geolocalização"
    local geo
    if [[ -n "$IPINFO_TOKEN" ]]; then
        geo=$(safe_curl "https://ipinfo.io/$ip?token=$IPINFO_TOKEN")
    else
        geo=$(safe_curl "https://ipinfo.io/$ip")
    fi

    if [[ -n "$geo" ]]; then
        local city country org timezone loc
        city=$(echo "$geo" | jq -r '.city // "?"')
        country=$(echo "$geo" | jq -r '.country // "?"')
        org=$(echo "$geo" | jq -r '.org // "?"')
        timezone=$(echo "$geo" | jq -r '.timezone // "?"')
        loc=$(echo "$geo" | jq -r '.loc // "?"')

        echo "  Cidade   : $city"
        echo "  País     : $country"
        echo "  ASN/Org  : $org"
        echo "  Timezone : $timezone"
        echo "  Coords   : $loc"

        append_html "<div class='subsection'><h3>Geolocalização</h3><div class='grid'>
          <div class='card'><div class='label'>Cidade</div><div class='value'>$city, $country</div></div>
          <div class='card'><div class='label'>ASN/Org</div><div class='value'>$org</div></div>
          <div class='card'><div class='label'>Timezone</div><div class='value'>$timezone</div></div>
          <div class='card'><div class='label'>Coordenadas</div><div class='value'>$loc</div></div>
        </div></div>"
        append_csv "IP" "Geo" "Cidade" "$city, $country"
        append_csv "IP" "Geo" "ASN" "$org"
    fi

    # --- WHOIS IP ---
    subsection "WHOIS IP"
    local whois_ip
    whois_ip=$(whois "$ip" 2>/dev/null | grep -E "^(NetName|OrgName|Country|CIDR|inetnum|netname|descr|route):" | head -15)
    echo "$whois_ip"
    append_html "<div class='subsection'><h3>WHOIS IP</h3><pre>$whois_ip</pre></div>"

    # --- Reverse DNS ---
    subsection "Reverse DNS"
    local rev_dns
    rev_dns=$(host "$ip" 2>/dev/null)
    echo "$rev_dns"
    append_html "<div class='subsection'><h3>Reverse DNS</h3><pre>$rev_dns</pre></div>"

    # --- AbuseIPDB ---
    if [[ -n "$ABUSEIPDB_API_KEY" ]]; then
        subsection "AbuseIPDB (reputação)"
        rate_limit
        local abuse_data
        abuse_data=$(safe_curl "https://api.abuseipdb.com/api/v2/check" \
            -H "Key: $ABUSEIPDB_API_KEY" -H "Accept: application/json" \
            -d "ipAddress=$ip&maxAgeInDays=90")
        local abuse_score abuse_reports
        abuse_score=$(echo "$abuse_data" | jq -r '.data.abuseConfidenceScore // 0')
        abuse_reports=$(echo "$abuse_data" | jq -r '.data.totalReports // 0')
        if [[ "$abuse_score" -gt 50 ]]; then
            warning "ALERTA: Score de abuso $abuse_score/100 ($abuse_reports reports)"
        else
            found "Score de abuso: $abuse_score/100 ($abuse_reports reports)"
        fi
        append_html "<div class='subsection'><h3>AbuseIPDB</h3>
          <div class='grid'>
            <div class='card'><div class='label'>Abuse Score</div><div class='value $([ "$abuse_score" -gt 50 ] && echo "severity-high" || echo "found")'>$abuse_score/100</div></div>
            <div class='card'><div class='label'>Reports</div><div class='value'>$abuse_reports</div></div>
          </div></div>"
        append_csv "IP" "AbuseIPDB" "Score" "$abuse_score"
    fi

    # --- GreyNoise ---
    if [[ -n "$GREYNOISE_API_KEY" ]]; then
        subsection "GreyNoise (classificação de ruído)"
        rate_limit
        local gn_data
        gn_data=$(safe_curl "https://api.greynoise.io/v3/community/$ip" \
            -H "key: $GREYNOISE_API_KEY")
        local gn_noise gn_riot gn_classification
        gn_noise=$(echo "$gn_data" | jq -r '.noise // false')
        gn_riot=$(echo "$gn_data" | jq -r '.riot // false')
        gn_classification=$(echo "$gn_data" | jq -r '.classification // "unknown"')
        echo "  Noise        : $gn_noise"
        echo "  RIOT (legit) : $gn_riot"
        echo "  Classificação: $gn_classification"
        append_html "<div class='subsection'><h3>GreyNoise</h3><div class='grid'>
          <div class='card'><div class='label'>Noise</div><div class='value'>$gn_noise</div></div>
          <div class='card'><div class='label'>RIOT (legítimo)</div><div class='value'>$gn_riot</div></div>
          <div class='card'><div class='label'>Classificação</div><div class='value'>$gn_classification</div></div>
        </div></div>"
    fi

    # --- Shodan ---
    if [[ -n "$SHODAN_API_KEY" ]]; then
        subsection "Shodan (serviços expostos)"
        rate_limit
        local shodan_ip
        shodan_ip=$(safe_curl "https://api.shodan.io/shodan/host/$ip?key=$SHODAN_API_KEY")
        if echo "$shodan_ip" | jq -e '.ip_str' &>/dev/null; then
            local ports vulns
            ports=$(echo "$shodan_ip" | jq -r '.ports[]' 2>/dev/null | tr '\n' ', ')
            vulns=$(echo "$shodan_ip" | jq -r '.vulns | keys[]' 2>/dev/null | head -10)
            echo "  Portas abertas: $ports"
            [[ -n "$vulns" ]] && warning "CVEs encontrados:\n$vulns"
            append_html "<div class='subsection'><h3>Shodan</h3>
              <div class='card'><div class='label'>Portas</div><div class='value'>$ports</div></div>
              $([ -n "$vulns" ] && echo "<div class='card'><div class='label severity-high'>CVEs</div><div class='value severity-high'>$vulns</div></div>")</div>"
        fi
    fi

    # --- Censys ---
    if [[ -n "$CENSYS_API_ID" && -n "$CENSYS_API_SECRET" ]]; then
        subsection "Censys"
        rate_limit
        local censys_data
        censys_data=$(safe_curl "https://search.censys.io/api/v2/hosts/$ip" \
            -u "$CENSYS_API_ID:$CENSYS_API_SECRET")
        echo "$censys_data" | jq '.result.services[] | "\(.port)/\(.transport_protocol) \(.service_name)"' 2>/dev/null | head -10
        append_html "<div class='subsection'><h3>Censys</h3><pre>$(echo "$censys_data" | jq '.result.services[]' 2>/dev/null)</pre></div>"
    fi

    # --- VirusTotal ---
    if [[ -n "$VIRUSTOTAL_API_KEY" ]]; then
        subsection "VirusTotal"
        rate_limit
        local vt_data
        vt_data=$(safe_curl "https://www.virustotal.com/api/v3/ip_addresses/$ip" \
            -H "x-apikey: $VIRUSTOTAL_API_KEY")
        local malicious suspicious
        malicious=$(echo "$vt_data" | jq '.data.attributes.last_analysis_stats.malicious // 0')
        suspicious=$(echo "$vt_data" | jq '.data.attributes.last_analysis_stats.suspicious // 0')
        [[ "$malicious" -gt 0 ]] && warning "MALICIOSO em $malicious engines!" || found "Limpo"
        echo "  Malicioso  : $malicious"
        echo "  Suspeito   : $suspicious"
        append_html "<div class='subsection'><h3>VirusTotal</h3><div class='grid'>
          <div class='card'><div class='label'>Malicioso</div><div class='value $([ "$malicious" -gt 0 ] && echo "severity-high" || echo "found")'>$malicious engines</div></div>
          <div class='card'><div class='label'>Suspeito</div><div class='value'>$suspicious engines</div></div>
        </div></div>"
    fi

    # --- Traceroute ---
    subsection "Traceroute"
    if command -v traceroute &>/dev/null; then
        local trace
        trace=$(traceroute -n -w 2 -q 1 "$ip" 2>/dev/null | head -20)
        echo "$trace"
        append_html "<div class='subsection'><h3>Traceroute</h3><pre>$trace</pre></div>"
    fi

    # --- ASN Info ---
    subsection "Informações ASN"
    local asn_info
    asn_info=$(safe_curl "https://api.hackertarget.com/aslookup/?q=$ip")
    echo "$asn_info"
    append_html "<div class='subsection'><h3>ASN</h3><pre>$asn_info</pre></div>"

    # --- Checar se é TOR ---
    subsection "Verificação TOR/VPN"
    local tor_check
    tor_check=$(safe_curl "https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=$ip&port=80" 2>/dev/null)
    if echo "$tor_check" | grep -q "$ip"; then
        warning "IP está na lista de saída TOR!"
        append_html "<div class='subsection'><h3>TOR</h3><p class='warning'>⚠ IP identificado como saída TOR!</p></div>"
    else
        found "IP não está em listas TOR conhecidas"
    fi

    append_html "</div>"
}

# ========================= MÓDULO 4: USERNAME ====================
username_search() {
    local username="$1"
    section "BUSCA DE USERNAME: $username"
    append_html "<div class='section' id='username'><h2>👤 Username <span class='badge'>$username</span></h2>"

    local found_count=0
    local not_found_count=0

    declare -A SITES=(
        ["GitHub"]="github.com/$username"
        ["GitLab"]="gitlab.com/$username"
        ["Twitter/X"]="twitter.com/$username"
        ["Instagram"]="instagram.com/$username"
        ["Facebook"]="facebook.com/$username"
        ["LinkedIn"]="linkedin.com/in/$username"
        ["TikTok"]="tiktok.com/@$username"
        ["Reddit"]="reddit.com/user/$username"
        ["YouTube"]="youtube.com/@$username"
        ["Twitch"]="twitch.tv/$username"
        ["Telegram"]="t.me/$username"
        ["Medium"]="medium.com/@$username"
        ["Dev.to"]="dev.to/$username"
        ["Pinterest"]="pinterest.com/$username"
        ["Snapchat"]="snapchat.com/add/$username"
        ["Keybase"]="keybase.io/$username"
        ["Pastebin"]="pastebin.com/u/$username"
        ["HackerNews"]="news.ycombinator.com/user?id=$username"
        ["ProductHunt"]="producthunt.com/@$username"
        ["Behance"]="behance.net/$username"
        ["Dribbble"]="dribbble.com/$username"
        ["Steam"]="steamcommunity.com/id/$username"
        ["Spotify"]="open.spotify.com/user/$username"
        ["SoundCloud"]="soundcloud.com/$username"
        ["Flickr"]="flickr.com/people/$username"
        ["Vimeo"]="vimeo.com/$username"
        ["Tumblr"]="$username.tumblr.com"
        ["WordPress"]="$username.wordpress.com"
        ["Blogger"]="$username.blogspot.com"
        ["About.me"]="about.me/$username"
        ["Gravatar"]="gravatar.com/$username"
        ["Foursquare"]="foursquare.com/$username"
        ["Cash.app"]="cash.app/\$$username"
        ["Venmo"]="venmo.com/$username"
        ["DockerHub"]="hub.docker.com/u/$username"
        ["NPM"]="npmjs.com/~$username"
        ["PyPI"]="pypi.org/user/$username"
        ["Replit"]="replit.com/@$username"
        ["CodePen"]="codepen.io/$username"
    )

    append_html "<div class='subsection'><h3>Redes Sociais e Plataformas</h3><div style='font-family:monospace;font-size:0.85rem;'>"

    for site_name in "${!SITES[@]}"; do
        local url="https://${SITES[$site_name]}"
        local status
        status=$(curl -s -o /dev/null -w "%{http_code}" -A "$USER_AGENT" --max-time 8 -L "$url" 2>/dev/null)

        if [[ "$status" == "200" ]]; then
            found "$site_name: $url"
            append_html "<div class='found'>✓ <a href='$url' target='_blank'>$site_name — $url</a></div>"
            append_csv "Username" "Redes Sociais" "$site_name" "$url"
            ((found_count++))
        elif [[ "$status" == "404" ]]; then
            not_found "$site_name: não encontrado"
            append_html "<div class='notfound' style='color:#333'>✗ $site_name</div>"
            ((not_found_count++))
        else
            echo -e "  ${GRAY}[?] $site_name: HTTP $status${NC}"
            append_html "<div style='color:#4a6080'>? $site_name (HTTP $status)</div>"
        fi
        rate_limit
    done

    echo ""
    found "Total encontrado: $found_count plataformas"
    not_found "Não encontrado: $not_found_count plataformas"
    append_html "</div></div>"

    # --- Busca em motores de busca ---
    subsection "Google Dorks para o username"
    echo '  Dorks sugeridos:'
    echo "  → \"$username\" site:linkedin.com"
    echo "  → \"$username\" filetype:pdf OR filetype:docx"
    echo "  → intext:\"$username\" email"
    echo "  → \"$username\" site:github.com"
    append_html "<div class='subsection'><h3>Google Dorks</h3><pre>
\"$username\" site:linkedin.com
\"$username\" filetype:pdf OR filetype:docx
intext:\"$username\" email
\"$username\" site:github.com
intitle:\"$username\" -site:facebook.com -site:instagram.com</pre></div>"

    append_html "</div>"
}

# ========================= MÓDULO 5: PORT SCAN ===================
port_scan_full() {
    local target="$1"
    section "SCAN DE PORTAS: $target"
    append_html "<div class='section' id='portscan'><h2>🔌 Port Scan <span class='badge'>$target</span></h2>"

    # Scan rápido
    subsection "Scan rápido (top 1000 portas)"
    local nmap_quick
    nmap_quick=$(nmap -F -sV -sC --open -T4 "$target" 2>/dev/null)
    echo "$nmap_quick" | grep -E "^[0-9]|open|filtered"
    append_html "<div class='subsection'><h3>Nmap Rápido</h3><pre>$nmap_quick</pre></div>"

    # Scan de scripts de vulnerabilidade
    subsection "NSE Scripts (vulnerabilidades comuns)"
    local nmap_vuln
    nmap_vuln=$(nmap --script=vuln,exploit -sV --open -T3 "$target" -p 21,22,23,25,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443 2>/dev/null)
    echo "$nmap_vuln" | grep -E "VULNERABLE|CVE|critical|HIGH|MEDIUM"
    append_html "<div class='subsection'><h3>Vulnerabilidades (NSE)</h3><pre class='severity-medium'>$nmap_vuln</pre></div>"

    # Masscan (se disponível e root)
    if command -v masscan &>/dev/null && [[ $EUID -eq 0 ]]; then
        subsection "Masscan (todas as 65535 portas)"
        warning "Executando masscan... (requer root)"
        local masscan_out="$TEMP_DIR/masscan_$target.txt"
        masscan "$target" -p1-65535 --rate=2000 -oG "$masscan_out" 2>/dev/null
        local open_ports
        open_ports=$(grep -oP 'Ports: \K[0-9]+' "$masscan_out" | sort -n | tr '\n' ',' | sed 's/,$//')
        echo "  Portas abertas: $open_ports"
        append_html "<div class='subsection'><h3>Masscan (todas portas)</h3><pre>$open_ports</pre></div>"

        # Scan detalhado nas portas encontradas
        if [[ -n "$open_ports" ]]; then
            subsection "Scan detalhado das portas abertas"
            local nmap_detailed
            nmap_detailed=$(nmap -sV -sC -p "$open_ports" "$target" 2>/dev/null)
            echo "$nmap_detailed"
            append_html "<div class='subsection'><h3>Serviços Detalhados</h3><pre>$nmap_detailed</pre></div>"
        fi
    fi

    append_html "</div>"
}

# ========================= MÓDULO 6: METADADOS ==================
metadata_extract() {
    local target="$1"
    section "EXTRAÇÃO DE METADADOS: $target"
    append_html "<div class='section' id='metadata'><h2>📄 Metadados <span class='badge'>$target</span></h2>"

    local tmp_file="$TEMP_DIR/metadata_dl"

    if [[ "$target" =~ ^https?:// ]]; then
        subsection "Download e análise de URL"
        curl -s -L -A "$USER_AGENT" "$target" -o "$tmp_file" --max-time 30
        local mime_type
        mime_type=$(file --mime-type -b "$tmp_file")
        info "Tipo MIME: $mime_type"

        case "$mime_type" in
            image/*)
                local exif_data
                exif_data=$(exiftool "$tmp_file" 2>/dev/null)
                echo "$exif_data"
                # Extrai GPS se houver
                local gps
                gps=$(echo "$exif_data" | grep -i "GPS")
                [[ -n "$gps" ]] && warning "ALERTA: Dados GPS encontrados!\n$gps"
                append_html "<div class='subsection'><h3>EXIF (imagem)</h3><pre>$exif_data</pre>
                  $([ -n "$gps" ] && echo "<p class='warning'>⚠ GPS encontrado: $gps</p>")</div>"
                ;;
            application/pdf)
                local pdf_meta
                pdf_meta=$(exiftool "$tmp_file" 2>/dev/null | grep -E "^(Author|Creator|Producer|Create Date|Modify Date|Title|Subject|Keywords|Company|Software)")
                echo "$pdf_meta"
                append_html "<div class='subsection'><h3>Metadados PDF</h3><pre>$pdf_meta</pre></div>"
                # Extrai links do PDF
                if command -v pdfgrep &>/dev/null; then
                    local pdf_links
                    pdf_links=$(pdfgrep -oP 'https?://[^\s>]+' "$tmp_file" | sort -u | head -20)
                    [[ -n "$pdf_links" ]] && append_html "<div class='subsection'><h3>URLs no PDF</h3><pre>$pdf_links</pre></div>"
                fi
                ;;
            text/html*)
                subsection "Análise HTML"
                local title author generator description
                title=$(grep -oP '(?i)(?<=<title>).*?(?=</title>)' "$tmp_file" | head -1)
                author=$(grep -oP '(?i)(?<=name="author" content=")[^"]+' "$tmp_file" | head -1)
                generator=$(grep -oP '(?i)(?<=name="generator" content=")[^"]+' "$tmp_file" | head -1)
                description=$(grep -oP '(?i)(?<=name="description" content=")[^"]+' "$tmp_file" | head -1)
                echo "  Título     : $title"
                echo "  Autor      : $author"
                echo "  Generator  : $generator"
                echo "  Descrição  : $description"
                # Extrai emails da página
                local emails_found
                emails_found=$(grep -oP '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' "$tmp_file" | sort -u | head -20)
                [[ -n "$emails_found" ]] && found "E-mails encontrados na página:\n$emails_found"
                # Extrai IPs da página
                local ips_found
                ips_found=$(grep -oP '\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b' "$tmp_file" | sort -u | grep -v '^0\.\|^127\.\|^255\.' | head -10)
                [[ -n "$ips_found" ]] && info "IPs encontrados:\n$ips_found"
                # Extrai comentários HTML (podem conter info sensível)
                local html_comments
                html_comments=$(grep -oP '<!--.*?-->' "$tmp_file" | head -10)
                [[ -n "$html_comments" ]] && warning "Comentários HTML:\n$html_comments"
                append_html "<div class='subsection'><h3>HTML Meta</h3><div class='grid'>
                  <div class='card'><div class='label'>Título</div><div class='value'>$title</div></div>
                  <div class='card'><div class='label'>Autor</div><div class='value'>$author</div></div>
                  <div class='card'><div class='label'>Generator</div><div class='value'>$generator</div></div>
                </div>
                $([ -n "$emails_found" ] && echo "<p class='found'>Emails: $emails_found</p>")
                $([ -n "$html_comments" ] && echo "<p class='warning'>Comentários: $html_comments</p>")</div>"
                ;;
            *)
                local generic_meta
                generic_meta=$(exiftool "$tmp_file" 2>/dev/null)
                echo "$generic_meta"
                append_html "<div class='subsection'><h3>Metadados Genéricos</h3><pre>$generic_meta</pre></div>"
                ;;
        esac
    else
        # Arquivo local
        if [[ -f "$target" ]]; then
            local meta
            meta=$(exiftool "$target" 2>/dev/null)
            echo "$meta"
            append_html "<div class='subsection'><h3>EXIF Local</h3><pre>$meta</pre></div>"
        else
            error "Arquivo não encontrado: $target"
        fi
    fi

    append_html "</div>"
}

# ========================= MÓDULO 7: TELEFONE ====================
phone_osint() {
    local phone="$1"
    section "OSINT DE TELEFONE: $phone"
    append_html "<div class='section' id='phone'><h2>📱 Telefone <span class='badge'>$phone</span></h2>"

    # Normaliza o número
    local clean_phone
    clean_phone=$(echo "$phone" | tr -d ' ()-')

    # NumVerify
    if [[ -n "$NUMVERIFY_API_KEY" ]]; then
        subsection "NumVerify"
        local nv_data
        nv_data=$(safe_curl "http://apilayer.net/api/validate?access_key=$NUMVERIFY_API_KEY&number=$clean_phone&country_code=&format=1")
        local valid carrier country_name line_type
        valid=$(echo "$nv_data" | jq -r '.valid')
        carrier=$(echo "$nv_data" | jq -r '.carrier // "?"')
        country_name=$(echo "$nv_data" | jq -r '.country_name // "?"')
        line_type=$(echo "$nv_data" | jq -r '.line_type // "?"')
        echo "  Válido  : $valid"
        echo "  Operadora: $carrier"
        echo "  País    : $country_name"
        echo "  Tipo    : $line_type"
        append_html "<div class='subsection'><h3>NumVerify</h3><div class='grid'>
          <div class='card'><div class='label'>Válido</div><div class='value'>$valid</div></div>
          <div class='card'><div class='label'>Operadora</div><div class='value'>$carrier</div></div>
          <div class='card'><div class='label'>País</div><div class='value'>$country_name</div></div>
          <div class='card'><div class='label'>Tipo</div><div class='value'>$line_type</div></div>
        </div></div>"
    fi

    # Truecaller lookup (via API não oficial)
    subsection "Busca pública do número"
    echo "  Links úteis para verificação manual:"
    echo "  → https://www.truecaller.com/search/br/$clean_phone"
    echo "  → https://sync.me/search/?number=$clean_phone"
    echo "  → https://www.infobel.com/br/world"
    append_html "<div class='subsection'><h3>Recursos Manuais</h3><pre>
Truecaller: https://www.truecaller.com/search/br/$clean_phone
Sync.me: https://sync.me/search/?number=$clean_phone
</pre></div>"

    # WhatsApp check
    subsection "WhatsApp"
    echo "  Verifique: https://wa.me/$clean_phone"
    append_html "<div class='subsection'><h3>WhatsApp</h3><a href='https://wa.me/$clean_phone' target='_blank'>Verificar número no WhatsApp</a></div>"

    append_html "</div>"
}

# ========================= MÓDULO 8: CVE / VULN LOOKUP ===========
cve_lookup() {
    local query="$1"
    section "LOOKUP DE CVE/VULNERABILIDADE: $query"
    append_html "<div class='section' id='cve'><h2>🛡️ CVE Lookup <span class='badge'>$query</span></h2>"

    # NVD API
    subsection "NVD (National Vulnerability Database)"
    local nvd_data
    if [[ "$query" =~ CVE-[0-9]{4}-[0-9]+ ]]; then
        # Busca CVE específico
        nvd_data=$(safe_curl "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=$query")
    else
        # Busca por keyword
        nvd_data=$(safe_curl "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=$query&resultsPerPage=10")
    fi

    if [[ -n "$nvd_data" ]]; then
        echo "$nvd_data" | jq -r '.vulnerabilities[]? | {cve: .cve.id, desc: (.cve.descriptions[0].value | .[0:200]), score: (.cve.metrics.cvssMetricV31[0].cvssData.baseScore // "N/A"), severity: (.cve.metrics.cvssMetricV31[0].cvssData.baseSeverity // "N/A")} | "\(.cve) [\(.severity)/\(.score)]\n\(.desc)\n"' 2>/dev/null | head -60
        append_html "<div class='subsection'><h3>NVD Results</h3><pre>$(echo "$nvd_data" | jq -r '.vulnerabilities[]?.cve | "\(.id) — \(.descriptions[0].value | .[0:200])"' 2>/dev/null | head -20)</pre></div>"
    fi

    # ExploitDB (se nuclei disponível)
    if command -v searchsploit &>/dev/null; then
        subsection "SearchSploit (ExploitDB)"
        local exploits
        exploits=$(searchsploit "$query" 2>/dev/null | head -20)
        echo "$exploits"
        append_html "<div class='subsection'><h3>ExploitDB</h3><pre>$exploits</pre></div>"
    fi

    append_html "</div>"
}

# ========================= MÓDULO 9: CRYPTO ADDRESS ==============
crypto_osint() {
    local address="$1"
    section "OSINT CRYPTO: $address"
    append_html "<div class='section' id='crypto'><h2>₿ Crypto Address <span class='badge'>$address</span></h2>"

    # Detecta o tipo pela regex
    local crypto_type
    if [[ "$address" =~ ^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$ ]] || [[ "$address" =~ ^bc1[a-z0-9]{39,59}$ ]]; then
        crypto_type="Bitcoin"
    elif [[ "$address" =~ ^0x[a-fA-F0-9]{40}$ ]]; then
        crypto_type="Ethereum"
    elif [[ "$address" =~ ^[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}$ ]]; then
        crypto_type="Litecoin"
    else
        crypto_type="Desconhecido"
    fi

    info "Tipo detectado: $crypto_type"
    append_html "<div class='subsection'><h3>Tipo</h3><p>$crypto_type</p></div>"

    # Blockchain.com API (Bitcoin)
    if [[ "$crypto_type" == "Bitcoin" ]]; then
        subsection "Blockchain.info"
        local btc_data
        btc_data=$(safe_curl "https://blockchain.info/rawaddr/$address?limit=5")
        if [[ -n "$btc_data" ]]; then
            local total_received total_sent final_balance n_tx
            total_received=$(echo "$btc_data" | jq '.total_received // 0')
            total_sent=$(echo "$btc_data" | jq '.total_sent // 0')
            final_balance=$(echo "$btc_data" | jq '.final_balance // 0')
            n_tx=$(echo "$btc_data" | jq '.n_tx // 0')
            echo "  Transações     : $n_tx"
            echo "  Total recebido : $(echo "scale=8; $total_received/100000000" | bc) BTC"
            echo "  Total enviado  : $(echo "scale=8; $total_sent/100000000" | bc) BTC"
            echo "  Saldo atual    : $(echo "scale=8; $final_balance/100000000" | bc) BTC"
            append_html "<div class='subsection'><h3>Blockchain Stats</h3><div class='grid'>
              <div class='card'><div class='label'>Transações</div><div class='value'>$n_tx</div></div>
              <div class='card'><div class='label'>Saldo</div><div class='value'>$(echo "scale=8; $final_balance/100000000" | bc) BTC</div></div>
            </div></div>"
        fi
    fi

    # Etherscan (Ethereum)
    if [[ "$crypto_type" == "Ethereum" ]]; then
        subsection "Etherscan"
        local eth_data
        eth_data=$(safe_curl "https://api.etherscan.io/api?module=account&action=balance&address=$address&tag=latest&apikey=YourApiKeyToken")
        local eth_balance
        eth_balance=$(echo "$eth_data" | jq -r '.result // "0"')
        echo "  Saldo: $(echo "scale=18; $eth_balance/1000000000000000000" | bc) ETH"
        append_html "<div class='subsection'><h3>Etherscan</h3><p>Saldo: $(echo "scale=18; $eth_balance/1000000000000000000" | bc) ETH</p></div>"
    fi

    # Links de exploradores
    append_html "<div class='subsection'><h3>Exploradores</h3><pre>
Bitcoin:  https://www.blockchain.com/explorer/addresses/btc/$address
Ethereum: https://etherscan.io/address/$address
Geral:    https://www.coingecko.com
</pre></div>"

    append_html "</div>"
}

# ========================= MÓDULO 10: GOOGLE DORKS ===============
google_dorks() {
    local target="$1"
    section "GOOGLE DORKS: $target"
    append_html "<div class='section' id='dorks'><h2>🔎 Google Dorks <span class='badge'>$target</span></h2>"

    echo -e "\n${WHITE}${BOLD}Copie e cole estes dorks no Google:${NC}\n"

    declare -A DORKS=(
        ["Arquivos sensíveis"]="site:$target filetype:pdf OR filetype:docx OR filetype:xlsx OR filetype:sql OR filetype:env OR filetype:conf OR filetype:bak"
        ["Diretórios abertos"]="site:$target intitle:\"index of\""
        ["Painéis de login"]="site:$target inurl:admin OR inurl:login OR inurl:dashboard OR inurl:wp-admin OR inurl:cpanel"
        ["Config files"]="site:$target ext:xml OR ext:json OR ext:yml OR ext:yaml OR ext:config"
        ["Senhas expostas"]="site:$target intext:\"password\" OR intext:\"passwd\" OR intext:\"api_key\" OR intext:\"secret\""
        ["Câmeras IP"]="site:$target intitle:\"Live View\" OR intitle:\"Network Camera\""
        ["Erros PHP/SQL"]="site:$target intext:\"Warning: mysql_\" OR intext:\"Fatal error\""
        ["Subdomínios"]="site:*.$target -www"
        ["Emails expostos"]="site:$target intext:\"@$target\""
        ["GitHub/Pastebin"]="\"$target\" site:github.com OR site:pastebin.com"
        ["LinkedIn funcionários"]="site:linkedin.com/in \"$target\""
        ["Cache pages"]="cache:$target"
        ["Related sites"]="related:$target"
    )

    for dork_name in "${!DORKS[@]}"; do
        echo -e "  ${YELLOW}[$dork_name]${NC}"
        echo "  ${DORKS[$dork_name]}"
        echo ""
    done

    append_html "<div class='subsection'><h3>Dorks Gerados</h3><pre>"
    for dork_name in "${!DORKS[@]}"; do
        append_html "[$dork_name]\n${DORKS[$dork_name]}\n"
    done
    append_html "</pre></div></div>"
}

# ========================= MÓDULO 11: EMPRESA ====================
company_osint() {
    local company="$1"
    section "OSINT DE EMPRESA: $company"
    append_html "<div class='section' id='company'><h2>🏢 Empresa <span class='badge'>$company</span></h2>"

    subsection "Busca por registros públicos"
    echo "  Sugestões de busca manual:"
    echo "  → LinkedIn: https://www.linkedin.com/search/results/companies/?keywords=$company"
    echo "  → CNPJ (BR): https://www.receitafederal.gov.br/Convenios/sdcadastros/fcpf/consulta.htm"
    echo "  → Crunchbase: https://www.crunchbase.com/search/organizations/field/organizations/facet_ids/$company"
    echo "  → SEC EDGAR (EUA): https://www.sec.gov/cgi-bin/browse-edgar?company=$company"

    # theHarvester para empresa
    if command -v theHarvester &>/dev/null; then
        subsection "theHarvester (emails da empresa)"
        local domain_guess
        domain_guess=$(echo "$company" | tr '[:upper:]' '[:lower:]' | tr ' ' '-' | sed 's/[^a-z0-9-]//g')
        local harvester_out
        harvester_out=$(theHarvester -d "$domain_guess.com" -b all -l 50 2>/dev/null | grep -E "@|linkedin|twitter" | head -30)
        echo "$harvester_out"
        append_html "<div class='subsection'><h3>theHarvester</h3><pre>$harvester_out</pre></div>"
    fi

    subsection "Shodan (infraestrutura)"
    if [[ -n "$SHODAN_API_KEY" ]]; then
        local shodan_org
        shodan_org=$(safe_curl "https://api.shodan.io/shodan/host/search?key=$SHODAN_API_KEY&query=org:\"$company\"")
        echo "$shodan_org" | jq -r '.matches[] | "\(.ip_str) — \(.port) — \(.product // "?")"' 2>/dev/null | head -15
        append_html "<div class='subsection'><h3>Shodan Infra</h3><pre>$(echo "$shodan_org" | jq -r '.matches[] | "\(.ip_str) — \(.port)"' 2>/dev/null | head -20)</pre></div>"
    fi

    subsection "Google Dorks para empresa"
    echo "  site:linkedin.com \"$company\""
    echo "  \"$company\" filetype:pdf OR filetype:docx"
    echo "  \"$company\" email OR contact"
    echo "  intext:\"$company\" site:glassdoor.com"

    append_html "<div class='subsection'><h3>Dorks</h3><pre>
site:linkedin.com \"$company\"
\"$company\" filetype:pdf OR filetype:docx
\"$company\" site:glassdoor.com
\"$company\" site:crunchbase.com</pre></div></div>"
}

# ========================= MÓDULO 12: CABEÇALHOS HTTP ============
http_headers_analysis() {
    local url="$1"
    section "ANÁLISE DE CABEÇALHOS HTTP: $url"
    append_html "<div class='section' id='headers'><h2>🌐 Headers HTTP <span class='badge'>$url</span></h2>"

    local headers
    headers=$(curl -s -I -L -A "$USER_AGENT" "$url" --max-time 10 2>/dev/null)

    echo "$headers"

    # Analisa cabeçalhos de segurança
    subsection "Análise de Segurança"
    local security_headers=("Strict-Transport-Security" "Content-Security-Policy" "X-Frame-Options" "X-Content-Type-Options" "Referrer-Policy" "Permissions-Policy" "X-XSS-Protection")

    append_html "<div class='subsection'><h3>Security Headers</h3><div class='grid'>"
    for header in "${security_headers[@]}"; do
        if echo "$headers" | grep -qi "^$header:"; then
            local val; val=$(echo "$headers" | grep -i "^$header:" | cut -d: -f2- | xargs)
            found "$header: OK"
            append_html "<div class='card'><div class='label'>$header</div><div class='value found'>✓ $val</div></div>"
        else
            warning "$header: AUSENTE"
            append_html "<div class='card'><div class='label'>$header</div><div class='value severity-medium'>✗ Ausente</div></div>"
        fi
    done
    append_html "</div></div>"

    # Servidor e tecnologias expostas
    subsection "Informações do Servidor"
    local server_header
    server_header=$(echo "$headers" | grep -i "^Server:\|^X-Powered-By:\|^X-AspNet\|^X-Generator")
    echo "$server_header"
    [[ -n "$server_header" ]] && warning "Informações de servidor expostas: $server_header"
    append_html "<div class='subsection'><h3>Tecnologias Expostas</h3><pre class='warning'>$server_header</pre></div>"

    append_html "</div>"
}

# ========================= RELATÓRIO COMPLETO ===================
full_report() {
    local target="$1"
    generate_html_header
    init_csv

    append_html "<div class='toc'><h2>📋 Índice</h2>"

    if [[ "$target" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
        # É um email
        append_html "<a href='#email'>📧 E-mail OSINT</a></div>"
        email_osint "$target"
    elif [[ "$target" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        # É um IP
        append_html "<a href='#ip'>🌍 IP Intelligence</a>
          <a href='#portscan'>🔌 Port Scan</a></div>"
        ip_geo_intel "$target"
        port_scan_full "$target"
    elif [[ "$target" =~ ^(CVE-|cve-) ]]; then
        # É um CVE
        append_html "<a href='#cve'>🛡️ CVE Lookup</a></div>"
        cve_lookup "$target"
    elif [[ "$target" =~ ^(0x|1|3|bc1)[a-zA-Z0-9]{20,} ]]; then
        # É um endereço crypto
        append_html "<a href='#crypto'>₿ Crypto OSINT</a></div>"
        crypto_osint "$target"
    else
        # É um domínio
        append_html "<a href='#domain'>🌐 Domínio</a>
          <a href='#portscan'>🔌 Port Scan</a>
          <a href='#dorks'>🔎 Dorks</a>
          <a href='#headers'>🌐 HTTP Headers</a></div>"
        domain_recon "$target"
        port_scan_full "$target"
        http_headers_analysis "https://$target"
        google_dorks "$target"
    fi

    close_html
    echo ""
    success "Relatório HTML: $HTML_REPORT"
    success "Relatório CSV : $CSV_REPORT"
    success "Log completo  : $LOG_FILE"
}

# ========================= MODO SILENCIOSO =======================
silent_scan() {
    local target="$1"
    SILENT_MODE=true
    full_report "$target"
}

# ========================= CONFIGURAR APIs =======================
configure_apis() {
    echo -e "${CYAN}${BOLD}═══ CONFIGURAÇÃO DE APIs ═══${NC}"
    echo -e "${DIM}Pressione Enter para manter o valor atual${NC}\n"

    read -rp "Shodan API Key [$SHODAN_API_KEY]: " input
    [[ -n "$input" ]] && SHODAN_API_KEY="$input"

    read -rp "SecurityTrails API Key [$SECURITYTRAILS_API_KEY]: " input
    [[ -n "$input" ]] && SECURITYTRAILS_API_KEY="$input"

    read -rp "Have I Been Pwned API Key [$HIBP_API_KEY]: " input
    [[ -n "$input" ]] && HIBP_API_KEY="$input"

    read -rp "IPInfo Token [$IPINFO_TOKEN]: " input
    [[ -n "$input" ]] && IPINFO_TOKEN="$input"

    read -rp "VirusTotal API Key [$VIRUSTOTAL_API_KEY]: " input
    [[ -n "$input" ]] && VIRUSTOTAL_API_KEY="$input"

    read -rp "AbuseIPDB API Key [$ABUSEIPDB_API_KEY]: " input
    [[ -n "$input" ]] && ABUSEIPDB_API_KEY="$input"

    read -rp "GreyNoise API Key [$GREYNOISE_API_KEY]: " input
    [[ -n "$input" ]] && GREYNOISE_API_KEY="$input"

    read -rp "Hunter.io API Key [$HUNTER_API_KEY]: " input
    [[ -n "$input" ]] && HUNTER_API_KEY="$input"

    read -rp "Censys API ID [$CENSYS_API_ID]: " input
    [[ -n "$input" ]] && CENSYS_API_ID="$input"

    read -rp "Censys API Secret [$CENSYS_API_SECRET]: " input
    [[ -n "$input" ]] && CENSYS_API_SECRET="$input"

    read -rp "NumVerify API Key [$NUMVERIFY_API_KEY]: " input
    [[ -n "$input" ]] && NUMVERIFY_API_KEY="$input"

    # Salva em arquivo de configuração
    cat > "$SCRIPT_DIR/.osintool_config" << EOF
SHODAN_API_KEY="$SHODAN_API_KEY"
SECURITYTRAILS_API_KEY="$SECURITYTRAILS_API_KEY"
HIBP_API_KEY="$HIBP_API_KEY"
IPINFO_TOKEN="$IPINFO_TOKEN"
VIRUSTOTAL_API_KEY="$VIRUSTOTAL_API_KEY"
ABUSEIPDB_API_KEY="$ABUSEIPDB_API_KEY"
GREYNOISE_API_KEY="$GREYNOISE_API_KEY"
HUNTER_API_KEY="$HUNTER_API_KEY"
CENSYS_API_ID="$CENSYS_API_ID"
CENSYS_API_SECRET="$CENSYS_API_SECRET"
NUMVERIFY_API_KEY="$NUMVERIFY_API_KEY"
EOF
    success "Configuração salva em .osintool_config"
}

# Carrega configuração salva
load_config() {
    if [[ -f "$SCRIPT_DIR/.osintool_config" ]]; then
        source "$SCRIPT_DIR/.osintool_config"
        info "Configuração carregada de .osintool_config"
    fi
}

# ========================= MENU PRINCIPAL ========================
main_menu() {
    while true; do
        echo -e "\n${CYAN}${BOLD}══════════════════════════════════════════════════════${NC}"
        echo -e "${WHITE}${BOLD}                    MENU PRINCIPAL                      ${NC}"
        echo -e "${CYAN}${BOLD}══════════════════════════════════════════════════════${NC}"
        echo ""
        echo -e " ${GREEN}[1]${NC}  🌐  Domínio          (DNS, WHOIS, Subdomínios, SSL, Nikto)"
        echo -e " ${GREEN}[2]${NC}  📧  E-mail            (Breaches, HIBP, Gravatar, Pastebins)"
        echo -e " ${GREEN}[3]${NC}  🌍  IP                (Geo, ASN, Shodan, VirusTotal, TOR check)"
        echo -e " ${GREEN}[4]${NC}  👤  Username          (40+ redes sociais)"
        echo -e " ${GREEN}[5]${NC}  🔌  Port Scan         (Nmap + Masscan + NSE vuln scripts)"
        echo -e " ${GREEN}[6]${NC}  📄  Metadados         (EXIF, PDF, HTML, GPS extractor)"
        echo -e " ${GREEN}[7]${NC}  📱  Telefone          (NumVerify, WhatsApp check)"
        echo -e " ${GREEN}[8]${NC}  🛡️   CVE Lookup        (NVD, ExploitDB, SearchSploit)"
        echo -e " ${GREEN}[9]${NC}  ₿   Crypto Address    (Bitcoin, Ethereum, Litecoin)"
        echo -e " ${GREEN}[10]${NC} 🔎  Google Dorks      (Gerador avançado de dorks)"
        echo -e " ${GREEN}[11]${NC} 🏢  Empresa           (OSINT corporativo)"
        echo -e " ${GREEN}[12]${NC} 🌐  HTTP Headers      (Análise segurança de cabeçalhos)"
        echo -e " ${GREEN}[13]${NC} 📋  Relatório Completo (HTML + CSV + Log automático)"
        echo -e " ${GREEN}[14]${NC} ⚡  Scan Silencioso   (Sem output, só relatório)"
        echo -e " ${GREEN}[15]${NC} ⚙️   Configurar APIs"
        echo -e " ${GREEN}[16]${NC} 🔧  Verificar Dependências"
        echo -e " ${GREEN}[0]${NC}  ❌  Sair"
        echo ""
        echo -n -e "${YELLOW}${BOLD}  ➜ ${NC}"
        read -r opt

        case $opt in
            1)
                read -rp "  Domínio: " d
                domain_recon "$d"
                ;;
            2)
                read -rp "  E-mail: " e
                email_osint "$e"
                ;;
            3)
                read -rp "  IP: " i
                ip_geo_intel "$i"
                ;;
            4)
                read -rp "  Username: " u
                username_search "$u"
                ;;
            5)
                read -rp "  Alvo (IP/domínio): " p
                port_scan_full "$p"
                ;;
            6)
                read -rp "  URL ou arquivo local: " m
                metadata_extract "$m"
                ;;
            7)
                read -rp "  Número (ex: +5511999999999): " ph
                phone_osint "$ph"
                ;;
            8)
                read -rp "  CVE ou software (ex: CVE-2021-44228 ou apache): " cve
                cve_lookup "$cve"
                ;;
            9)
                read -rp "  Endereço crypto: " ca
                crypto_osint "$ca"
                ;;
            10)
                read -rp "  Domínio/alvo para dorks: " dork_target
                google_dorks "$dork_target"
                ;;
            11)
                read -rp "  Nome da empresa: " company
                company_osint "$company"
                ;;
            12)
                read -rp "  URL (ex: https://example.com): " url_h
                http_headers_analysis "$url_h"
                ;;
            13)
                read -rp "  Alvo (domínio/IP/email): " full_target
                full_report "$full_target"
                ;;
            14)
                read -rp "  Alvo (domínio/IP/email): " silent_target
                silent_scan "$silent_target"
                ;;
            15)
                configure_apis
                ;;
            16)
                check_deps
                ;;
            0)
                success "Encerrando OSINTool v4.0. Fique seguro!"
                rm -rf "$TEMP_DIR"
                exit 0
                ;;
            *)
                error "Opção inválida: $opt"
                ;;
        esac
    done
}

# ========================= CLI ARGS ==============================
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -d|--domain)     domain_recon "$2"; shift 2;;
            -e|--email)      email_osint "$2"; shift 2;;
            -i|--ip)         ip_geo_intel "$2"; shift 2;;
            -u|--username)   username_search "$2"; shift 2;;
            -p|--portscan)   port_scan_full "$2"; shift 2;;
            -m|--metadata)   metadata_extract "$2"; shift 2;;
            -ph|--phone)     phone_osint "$2"; shift 2;;
            -c|--cve)        cve_lookup "$2"; shift 2;;
            -cr|--crypto)    crypto_osint "$2"; shift 2;;
            -dk|--dorks)     google_dorks "$2"; shift 2;;
            -co|--company)   company_osint "$2"; shift 2;;
            -hh|--headers)   http_headers_analysis "$2"; shift 2;;
            -f|--full)       full_report "$2"; shift 2;;
            -s|--silent)     silent_scan "$2"; shift 2;;
            --no-banner)     SILENT_MODE=true; shift;;
            -h|--help)
                echo "Uso: $0 [opção] [alvo]"
                echo ""
                echo "  -d, --domain    <domínio>    Recon de domínio"
                echo "  -e, --email     <email>      OSINT de e-mail"
                echo "  -i, --ip        <ip>         Intel de IP"
                echo "  -u, --username  <user>       Busca de username"
                echo "  -p, --portscan  <alvo>       Scan de portas"
                echo "  -m, --metadata  <url|file>   Extração de metadados"
                echo "  -ph,--phone     <número>     OSINT de telefone"
                echo "  -c, --cve       <cve|soft>   Lookup de CVE"
                echo "  -cr,--crypto    <endereço>   OSINT de crypto"
                echo "  -dk,--dorks     <alvo>       Google dorks"
                echo "  -co,--company   <empresa>    OSINT empresarial"
                echo "  -hh,--headers   <url>        Análise HTTP headers"
                echo "  -f, --full      <alvo>       Relatório completo"
                echo "  -s, --silent    <alvo>       Modo silencioso"
                echo "  -h, --help                   Esta ajuda"
                echo ""
                exit 0
                ;;
            *)
                error "Argumento desconhecido: $1"
                exit 1
                ;;
        esac
    done
}

# ========================= INÍCIO ================================
trap 'echo -e "\n${RED}[!] Interrompido pelo usuário${NC}"; rm -rf "$TEMP_DIR"; exit 130' INT TERM

load_config

if [[ $# -gt 0 ]]; then
    # Modo CLI
    generate_html_header
    init_csv
    parse_args "$@"
    close_html
    success "Relatório salvo em $OUTPUT_DIR/"
else
    # Modo interativo
    banner
    check_deps
    generate_html_header
    init_csv
    main_menu
fi
