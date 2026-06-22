#!/usr/bin/env bash
# Batch scan: lê domínios de domains.txt, roda UM scan deep ISOLADO por alvo,
# gera relatório HTML + IA e notifica o Discord ao terminar cada um.
#
# IMPORTANTE — isolamento por domínio:
#   Cada alvo roda com -S (stateless) + --format html,sqlite para NÃO reutilizar
#   hosts/findings de scans anteriores no DB global (~/.vigolium). Sem -S, o
#   vigolium puxa dezenas de milhares de HTTP records do projeto e acaba
#   visitando domínios antigos (ex.: photonow.com.br) mesmo com --scope-origin strict.
#
#   NÃO use:  vigolium scan -T domains.txt   (varios alvos num scan só)
#   USE:      loop com -t https://um-dominio-por-vez  (este script faz isso)
#
# GhostRecon: o módulo vigolium_dast usa o mesmo perfil via bridge/vigolium-vps-profile.mjs
# (sem Discord/IA — isso fica no finalize do GhostRecon). Scan isolado também em:
#   scripts/vigolium-ghostrecon-scan.sh <url> <saida-base>
#
# Uso:
#   export DISCORD_WEBHOOK="https://discord.com/api/webhooks/..."
#   I_HAVE_AUTHORIZATION=1 ./ataque.sh
#
# Variáveis opcionais:
#   DOMAINS_FILE         caminho do arquivo de domínios (default: domains.txt)
#   VIGOLIUM             binário vigolium (default: vigolium)
#   REPORTS_DIR          pasta dos relatórios (default: ./reports)
#   LOG_DIR              pasta dos logs (default: ./logs)
#   REPORT_MODE          inline | discovery (default: inline)
#                        inline    = HTML gerado no próprio scan (-S --format html,sqlite)
#                        discovery = re-roda só discovery p/ HTML de content-discovery
#
# Relatório IA (OpenRouter → fallback Gemini free):
#   OPENROUTER_API_KEY   chave OpenRouter (tentativa primária)
#   OPENROUTER_MODEL     modelo OpenRouter (default: google/gemini-2.0-flash-exp:free)
#   GEMINI_API_KEY       chave Google AI Studio / Gemini (fallback free)
#   GEMINI_MODEL         modelo Gemini (default: gemini-2.0-flash)
#   AI_REPORT_LANG       idioma do relatório (default: pt)
#   AI_FINDINGS_LIMIT    máx. findings enviados ao modelo (default: 80)
#   CONTINUE_ON_ERROR    continua próximo domínio se um falhar (default: 1)
#   SKIP_EXTERNAL_HARVEST  1 = pula external-harvest (default: 1, recomendado)
#                          O deep liga harvest (Wayback/OTX) que traz URLs de
#                          domínios aleatórios (kyotopet, photonow…) e o vigolium
#                          busca essas URLs antes do spider. Para scan por lista,
#                          isso só gera ruído. Use 0 para reativar.
#   USE_CODEX             auto | 0 | 1 (default: auto)
#                        auto = pergunta no início se o relatório IA deve usar
#                               Codex; sem tty cai para 0
#                        0    = mantém o fluxo atual (OpenRouter -> Gemini)
#                        1    = tenta usar Codex primeiro para o relatório IA

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

DOMAINS_FILE="${DOMAINS_FILE:-${SCRIPT_DIR}/domains.txt}"
VIGOLIUM="${VIGOLIUM:-vigolium}"
REPORTS_DIR="${REPORTS_DIR:-./reports}"
LOG_DIR="${LOG_DIR:-./logs}"
REPORT_MODE="${REPORT_MODE:-inline}"
CONTINUE_ON_ERROR="${CONTINUE_ON_ERROR:-1}"
OPENROUTER_MODEL="${OPENROUTER_MODEL:-google/gemini-2.0-flash-exp:free}"
GEMINI_MODEL="${GEMINI_MODEL:-gemini-2.0-flash}"
AI_REPORT_LANG="${AI_REPORT_LANG:-pt}"
AI_FINDINGS_LIMIT="${AI_FINDINGS_LIMIT:-80}"
AI_HTTP_TIMEOUT="${AI_HTTP_TIMEOUT:-180}"
SKIP_EXTERNAL_HARVEST="${SKIP_EXTERNAL_HARVEST:-1}"
USE_CODEX="${USE_CODEX:-auto}"
USE_CODEX_ENABLED=0

if [[ "${I_HAVE_AUTHORIZATION:-1}" != "1" ]]; then
  echo "Erro: defina I_HAVE_AUTHORIZATION=1 para confirmar autorização dos alvos." >&2
  exit 1
fi

if [[ -z "${DISCORD_WEBHOOK:-}" ]]; then
  echo "Erro: defina DISCORD_WEBHOOK com a URL do webhook do Discord." >&2
  echo '  export DISCORD_WEBHOOK="https://discord.com/api/webhooks/ID/TOKEN"' >&2
  exit 1
fi

if [[ ! -f "$DOMAINS_FILE" ]]; then
  echo "Erro: arquivo de domínios não encontrado: $DOMAINS_FILE" >&2
  exit 1
fi

if ! command -v "$VIGOLIUM" >/dev/null 2>&1; then
  echo "Erro: vigolium não encontrado ($VIGOLIUM). Use VIGOLIUM=./bin/vigolium se necessário." >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "Erro: jq é necessário para montar payloads do Discord." >&2
  exit 1
fi

mkdir -p "$REPORTS_DIR" "$LOG_DIR"

choose_execution_mode() {
  case "${USE_CODEX,,}" in
    1|true|yes|on)
      USE_CODEX_ENABLED=1
      return
      ;;
    0|false|no|off)
      USE_CODEX_ENABLED=0
      return
      ;;
  esac

  if [[ -t 0 && -t 1 ]]; then
    while true; do
      read -r -p "Executar com Codex no relatorio IA? [s/N] " answer || answer=""
      case "${answer,,}" in
        s|sim|y|yes)
          USE_CODEX_ENABLED=1
          return
          ;;
        ""|n|nao|no)
          USE_CODEX_ENABLED=0
          return
          ;;
      esac
    done
  fi

  USE_CODEX_ENABLED=0
}

choose_execution_mode

# --- helpers -----------------------------------------------------------------

normalize_domain() {
  local raw="$1"

  raw="${raw%%#*}"
  raw="${raw#"${raw%%[![:space:]]*}"}"
  raw="${raw%"${raw##*[![:space:]]}"}"
  [[ -z "$raw" ]] && return 1

  raw="${raw,,}"
  raw="${raw#https://}"
  raw="${raw#http://}"
  raw="${raw%%/*}"
  raw="${raw%.}"

  if [[ ! "$raw" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}(:[0-9]{1,5})?$ ]]; then
    echo "Aviso: domínio inválido ignorado: $1" >&2
    return 1
  fi

  printf '%s\n' "$raw"
}

safe_name() {
  printf '%s' "$1" |
    sed -E 's/[^A-Za-z0-9._-]+/_/g; s/^\.+/_/; s/\.+$//'
}

discord_json() {
  curl -fsS \
    --connect-timeout 10 \
    --max-time 30 \
    --retry 3 \
    --retry-delay 2 \
    -H "Content-Type: application/json" \
    -d @- "$DISCORD_WEBHOOK"
}

safe_notify() {
  "$@" || echo "Aviso: falha ao notificar Discord; seguindo execução." >&2
}

call_codex() {
  local prompt="$1"
  command -v codex >/dev/null 2>&1 || return 1

  local prompt_file output_file err_file
  prompt_file="$(mktemp)"
  output_file="$(mktemp)"
  err_file="$(mktemp)"

  printf '%s\n' "$prompt" > "$prompt_file"

  if ! codex exec \
    --ephemeral \
    --skip-git-repo-check \
    --cd "$SCRIPT_DIR" \
    --sandbox read-only \
    --output-last-message "$output_file" \
    - < "$prompt_file" \
    >"$err_file" 2>&1; then
    echo "Codex falhou: $(tr '\n' ' ' < "$err_file")" >&2
    rm -f "$prompt_file" "$output_file" "$err_file"
    return 1
  fi

  cat "$output_file"
  rm -f "$prompt_file" "$output_file" "$err_file"
}

discord_notify() {
  local content="$1"
  jq -n --arg content "$content" '{content: $content}' | discord_json >/dev/null
}

discord_notify_embed() {
  local title="$1" description="$2" color="$3"
  jq -n \
    --arg title "$title" \
    --arg description "$description" \
    --argjson color "$color" \
    '{embeds: [{title: $title, description: $description, color: $color}]}' \
    | discord_json >/dev/null
}

discord_notify_file() {
  local content="$1"
  shift
  local payload args=(-fsS --connect-timeout 10 --max-time 60 --retry 3 --retry-delay 2)
  payload="$(jq -n --arg content "$content" '{content: $content}')"
  args+=(-F "payload_json=${payload}")
  local i=0 f
  for f in "$@"; do
    [[ -f "$f" ]] || continue
    args+=(-F "files[${i}]=@${f};filename=$(basename "$f")")
    i=$((i + 1))
  done
  [[ "$i" -gt 0 ]] || return 1
  curl "${args[@]}" "$DISCORD_WEBHOOK" >/dev/null
}

# Discord embed description limit = 4096; reserve headroom.
discord_truncate() {
  local text="$1" max="${2:-3800}"
  if [[ ${#text} -le $max ]]; then
    printf '%s' "$text"
    return
  fi
  printf '%s\n\n…_(truncado — veja o arquivo anexo)_' "${text:0:max}"
}

collect_findings_json() {
  local host="$1" sqlite_path="$2"
  if [[ ! -f "$sqlite_path" ]]; then
    echo '{"findings":[],"total":0}'
    return
  fi
  "$VIGOLIUM" finding -j -S --db "$sqlite_path" \
    --host "$host" \
    --compact \
    --min-severity info \
    --limit "$AI_FINDINGS_LIMIT" \
    2>/dev/null || echo '{"findings":[],"total":0}'
}

redact_sensitive_json() {
  jq '
    walk(
      if type == "string" then
        gsub("(?i)(?<key>token|api_key|apikey|password|passwd|secret|session|jwt)=([^&\\s]+)"; "\(.key)=REDACTED")
      else
        .
      end
    )
  '
}

build_ai_prompt() {
  local domain="$1" url="$2" scan_uuid="$3" findings_json="$4" stats_json="$5"
  local lang="$AI_REPORT_LANG"
  cat <<EOF
Você é um analista de segurança ofensiva sênior. Produza um relatório executivo de pentest web com base nos dados abaixo.

Requisitos:
- Idioma: ${lang}
- Formato: Markdown
- Seções obrigatórias:
  1. Resumo executivo (3–6 frases)
  2. Superfície analisada
  3. Achados por severidade (critical/high primeiro; depois medium/low/info)
  4. Top 5 riscos prioritários (com impacto e exploração provável)
  5. Recomendações práticas de remediação (bullet points)
  6. Limitações / próximos passos
- Seja objetivo; não invente CVEs ou achados ausentes nos dados.
- Se não houver findings, diga explicitamente e comente a cobertura do scan.

Alvo: ${url}
Domínio: ${domain}
Scan ID: ${scan_uuid:-desconhecido}

Estatísticas:
${stats_json}

Findings (JSON compacto):
${findings_json}
EOF
}

call_openrouter() {
  local prompt="$1"
  [[ -n "${OPENROUTER_API_KEY:-}" ]] || return 1

  local body response
  body="$(jq -n \
    --arg model "$OPENROUTER_MODEL" \
    --arg prompt "$prompt" \
    '{
      model: $model,
      messages: [
        {role: "system", content: "Você escreve relatórios técnicos de segurança claros e acionáveis."},
        {role: "user", content: $prompt}
      ],
      temperature: 0.2,
      max_tokens: 4096
    }')"

  if ! response="$(curl -sf --max-time "$AI_HTTP_TIMEOUT" \
    https://openrouter.ai/api/v1/chat/completions \
    -H "Authorization: Bearer ${OPENROUTER_API_KEY}" \
    -H "Content-Type: application/json" \
    -H "HTTP-Referer: https://github.com/vigolium/vigolium" \
    -H "X-Title: Vigolium Batch Scan" \
    -d "$body" 2>&1)"; then
    echo "OpenRouter falhou: ${response}" >&2
    return 1
  fi

  local text err
  text="$(echo "$response" | jq -r '.choices[0].message.content // empty' 2>/dev/null || true)"
  err="$(echo "$response" | jq -r '.error.message // empty' 2>/dev/null || true)"
  if [[ -n "$text" ]]; then
    printf '%s' "$text"
    return 0
  fi
  echo "OpenRouter sem conteúdo: ${err:-resposta inválida}" >&2
  return 1
}

call_gemini() {
  local prompt="$1"
  [[ -n "${GEMINI_API_KEY:-}" ]] || return 1

  local body response url
  url="https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent"
  body="$(jq -n \
    --arg prompt "$prompt" \
    '{
      contents: [{parts: [{text: $prompt}]}],
      generationConfig: {temperature: 0.2, maxOutputTokens: 4096}
    }')"

  if ! response="$(curl -sf --max-time "$AI_HTTP_TIMEOUT" \
    -H "Content-Type: application/json" \
    -H "x-goog-api-key: ${GEMINI_API_KEY}" \
    -d "$body" \
    "$url" 2>&1)"; then
    echo "Gemini falhou: ${response}" >&2
    return 1
  fi

  local text err
  text="$(echo "$response" | jq -r '.candidates[0].content.parts[0].text // empty' 2>/dev/null || true)"
  err="$(echo "$response" | jq -r '.error.message // empty' 2>/dev/null || true)"
  if [[ -n "$text" ]]; then
    printf '%s' "$text"
    return 0
  fi
  echo "Gemini sem conteúdo: ${err:-resposta inválida}" >&2
  return 1
}

generate_ai_report() {
  local domain="$1" url="$2" scan_uuid="$3" out_path="$4" sqlite_path="$5"
  local findings_json stats_json prompt report provider=""

  if [[ -z "${OPENROUTER_API_KEY:-}" && -z "${GEMINI_API_KEY:-}" ]]; then
    echo "Nenhuma chave IA configurada (OPENROUTER_API_KEY / GEMINI_API_KEY); pulando relatório IA." >&2
    return 2
  fi

  findings_json="$(collect_findings_json "$domain" "$sqlite_path" | redact_sensitive_json)"
  stats_json="$(finding_summary "$domain" "$sqlite_path")"

  # Limita payload para evitar estourar contexto / timeout.
  if [[ ${#findings_json} -gt 60000 ]]; then
    findings_json="$(echo "$findings_json" | jq --argjson lim "$AI_FINDINGS_LIMIT" \
      '{total, limit: $lim, findings: (.findings[:$lim] // [])}')"
  fi

  prompt="$(build_ai_prompt "$domain" "$url" "$scan_uuid" "$findings_json" "$stats_json")"

  if [[ "$USE_CODEX_ENABLED" -eq 1 ]] && report="$(call_codex "$prompt")"; then
    provider="codex"
  elif report="$(call_openrouter "$prompt")"; then
    provider="openrouter (${OPENROUTER_MODEL})"
  elif report="$(call_gemini "$prompt")"; then
    provider="gemini (${GEMINI_MODEL})"
  else
    echo "Falha ao gerar relatório IA (OpenRouter e Gemini)." >&2
    return 1
  fi

  {
    echo "# Relatório IA — ${domain}"
    echo ""
    echo "- **Alvo:** ${url}"
    echo "- **Scan ID:** ${scan_uuid:-n/a}"
    echo "- **Gerado em:** $(date -Iseconds)"
    echo "- **Provedor:** ${provider}"
    echo ""
    echo "---"
    echo ""
    printf '%s\n' "$report"
  } > "$out_path"

  echo "$provider"
}

finding_summary() {
  local host="$1" sqlite_path="$2"
  local findings_json
  if [[ ! -f "$sqlite_path" ]]; then
    echo "_(sqlite do scan não encontrado)_"
    return
  fi
  if ! findings_json="$("$VIGOLIUM" finding -j -S --db "$sqlite_path" --host "$host" --compact --limit 1000 2>/dev/null)"; then
    echo "_(stats indisponíveis)_"
    return
  fi
  local total crit high med low info
  total="$(echo "$findings_json" | jq -r '.total // 0')"
  crit="$(echo "$findings_json" | jq '[.findings[]? | select(.severity=="critical")] | length')"
  high="$(echo "$findings_json" | jq '[.findings[]? | select(.severity=="high")] | length')"
  med="$(echo "$findings_json" | jq '[.findings[]? | select(.severity=="medium")] | length')"
  low="$(echo "$findings_json" | jq '[.findings[]? | select(.severity=="low")] | length')"
  info="$(echo "$findings_json" | jq '[.findings[]? | select(.severity=="info")] | length')"
  cat <<EOF
**Findings:** ${total} total
• critical: ${crit}
• high: ${high}
• medium: ${med}
• low: ${low}
• info: ${info}
EOF
}

generate_report() {
  local url="$1" host="$2" report_path="$3"
  case "$REPORT_MODE" in
    inline)
      # HTML já gerado pelo scan principal (-S --format html,sqlite).
      [[ -f "$report_path" ]]
      ;;
    discovery)
      "$VIGOLIUM" scan -t "$url" \
        -S \
        --only discovery \
        --scope-origin strict \
        --format html \
        -o "${report_path%.html}"
      ;;
    *)
      echo "REPORT_MODE inválido: $REPORT_MODE (use inline ou discovery)" >&2
      return 1
      ;;
  esac
}

run_domain() {
  local domain="$1"
  local url="https://${domain}"
  local safe ts logfile output_base report_path sqlite_path ai_report_path
  local scan_exit=0 report_exit=0 ai_exit=0 ai_provider=""

  safe="$(safe_name "$domain")"
  ts="$(date +%Y%m%d-%H%M%S)"
  logfile="${LOG_DIR}/${safe}-${ts}.log"
  output_base="${REPORTS_DIR}/${safe}-${ts}"
  report_path="${output_base}.html"
  sqlite_path="${output_base}.sqlite"
  ai_report_path="${REPORTS_DIR}/${safe}-${ts}-ai-report.md"

  safe_notify discord_notify "▶️ **Iniciando scan** \`${domain}\` (\`deep\`, \`scope-origin strict\`, \`stateless\`)"

  local -a scan_args=(
    scan -t "$url"
    -S
    --format html,sqlite
    -o "$output_base"
    --strategy deep
    --scope-origin strict
  )
  if [[ "$SKIP_EXTERNAL_HARVEST" == "1" ]]; then
    scan_args+=(--skip external-harvest)
  fi

  set +e
  "$VIGOLIUM" "${scan_args[@]}" \
    2>&1 | tee "$logfile"
  scan_exit="${PIPESTATUS[0]}"
  set -e

  local scan_uuid=""
  scan_uuid="$(grep -E 'Scan ID:' "$logfile" 2>/dev/null | tail -1 | sed -E 's/.*Scan ID:[[:space:]]*//' || true)"

  if [[ "$scan_exit" -ne 0 ]]; then
    local fail_desc
    fail_desc="$(cat <<EOF
Exit code: \`${scan_exit}\`
Log: \`${logfile}\`
${scan_uuid:+Scan ID: \`${scan_uuid}\`}
EOF
)"
    safe_notify discord_notify_embed \
      "❌ Scan falhou: ${domain}" \
      "$fail_desc" \
      15158332
    return "$scan_exit"
  fi

  set +e
  generate_report "$url" "$domain" "$report_path"
  report_exit=$?

  ai_provider="$(generate_ai_report "$domain" "$url" "$scan_uuid" "$ai_report_path" "$sqlite_path")"
  ai_exit=$?
  set -e

  local summary ai_note=""
  summary="$(finding_summary "$domain" "$sqlite_path")"

  case "$ai_exit" in
    0) ai_note="**Relatório IA:** \`${ai_report_path}\` (${ai_provider})" ;;
    2) ai_note="_Relatório IA omitido (sem OPENROUTER_API_KEY / GEMINI_API_KEY)_" ;;
    *) ai_note="_Relatório IA falhou (OpenRouter e Gemini indisponíveis)_" ;;
  esac

  local desc
  desc="$(cat <<EOF
**Alvo:** ${url}
**Scan ID:** ${scan_uuid:-n/a}
**Log:** \`${logfile}\`
**Relatório HTML:** \`${report_path}\`
**SQLite:** \`${sqlite_path}\`
${ai_note}

${summary}
EOF
)"

  if [[ "$report_exit" -ne 0 ]]; then
    local report_fail_desc
    report_fail_desc="$(cat <<EOF
${desc}

_Geração HTML exit ${report_exit}_
EOF
)"
    safe_notify discord_notify_embed \
      "⚠️ Scan OK, relatório HTML falhou: ${domain}" \
      "$(discord_truncate "$report_fail_desc")" \
      16776960
    return 0
  fi

  local attachments=()
  [[ -f "$report_path" ]] && attachments+=("$report_path")
  [[ -f "$ai_report_path" && "$ai_exit" -eq 0 ]] && attachments+=("$ai_report_path")

  if [[ ${#attachments[@]} -gt 0 ]]; then
    discord_notify_file "✅ **Scan concluído:** \`${domain}\`" "${attachments[@]}" || \
      safe_notify discord_notify_embed "✅ Scan concluído: ${domain}" "$(discord_truncate "$desc")" 3066993
  else
    safe_notify discord_notify_embed "✅ Scan concluído: ${domain}" "$(discord_truncate "$desc")" 3066993
  fi

  # Resumo executivo IA inline (primeiros parágrafos) quando couber no embed.
  if [[ -f "$ai_report_path" && "$ai_exit" -eq 0 ]]; then
    local ai_preview
    ai_preview="$(awk 'found {print} /^---$/ {found=1}' "$ai_report_path" 2>/dev/null | head -c 3500 || true)"
    if [[ -n "$ai_preview" ]]; then
      safe_notify discord_notify_embed \
        "🤖 Resumo IA — ${domain}" \
        "$(discord_truncate "$ai_preview")" \
        3447003
    fi
  fi
}

# --- main loop ---------------------------------------------------------------

total=0
ok=0
fail=0

while IFS= read -r line || [[ -n "$line" ]]; do
  domain="$(normalize_domain "$line" || true)"
  [[ -z "${domain:-}" ]] && continue
  total=$((total + 1))

  echo ""
  echo "════════════════════════════════════════════════════════════"
  echo " [$total] Scanning: $domain"
  echo "════════════════════════════════════════════════════════════"

  if run_domain "$domain"; then
    ok=$((ok + 1))
  else
    fail=$((fail + 1))
    if [[ "$CONTINUE_ON_ERROR" != "1" ]]; then
      echo "Abortando (CONTINUE_ON_ERROR=0)." >&2
      break
    fi
  fi
done < "$DOMAINS_FILE"

summary_msg="🏁 **Batch finalizado** — total: ${total}, ok: ${ok}, falhas: ${fail}"
safe_notify discord_notify "$summary_msg"
echo ""
echo "$summary_msg"

if [[ "$fail" -gt 0 ]]; then
  exit 1
fi