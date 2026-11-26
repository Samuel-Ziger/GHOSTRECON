#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

if [[ ! -t 0 && "${GHOSTRECON_ENGAGEMENT_ALLOW_PIPE:-0}" != "1" ]]; then
  printf 'Este assistente exige um terminal interativo.\n' >&2
  printf 'Para testes automatizados, defina GHOSTRECON_ENGAGEMENT_ALLOW_PIPE=1.\n' >&2
  exit 2
fi

if ! command -v node >/dev/null 2>&1; then
  printf 'Erro: Node.js não foi encontrado no PATH.\n' >&2
  exit 1
fi

cd "$ROOT_DIR"

run_engagement_cli() {
  node --input-type=module -e '
    import { cliMain } from "./server/modules/cli/main.mjs";
    process.exitCode = await cliMain(["engagement", ...process.argv.slice(1)]);
  ' -- "$@"
}

fail() {
  printf '\nErro: %s\n' "$*" >&2
  exit 1
}

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

ask() {
  local variable="$1" label="$2" default_value="${3-}" input_value
  if [[ -n "$default_value" ]]; then
    printf '%s [%s]: ' "$label" "$default_value" >&2
  else
    printf '%s: ' "$label" >&2
  fi
  IFS= read -r input_value || fail 'entrada encerrada antes da conclusão'
  input_value="$(trim "$input_value")"
  printf -v "$variable" '%s' "${input_value:-$default_value}"
}

ask_required() {
  local variable="$1" label="$2" answer
  while true; do
    ask answer "$label"
    if [[ -n "$answer" ]]; then
      printf -v "$variable" '%s' "$answer"
      return
    fi
    printf 'Este campo é obrigatório.\n' >&2
  done
}

ask_yes_no() {
  local variable="$1" label="$2" default_value="${3:-n}" answer
  while true; do
    ask answer "$label (s/n)" "$default_value"
    case "${answer,,}" in
      s|sim|y|yes) printf -v "$variable" '%s' '1'; return ;;
      n|nao|não|no) printf -v "$variable" '%s' '0'; return ;;
      *) printf 'Responda s ou n.\n' >&2 ;;
    esac
  done
}

csv_to_array() {
  local raw="$1" output_name="$2" part cleaned
  local -n output_ref="$output_name"
  local -a parts=()
  output_ref=()
  IFS=',' read -r -a parts <<< "$raw"
  for part in "${parts[@]}"; do
    cleaned="$(trim "$part")"
    [[ -z "$cleaned" ]] || output_ref+=("$cleaned")
  done
}

domain_candidate() {
  local rule="${1,,}"
  if [[ "$rule" == \*.* ]]; then
    printf 'validation.%s' "${rule#*.}"
  else
    printf '%s' "$rule"
  fi
}

ip_candidate() {
  printf '%s' "${1%%/*}"
}

domain_rule_matches() {
  node --input-type=module -e '
    import { hostnameMatchesDomainScopeRule } from "./server/modules/scope.js";
    process.exit(hostnameMatchesDomainScopeRule(process.argv[1], process.argv[2]) ? 0 : 1);
  ' "$1" "$2"
}

ip_rule_matches() {
  node --input-type=module -e '
    import { ipMatchesScopeRule } from "./server/modules/scope.js";
    process.exit(ipMatchesScopeRule(process.argv[1], process.argv[2]) ? 0 : 1);
  ' "$1" "$2"
}

target_is_excluded() {
  node --input-type=module -e '
    import { hostnameMatchesOutOfScope } from "./server/modules/scope.js";
    process.exit(hostnameMatchesOutOfScope(process.argv[1], [process.argv[2]]) ? 0 : 1);
  ' "$1" "$2"
}

normalize_target() {
  node --input-type=module -e '
    import { parseReconTarget } from "./server/modules/recon-target.js";
    const parsed = parseReconTarget(process.argv[1]);
    if (!parsed.ok) { console.error(parsed.message); process.exit(1); }
    process.stdout.write(parsed.target);
  ' "$1"
}

validate_window() {
  node -e '
    const start = new Date(process.argv[1]);
    const end = new Date(process.argv[2]);
    if (!Number.isFinite(start.getTime()) || !Number.isFinite(end.getTime())) process.exit(1);
    if (end <= start) process.exit(2);
  ' "$1" "$2"
}

generated_id="ENG-$(date -u +%Y%m%d-%H%M%S)"
default_start="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
default_end="$(date -u -d '+8 hours' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || true)"
[[ -n "$default_end" ]] || default_end="$(node -e 'process.stdout.write(new Date(Date.now()+8*60*60*1000).toISOString())')"

printf '\nGHOSTRECON · Criador de Engagement Autorizado\n'
printf 'Nada será gravado antes da confirmação final.\n\n'

while true; do
  ask engagement_id 'ID do engagement' "$generated_id"
  [[ -n "$engagement_id" ]] || continue
  if (( ${#engagement_id} > 120 )) || [[ ! "$engagement_id" =~ ^[A-Za-z0-9._:@/-]+$ ]]; then
    printf 'ID inválido. Use até 120 caracteres: A-Z, a-z, 0-9, ponto, _, :, @, / ou -.\n' >&2
    continue
  fi
  if run_engagement_cli --show "$engagement_id" >/dev/null 2>&1; then
    ask_yes_no update_existing "O engagement $engagement_id já existe. Atualizar" 'n'
    [[ "$update_existing" == '1' ]] && break
    printf 'Escolha outro ID.\n' >&2
    continue
  fi
  break
done

ask_required client_name 'Cliente, empresa ou programa'
ask_required operator_name 'Responsável pelo teste'
ask scope_domains_raw 'Domínios autorizados, separados por vírgula (wildcard: *.exemplo.com)'
ask scope_ips_raw 'IPs ou CIDRs IPv4 autorizados, separados por vírgula'

declare -a scope_domains scope_ips exclusions source_ips
csv_to_array "$scope_domains_raw" scope_domains
csv_to_array "$scope_ips_raw" scope_ips
(( ${#scope_domains[@]} + ${#scope_ips[@]} > 0 )) || fail 'informe pelo menos um domínio, IP ou CIDR autorizado'

for rule in "${scope_domains[@]}"; do
  candidate="$(domain_candidate "$rule")"
  domain_rule_matches "$candidate" "$rule" || fail "regra de domínio inválida: $rule"
done
for rule in "${scope_ips[@]}"; do
  candidate="$(ip_candidate "$rule")"
  ip_rule_matches "$candidate" "$rule" || fail "regra de IP/CIDR inválida ou não suportada: $rule"
done

if (( ${#scope_domains[@]} > 0 )); then
  default_target="$(domain_candidate "${scope_domains[0]}")"
else
  default_target="$(ip_candidate "${scope_ips[0]}")"
fi
ask validation_target 'Alvo exato para validar o escopo' "$default_target"
validation_target="$(normalize_target "$validation_target")" || fail 'alvo de validação inválido'

target_in_scope=0
for rule in "${scope_domains[@]}"; do
  if domain_rule_matches "$validation_target" "$rule"; then target_in_scope=1; break; fi
done
if [[ "$target_in_scope" == '0' ]]; then
  for rule in "${scope_ips[@]}"; do
    if ip_rule_matches "$validation_target" "$rule"; then target_in_scope=1; break; fi
  done
fi
[[ "$target_in_scope" == '1' ]] || fail "$validation_target não pertence ao escopo informado"

ask exclusions_raw 'Exclusões/out-of-scope, separadas por vírgula (opcional)'
ask source_ips_raw 'IPs de origem autorizados para o operador, separados por vírgula (opcional)'
csv_to_array "$exclusions_raw" exclusions
csv_to_array "$source_ips_raw" source_ips
for rule in "${source_ips[@]}"; do
  [[ "$rule" != */* ]] || fail "IP de origem deve ser exato, sem CIDR: $rule"
  ip_rule_matches "$rule" "$rule" || fail "IP de origem inválido: $rule"
done
for rule in "${exclusions[@]}"; do
  if target_is_excluded "$validation_target" "$rule"; then
    fail "o alvo de validação está coberto pela exclusão: $rule"
  fi
done

ask starts_at 'Início da janela em ISO-8601' "$default_start"
ask ends_at 'Fim da janela em ISO-8601' "$default_end"
ask timezone_name 'Fuso horário descritivo' 'America/Sao_Paulo'
validate_window "$starts_at" "$ends_at" || fail 'janela inválida: use datas ISO-8601 e garanta que o fim seja posterior ao início'

ask roe_url 'URL ou referência do Rules of Engagement (ROE)'
ask_yes_no roe_signed 'O ROE está formalmente aprovado/assinado' 'n'
[[ "$roe_signed" == '1' ]] || fail 'um engagement autorizado exige ROE formalmente aprovado/assinado'

ask escalation_name 'Contato de emergência/escalation (nome)'
ask escalation_email 'Contato de emergência (e-mail)'
ask escalation_phone 'Contato de emergência (telefone)'
ask note_text 'Observação operacional (opcional)'

printf '\nResumo que será gravado\n'
printf '  ID:          %s\n' "$engagement_id"
printf '  Cliente:     %s\n' "$client_name"
printf '  Responsável:%s\n' " $operator_name"
printf '  Domínios:    %s\n' "${scope_domains[*]:-(nenhum)}"
printf '  IPs/CIDRs:   %s\n' "${scope_ips[*]:-(nenhum)}"
printf '  Exclusões:   %s\n' "${exclusions[*]:-(nenhuma)}"
printf '  Janela:      %s → %s (%s)\n' "$starts_at" "$ends_at" "$timezone_name"
printf '  Alvo teste:  %s\n' "$validation_target"
printf '  ROE assinado:sim\n\n'
printf 'Digite AUTORIZO para criar/atualizar este engagement: ' >&2
IFS= read -r final_confirmation || fail 'confirmação não recebida'
[[ "$final_confirmation" == 'AUTORIZO' ]] || fail 'operação cancelada; nenhuma alteração foi gravada'

args=(--add --id "$engagement_id" --client "$client_name" --starts-at "$starts_at" --ends-at "$ends_at" --tz "$timezone_name" --roe-signed)
for value in "${scope_domains[@]}"; do args+=(--scope-domain "$value"); done
for value in "${scope_ips[@]}"; do args+=(--scope-ip "$value"); done
for value in "${exclusions[@]}"; do args+=(--exclude "$value"); done
for value in "${source_ips[@]}"; do args+=(--source-ip "$value"); done
[[ -z "$roe_url" ]] || args+=(--roe-url "$roe_url")

if [[ -n "$escalation_name$escalation_email$escalation_phone" ]]; then
  escalation_value="${escalation_name:-Contato}"
  if [[ -n "$escalation_email" ]]; then
    escalation_value+=" <$escalation_email>"
    [[ -z "$escalation_phone" ]] || escalation_value+=" <$escalation_phone>"
  fi
  args+=(--escalation "$escalation_value")
fi

combined_note="Responsável: $operator_name."
[[ -z "$note_text" ]] || combined_note+=" $note_text"
args+=(--note "$combined_note")

creation_output="$(run_engagement_cli "${args[@]}")"
printf '%s\n' "$creation_output"

if checklist_output="$(run_engagement_cli --checklist --id "$engagement_id" --target "$validation_target")"; then
  printf '%s\n' "$checklist_output"
else
  checklist_status=$?
  printf '%s\n' "$checklist_output"
  printf 'Aviso: o engagement foi gravado, mas o checklist operacional retornou status %s.\n' "$checklist_status" >&2
fi

printf '\nEngagement autorizado criado com sucesso.\n'
printf 'Use este ID no Auto/NeuroSploit/HackBot: %s\n' "$engagement_id"
printf 'Exemplo CLI: --engagement %q\n\n' "$engagement_id"
printf '%s\n' 'JSON final:'
final_output="$(run_engagement_cli --show "$engagement_id")"
printf '%s\n' "$final_output"
