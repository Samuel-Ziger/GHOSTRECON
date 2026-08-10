/** Aliases legados (kebab-case / UI antiga) → snake_case canónico. */
const MODULE_ALIASES = new Map([
  ['cookie-session-audit', 'cookie_session_audit'],
  ['csrf-flow-audit', 'csrf_flow_audit'],
  ['jwt-jwks-audit', 'jwt_jwks_audit'],
  ['http3-quic-surface', 'http3_quic_surface'],
  ['nginx-http3-cve-2026-42530', 'nginx_http3_cve_2026_42530'],
  ['cve-correlation', 'cve_correlation'],
  ['panel-exposure-audit', 'panel_exposure_audit'],
  ['service-worker-audit', 'service_worker_audit'],
  ['api-contract-diff', 'api_contract_diff'],
  ['websocket-recon', 'websocket_recon'],
  ['hpp-param-pollution', 'hpp_param_pollution'],
  ['dom-clobbering-audit', 'dom_clobbering_audit'],
  ['email-security-deep', 'email_security_deep'],
  ['hexstrike-orchestrator', 'hexstrike_orchestrator'],
  ['secrets-context-ranker', 'secrets_context_ranker'],
  ['risk-explainer', 'risk_explainer'],
]);

/**
 * Normaliza ID de módulo para snake_case canónico (contrato do registry).
 */
export function normalizeModuleId(id) {
  const raw = String(id || '').trim().toLowerCase();
  if (!raw) return '';
  if (MODULE_ALIASES.has(raw)) return MODULE_ALIASES.get(raw);
  return raw.replace(/-/g, '_');
}

/** Verifica se o módulo está activo no array `modules` (com aliases). */
export function moduleEnabled(modules, moduleId) {
  const want = normalizeModuleId(moduleId);
  if (!want) return false;
  return (modules || []).some((m) => normalizeModuleId(m) === want);
}
