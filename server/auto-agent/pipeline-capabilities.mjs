/**
 * Auto-facing view of legacy pipeline capabilities.
 *
 * The main pipeline still contains modules that predate module manifests.  They
 * must nevertheless be visible to the planner and, more importantly, pass the
 * same risk gates as manifested modules.  Keep this list aligned with the
 * module checkboxes and phase guards until the legacy phases are fully migrated
 * to the module registry.
 */

const INTRUSIVE = new Set([
  'active_param_discovery',
  'authz_matrix',
  'browser_xss_verify',
  'cloud_bruteforce',
  'cred_spray',
  'dom_xss_verify',
  'evidence_verification',
  'info_disclosure_errors',
  'info_disclosure_hunter',
  'kali_dalfox',
  'kali_dirsearch',
  'kali_ffuf',
  'kali_nmap_aggressive',
  'kali_nmap_udp',
  'kali_nuclei',
  'kali_proxychains',
  'kali_wpscan',
  'kali_xss_vibes',
  'micro_exploit',
  'mysql_3306_intel',
  'nmap_backport_review',
  'nmap_cve_match',
  'nmap_service_followups',
  'race_harness',
  'secret_validation',
  'shannon_whitebox',
  'sqlmap',
  'verify_sqli_deep',
  'vigolium_autopilot',
  'vigolium_dast',
  'vigolium_swarm',
  'webshell_probe',
]);

/**
 * Capabilities that must never be delegated to Auto Mode.
 *
 * Some of these legacy switches are not literally destructive in their
 * current implementation (for example, cred_spray only builds a plan today),
 * but their purpose is credential attack, scope expansion, or identity
 * concealment. Keeping them out of the catalogue prevents a future
 * implementation change from silently widening an already-approved Auto plan.
 * They remain available to explicitly gated/manual laboratory workflows.
 */
export const AUTO_PROHIBITED_CAPABILITY_IDS = Object.freeze([
  'cloud_bruteforce',
  'cred_spray',
  'ftp_write_probe',
  'identity_rotation',
  'kali_proxychains',
  'navegation',
  'stealth_requests',
]);

const DESTRUCTIVE = new Set(AUTO_PROHIBITED_CAPABILITY_IDS);

const ACTIVE = new Set([
  'api_contract_diff',
  'asset_discovery',
  'client_auth_audit',
  'client_surface_audit',
  'cookie_session_audit',
  'cors_audit',
  'csrf_flow_audit',
  'curl_probe',
  'directory',
  'firebase_audit',
  'graphql_probe',
  'graphql_recon',
  'header_intel',
  'high_recheck',
  'http_probe',
  'http3_quic_surface',
  'js_intel',
  'jwt_jwks_audit',
  'kali_whois',
  'lovable_fingerprint',
  'nginx_http3_cve_2026_42530',
  'openapi_specs',
  'panel_exposure_audit',
  'robots_sitemap',
  'security_headers',
  'service_worker_audit',
  'supabase_audit',
  'wafw00f',
  'wellknown_openid',
  'wellknown_security_txt',
  'vigolium_audit',
]);

const DEEP_PASSIVE = new Set([
  'dom_clobbering_audit',
  'email_security_deep',
  'hpp_param_pollution',
  'secrets_context_ranker',
  'websocket_recon',
]);

const REQUIRES_KALI = new Set([
  'info_disclosure_errors',
  'info_disclosure_hunter',
  'kali_dalfox',
  'kali_dirsearch',
  'kali_ffuf',
  'kali_nmap_aggressive',
  'kali_nmap_udp',
  'kali_nuclei',
  'kali_proxychains',
  'kali_whois',
  'kali_wpscan',
  'kali_xss_vibes',
  'mysql_3306_intel',
  'nmap_backport_review',
  'nmap_cve_match',
  'nmap_service_followups',
  'sqlmap',
]);

const IDS = [
  'active_param_discovery',
  'amass',
  'api_contract_diff',
  'asset_discovery',
  'authz_matrix',
  'backup',
  'bounty_estimator',
  'bounty_scope',
  'browser_xss_verify',
  'chaining',
  'client_auth_audit',
  'client_surface_audit',
  'cloud_bruteforce',
  'common_crawl',
  'config',
  'cookie_session_audit',
  'cors_audit',
  'cred_spray',
  'csrf_flow_audit',
  'ct_monitor',
  'curl_probe',
  'cve_correlation',
  'database',
  'directory',
  'dns_enrichment',
  'documents',
  'dom_clobbering_audit',
  'dom_xss_verify',
  'email_security_deep',
  'evidence_verification',
  'firebase_audit',
  'ftp_write_probe',
  'gau',
  'github',
  'google_cse',
  'graphql_probe',
  'graphql_recon',
  'header_intel',
  'high_recheck',
  'hpp_param_pollution',
  'http_probe',
  'http3_quic_surface',
  'identity_rotation',
  'info_disclosure_errors',
  'info_disclosure_hunter',
  'js_intel',
  'jwt_jwks_audit',
  'jwt_lab',
  'kali_dalfox',
  'kali_dirsearch',
  'kali_ffuf',
  'kali_nmap_aggressive',
  'kali_nmap_udp',
  'kali_nuclei',
  'kali_proxychains',
  'kali_whois',
  'kali_wpscan',
  'kali_xss_vibes',
  'login',
  'logs',
  'lovable_fingerprint',
  'micro_exploit',
  'mysql_3306_intel',
  'navegation',
  'nginx_http3_cve_2026_42530',
  'nmap_backport_review',
  'nmap_cve_match',
  'nmap_service_followups',
  'oob_collaborator',
  'openapi_specs',
  'origin_discovery',
  'out_of_scope',
  'panel_exposure_audit',
  'passwords',
  'pastebin',
  'payload_mutator',
  'pentestgpt_validate',
  'phperrors',
  'phpinfo',
  'race_harness',
  'rdap',
  'risk_explainer',
  'robots_sitemap',
  'secrets_context_ranker',
  'security_headers',
  'secret_validation',
  'sensitive',
  'service_worker_audit',
  'shannon_whitebox',
  'shodan',
  'sqlerrors',
  'sqlmap',
  'stealth_requests',
  'subdomains',
  'subfinder',
  'supabase_audit',
  'verify_sqli_deep',
  'vigolium_audit',
  'vigolium_autopilot',
  'vigolium_dast',
  'vigolium_swarm',
  'virustotal',
  'wafw00f',
  'wayback',
  'waybackurls',
  'webshell_probe',
  'websocket_recon',
  'wellknown_openid',
  'wellknown_security_txt',
];

const PIPELINE_PHASES = Object.freeze({
  fingerprint: Object.freeze([
    'firebase_audit',
    'lovable_fingerprint',
    'supabase_audit',
  ]),
  discovery: Object.freeze([
    'amass',
    'ct_monitor',
    'dns_enrichment',
    'email_security_deep',
    'origin_discovery',
    'rdap',
    'subdomains',
    'subfinder',
    'virustotal',
  ]),
  probe: Object.freeze([
    'api_contract_diff',
    'cookie_session_audit',
    'cors_audit',
    'csrf_flow_audit',
    'header_intel',
    'http_probe',
    'http3_quic_surface',
    'jwt_jwks_audit',
    'nginx_http3_cve_2026_42530',
    'openapi_specs',
    'panel_exposure_audit',
    'robots_sitemap',
    'security_headers',
    'service_worker_audit',
    'shodan',
    'wafw00f',
    'wellknown_openid',
    'wellknown_security_txt',
  ]),
  content_discovery: Object.freeze([
    'backup',
    'client_auth_audit',
    'client_surface_audit',
    'common_crawl',
    'config',
    'database',
    'directory',
    'documents',
    'dom_clobbering_audit',
    'gau',
    'github',
    'google_cse',
    'graphql_probe',
    'graphql_recon',
    'hpp_param_pollution',
    'js_intel',
    'login',
    'logs',
    'out_of_scope',
    'passwords',
    'pastebin',
    'phperrors',
    'phpinfo',
    'secret_validation',
    'secrets_context_ranker',
    'sensitive',
    'shannon_whitebox',
    'sqlerrors',
    'wayback',
    'waybackurls',
    'websocket_recon',
  ]),
  go_engine: Object.freeze([
    'vigolium_dast',
  ]),
  validation: Object.freeze([
    'active_param_discovery',
    'authz_matrix',
    'cred_spray',
    'curl_probe',
    'dom_xss_verify',
    'evidence_verification',
    'hexstrike_orchestrator',
    'jwt_lab',
    'micro_exploit',
    'oob_collaborator',
    'payload_mutator',
    'race_harness',
    'sqlmap',
    'verify_sqli_deep',
    'webshell_probe',
  ]),
  aggressive: Object.freeze([
    'info_disclosure_errors',
    'info_disclosure_hunter',
    'kali_dalfox',
    'kali_dirsearch',
    'kali_ffuf',
    'kali_nmap_aggressive',
    'kali_nmap_udp',
    'kali_nuclei',
    'kali_proxychains',
    'kali_whois',
    'kali_wpscan',
    'kali_xss_vibes',
    'mysql_3306_intel',
    'nmap_backport_review',
    'nmap_cve_match',
    'nmap_service_followups',
    'ftp_write_probe',
  ]),
  asset_discovery: Object.freeze([
    'asset_discovery',
    'cloud_bruteforce',
    'navegation',
  ]),
  go_agent: Object.freeze([
    'vigolium_audit',
    'vigolium_autopilot',
    'vigolium_swarm',
  ]),
  finalize: Object.freeze([
    'bounty_estimator',
    'bounty_scope',
    'browser_xss_verify',
    'chaining',
    'cve_correlation',
    'high_recheck',
    'pentestgpt_validate',
    'risk_explainer',
  ]),
});

const PIPELINE_PHASE_BY_CAPABILITY = new Map(
  Object.entries(PIPELINE_PHASES).flatMap(([phase, ids]) => ids.map((id) => [id, phase])),
);

function humanName(id) {
  return id.split('_').map((part) => part.charAt(0).toUpperCase() + part.slice(1)).join(' ');
}

export const AUTO_LEGACY_CAPABILITIES = Object.freeze(IDS.map((id) => Object.freeze({
  id,
  name: humanName(id),
  source: id.startsWith('vigolium_') ? 'vigolium' : 'ghostrecon',
  class: DESTRUCTIVE.has(id)
    ? 'destructive'
    : INTRUSIVE.has(id)
      ? 'intrusive'
      : ACTIVE.has(id)
        ? 'active'
        : DEEP_PASSIVE.has(id)
          ? 'deep_passive'
          : 'passive',
  intrusive: INTRUSIVE.has(id),
  destructive: DESTRUCTIVE.has(id),
  requiresKali: REQUIRES_KALI.has(id),
  requiresAuth: false,
  timeoutMs: INTRUSIVE.has(id) ? 5 * 60_000 : ACTIVE.has(id) ? 2 * 60_000 : 90_000,
  concurrency: INTRUSIVE.has(id) ? 2 : ACTIVE.has(id) ? 4 : 6,
  outputs: ['finding'],
})));

export const AUTO_ENGINE_CAPABILITIES = Object.freeze([
  Object.freeze({
    id: 'frameseven_recon',
    name: 'FrameSeven Recon and CVE Enrichment',
    source: 'frameseven',
    class: 'active',
    intrusive: false,
    requiresAuth: false,
    requiresKali: false,
    timeoutMs: 10 * 60_000,
    concurrency: 4,
    outputs: ['finding', 'artifact'],
  }),
  Object.freeze({
    id: 'frameseven_active',
    name: 'FrameSeven Bounded Active Tool Set',
    source: 'frameseven',
    class: 'intrusive',
    intrusive: true,
    requiresAuth: false,
    requiresKali: false,
    timeoutMs: 30 * 60_000,
    concurrency: 10,
    outputs: ['finding', 'artifact'],
  }),
  Object.freeze({
    id: 'frameseven_authenticated',
    name: 'FrameSeven Authenticated Bounded Offensive Tool Set',
    source: 'frameseven',
    class: 'intrusive',
    intrusive: true,
    requiresAuth: true,
    requiresKali: false,
    timeoutMs: 30 * 60_000,
    concurrency: 10,
    outputs: ['finding', 'artifact'],
  }),
]);

export function autoCapabilityClass(id) {
  const normalized = String(id || '').trim().toLowerCase().replace(/-/g, '_');
  return AUTO_ENGINE_CAPABILITIES.find((item) => item.id === normalized)?.class
    || AUTO_LEGACY_CAPABILITIES.find((item) => item.id === normalized)?.class
    || null;
}

/**
 * Retorna a fase que realmente contém uma capacidade legada.
 *
 * O mapa alimenta apenas telemetria e avaliação; ele não altera a seleção nem
 * a ordem de execução. Módulos Forge podem declarar uma das fases conhecidas e,
 * na ausência dessa declaração, pertencem à fronteira `dynamic_modules`.
 */
export function autoCapabilityPhase(id, manifest = null) {
  const normalized = String(id || '').trim().toLowerCase().replace(/-/g, '_');
  const known = PIPELINE_PHASE_BY_CAPABILITY.get(normalized);
  if (known) return known;
  if (String(manifest?.source || '') === 'ai-forge') {
    const declared = String(manifest?.phase || '').trim().toLowerCase();
    return Object.hasOwn(PIPELINE_PHASES, declared) ? declared : 'dynamic_modules';
  }
  return null;
}
