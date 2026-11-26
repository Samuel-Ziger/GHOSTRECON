import {
  apiUrl,
  buildApiHeaders,
  type OptionalAuthConfig,
} from '../../services/api-client';
import {
  readJson,
  safeWrite,
  STORAGE_KEYS,
  type StorageLike,
} from '../../services/storage';

export type VigoliumRunProfile = {
  engine: string;
  strategy: string;
  preferPath: boolean;
  useCodex: boolean;
  dast: boolean;
  audit: boolean;
  swarm: boolean;
  autopilot: boolean;
  source: string;
  authFile: string;
  authEntries: string;
  inputFile: string;
  inputType: string;
  only: string;
  reportOnly: string;
  htmlReport: boolean;
  moduleTags: string;
  auditMode: string;
  savedAt: string;
};

export type VigoliumAgentMode = 'autopilot' | 'swarm' | 'audit' | 'none';

export type VigoliumGuardrailMessage = {
  level: 'block' | 'warn';
  text: string;
};

export type VigoliumGuardrailInput = {
  modules?: string[];
  source?: unknown;
  useCodex?: unknown;
  moduleTags?: unknown;
  only?: unknown;
  codexInstalled?: unknown;
};

export type VigoliumCatalogQuery = {
  q?: unknown;
  tag?: unknown;
  limit?: unknown;
};

export type VigoliumServiceDependencies = {
  apiBase: () => string;
  auth: () => OptionalAuthConfig | null;
  fetchImpl: typeof fetch;
  storage?: StorageLike | null;
  now?: () => Date;
};

const PROFILE_DEFAULTS: Omit<VigoliumRunProfile, 'savedAt'> = {
  engine: 'node',
  strategy: 'lite',
  preferPath: false,
  useCodex: false,
  dast: false,
  audit: false,
  swarm: false,
  autopilot: false,
  source: '',
  authFile: '',
  authEntries: '',
  inputFile: '',
  inputType: '',
  only: '',
  reportOnly: '',
  htmlReport: false,
  moduleTags: '',
  auditMode: 'lite',
};

export const SMART_FAST_MODULES = new Set([
  'subdomains',
  'wayback',
  'rdap',
  'dns_enrichment',
  'security_headers',
  'header_intel',
  'robots_sitemap',
  'http3_quic_surface',
  'nginx_http3_cve_2026_42530',
  'cve_correlation',
  'panel_exposure_audit',
  'cookie_session_audit',
  'csrf_flow_audit',
  'jwt_jwks_audit',
  'openapi_specs',
  'api_contract_diff',
  'kali_nmap',
  'ftp_anonymous_audit',
  'nmap_cve_match',
  'nmap_backport_review',
  'mysql_3306_intel',
  'risk_explainer',
]);

export const FULL_MODULES_EXCLUDE = new Set([
  'navegation',
  'kali_ffuf',
  'kali_dirsearch',
  'kali_proxychains',
  'kali_nmap_aggressive',
  'kali_nmap_udp',
  'ftp_write_probe',
  'info_disclosure_errors',
  'webshell_probe',
  'out_of_scope',
]);

function text(value: unknown): string {
  return String(value ?? '').trim();
}

function boolean(value: unknown): boolean {
  return value === true;
}

function errorMessage(body: unknown, status: number): string {
  const record = body && typeof body === 'object' ? body as Record<string, unknown> : {};
  return String(record.error || record.message || `HTTP ${status}`);
}

export function normalizeVigoliumRunProfile(
  value: unknown,
  now = new Date(),
): VigoliumRunProfile {
  const source = value && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
  return {
    engine: text(source.engine) || PROFILE_DEFAULTS.engine,
    strategy: text(source.strategy) || PROFILE_DEFAULTS.strategy,
    preferPath: boolean(source.preferPath),
    useCodex: boolean(source.useCodex),
    dast: boolean(source.dast),
    audit: boolean(source.audit),
    swarm: boolean(source.swarm),
    autopilot: boolean(source.autopilot),
    source: text(source.source),
    authFile: text(source.authFile),
    authEntries: String(source.authEntries ?? '').trim(),
    inputFile: text(source.inputFile),
    inputType: text(source.inputType),
    only: text(source.only),
    reportOnly: text(source.reportOnly),
    htmlReport: boolean(source.htmlReport),
    moduleTags: text(source.moduleTags),
    auditMode: text(source.auditMode) || PROFILE_DEFAULTS.auditMode,
    savedAt: text(source.savedAt) || now.toISOString(),
  };
}

export function mergeUniqueLines(current: unknown, additions: unknown[]): string {
  const result = String(current ?? '').split(/\r?\n/).map((entry) => entry.trim()).filter(Boolean);
  const seen = new Set(result.map((entry) => entry.toLowerCase()));
  for (const raw of additions || []) {
    const entry = text(raw);
    const key = entry.toLowerCase();
    if (entry && !seen.has(key)) {
      result.push(entry);
      seen.add(key);
    }
  }
  return result.join('\n');
}

export function mergeUniqueCsv(current: unknown, additions: unknown[]): string {
  const result = String(current ?? '').split(',').map((entry) => entry.trim()).filter(Boolean);
  const seen = new Set(result.map((entry) => entry.toLowerCase()));
  for (const raw of additions || []) {
    const entry = text(raw);
    const key = entry.toLowerCase();
    if (entry && !seen.has(key)) {
      result.push(entry);
      seen.add(key);
    }
  }
  return result.join(',');
}

export function vigoliumAuthEntry(role: unknown, raw: unknown): string {
  const normalizedRole = text(role).toLowerCase();
  const value = text(raw);
  if (!normalizedRole || !value) return '';
  if (new RegExp(`^${normalizedRole}:`, 'i').test(value)) return value;
  if (/^(cookie|header|bearer):/i.test(value)) return `${normalizedRole}:${value}`;
  const kind = /^authorization\s*[:=]/i.test(value) || /^[a-z0-9-]+\s*:/i.test(value)
    ? 'Header'
    : 'Cookie';
  return `${normalizedRole}:${kind}:${value}`;
}

export function vigoliumAgentMode(modules: unknown): VigoliumAgentMode {
  const selected = new Set(Array.isArray(modules) ? modules.map(String) : []);
  if (selected.has('vigolium_autopilot')) return 'autopilot';
  if (selected.has('vigolium_swarm')) return 'swarm';
  if (selected.has('vigolium_audit')) return 'audit';
  return 'none';
}

export function vigoliumGuardrailMessages(
  input: VigoliumGuardrailInput = {},
): VigoliumGuardrailMessage[] {
  const mode = vigoliumAgentMode(input.modules || []);
  if (mode === 'none') return [];
  const source = text(input.source);
  const moduleTags = text(input.moduleTags);
  const only = text(input.only);
  const useCodex = boolean(input.useCodex);
  const messages: VigoliumGuardrailMessage[] = [];
  if (mode === 'audit' && !source) {
    messages.push({ level: 'block', text: 'audit precisa de caminho do codigo-fonte; sem isso o agent sera ignorado.' });
  }
  if (mode === 'autopilot') {
    messages.push({ level: 'warn', text: 'autopilot roda somente em prévia (dry-run) até existir aprovação por comando no motor Vigolium.' });
    if (!useCodex) messages.push({ level: 'warn', text: 'autopilot sem Codex marcado pode cair em provider externo/indefinido do Vigolium.' });
    if (!source) messages.push({ level: 'warn', text: 'sem source, autopilot fica limitado ao alvo web e perde code review.' });
  }
  if (mode === 'swarm') {
    messages.push({ level: 'warn', text: 'swarm será ignorado: o motor nativo ainda não garante execução restrita ao plano aprovado.' });
  }
  if (mode === 'autopilot' && !moduleTags && !only) {
    messages.push({ level: 'block', text: 'autopilot exige tags de módulos ou --only para compor a prévia do plano interno.' });
  }
  if (useCodex && input.codexInstalled === false) {
    messages.push({ level: 'warn', text: 'Codex nao foi detectado no PATH deste ambiente.' });
  }
  return messages;
}

export function moduleSelectionForPreset(
  available: unknown[],
  preset: 'smart-fast' | 'full',
): string[] {
  const values = available.map(String);
  if (preset === 'smart-fast') return values.filter((value) => SMART_FAST_MODULES.has(value));
  return values.filter((value) => !FULL_MODULES_EXCLUDE.has(value));
}

export function createVigoliumService(dependencies: VigoliumServiceDependencies) {
  const {
    apiBase,
    auth,
    fetchImpl,
    storage = null,
    now = () => new Date(),
  } = dependencies;

  function saveProfile(value: unknown): VigoliumRunProfile {
    const profile = normalizeVigoliumRunProfile(value, now());
    if (!safeWrite(storage, STORAGE_KEYS.vigoliumProfile, JSON.stringify(profile))) {
      throw new Error('storage indisponivel');
    }
    return profile;
  }

  function loadProfile(): VigoliumRunProfile | null {
    const parsed = readJson<unknown>(storage, STORAGE_KEYS.vigoliumProfile, null);
    return parsed ? normalizeVigoliumRunProfile(parsed, now()) : null;
  }

  function clearProfile(): boolean {
    return safeWrite(storage, STORAGE_KEYS.vigoliumProfile, null);
  }

  async function getJson(pathname: string, signal?: AbortSignal): Promise<Record<string, any>> {
    const response = await fetchImpl(apiUrl(pathname, apiBase()), {
      headers: buildApiHeaders({ auth: auth() }),
      signal,
    });
    const body = await response.json().catch(() => ({})) as Record<string, any>;
    if (!response.ok || body.ok === false) throw new Error(errorMessage(body, response.status));
    return body;
  }

  async function capabilities(signal?: AbortSignal): Promise<Record<string, any>> {
    return getJson('/api/capabilities', signal);
  }

  async function catalog(
    query: VigoliumCatalogQuery = {},
    signal?: AbortSignal,
  ): Promise<Record<string, any>> {
    const limit = Math.max(1, Math.min(100, Number(query.limit) || 40));
    const params = new URLSearchParams({ limit: String(limit) });
    const q = text(query.q);
    const tag = text(query.tag);
    if (q) params.set('q', q);
    if (tag) params.set('tag', tag);
    return getJson(`/api/vigolium/modules?${params.toString()}`, signal);
  }

  return Object.freeze({
    authEntry: vigoliumAuthEntry,
    agentMode: vigoliumAgentMode,
    capabilities,
    catalog,
    clearProfile,
    guardrailMessages: vigoliumGuardrailMessages,
    loadProfile,
    mergeCsv: mergeUniqueCsv,
    mergeLines: mergeUniqueLines,
    normalizeProfile: (value: unknown) => normalizeVigoliumRunProfile(value, now()),
    selectPreset: moduleSelectionForPreset,
    saveProfile,
  });
}

