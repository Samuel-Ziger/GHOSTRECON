import { createHash } from 'node:crypto';

export const moduleManifest = {
  id: 'api_excessive_data_audit',
  name: 'API Excessive Data Audit',
  category: 'surface',
  intrusive: false,
  requiresAuth: false,
  requiresKali: false,
  timeoutMs: 10_000,
  concurrency: 1,
  outputs: ['finding', 'metric'],
};

const MAX_ROWS = 5_000;
const IDENTITY_FIELDS = new Set([
  'email', 'emailaddress', 'phone', 'phonenumber', 'mobile', 'fullname',
  'firstname', 'lastname', 'userid', 'accountid', 'customerid', 'username',
]);
const PAGINATION_FIELDS = new Set([
  'page', 'pages', 'pagesize', 'limit', 'offset', 'cursor', 'nextcursor',
  'nextpage', 'hasmore', 'totalpages',
]);

function canonical(value) {
  return String(value || '').toLowerCase().replace(/[^a-z0-9]/g, '');
}

function fingerprint(value) {
  return createHash('sha256').update(String(value)).digest('hex');
}

function safeUrl(value) {
  try {
    const parsed = new URL(String(value || ''));
    parsed.username = '';
    parsed.password = '';
    parsed.search = '';
    parsed.hash = '';
    return parsed.href;
  } catch {
    return '';
  }
}

function findLargestRowArray(value, depth = 0) {
  if (depth > 8 || value == null) return [];
  if (Array.isArray(value)) {
    if (value.some((item) => item && typeof item === 'object' && !Array.isArray(item))) {
      return value.slice(0, MAX_ROWS);
    }
    return [];
  }
  if (typeof value !== 'object') return [];
  let best = [];
  for (const child of Object.values(value)) {
    const candidate = findLargestRowArray(child, depth + 1);
    if (candidate.length > best.length) best = candidate;
  }
  return best;
}

function hasPagination(value, depth = 0) {
  if (depth > 5 || value == null || typeof value !== 'object') return false;
  for (const [key, child] of Object.entries(value)) {
    if (PAGINATION_FIELDS.has(canonical(key))) return true;
    if (hasPagination(child, depth + 1)) return true;
  }
  return false;
}

function identityCoverage(rows) {
  const fields = new Map();
  for (const row of rows) {
    if (!row || typeof row !== 'object' || Array.isArray(row)) continue;
    for (const [key, value] of Object.entries(row)) {
      const normalized = canonical(key);
      if (!IDENTITY_FIELDS.has(normalized) || value == null || String(value).trim() === '') continue;
      fields.set(normalized, (fields.get(normalized) || 0) + 1);
    }
  }
  return fields;
}

function looksLikePublicDirectory(url) {
  try {
    return /(?:^|\/)(?:directory|catalog|authors|team|contributors|public-users)(?:\/|$)/i.test(new URL(url).pathname);
  } catch {
    return false;
  }
}

export function analyzeApiExcessiveData({
  url = '',
  status = 0,
  json = null,
  authTrust = 'anonymous',
  expectedPublicDirectory = false,
  syntheticDataset = false,
  minimumRows = 10,
} = {}) {
  const publicUrl = safeUrl(url);
  if (Number(status) < 200 || Number(status) >= 300 || json == null) {
    return { state: 'executed_no_finding', reason: 'non_success_or_non_json', findings: [] };
  }
  const rows = findLargestRowArray(json);
  const pagination = hasPagination(json);
  const coverage = identityCoverage(rows);
  const lowTrust = ['anonymous', 'low_trust'].includes(String(authTrust));
  const excluded = expectedPublicDirectory || syntheticDataset || looksLikePublicDirectory(publicUrl);
  const commonIdentityFields = [...coverage.entries()]
    .filter(([, count]) => count >= Math.max(2, Math.ceil(rows.length * 0.5)))
    .map(([field]) => field)
    .sort();

  if (excluded) return { state: 'executed_no_finding', reason: 'public_or_synthetic_dataset', findings: [] };
  if (!lowTrust) return { state: 'executed_no_finding', reason: 'trusted_auth_context', findings: [] };
  if (rows.length < minimumRows || commonIdentityFields.length < 2) {
    return { state: 'executed_no_finding', reason: 'insufficient_identity_density', findings: [] };
  }
  if (pagination) return { state: 'executed_no_finding', reason: 'pagination_present', findings: [] };

  const finding = {
    type: 'api_excessive_data_exposure',
    prio: 'med',
    score: 68,
    value: 'API expõe coleção ampla de dados de identidade a contexto de baixa confiança',
    meta: [
      'source=api_excessive_data_audit',
      'classification=probable',
      `auth_trust=${authTrust}`,
      `rows=${rows.length}`,
      `identity_fields=${commonIdentityFields.join(',')}`,
      'pagination=false',
      'raw_values_stored=false',
    ].join(' • '),
    url: publicUrl || undefined,
    state: 'probable',
    evidence: {
      responseFingerprint: fingerprint(JSON.stringify({ rows: rows.length, fields: commonIdentityFields })),
      rowCount: rows.length,
      identityFields: commonIdentityFields,
    },
  };
  return { state: 'probable', reason: 'dense_identity_collection_without_pagination', findings: [finding] };
}

export async function runApiExcessiveDataAudit({ observations = [] } = {}) {
  const findings = [];
  const outcomes = [];
  for (const observation of (Array.isArray(observations) ? observations : []).slice(0, 128)) {
    const result = analyzeApiExcessiveData(observation);
    findings.push(...result.findings);
    outcomes.push({ url: safeUrl(observation?.url), state: result.state, reason: result.reason });
  }
  return {
    findings,
    outcomes,
    status: outcomes.length ? 'done' : 'skipped',
    reason: outcomes.length ? undefined : 'no_observations',
    metrics: { observations: outcomes.length, probable: findings.length },
  };
}
