import { createHash } from 'node:crypto';

import { limits } from '../config.js';
import { readResponseSnippet } from './module-runner.mjs';
import { fetchScoped, urlAllowedOrSameOrigin } from './scoped-fetch.mjs';
import { combineAbortSignals, isAbortError, throwIfAborted } from './http-utils.js';

export const moduleManifest = {
  id: 'cloud_debug_env_audit',
  name: 'Cloud Debug / Environment Exposure Audit',
  category: 'surface',
  intrusive: false,
  requiresAuth: false,
  requiresKali: false,
  timeoutMs: 20_000,
  concurrency: 2,
  outputs: ['finding', 'intel', 'metric'],
};

const MAX_BODY = 240_000;
const MAX_DEPTH = 12;
const MAX_KEYS = 2_000;
const SECRET_KEYS = new Set([
  'awsaccesskeyid',
  'awssecretaccesskey',
  'awssessiontoken',
  'awslambdametadatatoken',
  'awsmetadatatoken',
  'awsmetadatasessiontoken',
  'accesstoken',
  'sessiontoken',
  'secretaccesskey',
  'privatekey',
]);
const METADATA_KEYS = new Map([
  ['awsaccountid', 'account_id'],
  ['accountid', 'account_id'],
  ['functionarn', 'function_arn'],
  ['lambdaarn', 'function_arn'],
  ['awsregion', 'region'],
  ['region', 'region'],
  ['bucketname', 'bucket_name'],
  ['s3bucket', 'bucket_name'],
  ['functionurl', 'function_url'],
  ['awsloggroupname', 'log_group'],
  ['awslogstreamname', 'log_stream'],
]);

function canonicalKey(value) {
  return String(value || '').toLowerCase().replace(/[^a-z0-9]/g, '');
}

function secretFingerprint(value) {
  return createHash('sha256').update(String(value)).digest('hex');
}

function safeMetadataValue(kind, value) {
  const text = String(value ?? '').trim().slice(0, 500);
  if (!text) return '';
  if (kind === 'account_id' && !/^\d{12}$/.test(text)) return '';
  if (kind === 'function_arn' && !/^arn:aws(?:-[a-z]+)?:lambda:/i.test(text)) return '';
  if (kind === 'function_url') {
    try {
      const parsed = new URL(text);
      if (!/^https?:$/.test(parsed.protocol)) return '';
      parsed.username = '';
      parsed.password = '';
      parsed.search = '';
      parsed.hash = '';
      return parsed.href;
    } catch {
      return '';
    }
  }
  return text.replace(/[\r\n\0]/g, ' ');
}

function walkCloudObject(value, state, path = '$', depth = 0) {
  if (depth > MAX_DEPTH || state.keysVisited >= MAX_KEYS || value == null) return;
  if (Array.isArray(value)) {
    for (let i = 0; i < Math.min(value.length, 200); i += 1) {
      walkCloudObject(value[i], state, `${path}[${i}]`, depth + 1);
    }
    return;
  }
  if (typeof value !== 'object') return;

  for (const [key, child] of Object.entries(value)) {
    state.keysVisited += 1;
    if (state.keysVisited > MAX_KEYS) return;
    const canonical = canonicalKey(key);
    const childPath = `${path}.${String(key).replace(/[^a-zA-Z0-9_-]/g, '_')}`;
    if (canonical === 'environmentvariables' || canonical === 'environment') {
      state.hasEnvironmentContainer = true;
    }
    if (SECRET_KEYS.has(canonical) && child != null && String(child).trim()) {
      const text = String(child);
      state.secretRefs.push({
        kind: canonical,
        path: childPath,
        fingerprint: `sha256:${secretFingerprint(text)}`,
        length: text.length,
      });
      continue;
    }
    const metadataKind = METADATA_KEYS.get(canonical);
    if (metadataKind && child != null && typeof child !== 'object') {
      const safe = safeMetadataValue(metadataKind, child);
      if (safe) state.metadata[metadataKind] = safe;
    }
    walkCloudObject(child, state, childPath, depth + 1);
  }
}

function contentTypeOf(headers) {
  if (!headers) return '';
  if (typeof headers.get === 'function') return String(headers.get('content-type') || '');
  const entry = Object.entries(headers).find(([key]) => key.toLowerCase() === 'content-type');
  return String(entry?.[1] || '');
}

function parseJsonBody(body) {
  const text = String(body ?? '').slice(0, MAX_BODY).trim();
  if (!text || !/^[{[]/.test(text)) return null;
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function isDocumentationURL(url) {
  try {
    return /(?:^|\/)(?:docs?|swagger|openapi|examples?|samples?)(?:\/|$)/i.test(new URL(url).pathname);
  } catch {
    return false;
  }
}

function isDebugLikeURL(url) {
  try {
    return /(?:^|\/)(?:debug|config|env|environment|runtime|internal)(?:\/|$)/i.test(new URL(url).pathname);
  } catch {
    return false;
  }
}

export function analyzeCloudDebugObservation({
  url = '', status = 0, body = '', headers = null,
} = {}) {
  if (Number(status) < 200 || Number(status) >= 300) return null;
  const parsed = parseJsonBody(body);
  if (!parsed) return null;

  const state = {
    keysVisited: 0,
    hasEnvironmentContainer: false,
    metadata: {},
    secretRefs: [],
  };
  walkCloudObject(parsed, state);
  const metadataKinds = Object.keys(state.metadata);
  const indicators = metadataKinds.length + (state.hasEnvironmentContainer ? 1 : 0);
  if (!indicators && !state.secretRefs.length) return null;

  const documentation = isDocumentationURL(url);
  const debugLike = isDebugLikeURL(url);
  const confirmed = !documentation && (
    (debugLike && indicators >= 2)
    || (state.hasEnvironmentContainer && state.secretRefs.length > 0)
    || (metadataKinds.includes('function_arn') && metadataKinds.includes('account_id'))
  );
  const classification = confirmed ? 'confirmed' : 'candidate';
  const prio = confirmed && state.secretRefs.length ? 'high' : confirmed ? 'med' : 'info';
  const score = confirmed && state.secretRefs.length ? 86 : confirmed ? 64 : 25;
  const contentType = contentTypeOf(headers).toLowerCase();

  return {
    classification,
    prio,
    score,
    url,
    metadata: state.metadata,
    secretRefs: state.secretRefs,
    metrics: {
      keysVisited: state.keysVisited,
      metadataFields: metadataKinds.length,
      secrets: state.secretRefs.length,
      contentTypeMismatch: !contentType.includes('json'),
    },
    finding: {
      type: 'cloud_debug_env_exposure',
      prio,
      score,
      value: confirmed
        ? 'Configuração de runtime cloud exposta por endpoint de debug'
        : 'Possível configuração cloud presente em resposta JSON',
      meta: [
        `source=cloud_debug_env_audit`,
        `classification=${classification}`,
        `metadata=${metadataKinds.join(',') || 'none'}`,
        `secret_refs=${state.secretRefs.length}`,
        `content_type_mismatch=${!contentType.includes('json')}`,
        'raw_secrets_stored=false',
      ].join(' • '),
      url,
      cloudMetadata: state.metadata,
      secretRefs: state.secretRefs,
    },
  };
}

function normalizedBody(body) {
  return String(body || '').slice(0, 64_000).replace(/\s+/g, ' ').trim();
}

async function fetchObservation(url, { fetchImpl, urlAllowed, signal }) {
  const res = await fetchScoped(url, {
    fetchImpl,
    method: 'GET',
    urlAllowed: urlAllowedOrSameOrigin(url, urlAllowed),
    signal: combineAbortSignals(signal, Math.min(9_000, limits.probeTimeoutMs || 9_000)),
    headers: { Accept: 'application/json,text/plain,*/*;q=0.5' },
  });
  return {
    url: res.url || url,
    status: res.status,
    headers: res.headers,
    body: await readResponseSnippet(res, MAX_BODY),
  };
}

export async function runCloudDebugEnvAudit({
  observations = [],
  origins = [],
  probeOrigins = false,
  fetchImpl = fetch,
  urlAllowed = null,
  signal = null,
  baselinePathFactory = () => `/ghostrecon-cloud-baseline-${Date.now().toString(36)}-not-found`,
} = {}) {
  throwIfAborted(signal);
  const inputs = [...(Array.isArray(observations) ? observations : [])];
  const passiveObservationCount = inputs.length;
  const outcomes = [];
  let requestsAttempted = 0;

  if (probeOrigins) {
    for (const origin of [...new Set(origins.map(String))].slice(0, 8)) {
      try {
        const baselineURL = new URL(baselinePathFactory(origin), `${origin.replace(/\/$/, '')}/`).href;
        const debugURL = new URL('/debug', `${origin.replace(/\/$/, '')}/`).href;
        requestsAttempted += 2;
        const baseline = await fetchObservation(baselineURL, { fetchImpl, urlAllowed, signal });
        const debug = await fetchObservation(debugURL, { fetchImpl, urlAllowed, signal });
        if (baseline.status === debug.status && normalizedBody(baseline.body) === normalizedBody(debug.body)) {
          outcomes.push({ origin, state: 'skipped', reason: 'soft_404_baseline_match' });
        } else {
          inputs.push(debug);
          outcomes.push({ origin, state: 'observed', status: debug.status });
        }
      } catch (error) {
        if (isAbortError(error, signal)) throw error;
        outcomes.push({ origin, state: 'error', reason: String(error?.message || error).slice(0, 160) });
      }
    }
  }

  const findings = [];
  const analyses = [];
  const seen = new Set();
  for (const observation of inputs.slice(0, 128)) {
    const analysis = analyzeCloudDebugObservation(observation);
    if (!analysis) continue;
    const key = `${analysis.url}|${analysis.classification}`;
    if (seen.has(key)) continue;
    seen.add(key);
    analyses.push(analysis);
    findings.push(analysis.finding);
  }

  return {
    findings,
    analyses,
    outcomes,
    status: passiveObservationCount === 0 && requestsAttempted === 0
      ? 'skipped'
      : outcomes.some((row) => row.state === 'error') ? 'partial' : 'done',
    reason: passiveObservationCount === 0 && requestsAttempted === 0 ? 'no_observations_or_origins' : undefined,
    metrics: {
      observations: inputs.length,
      passiveObservations: passiveObservationCount,
      requestsAttempted,
      findings: findings.length,
      confirmed: analyses.filter((row) => row.classification === 'confirmed').length,
      secretRefs: analyses.reduce((sum, row) => sum + row.secretRefs.length, 0),
    },
  };
}
