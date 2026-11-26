import { readResponseSnippet } from './module-runner.mjs';
import { isSqliParameterCandidate, responseLooksLikeSqlError } from './verify.js';
import { sqliResponseFingerprint } from './sqli-deep-verify.mjs';

export const moduleManifest = Object.freeze({
  id: 'sqli_targeted_verify',
  name: 'SQLi Targeted Verification Coordinator',
  category: 'validation',
  intrusive: true,
  requiresAuth: false,
  requiresKali: false,
  timeoutMs: 90_000,
  concurrency: 1,
  outputs: ['finding', 'metric', 'outcome'],
  risk: 'active',
  sideEffects: 'read_only_requests_or_explicit_post_replay',
});

function exactOrigin(expected, candidate) {
  try { return new URL(expected).origin === new URL(candidate).origin; } catch { return false; }
}

function formKeys(body) {
  try { return [...new URLSearchParams(String(body || '')).keys()]; } catch { return []; }
}

function jsonKeys(body) {
  try {
    const value = typeof body === 'string' ? JSON.parse(body) : body;
    return value && typeof value === 'object' && !Array.isArray(value) ? Object.keys(value) : [];
  } catch { return []; }
}

export function selectSqliInsertionPoint(requestSpec, parameter) {
  const url = String(requestSpec?.absoluteUrl || requestSpec?.url || '');
  const name = String(parameter || '').trim();
  if (!url || !isSqliParameterCandidate(name)) return null;
  let parsed;
  try { parsed = new URL(url); } catch { return null; }
  if (parsed.searchParams.has(name)) return { location: 'query', parameter: name, url: parsed.href };
  const contentType = String(requestSpec?.contentType || requestSpec?.headers?.['content-type'] || requestSpec?.headers?.['Content-Type'] || '').toLowerCase();
  const keys = contentType.includes('json')
    ? jsonKeys(requestSpec?.body)
    : contentType.includes('x-www-form-urlencoded')
      ? formKeys(requestSpec?.body)
      : [];
  if (keys.includes(name)) return { location: 'body', parameter: name, url: parsed.href, contentType };
  return null;
}

function booleanValues(baseValue) {
  const base = String(baseValue ?? '1');
  if (/^-?\d+(?:\.\d+)?$/.test(base)) {
    return { trueValue: `${base} AND 1=1`, falseValue: `${base} AND 1=2` };
  }
  return { trueValue: `${base}' AND '1'='1`, falseValue: `${base}' AND '1'='2` };
}

function queryMutation(requestSpec, parameter, value) {
  try {
    const url = new URL(requestSpec?.absoluteUrl || requestSpec?.url || '');
    if (!url.searchParams.has(parameter)) return null;
    const baseValue = url.searchParams.get(parameter);
    url.searchParams.set(parameter, String(value));
    return {
      url: url.href,
      body: requestSpec?.body,
      baseValue,
      contentType: requestSpec?.contentType,
    };
  } catch { return null; }
}

function bodyMutation(requestSpec, parameter, value) {
  const contentType = String(requestSpec?.contentType
    || requestSpec?.headers?.['content-type']
    || requestSpec?.headers?.['Content-Type']
    || '').toLowerCase();
  if (contentType.includes('json')) {
    try {
      const parsed = typeof requestSpec?.body === 'string'
        ? JSON.parse(requestSpec.body)
        : requestSpec?.body;
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)
        || !Object.hasOwn(parsed, parameter)) return null;
      return {
        body: JSON.stringify({ ...parsed, [parameter]: value }),
        baseValue: parsed[parameter],
        contentType: 'application/json',
      };
    } catch { return null; }
  }
  if (contentType.includes('x-www-form-urlencoded')) {
    const parsed = new URLSearchParams(String(requestSpec?.body || ''));
    if (!parsed.has(parameter)) return null;
    const baseValue = parsed.get(parameter);
    parsed.set(parameter, String(value));
    return { body: parsed.toString(), baseValue, contentType: 'application/x-www-form-urlencoded' };
  }
  return null;
}

function publicRequestUrl(value) {
  try {
    const url = new URL(value);
    url.username = '';
    url.password = '';
    for (const key of url.searchParams.keys()) url.searchParams.set(key, '<redacted>');
    return url.href;
  } catch { return undefined; }
}

async function defaultRequestSpecScanner({
  requestSpec,
  insertionPoint,
  budget,
  fetchImpl,
  urlAllowed,
  signal,
  mutationBuilder,
  defaultMethod,
}) {
  const method = String(requestSpec?.method || defaultMethod).toUpperCase();
  const initial = mutationBuilder(requestSpec, insertionPoint.parameter, '');
  if (!initial) return { status: 'skipped', reason: 'insertion_point_unavailable', findings: [], metrics: { requests: 0 } };
  const baseValue = initial.baseValue == null ? '' : String(initial.baseValue);
  const headers = { Accept: 'text/html,application/json,*/*;q=0.8', ...(requestSpec?.headers || {}) };
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === 'content-length') delete headers[key];
  }
  if (initial.contentType && !Object.keys(headers).some((key) => key.toLowerCase() === 'content-type')) {
    headers['Content-Type'] = initial.contentType;
  }
  if (requestSpec?.auth?.headers && typeof requestSpec.auth.headers === 'object') {
    Object.assign(headers, requestSpec.auth.headers);
  }
  if (requestSpec?.auth?.cookie) headers.Cookie = String(requestSpec.auth.cookie);
  let requests = 0;
  let requestErrors = 0;
  const request = async (value) => {
    if (signal?.aborted) throw signal.reason || new DOMException('cancelled', 'AbortError');
    if (requests >= budget) return null;
    const mutation = mutationBuilder(requestSpec, insertionPoint.parameter, value);
    if (!mutation) return null;
    const requestUrl = mutation.url || insertionPoint.url;
    if (urlAllowed(requestUrl) !== true || !exactOrigin(insertionPoint.url, requestUrl)) return null;
    requests += 1;
    const timeoutSignal = AbortSignal.timeout(12_000);
    const requestSignal = signal ? AbortSignal.any([signal, timeoutSignal]) : timeoutSignal;
    try {
      const response = await fetchImpl(requestUrl, {
        method,
        headers,
        ...(!['GET', 'HEAD'].includes(method) && mutation.body != null ? { body: mutation.body } : {}),
        redirect: 'manual',
        signal: requestSignal,
      });
      return { status: response.status, text: await readResponseSnippet(response, 192_000) };
    } catch (error) {
      if (signal?.aborted) throw signal.reason || error;
      requestErrors += 1;
      return null;
    }
  };

  const baselineA = await request(baseValue);
  const baselineB = await request(baseValue);
  if (!baselineA || !baselineB
    || [baselineA, baselineB].some((row) => row.status < 200 || row.status >= 300)
    || sqliResponseFingerprint(baselineA) !== sqliResponseFingerprint(baselineB)) {
    return { status: 'partial', findings: [], metrics: { requests, requestErrors } };
  }
  const baselineFingerprint = sqliResponseFingerprint(baselineA);
  const quoteA = await request(`${baseValue}'`);
  const quoteB = await request(`${baseValue}'`);
  let evidenceKind = null;
  let probeStatus = quoteA?.status || 0;
  if (quoteA && quoteB
    && !responseLooksLikeSqlError(baselineA.text)
    && !responseLooksLikeSqlError(baselineB.text)
    && responseLooksLikeSqlError(quoteA.text)
    && responseLooksLikeSqlError(quoteB.text)
    && sqliResponseFingerprint(quoteA) === sqliResponseFingerprint(quoteB)
    && ![quoteA, quoteB].some((row) => [401, 403, 429].includes(row.status))) {
    evidenceKind = 'repeated_database_error_transition';
  } else {
    const values = booleanValues(baseValue);
    const trueResponse = await request(values.trueValue);
    const falseA = await request(values.falseValue);
    const falseB = await request(values.falseValue);
    if (trueResponse && falseA && falseB
      && [trueResponse, falseA, falseB].every((row) => row.status >= 200 && row.status < 300)
      && sqliResponseFingerprint(trueResponse) === baselineFingerprint
      && sqliResponseFingerprint(falseA) === sqliResponseFingerprint(falseB)
      && sqliResponseFingerprint(falseA) !== baselineFingerprint) {
      evidenceKind = 'stable_boolean_true_false_differential';
      probeStatus = falseA.status;
    }
  }
  const findings = evidenceKind ? [{
    type: 'sqli',
    prio: 'med',
    score: evidenceKind.startsWith('repeated_database') ? 68 : 64,
    value: `SQLi probable: diferencial repetível no campo ${insertionPoint.parameter}`,
    meta: `verify=sqli_targeted_${insertionPoint.location} • evidence=${evidenceKind} • requests_bounded=yes • no_union=yes • no_time_delay=yes`,
    url: publicRequestUrl(insertionPoint.url),
    verification: {
      classification: 'probable',
      evidence: {
        source: `sqli_targeted_${insertionPoint.location}_differential`,
        method,
        parameter: insertionPoint.parameter,
        status: probeStatus,
        baselineFingerprint,
        evidenceKind,
      },
      verifiedAt: new Date().toISOString(),
    },
  }] : [];
  return {
    status: requestErrors ? 'partial' : 'done',
    findings,
    metrics: { requests, requestErrors },
  };
}

async function defaultQueryScanner(ctx) {
  return defaultRequestSpecScanner({
    ...ctx,
    mutationBuilder: queryMutation,
    defaultMethod: 'GET',
  });
}

async function defaultBodyScanner(ctx) {
  const method = String(ctx.requestSpec?.method || 'POST').toUpperCase();
  if (method !== 'POST') {
    return { status: 'skipped', reason: 'unsupported_body_method', findings: [], metrics: { requests: 0 } };
  }
  return defaultRequestSpecScanner({
    ...ctx,
    mutationBuilder: bodyMutation,
    defaultMethod: 'POST',
  });
}

export async function runSqliTargetedVerify({
  requestSpec,
  parameter,
  allowActive = false,
  requestBudget = 16,
  urlAllowed,
  fetchImpl = fetch,
  queryScanner = defaultQueryScanner,
  bodyScanner = defaultBodyScanner,
  allowNonGetReplay = false,
  signal = null,
} = {}) {
  const skipped = (reason) => ({ status: 'skipped', reason, findings: [], outcomes: [], metrics: { requestsAttempted: 0 } });
  if (allowActive !== true) return skipped('active_not_authorized');
  if (typeof urlAllowed !== 'function') return skipped('scope_guard_required');
  const requestMethod = String(requestSpec?.method || 'GET').toUpperCase();
  if (!['GET', 'HEAD', 'POST'].includes(requestMethod)) return skipped('unsafe_request_method_rejected');
  if (requestMethod === 'POST' && allowNonGetReplay !== true) {
    return skipped('post_replay_requires_mutating_capability');
  }
  const insertionPoint = selectSqliInsertionPoint(requestSpec, parameter);
  if (!insertionPoint) return skipped('parameter_not_observed_or_ineligible');
  const expectedOrigin = String(requestSpec?.origin || insertionPoint.url);
  if (!exactOrigin(expectedOrigin, insertionPoint.url) || urlAllowed(insertionPoint.url) !== true) return skipped('out_of_exact_origin_scope');
  const requestedBudget = Math.floor(Number(requestBudget));
  if (!Number.isFinite(requestedBudget) || requestedBudget < 7) {
    return skipped('request_budget_below_safe_minimum');
  }
  const budget = Math.min(48, requestedBudget);
  if (signal?.aborted) throw signal.reason || new DOMException('cancelled', 'AbortError');

  const scanner = insertionPoint.location === 'query' ? queryScanner : bodyScanner;
  if (typeof scanner !== 'function') return skipped(`${insertionPoint.location}_scanner_unavailable`);
  const result = await scanner({
    requestSpec: {
      ...requestSpec,
      method: requestMethod,
    },
    insertionPoint,
    budget,
    fetchImpl,
    urlAllowed,
    signal,
  });
  const findings = Array.isArray(result?.findings) ? result.findings : [];
  const requestsAttempted = Number(result?.metrics?.requests ?? result?.metrics?.requestsAttempted ?? 0);
  if (result?.status === 'skipped') return skipped(result.reason || 'scanner_skipped');
  return {
    status: result?.status === 'partial' ? 'partial' : 'done',
    reason: findings.length ? 'targeted_scanner_signal' : 'targeted_scanner_no_finding',
    findings,
    outcomes: [{
      state: findings.length ? 'probable' : 'executed_no_finding',
      location: insertionPoint.location,
      parameter: insertionPoint.parameter,
    }],
    metrics: {
      requestsAttempted,
      requestBudget: budget,
      parameters: 1,
      location: insertionPoint.location,
    },
  };
}
