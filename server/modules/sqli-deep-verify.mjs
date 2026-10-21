import crypto from 'node:crypto';

import { readResponseSnippet } from './module-runner.mjs';
import { responseLooksLikeSqlError, SQLI_PARAM_RE } from './verify.js';

export const moduleManifest = Object.freeze({
  id: 'verify_sqli_deep',
  name: 'SQLi Deep Differential Verification',
  category: 'validation',
  intrusive: true,
  requiresAuth: false,
  requiresKali: false,
  timeoutMs: 90_000,
  concurrency: 1,
  outputs: ['finding', 'metric'],
});

const LOGIN_PATH_RE = /\/(?:login|signin|sign-in|auth)(?:\/|$)/i;

function abortError(signal) {
  const error = signal?.reason instanceof Error
    ? signal.reason
    : new DOMException('The operation was aborted', 'AbortError');
  if (!error.name || error.name === 'Error') error.name = 'AbortError';
  return error;
}

function stableBody(value) {
  return String(value || '')
    .slice(0, 192_000)
    .replace(/[a-f0-9]{8}-[a-f0-9-]{27,}/gi, '<uuid>')
    .replace(/\b[a-f0-9]{24,}\b/gi, '<hex>')
    .replace(/\b\d{10,13}\b/g, '<epoch>')
    .replace(/\s+/g, ' ')
    .trim();
}

export function sqliResponseFingerprint(response) {
  const normalized = stableBody(response?.text);
  return crypto.createHash('sha256')
    .update(`${Number(response?.status) || 0}\n${normalized}`)
    .digest('hex');
}

function safeEvidenceUrl(url, param) {
  try {
    const parsed = new URL(url);
    parsed.username = '';
    parsed.password = '';
    for (const key of parsed.searchParams.keys()) parsed.searchParams.set(key, '<redacted>');
    if (param) parsed.searchParams.set(param, '<probe>');
    return parsed.toString();
  } catch {
    return null;
  }
}

function collectCandidates(findings, maxEndpoints) {
  const urls = new Set();
  for (const finding of findings || []) {
    const candidate = finding?.type === 'endpoint'
      ? finding.value
      : finding?.type === 'param'
        ? finding.url
        : null;
    if (typeof candidate !== 'string' || !/^https?:\/\//i.test(candidate)) continue;
    try {
      const parsed = new URL(candidate);
      if (parsed.username || parsed.password) continue;
      if (LOGIN_PATH_RE.test(parsed.pathname)) continue;
      if ([...parsed.searchParams.keys()].some((key) => SQLI_PARAM_RE.test(key))) urls.add(parsed.href);
    } catch {
      // Entrada não confiável: ignorar.
    }
    if (urls.size >= maxEndpoints) break;
  }
  return [...urls];
}

function buildBooleanValues(baseValue) {
  const base = String(baseValue || '1');
  if (/^-?\d+(?:\.\d+)?$/.test(base)) {
    return { trueValue: `${base} AND 1=1`, falseValue: `${base} AND 1=2` };
  }
  return {
    trueValue: `${base}' AND '1'='1`,
    falseValue: `${base}' AND '1'='2`,
  };
}

export async function runSqliDeepVerification({
  findings = [],
  auth = null,
  log = null,
  signal = null,
  urlAllowed = () => true,
  fetchImpl = fetch,
  identityCtrl = null,
  maxEndpoints = 6,
  maxParamsPerEndpoint = 2,
  maxRequests = 48,
  timeoutMs = 12_000,
} = {}) {
  const out = [];
  const metrics = {
    endpoints: 0,
    parameters: 0,
    requests: 0,
    unstableBaselines: 0,
    blockedByScope: 0,
    requestErrors: 0,
    timeouts: 0,
    unusableBaselines: 0,
  };
  const candidates = collectCandidates(findings, Math.max(1, maxEndpoints));

  const request = async (url) => {
    if (signal?.aborted) throw abortError(signal);
    if (urlAllowed(url) !== true) {
      metrics.blockedByScope += 1;
      return null;
    }
    if (metrics.requests >= maxRequests) return null;
    metrics.requests += 1;
    const timeoutSignal = AbortSignal.timeout(Math.max(1_000, Number(timeoutMs) || 12_000));
    const requestSignal = signal ? AbortSignal.any([signal, timeoutSignal]) : timeoutSignal;
    const headers = {
      Accept: 'text/html,application/json,*/*;q=0.8',
      ...(auth?.headers && typeof auth.headers === 'object' ? auth.headers : {}),
    };
    if (auth?.cookie) headers.Cookie = String(auth.cookie);
    const init = { method: 'GET', redirect: 'manual', signal: requestSignal, headers };
    try {
      const response = identityCtrl?.enabled
        ? await identityCtrl.fetchVerifyGet(url, init)
        : await fetchImpl(url, init);
      return {
        status: response.status,
        text: await readResponseSnippet(response, 192_000),
        contentType: response.headers?.get?.('content-type') || '',
      };
    } catch (error) {
      if (signal?.aborted) throw abortError(signal);
      metrics.requestErrors += 1;
      if (requestSignal.aborted || error?.name === 'TimeoutError') metrics.timeouts += 1;
      return null;
    }
  };

  for (const candidate of candidates) {
    if (metrics.requests >= maxRequests) break;
    if (urlAllowed(candidate) !== true) {
      metrics.blockedByScope += 1;
      continue;
    }
    const parsed = new URL(candidate);
    metrics.endpoints += 1;
    const params = [...parsed.searchParams.keys()]
      .filter((key) => SQLI_PARAM_RE.test(key))
      .slice(0, Math.max(1, maxParamsPerEndpoint));

    for (const param of params) {
      if (metrics.requests + 7 > maxRequests) break;
      metrics.parameters += 1;
      const baseValue = parsed.searchParams.get(param) || '1';
      const baselineUrl = new URL(parsed.href);
      baselineUrl.searchParams.set(param, baseValue);
      const baselineA = await request(baselineUrl.href);
      if (!baselineA) continue;
      const baselineB = await request(baselineUrl.href);
      if (!baselineB) continue;
      if ([baselineA, baselineB].some((row) => row.status < 200 || row.status >= 300)) {
        metrics.unusableBaselines += 1;
        continue;
      }
      const baselineFingerprint = sqliResponseFingerprint(baselineA);
      if (baselineFingerprint !== sqliResponseFingerprint(baselineB)) {
        metrics.unstableBaselines += 1;
        continue;
      }

      const quoteUrl = new URL(parsed.href);
      quoteUrl.searchParams.set(param, `${baseValue}'`);
      const quoteA = await request(quoteUrl.href);
      if (!quoteA) continue;
      const quoteB = await request(quoteUrl.href);
      if (!quoteB) continue;
      const baselineSqlError = responseLooksLikeSqlError(baselineA.text)
        || responseLooksLikeSqlError(baselineB.text);
      const repeatedSqlError = responseLooksLikeSqlError(quoteA.text)
        && responseLooksLikeSqlError(quoteB.text);

      let classification = null;
      let score = 0;
      let evidenceKind = null;
      let probeStatus = quoteA.status;
      if (!baselineSqlError && repeatedSqlError
        && ![quoteA, quoteB].some((row) => [401, 403, 429].includes(row.status) || (row.status >= 300 && row.status < 400))
        && sqliResponseFingerprint(quoteA) === sqliResponseFingerprint(quoteB)) {
        classification = 'probable';
        score = 68;
        evidenceKind = 'repeated_database_error_transition';
      } else {
        const values = buildBooleanValues(baseValue);
        const trueUrl = new URL(parsed.href);
        const falseUrl = new URL(parsed.href);
        trueUrl.searchParams.set(param, values.trueValue);
        falseUrl.searchParams.set(param, values.falseValue);
        const trueResponse = await request(trueUrl.href);
        const falseA = await request(falseUrl.href);
        const falseB = await request(falseUrl.href);
        if (!trueResponse || !falseA || !falseB) continue;
        const trueMatchesBaseline = sqliResponseFingerprint(trueResponse) === baselineFingerprint;
        const falseFingerprint = sqliResponseFingerprint(falseA);
        const falseStable = falseFingerprint === sqliResponseFingerprint(falseB);
        const falseDiffers = falseFingerprint !== baselineFingerprint;
        const successfulStatuses = [baselineA, trueResponse, falseA, falseB]
          .every((row) => row.status >= 200 && row.status < 300);
        if (trueMatchesBaseline && falseStable && falseDiffers && successfulStatuses) {
          classification = 'probable';
          score = 64;
          evidenceKind = 'stable_boolean_true_false_differential';
          probeStatus = falseA.status;
        }
      }

      if (!classification) continue;
      out.push({
        type: 'sqli',
        prio: 'med',
        score,
        value: `SQLi ${classification}: diferencial repetível em ?${param}=`,
        meta: `verify=sqli_deep • evidence=${evidenceKind} • requests_bounded=yes • no_union=yes • no_time_delay=yes • no_login_bypass=yes`,
        url: safeEvidenceUrl(candidate, param),
        verification: {
          classification,
          evidence: {
            source: 'sqli_deep_differential',
            url: safeEvidenceUrl(candidate, param),
            method: 'GET',
            parameter: param,
            status: probeStatus,
            baselineFingerprint,
            evidenceKind,
            impactVerified: false,
            databaseExecutionVerified: false,
          },
          verifiedAt: new Date().toISOString(),
        },
      });
    }
  }

  log?.(
    `SQLi deep: ${out.length} achado(s), ${metrics.parameters} parâmetro(s), ${metrics.requests} request(s).`,
    out.length ? 'warn' : 'info',
  );
  return { findings: out, metrics, status: metrics.requestErrors || metrics.unstableBaselines || metrics.unusableBaselines || metrics.blockedByScope ? 'partial' : 'done' };
}
