import { createHash } from 'node:crypto';

export const moduleManifest = {
  id: 'cloud_object_proxy_authz',
  name: 'Cloud Object Proxy Authorization Audit',
  category: 'validation',
  intrusive: true,
  requiresAuth: true,
  requiresKali: false,
  timeoutMs: 20_000,
  concurrency: 1,
  outputs: ['finding', 'metric'],
  risk: 'active',
  sideEffects: 'read_only_requests',
};

function fingerprint(value) {
  return createHash('sha256').update(String(value ?? '')).digest('hex');
}

function normalizeObservation(value = {}) {
  const status = Number(value.status || 0);
  const text = String(value.text || '').slice(0, 8_000);
  const errorCode = String(value.errorCode || '');
  const rawEvidence = value.body ?? value.text;
  const evidenceText = rawEvidence == null ? '' : String(rawEvidence).trim();
  const generic = /^(?:ok|success|true|false|null|\{\s*\}|\[\s*\]|\{\s*"?(?:ok|success|status)"?\s*:\s*(?:true|"?ok"?)\s*\})$/i.test(evidenceText);
  const attestedFingerprint = value.bodyFingerprintAttested === true
    && Number(value.evidenceBytes) >= 8
    && /^[a-f0-9]{64}$/i.test(String(value.bodyFingerprint || ''));
  const evidencePresent = (evidenceText.length >= 8 && !generic) || attestedFingerprint;
  return {
    status,
    success: status >= 200 && status < 300,
    denied: [401, 403].includes(status),
    missing: status === 404 || /NoSuchKey|not[ _-]?found/i.test(`${errorCode} ${text}`),
    evidencePresent,
    bodyFingerprint: evidencePresent
      ? attestedFingerprint
        ? String(value.bodyFingerprint).toLowerCase()
        : fingerprint(evidenceText)
      : '',
  };
}

export function analyzeCloudObjectProxyAuthz({
  owner,
  crossPersona,
  missingControl,
  urlShapedControl,
} = {}) {
  const own = normalizeObservation(owner);
  const cross = normalizeObservation(crossPersona);
  const missing = normalizeObservation(missingControl);
  const urlControl = normalizeObservation(urlShapedControl);
  const ssrfNegative = urlControl.missing && !urlControl.success;

  if (!own.success || !own.evidencePresent || !own.bodyFingerprint) {
    return { state: 'executed_no_finding', reason: 'owner_baseline_not_available', findings: [], ssrfControl: ssrfNegative ? 'negative' : 'inconclusive' };
  }
  if (!missing.missing) {
    return { state: 'executed_no_finding', reason: 'missing_key_control_inconclusive', findings: [], ssrfControl: ssrfNegative ? 'negative' : 'inconclusive' };
  }
  if (!cross.success || !cross.evidencePresent || cross.bodyFingerprint !== own.bodyFingerprint) {
    return { state: 'executed_no_finding', reason: cross.denied ? 'cross_access_denied' : 'cross_object_not_equal', findings: [], ssrfControl: ssrfNegative ? 'negative' : 'inconclusive' };
  }

  return {
    state: 'confirmed',
    reason: 'cross_persona_received_owner_object',
    ssrfControl: ssrfNegative ? 'negative' : 'inconclusive',
    findings: [{
      type: 'cloud_object_proxy_bola',
      prio: 'high',
      score: 91,
      value: 'Proxy de objeto cloud retorna o objeto do proprietário para outra persona',
      meta: [
        'source=cloud_object_proxy_authz',
        'classification=confirmed',
        'control=missing_key',
        `ssrf_control=${ssrfNegative ? 'negative_nosuchkey' : 'inconclusive'}`,
        'raw_object_key_stored=false',
      ].join(' • '),
      state: 'confirmed',
      evidence: {
        objectFingerprint: own.bodyFingerprint,
        ownerStatus: own.status,
        crossStatus: cross.status,
        missingControlStatus: missing.status,
        urlShapedControlStatus: urlControl.status,
      },
    }],
  };
}

function exactOrigin(base, candidate) {
  try { return new URL(base).origin === new URL(candidate).origin; } catch { return false; }
}

function publicOrigin(value) {
  try { return `${new URL(value).origin}/`; } catch { return undefined; }
}

function finiteBudget(value) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return 0;
  return Math.min(64, Math.max(0, Math.floor(parsed)));
}

export async function runCloudObjectProxyAuthz({
  cases = [],
  transport,
  allowActive = false,
  urlAllowed,
  requestBudget = 16,
  signal,
} = {}) {
  if (allowActive !== true) return { status: 'skipped', reason: 'active_not_authorized', findings: [], outcomes: [], metrics: { requestsAttempted: 0 } };
  if (typeof transport !== 'function') throw new Error('cloud_object_proxy_authz: transport obrigatorio');
  if (typeof urlAllowed !== 'function') {
    return { status: 'skipped', reason: 'scope_guard_required', findings: [], outcomes: [], metrics: { requestsAttempted: 0 } };
  }
  const boundedBudget = finiteBudget(requestBudget);
  const maxCases = Math.floor(boundedBudget / 4);
  const findings = [];
  const outcomes = [];
  let requestsAttempted = 0;

  if (!Array.isArray(cases) || cases.length === 0) {
    return {
      status: 'skipped', reason: 'no_cases', findings, outcomes,
      metrics: { requestsAttempted, casesExecuted: 0, requestBudget: boundedBudget },
    };
  }

  for (const config of (Array.isArray(cases) ? cases : []).slice(0, maxCases)) {
    if (signal?.aborted) throw signal.reason || new DOMException('cancelled', 'AbortError');
    const urls = [config.ownerUrl, config.crossUrl, config.missingControlUrl, config.urlShapedControlUrl];
    const base = config.endpointOrigin || config.ownerUrl;
    const ownerAuthRef = String(config.ownerAuthRef || '');
    const crossAuthRef = String(config.crossAuthRef || '');
    if (!ownerAuthRef || !crossAuthRef || ownerAuthRef === crossAuthRef) {
      outcomes.push({ id: config.id || '', state: 'skipped_ineligible', reason: 'distinct_personas_required' });
      continue;
    }
    if (urls.some((url) => !url || !exactOrigin(base, url) || urlAllowed(url) !== true)) {
      outcomes.push({ id: config.id || '', state: 'skipped_ineligible', reason: 'missing_or_out_of_exact_origin_scope' });
      continue;
    }
    const call = async (url, authRef) => {
      if (signal?.aborted) throw signal.reason || new DOMException('cancelled', 'AbortError');
      requestsAttempted += 1;
      return transport({ url, method: 'GET', authRef, signal });
    };
    const owner = await call(config.ownerUrl, config.ownerAuthRef);
    const crossPersona = await call(config.crossUrl, config.crossAuthRef);
    const missingControl = await call(config.missingControlUrl, config.crossAuthRef);
    const urlShapedControl = await call(config.urlShapedControlUrl, config.crossAuthRef);
    const result = analyzeCloudObjectProxyAuthz({ owner, crossPersona, missingControl, urlShapedControl });
    findings.push(...result.findings.map((finding) => ({ ...finding, url: publicOrigin(base) })));
    outcomes.push({ id: config.id || '', state: result.state, reason: result.reason, ssrfControl: result.ssrfControl });
  }
  return {
    status: requestsAttempted > 0 ? 'done' : 'skipped',
    reason: requestsAttempted > 0 ? undefined : 'no_eligible_cases',
    findings,
    outcomes,
    metrics: { requestsAttempted, casesExecuted: outcomes.length, requestBudget: boundedBudget },
  };
}
