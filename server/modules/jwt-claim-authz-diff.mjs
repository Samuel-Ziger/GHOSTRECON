import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { decodeJwt } from './jwt-lab.mjs';
import { fetchScoped, urlAllowedOrSameOrigin } from './scoped-fetch.mjs';
import { readResponseSnippet } from './module-runner.mjs';

export const moduleManifest = {
  id: 'jwt_claim_authz_diff',
  name: 'JWT Claim Authorization Differential',
  category: 'authz',
  intrusive: true,
  requiresAuth: true,
  requiresKali: false,
  timeoutMs: 20_000,
  concurrency: 1,
  outputs: ['finding', 'outcome'],
  risk: 'active',
  sideEffects: 'read_only_requests',
};

const IDENTITY_CLAIMS = new Set(['sub', 'user_id', 'userid', 'account_id', 'accountid', 'owner_id']);
const PRIVILEGE_CLAIMS = new Set(['role', 'roles', 'scope', 'permissions', 'isadmin', 'admin']);
const DENIED_STATUSES = new Set([401, 403]);

function b64url(value) {
  return Buffer.from(value).toString('base64url');
}

function fingerprint(value) {
  return createHash('sha256').update(value).digest('hex');
}

function safeEqualString(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  return left.length === right.length && timingSafeEqual(left, right);
}

function hmacAlgorithm(alg) {
  return ({ HS256: 'sha256', HS384: 'sha384', HS512: 'sha512' })[String(alg || '').toUpperCase()] || null;
}

export function signJwtClaims(decoded, claims, secret) {
  const alg = String(decoded?.header?.alg || '').toUpperCase();
  const hash = hmacAlgorithm(alg);
  if (!hash) throw new Error(`unsupported_jwt_alg:${alg || 'missing'}`);
  const header = b64url(JSON.stringify(decoded.header));
  const payload = b64url(JSON.stringify(claims));
  const signature = createHmac(hash, secret).update(`${header}.${payload}`).digest('base64url');
  return `${header}.${payload}.${signature}`;
}

function corruptSignature(token) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3 || !parts[2]) throw new Error('invalid_signed_jwt');
  const replacement = parts[2].startsWith('A') ? 'B' : 'A';
  parts[2] = `${replacement}${parts[2].slice(1)}`;
  return parts.join('.');
}

function normalizeObservation(value = {}) {
  const status = Number(value.status || 0);
  return {
    status,
    denied: value.denied === true || DENIED_STATUSES.has(status),
    identity: value.identity == null ? null : String(value.identity),
    effect: value.effect === true,
    bodyFingerprint: value.bodyFingerprint || '',
  };
}

export function analyzeJwtClaimDiff({ original, invalidControl, mutations = [] } = {}) {
  const base = normalizeObservation(original);
  const invalid = normalizeObservation(invalidControl);
  const findings = [];
  const outcomes = [];

  if (!invalid.denied) {
    return {
      state: 'executed_no_finding',
      reason: 'invalid_signature_not_rejected',
      findings,
      outcomes,
    };
  }

  for (const mutation of mutations) {
    const claim = String(mutation.claim || '');
    const kind = mutation.kind || (IDENTITY_CLAIMS.has(claim.toLowerCase()) ? 'identity' : 'privilege');
    const observed = normalizeObservation(mutation.observation);
    let confirmed = false;
    let findingType = '';
    let reason = 'semantic_control_not_satisfied';

    if (kind === 'identity' && !base.denied && !observed.denied) {
      const expected = mutation.expectedIdentity == null ? String(mutation.value) : String(mutation.expectedIdentity);
      confirmed = base.identity != null
        && observed.identity != null
        && !safeEqualString(base.identity, observed.identity)
        && safeEqualString(observed.identity, expected);
      findingType = 'jwt_claim_bola';
      reason = confirmed ? 'identity_changed_with_valid_resign' : reason;
    } else if (kind === 'privilege') {
      confirmed = (base.denied || base.effect === false) && !observed.denied && observed.effect === true;
      findingType = 'jwt_claim_bfla';
      reason = confirmed ? 'restricted_effect_enabled_by_single_claim' : reason;
    }

    outcomes.push({ claim, kind, state: confirmed ? 'confirmed' : 'executed_no_finding', reason });
    if (!confirmed) continue;
    findings.push({
      type: findingType,
      prio: 'high',
      score: kind === 'privilege' ? 94 : 90,
      value: kind === 'privilege'
        ? `Autorizacao alterada pela claim JWT ${claim}`
        : `Identidade/objeto alterado pela claim JWT ${claim}`,
      meta: `source=jwt_claim_authz_diff - claim=${claim} - control=invalid_signature_rejected - reason=${reason}`,
      owasp: 'A01:2021',
      mitre: 'T1098',
      state: 'confirmed',
      confidence: 'high',
      evidence: {
        claim,
        kind,
        originalStatus: base.status,
        mutationStatus: observed.status,
        invalidControlStatus: invalid.status,
      },
    });
  }

  return {
    state: findings.length ? 'confirmed' : 'executed_no_finding',
    reason: findings.length ? 'semantic_diff_confirmed' : 'no_semantic_diff',
    findings,
    outcomes,
  };
}

async function defaultTransport({
  url,
  token,
  placement,
  cookieName,
  method,
  headers,
  body,
  fetchImpl,
  urlAllowed,
  signal,
}) {
  const requestHeaders = { Accept: 'application/json,*/*;q=0.8', ...headers };
  if (placement === 'cookie') requestHeaders.Cookie = `${cookieName}=${token}`;
  else requestHeaders.Authorization = `Bearer ${token}`;
  const res = await fetchScoped(url, {
    fetchImpl,
    urlAllowed: urlAllowedOrSameOrigin(url, urlAllowed),
    method,
    headers: requestHeaders,
    body,
    signal,
  });
  const text = await readResponseSnippet(res, 512_000);
  let json = null;
  try { json = JSON.parse(text); } catch { /* explicit non-JSON */ }
  return {
    status: res.status,
    json,
    text,
    bodyFingerprint: fingerprint(text),
  };
}

function extractPath(value, path) {
  if (typeof path === 'function') return path(value);
  if (!path) return null;
  return String(path).split('.').filter(Boolean).reduce((acc, key) => acc?.[key], value);
}

function observationFromResponse(response, testCase) {
  const identity = extractPath(response?.json, testCase.identityPath);
  const effectValue = extractPath(response?.json, testCase.effectPath);
  return {
    status: response?.status,
    denied: DENIED_STATUSES.has(Number(response?.status || 0)),
    identity,
    effect: testCase.effectPath ? effectValue === (testCase.effectValue ?? true) : Boolean(response?.effect),
    bodyFingerprint: response?.bodyFingerprint || fingerprint(response?.text || ''),
  };
}

export async function runJwtClaimAuthzDiff({
  url,
  token,
  secretRef,
  resolveSecret,
  cases = [],
  allowActive = false,
  placement = 'authorization',
  cookieName = 'token',
  method = 'GET',
  headers = {},
  body,
  fetchImpl = fetch,
  transport = defaultTransport,
  urlAllowed = null,
  timeoutMs = moduleManifest.timeoutMs,
  signal,
} = {}) {
  if (allowActive !== true) return { state: 'skipped_ineligible', reason: 'active_not_authorized', findings: [], outcomes: [] };
  if (!url || !token || !secretRef || typeof resolveSecret !== 'function') {
    return { state: 'skipped_ineligible', reason: 'missing_token_or_secret_ref', findings: [], outcomes: [] };
  }
  const allowed = urlAllowedOrSameOrigin(url, urlAllowed);
  if (allowed(url) !== true) return { state: 'skipped_ineligible', reason: 'out_of_scope', findings: [], outcomes: [] };
  const decoded = decodeJwt(token);
  if (!decoded || !hmacAlgorithm(decoded.header?.alg)) {
    return { state: 'skipped_ineligible', reason: 'unsupported_or_invalid_jwt', findings: [], outcomes: [] };
  }
  const acceptedCases = cases.filter((item) => {
    const claim = String(item?.claim || '').toLowerCase();
    return IDENTITY_CLAIMS.has(claim) || PRIVILEGE_CLAIMS.has(claim);
  }).slice(0, 12);
  if (!acceptedCases.length) return { state: 'skipped_ineligible', reason: 'no_supported_claim_cases', findings: [], outcomes: [] };
  const methods = acceptedCases.map((item) => String(item?.method || method || 'GET').toUpperCase());
  if (methods.some((candidate) => !['GET', 'HEAD'].includes(candidate))) {
    return { state: 'skipped_ineligible', reason: 'non_read_only_method_rejected', findings: [], outcomes: [] };
  }

  const secret = await resolveSecret(secretRef);
  if (!secret || !Buffer.from(secret).length) throw new Error('secret_ref_unresolved');
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new Error('jwt_claim_authz_diff_timeout')), Math.max(100, timeoutMs));
  const forwardAbort = () => controller.abort(signal.reason || new Error('cancelled'));
  signal?.addEventListener('abort', forwardAbort, { once: true });
  const request = (requestToken, testCase = {}) => transport({
    url,
    token: requestToken,
    placement,
    cookieName,
    method: testCase.method || method,
    headers: { ...headers, ...(testCase.headers || {}) },
    body: testCase.body ?? body,
    fetchImpl,
    urlAllowed: allowed,
    signal: controller.signal,
  });

  try {
    const findings = [];
    const outcomes = [];
    for (const testCase of acceptedCases) {
      // Cada mutação recebe seu próprio baseline e controle inválido com
      // URL/método/headers/body/seletores idênticos. Apenas o token muda.
      const originalResponse = await request(token, testCase);
      const invalidResponse = await request(corruptSignature(token), testCase);
      const claims = { ...decoded.payload, [testCase.claim]: testCase.value };
      const signed = signJwtClaims(decoded, claims, secret);
      const response = await request(signed, testCase);
      const mutation = {
        claim: testCase.claim,
        value: testCase.value,
        kind: testCase.kind,
        expectedIdentity: testCase.expectedIdentity,
        observation: observationFromResponse(response, testCase),
      };
      const analyzed = analyzeJwtClaimDiff({
        original: observationFromResponse(originalResponse, testCase),
        invalidControl: observationFromResponse(invalidResponse, testCase),
        mutations: [mutation],
      });
      findings.push(...analyzed.findings);
      outcomes.push(...analyzed.outcomes);
    }
    return {
      state: findings.length ? 'confirmed' : 'executed_no_finding',
      reason: findings.length ? 'semantic_diff_confirmed' : 'no_semantic_diff',
      findings,
      outcomes,
      metrics: { requestsAttempted: acceptedCases.length * 3, casesExecuted: acceptedCases.length },
      tokenFingerprint: fingerprint(token),
      secretRef,
    };
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener('abort', forwardAbort);
    if (Buffer.isBuffer(secret)) secret.fill(0);
  }
}
