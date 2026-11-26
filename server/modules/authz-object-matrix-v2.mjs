import { createHash } from 'node:crypto';

export const moduleManifest = {
  id: 'authz_object_matrix_v2',
  name: 'Authorization Object Matrix v2',
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

const DENIED = new Set([401, 403, 404]);

function fingerprint(value) {
  return createHash('sha256').update(String(value ?? '')).digest('hex');
}

function norm(value = {}) {
  const status = Number(value.status || 0);
  return {
    status,
    denied: value.denied === true || DENIED.has(status) || value.loginWall === true,
    objectId: value.objectId == null ? null : String(value.objectId),
    ownerId: value.ownerId == null ? null : String(value.ownerId),
    public: value.public === true,
    bodyFingerprint: value.bodyFingerprint || '',
  };
}

function idsMatch(observed, expectedObject, expectedOwner) {
  if (!observed.objectId || !expectedObject || observed.objectId !== String(expectedObject)) return false;
  if (!observed.ownerId || !expectedOwner || observed.ownerId !== String(expectedOwner)) return false;
  return true;
}

function exactOrigin(expected, candidate) {
  try { return new URL(expected).origin === new URL(candidate).origin; } catch { return false; }
}

export function analyzeAuthzObjectMatrix({
  mode = 'fixed_object',
  personaAId,
  personaBId,
  objectAId,
  objectBId,
  personaAOwn,
  personaBOwn,
  personaBReadsA,
  anonymousReadsA,
  credentialsDistinct = false,
} = {}) {
  const aOwn = norm(personaAOwn);
  const bOwn = norm(personaBOwn);
  const bCross = norm(personaBReadsA);
  const anonCross = norm(anonymousReadsA);

  if (mode === 'session_relative') {
    const coherent = !aOwn.denied
      && !bOwn.denied
      && aOwn.ownerId === String(personaAId)
      && bOwn.ownerId === String(personaBId)
      && aOwn.ownerId !== bOwn.ownerId;
    return {
      state: 'executed_no_finding',
      reason: coherent ? 'session_relative_identity_isolated' : 'session_relative_inconclusive',
      findings: [],
    };
  }

  if (!personaAId || !personaBId || String(personaAId) === String(personaBId)
    || !objectAId || !objectBId || credentialsDistinct !== true) {
    return { state: 'skipped_ineligible', reason: 'missing_distinct_personas_or_object', findings: [] };
  }
  if (aOwn.denied || !idsMatch(aOwn, objectAId, personaAId)) {
    return { state: 'executed_no_finding', reason: 'owner_baseline_not_proven', findings: [] };
  }
  if (bOwn.denied || !idsMatch(bOwn, objectBId, personaBId)) {
    return { state: 'executed_no_finding', reason: 'second_owner_baseline_not_proven', findings: [] };
  }
  if (bCross.denied) return { state: 'executed_no_finding', reason: 'cross_access_denied', findings: [] };
  if (bCross.public === true || !bCross.ownerId) {
    return { state: 'executed_no_finding', reason: bCross.public ? 'public_resource' : 'owner_marker_missing', findings: [] };
  }
  const confirmed = idsMatch(bCross, objectAId, personaAId);
  if (!confirmed) return { state: 'executed_no_finding', reason: 'cross_response_not_owner_a_object', findings: [] };

  const anonymousAlsoReads = !anonCross.denied && idsMatch(anonCross, objectAId, personaAId);
  const finding = {
    type: 'bola_fixed_object',
    prio: anonymousAlsoReads ? 'critical' : 'high',
    score: anonymousAlsoReads ? 96 : 90,
    value: 'Persona B acessa objeto fixo pertencente a persona A',
    meta: `source=authz_object_matrix_v2 - control=owner_baseline - anonymous_access=${anonymousAlsoReads}`,
    state: 'confirmed',
    confidence: 'high',
    owasp: 'A01:2021',
    mitre: 'T1078',
    evidence: {
      objectFingerprint: fingerprint(objectAId),
      ownerFingerprint: fingerprint(personaAId),
      ownerStatus: aOwn.status,
      crossStatus: bCross.status,
      anonymousStatus: anonCross.status,
      anonymousAlsoReads,
    },
  };
  return { state: 'confirmed', reason: 'fixed_object_owner_a_returned_to_persona_b', findings: [finding] };
}

function extract(value, selector) {
  if (typeof selector === 'function') return selector(value);
  if (!selector) return null;
  return String(selector).split('.').filter(Boolean).reduce((acc, key) => acc?.[key], value);
}

function observe(response, config) {
  const status = Number(response?.status || 0);
  const json = response?.json;
  return {
    status,
    denied: DENIED.has(status),
    loginWall: response?.loginWall === true,
    objectId: extract(json, config.objectIdPath),
    ownerId: extract(json, config.ownerIdPath),
    public: response?.public === true || config.publicResource === true,
    bodyFingerprint: response?.bodyFingerprint || fingerprint(response?.text || JSON.stringify(json || null)),
  };
}

export async function runAuthzObjectMatrix({
  cases = [],
  transport,
  allowActive = false,
  urlAllowed,
  requestBudget = 24,
  signal,
  onConfirmedCrossResponse = null,
} = {}) {
  if (allowActive !== true) return { state: 'skipped_ineligible', reason: 'active_not_authorized', findings: [], outcomes: [] };
  if (typeof transport !== 'function') throw new Error('authz_object_matrix_v2: transport obrigatorio');
  const findings = [];
  const outcomes = [];
  let requestsAttempted = 0;

  if (!Array.isArray(cases) || cases.length === 0) {
    return {
      state: 'skipped_ineligible', reason: 'no_cases', findings, outcomes,
      metrics: { requestsAttempted, casesExecuted: 0 },
    };
  }

  for (const config of cases.slice(0, Math.floor(Math.max(0, requestBudget) / 4))) {
    if (signal?.aborted) throw signal.reason || new Error('cancelled');
    const authA = String(config.personaAAuthRef || '');
    const authB = String(config.personaBAuthRef || '');
    if (!authA || !authB || authA === authB) {
      outcomes.push({ id: config.id || '', state: 'skipped_ineligible', reason: 'distinct_credentials_required' });
      continue;
    }
    const urls = [config.urlAOwn, config.urlBOwn, config.urlBReadsA, config.urlAnonymousReadsA].filter(Boolean);
    const endpointOrigin = config.endpointOrigin || config.urlAOwn;
    if (urls.length !== 4 || urls.some((url) => !exactOrigin(endpointOrigin, url)
      || typeof urlAllowed === 'function' && urlAllowed(url) !== true)) {
      outcomes.push({ id: config.id || '', state: 'skipped_ineligible', reason: 'missing_or_out_of_exact_origin_scope' });
      continue;
    }
    const [aOwn, bOwn, bCross, anonCross] = await Promise.all([
      transport({ url: config.urlAOwn, authRef: config.personaAAuthRef, signal }),
      transport({ url: config.urlBOwn, authRef: config.personaBAuthRef, signal }),
      transport({ url: config.urlBReadsA, authRef: config.personaBAuthRef, signal }),
      transport({ url: config.urlAnonymousReadsA, authRef: null, signal }),
    ]);
    requestsAttempted += 4;
    const result = analyzeAuthzObjectMatrix({
      ...config,
      personaAOwn: observe(aOwn, config),
      personaBOwn: observe(bOwn, config),
      personaBReadsA: observe(bCross, config),
      anonymousReadsA: observe(anonCross, config),
      credentialsDistinct: true,
    });
    if (result.state === 'confirmed' && typeof onConfirmedCrossResponse === 'function') {
      await onConfirmedCrossResponse({
        caseId: config.id || '',
        url: config.urlBReadsA,
        response: bCross,
        accessFinding: result.findings[0],
        objectIdPath: config.objectIdPath,
        ownerIdPath: config.ownerIdPath,
      });
    }
    findings.push(...result.findings);
    outcomes.push({ id: config.id || '', state: result.state, reason: result.reason });
  }
  return {
    state: requestsAttempted === 0
      ? 'skipped_ineligible'
      : findings.length ? 'confirmed' : 'executed_no_finding',
    reason: requestsAttempted === 0 ? 'no_eligible_cases' : undefined,
    findings,
    outcomes,
    metrics: { requestsAttempted, casesExecuted: outcomes.length },
  };
}
