import { createHash, randomUUID } from 'node:crypto';

export const moduleManifest = {
  id: 'financial_integrity_audit',
  name: 'Financial Integrity Audit',
  category: 'aggressive',
  intrusive: true,
  requiresAuth: true,
  requiresKali: false,
  timeoutMs: 30_000,
  concurrency: 1,
  outputs: ['finding', 'metric'],
  risk: 'mutating',
  sideEffects: 'creates_disposable_financial_records_with_cleanup',
};

const HARD_NETWORK_REQUEST_BUDGET = 12;
const CLEANUP_TIMEOUT_MS = 10_000;

function fingerprint(value) {
  return createHash('sha256').update(String(value ?? '')).digest('hex');
}

function finiteAmount(value) {
  const amount = Number(value);
  return Number.isFinite(amount) ? Math.round(amount * 100) / 100 : null;
}

function normalizedFingerprint(value) {
  const raw = String(value || '');
  return /^[a-f0-9]{64}$/i.test(raw) ? raw.toLowerCase() : fingerprint(raw);
}

export function analyzeFinancialIntegrityObservations({
  displayedPrice,
  displayedMinimum,
  trials = [],
} = {}) {
  const price = finiteAmount(displayedPrice);
  const explicitMinimum = finiteAmount(displayedMinimum);
  const intendedFloor = explicitMinimum ?? price;
  if (intendedFloor == null) {
    return { state: 'skipped_ineligible', reason: 'displayed_floor_unknown', findings: [] };
  }
  const accepted = (Array.isArray(trials) ? trials : [])
    .map((trial) => ({
      requestedAmount: finiteAmount(trial.requestedAmount),
      acceptedAmount: finiteAmount(trial.acceptedAmount ?? trial.requestedAmount),
      accepted: trial.accepted === true,
      persisted: trial.persisted === true,
      status: Number(trial.status || 0),
      recordFingerprint: trial.recordFingerprint ? normalizedFingerprint(trial.recordFingerprint) : '',
    }))
    .filter((trial) => trial.accepted && trial.persisted && trial.acceptedAmount != null);
  if (!accepted.length) return { state: 'executed_no_finding', reason: 'no_persisted_mutation_accepted', findings: [] };
  const lowest = accepted.reduce((best, trial) => (trial.acceptedAmount < best.acceptedAmount ? trial : best));
  if (lowest.acceptedAmount >= intendedFloor) {
    return { state: 'executed_no_finding', reason: 'accepted_amount_respects_floor', findings: [] };
  }
  const severity = lowest.acceptedAmount <= 0 ? { prio: 'critical', score: 98 } : { prio: 'high', score: 92 };
  return {
    state: 'confirmed',
    reason: 'server_accepted_below_displayed_floor',
    lowestAcceptedAmount: lowest.acceptedAmount,
    findings: [{
      type: 'financial_integrity_price_floor_bypass',
      ...severity,
      value: 'Servidor aceitou valor inferior ao piso exibido para o produto',
      meta: [
        'source=financial_integrity_audit',
        'classification=confirmed',
        `displayed_price=${price ?? 'unknown'}`,
        `displayed_minimum=${explicitMinimum ?? 'not_declared'}`,
        `effective_floor=${intendedFloor}`,
        `lowest_accepted=${lowest.acceptedAmount}`,
      ].join(' • '),
      state: 'confirmed',
      evidence: {
        displayedPrice: price,
        displayedMinimum: explicitMinimum,
        effectiveFloor: intendedFloor,
        lowestAcceptedAmount: lowest.acceptedAmount,
        acceptedStatus: lowest.status,
        recordFingerprint: lowest.recordFingerprint,
      },
    }],
  };
}

function sameExactOrigin(expected, candidate) {
  try { return new URL(expected).origin === new URL(candidate).origin; } catch { return false; }
}

export async function runFinancialIntegrityAudit({
  url,
  endpointOrigin = url,
  displayedPrice,
  displayedMinimum,
  testAmounts = [],
  disposableAccountRef,
  allowMutatingActions = false,
  confirmedPlan = false,
  transport,
  cleanup,
  urlAllowed,
  requestBudget = 6,
  markerFactory = () => `ghostrecon-fi-${randomUUID()}`,
  signal,
} = {}) {
  const skipped = (reason) => ({ status: 'skipped', reason, findings: [], outcomes: [], metrics: { requestsAttempted: 0 } });
  if (allowMutatingActions !== true) return skipped('mutating_actions_not_authorized');
  if (confirmedPlan !== true) return skipped('mutating_plan_not_confirmed');
  if (!disposableAccountRef) return skipped('disposable_account_required');
  if (typeof transport !== 'function' || typeof cleanup !== 'function') return skipped('transport_and_cleanup_required');
  if (typeof urlAllowed !== 'function') return skipped('scope_guard_required');
  if (!url || !sameExactOrigin(endpointOrigin, url) || urlAllowed(url) !== true) return skipped('out_of_exact_origin_scope');

  // Budget total de rede: cada trial reserva uma mutação + uma tentativa
  // de cleanup, evitando que o custo real seja o dobro da telemetria.
  const budget = Math.min(HARD_NETWORK_REQUEST_BUDGET, Math.max(0, Math.floor(Number(requestBudget) || 0)));
  const mutationBudget = Math.floor(budget / 2);
  const amounts = [...new Set((Array.isArray(testAmounts) ? testAmounts : [])
    .map(finiteAmount)
    .filter((amount) => amount != null))].slice(0, mutationBudget);
  if (!amounts.length) return skipped('no_bounded_test_amounts');

  const trials = [];
  const cleanupTargets = [];
  const outcomes = [];
  const usedMarkers = new Set();
  let cleanupConfirmed = true;
  let cleanupAttempts = 0;
  let primaryError = null;
  try {
    for (const requestedAmount of amounts) {
      if (signal?.aborted) throw signal.reason || new DOMException('cancelled', 'AbortError');
      const marker = String(markerFactory() || '');
      if (!marker || marker.length > 128 || usedMarkers.has(marker) || !/^[A-Za-z0-9._:@+-]+$/.test(marker)) {
        throw new Error('financial_integrity_audit: marker invalido ou reutilizado');
      }
      usedMarkers.add(marker);
      // Registre o alvo de limpeza antes do POST: se o transporte falhar depois
      // de o servidor persistir o registro, o finally ainda tenta removê-lo.
      const cleanupTarget = { receiptRef: null, marker, requestedAmount };
      cleanupTargets.push(cleanupTarget);
      const response = await transport({
        url,
        method: 'POST',
        requestedAmount,
        accountRef: disposableAccountRef,
        marker,
        signal,
      });
      const accepted = response?.accepted === true;
      const persisted = response?.persisted === true;
      const receiptRef = response?.receiptRef || null;
      cleanupTarget.receiptRef = receiptRef;
      trials.push({
        requestedAmount,
        acceptedAmount: response?.acceptedAmount,
        accepted,
        persisted,
        status: response?.status,
        recordFingerprint: receiptRef ? fingerprint(receiptRef) : fingerprint(marker),
      });
      outcomes.push({ requestedAmount, accepted, persisted, status: Number(response?.status || 0) });
    }
  } catch (error) {
    primaryError = error;
  } finally {
    for (const target of cleanupTargets) {
      try {
        cleanupAttempts += 1;
        const cleanupSignal = AbortSignal.timeout(CLEANUP_TIMEOUT_MS);
        const result = await Promise.race([
          cleanup({ ...target, accountRef: disposableAccountRef, signal: cleanupSignal }),
          new Promise((_, reject) => cleanupSignal.addEventListener('abort', () => reject(
            cleanupSignal.reason || new DOMException('cleanup timeout', 'TimeoutError'),
          ), { once: true })),
        ]);
        if (result?.confirmed !== true) cleanupConfirmed = false;
      } catch {
        cleanupConfirmed = false;
      }
    }
  }
  if (primaryError) throw primaryError;

  const analysis = analyzeFinancialIntegrityObservations({ displayedPrice, displayedMinimum, trials });
  return {
    status: cleanupConfirmed ? 'done' : 'partial',
    reason: cleanupConfirmed ? analysis.reason : 'cleanup_not_confirmed',
    findings: analysis.findings.map((finding) => ({ ...finding, url, cleanupConfirmed })),
    outcomes,
    cleanup: { requested: cleanupTargets.length, confirmed: cleanupConfirmed },
    metrics: {
      requestsAttempted: trials.length + cleanupAttempts,
      mutationAttempts: trials.length,
      cleanupAttempts,
      accepted: trials.filter((trial) => trial.accepted).length,
      persisted: trials.filter((trial) => trial.persisted).length,
      cleanupTargets: cleanupTargets.length,
      requestBudget: budget,
      mutationBudget,
    },
  };
}
