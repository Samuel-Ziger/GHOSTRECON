import test from 'node:test';
import assert from 'node:assert/strict';

import {
  analyzeFinancialIntegrityObservations,
  runFinancialIntegrityAudit,
} from '../modules/financial-integrity-audit.mjs';

test('análise distingue piso exibido do menor valor realmente aceito', () => {
  const result = analyzeFinancialIntegrityObservations({
    displayedPrice: 100,
    displayedMinimum: 25,
    trials: [
      { requestedAmount: 25, acceptedAmount: 25, accepted: true, persisted: true, status: 201 },
      { requestedAmount: 0, acceptedAmount: 0, accepted: true, persisted: true, status: 201 },
    ],
  });
  assert.equal(result.state, 'confirmed');
  assert.equal(result.lowestAcceptedAmount, 0);
  assert.equal(result.findings[0].prio, 'critical');
  assert.equal(result.findings[0].evidence.effectiveFloor, 25);
});

test('não confirma sem persistência nem quando valor respeita o piso', () => {
  assert.equal(analyzeFinancialIntegrityObservations({
    displayedPrice: 100,
    trials: [{ requestedAmount: 0, accepted: true, persisted: false }],
  }).findings.length, 0);
  assert.equal(analyzeFinancialIntegrityObservations({
    displayedPrice: 100,
    trials: [{ requestedAmount: 100, acceptedAmount: 100, accepted: true, persisted: true }],
  }).findings.length, 0);
  assert.equal(analyzeFinancialIntegrityObservations({ trials: [] }).reason, 'displayed_floor_unknown');
});

test('gates mutating, plano, conta descartável, cleanup e scope falham fechados sem rede', async () => {
  let calls = 0;
  const transport = async () => { calls += 1; return {}; };
  const cleanup = async () => ({ confirmed: true });
  const base = {
    url: 'https://lab.invalid/purchase', displayedPrice: 100, testAmounts: [1],
    disposableAccountRef: 'account:fixture', transport, cleanup, confirmedPlan: true,
    allowMutatingActions: true, urlAllowed: () => true,
  };
  assert.equal((await runFinancialIntegrityAudit({ ...base, allowMutatingActions: false })).reason, 'mutating_actions_not_authorized');
  assert.equal((await runFinancialIntegrityAudit({ ...base, confirmedPlan: false })).reason, 'mutating_plan_not_confirmed');
  assert.equal((await runFinancialIntegrityAudit({ ...base, disposableAccountRef: '' })).reason, 'disposable_account_required');
  assert.equal((await runFinancialIntegrityAudit({ ...base, cleanup: null })).reason, 'transport_and_cleanup_required');
  assert.equal((await runFinancialIntegrityAudit({ ...base, urlAllowed: null })).reason, 'scope_guard_required');
  assert.equal((await runFinancialIntegrityAudit({ ...base, endpointOrigin: 'https://other.invalid' })).reason, 'out_of_exact_origin_scope');
  assert.equal(calls, 0);
});

test('runner limita mutações, limpa toda tentativa e não publica receipt/marker', async () => {
  const requests = [];
  const cleanups = [];
  let marker = 0;
  const result = await runFinancialIntegrityAudit({
    url: 'https://lab.invalid/purchase',
    displayedPrice: 100,
    displayedMinimum: 20,
    testAmounts: [0, 1, 5],
    requestBudget: 4,
    disposableAccountRef: 'account:fixture',
    allowMutatingActions: true,
    confirmedPlan: true,
    urlAllowed: (url) => new URL(url).origin === 'https://lab.invalid',
    markerFactory: () => `fixture-marker-${marker += 1}`,
    transport: async (request) => {
      requests.push(request);
      return {
        status: 201,
        accepted: true,
        persisted: true,
        acceptedAmount: request.requestedAmount,
        receiptRef: `private-receipt-${request.requestedAmount}`,
      };
    },
    cleanup: async (target) => { cleanups.push(target); return { confirmed: true }; },
  });
  assert.equal(requests.length, 2);
  assert.equal(cleanups.length, 2);
  assert.equal(result.metrics.requestsAttempted, 4);
  assert.equal(result.metrics.cleanupAttempts, 2);
  assert.equal(result.cleanup.confirmed, true);
  assert.equal(result.findings[0].evidence.lowestAcceptedAmount, 0);
  assert.doesNotMatch(JSON.stringify(result), /private-receipt|fixture-marker/);
});

test('cleanup não confirmado produz partial sem apagar finding confirmado', async () => {
  const result = await runFinancialIntegrityAudit({
    url: 'https://lab.invalid/purchase', displayedPrice: 10, testAmounts: [-1],
    disposableAccountRef: 'account:fixture', allowMutatingActions: true, confirmedPlan: true,
    urlAllowed: () => true,
    markerFactory: () => 'fixture-cleanup-failure',
    transport: async () => ({ status: 201, accepted: true, persisted: true, acceptedAmount: -1 }),
    cleanup: async () => ({ confirmed: false }),
  });
  assert.equal(result.status, 'partial');
  assert.equal(result.reason, 'cleanup_not_confirmed');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].cleanupConfirmed, false);
});

test('erro/timeout após início ainda tenta cleanup pelo marker e é propagado', async () => {
  const cleanups = [];
  const timeout = new DOMException('fixture deadline', 'TimeoutError');
  await assert.rejects(runFinancialIntegrityAudit({
    url: 'https://lab.invalid/purchase', displayedPrice: 10, testAmounts: [0],
    disposableAccountRef: 'account:fixture', allowMutatingActions: true, confirmedPlan: true,
    urlAllowed: () => true,
    markerFactory: () => 'fixture-timeout-marker',
    transport: async () => { throw timeout; },
    cleanup: async (target) => { cleanups.push(target); return { confirmed: true }; },
  }), (error) => error === timeout);
  assert.equal(cleanups.length, 1);
  assert.equal(cleanups[0].marker, 'fixture-timeout-marker');
});

test('cancelamento anterior à tentativa não faz POST nem cleanup', async () => {
  const controller = new AbortController();
  controller.abort(new DOMException('operator cancelled', 'AbortError'));
  let posts = 0;
  let cleanups = 0;
  await assert.rejects(runFinancialIntegrityAudit({
    url: 'https://lab.invalid/purchase', displayedPrice: 10, testAmounts: [0],
    disposableAccountRef: 'account:fixture', allowMutatingActions: true, confirmedPlan: true,
    urlAllowed: () => true, signal: controller.signal,
    transport: async () => { posts += 1; return {}; },
    cleanup: async () => { cleanups += 1; return { confirmed: true }; },
  }), /operator cancelled/);
  assert.equal(posts, 0);
  assert.equal(cleanups, 0);
});
