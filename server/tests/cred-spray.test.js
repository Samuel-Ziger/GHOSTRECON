import test from 'node:test';
import assert from 'node:assert/strict';
import { ENDPOINT_PRESETS, gateSpray, planSpray, runSpray } from '../modules/cred-spray.mjs';

test('spray: gateSpray bloqueia sem engagement', () => {
  const r = gateSpray({});
  assert.equal(r.ok, false);
});

test('spray: gateSpray bloqueia ROE não assinado', () => {
  const r = gateSpray({ engagement: { roeSigned: false }, confirm: true });
  assert.equal(r.ok, false);
});

test('spray: gateSpray bloqueia sem janela', () => {
  const r = gateSpray({ engagement: { roeSigned: true }, confirm: true });
  assert.equal(r.ok, false);
  assert.ok(/window/.test(r.reason));
});

test('spray: gateSpray bloqueia sem confirm', () => {
  const r = gateSpray({
    engagement: { roeSigned: true, window: { startsAt: '2020-01-01', endsAt: '2099-01-01' } },
    confirm: false,
  });
  assert.equal(r.ok, false);
});

test('spray: gateSpray ok quando tudo alinha', () => {
  const r = gateSpray({
    engagement: { roeSigned: true, window: { startsAt: '2020-01-01', endsAt: '2099-01-01' } },
    confirm: true,
  });
  assert.equal(r.ok, true);
});

test('spray: gateSpray bloqueia fora de escopo', () => {
  const r = gateSpray({
    engagement: { roeSigned: true, window: { startsAt: '2020-01-01', endsAt: '2099-01-01' }, scopeDomains: ['*.acme.com'] },
    confirm: true,
    target: 'evil.com',
  });
  assert.equal(r.ok, false);
  assert.ok(/escopo/.test(r.reason));
});

test('spray: planSpray gera batches por senha', () => {
  const plan = planSpray({ users: ['a', 'b', 'c'], passwords: ['p1', 'p2'], usersPerBatch: 2 });
  assert.equal(plan.batches.length, 4); // 2 batches × 2 senhas
  assert.equal(plan.estimateTotal, 6);
});

test('spray: ENDPOINT_PRESETS tem o365/okta', () => {
  assert.ok(ENDPOINT_PRESETS.o365);
  assert.ok(ENDPOINT_PRESETS.okta);
  assert.ok(typeof ENDPOINT_PRESETS.o365.successHeuristic === 'function');
});

test('spray: runSpray classifica responses por preset', async () => {
  const plan = planSpray({ users: ['a', 'b'], passwords: ['p1'], usersPerBatch: 5, attemptDelayMs: 1, cooldownMs: 1 });
  const exec = async ({ attempt }) => {
    if (attempt.user === 'a') return { status: 200, body: '{"access_token":"xyz"}' };
    return { status: 401, body: '{}' };
  };
  const r = await runSpray({ plan, preset: 'o365', customExecutor: exec, target: 'login.microsoft.com' });
  assert.equal(r.successes.length, 1);
  assert.equal(r.successes[0].user, 'a');
});

test('spray: runSpray aborta em lockout ratio', async () => {
  const plan = planSpray({ users: ['a', 'b', 'c', 'd'], passwords: ['p'], usersPerBatch: 4, attemptDelayMs: 1, cooldownMs: 1 });
  const exec = async () => ({ status: 423, body: '{"error":"AADSTS50053 locked"}' });
  const r = await runSpray({ plan, preset: 'o365', customExecutor: exec, lockoutAbortRatio: 0.5 });
  assert.equal(r.aborted, true);
});
