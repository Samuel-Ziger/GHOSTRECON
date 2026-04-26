import test from 'node:test';
import assert from 'node:assert/strict';
import { buildRacePlan, analyzeRaceResults, raceToFinding } from '../modules/race-harness.mjs';

test('race: buildRacePlan gera N slots iguais', () => {
  const plan = buildRacePlan({ request: { url: 'https://x.com/coupon', method: 'POST', body: '{"code":"X"}' }, parallel: 10 });
  assert.equal(plan.slots.length, 10);
  for (const s of plan.slots) assert.equal(s.url, 'https://x.com/coupon');
  assert.equal(plan.technique, 'last-byte-sync');
});

test('race: buildRacePlan exige url', () => {
  assert.throws(() => buildRacePlan({ request: {} }), /url obrigatório/);
});

test('race: analyzeRaceResults detecta duplicação de sucesso (race confirmada)', () => {
  const responses = [
    { status: 200, body: { ok: true } },
    { status: 200, body: { ok: true } },
    { status: 400, body: { error: 'used' } },
    { status: 400, body: { error: 'used' } },
  ];
  const a = analyzeRaceResults({ responses });
  assert.equal(a.successes, 2);
  assert.equal(a.raceConfirmed, true);
});

test('race: analyzeRaceResults sem sucessos duplos = não confirmada', () => {
  const responses = [
    { status: 200, body: { id: 'a' } },
    { status: 200, body: { id: 'b' } },
  ];
  const a = analyzeRaceResults({ responses, dedupKey: (r) => r.body.id });
  // 2 sucessos, mas keys diferentes → não dup
  assert.equal(a.raceConfirmed, false);
});

test('race: raceToFinding null quando não confirmada', () => {
  const f = raceToFinding({ request: { url: 'x' }, total: 5 }, { raceConfirmed: false });
  assert.equal(f, null);
});

test('race: raceToFinding emite high quando confirmada', () => {
  const plan = buildRacePlan({ request: { url: 'https://x.com/withdraw', method: 'POST' }, parallel: 5 });
  const a = { raceConfirmed: true, total: 5, successes: 3, statusCodes: [200, 400], successKeys: {} };
  const f = raceToFinding(plan, a, { contextHint: 'withdraw' });
  assert.equal(f.severity, 'high');
  assert.ok(f.title.includes('withdraw'));
});
