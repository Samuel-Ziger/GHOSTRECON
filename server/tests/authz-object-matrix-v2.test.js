import test from 'node:test';
import assert from 'node:assert/strict';
import {
  analyzeAuthzObjectMatrix,
  runAuthzObjectMatrix,
} from '../modules/authz-object-matrix-v2.mjs';

test('/me com Alice e Bob coerentes é seguro', () => {
  const result = analyzeAuthzObjectMatrix({
    mode: 'session_relative',
    personaAId: 'alice',
    personaBId: 'bob',
    personaAOwn: { status: 200, objectId: 'alice', ownerId: 'alice' },
    personaBOwn: { status: 200, objectId: 'bob', ownerId: 'bob' },
  });
  assert.equal(result.findings.length, 0);
  assert.equal(result.reason, 'session_relative_identity_isolated');
});

test('B recebe objeto fixo e owner de A: BOLA confirmada', () => {
  const result = analyzeAuthzObjectMatrix({
    personaAId: 'alice', personaBId: 'bob', objectAId: 'order-a', objectBId: 'order-b',
    credentialsDistinct: true,
    personaAOwn: { status: 200, objectId: 'order-a', ownerId: 'alice' },
    personaBOwn: { status: 200, objectId: 'order-b', ownerId: 'bob' },
    personaBReadsA: { status: 200, objectId: 'order-a', ownerId: 'alice' },
    anonymousReadsA: { status: 403 },
  });
  assert.equal(result.findings[0].type, 'bola_fixed_object');
  assert.equal(result.findings[0].prio, 'high');
  assert.doesNotMatch(JSON.stringify(result), /order-a|alice/);
});

test('catálogo público sem owner e denial não confirmam BOLA', () => {
  const base = {
    personaAId: 'alice', personaBId: 'bob', objectAId: '7', objectBId: '8', credentialsDistinct: true,
    personaAOwn: { status: 200, objectId: '7', ownerId: 'alice' },
    personaBOwn: { status: 200, objectId: '8', ownerId: 'bob' },
    anonymousReadsA: { status: 200, objectId: '7', public: true },
  };
  assert.equal(analyzeAuthzObjectMatrix({ ...base, personaBReadsA: { status: 200, objectId: '7', public: true } }).findings.length, 0);
  assert.equal(analyzeAuthzObjectMatrix({ ...base, personaBReadsA: { status: 403 } }).findings.length, 0);
});

test('não confirma BOLA sem credenciais distintas nem baseline próprio de B', () => {
  const base = {
    personaAId: 'alice', personaBId: 'bob', objectAId: 'a', objectBId: 'b',
    personaAOwn: { status: 200, objectId: 'a', ownerId: 'alice' },
    personaBOwn: { status: 200, objectId: 'a', ownerId: 'alice' },
    personaBReadsA: { status: 200, objectId: 'a', ownerId: 'alice' },
    anonymousReadsA: { status: 403 },
  };
  assert.equal(analyzeAuthzObjectMatrix(base).findings.length, 0);
  const withDistinctCredentials = analyzeAuthzObjectMatrix({ ...base, credentialsDistinct: true });
  assert.equal(withDistinctCredentials.findings.length, 0);
  assert.equal(withDistinctCredentials.reason, 'second_owner_baseline_not_proven');
});

test('runner respeita gate, escopo e budget', async () => {
  let calls = 0;
  const config = {
    id: 'order', personaAId: 'alice', personaBId: 'bob', objectAId: 'a', objectBId: 'b',
    urlAOwn: 'https://lab.invalid/orders/a', urlBOwn: 'https://lab.invalid/orders/b',
    urlBReadsA: 'https://lab.invalid/orders/a', urlAnonymousReadsA: 'https://lab.invalid/orders/a',
    objectIdPath: 'id', ownerIdPath: 'owner', personaAAuthRef: 'auth:a', personaBAuthRef: 'auth:b',
  };
  const inactive = await runAuthzObjectMatrix({ cases: [config], transport: async () => { calls += 1; } });
  assert.equal(inactive.reason, 'active_not_authorized');
  const active = await runAuthzObjectMatrix({
    cases: [config], allowActive: true, requestBudget: 4, urlAllowed: () => true,
    transport: async ({ url, authRef }) => {
      calls += 1;
      if (!authRef) return { status: 403, json: {} };
      if (url.endsWith('/b')) return { status: 200, json: { id: 'b', owner: 'bob' } };
      return { status: 200, json: { id: 'a', owner: 'alice' } };
    },
  });
  assert.equal(calls, 4);
  assert.equal(active.metrics.requestsAttempted, 4);
  assert.equal(active.findings.length, 1);
});

test('runner rejeita a mesma referência de autenticação antes de fazer requests', async () => {
  let calls = 0;
  const result = await runAuthzObjectMatrix({
    allowActive: true,
    requestBudget: 4,
    urlAllowed: () => true,
    cases: [{
      id: 'same-token', personaAId: 'alice', personaBId: 'bob', objectAId: 'a', objectBId: 'b',
      urlAOwn: 'https://lab.invalid/a', urlBOwn: 'https://lab.invalid/b',
      urlBReadsA: 'https://lab.invalid/a', urlAnonymousReadsA: 'https://lab.invalid/a',
      personaAAuthRef: 'auth:same', personaBAuthRef: 'auth:same',
    }],
    transport: async () => { calls += 1; return { status: 200 }; },
  });
  assert.equal(calls, 0);
  assert.equal(result.findings.length, 0);
  assert.equal(result.outcomes[0].reason, 'distinct_credentials_required');
});
