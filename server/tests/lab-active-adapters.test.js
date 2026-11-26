import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';

import { auditJwks } from '../modules/jwt-jwks-audit.mjs';
import { moduleRunners } from '../modules/module-registry-runners.mjs';
import { createPipelineState } from '../pipeline/pipeline-state.mjs';

function jwt(payload, secret = 'fixture-secret') {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT', kid: 'lab' })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = createHmac('sha256', secret).update(`${header}.${body}`).digest('base64url');
  return `${header}.${body}.${signature}`;
}

function baseState(overrides = {}) {
  return {
    modules: [],
    autoModeExecution: false,
    signal: null,
    log: () => {},
    urlInScope: (url) => new URL(url).origin === 'https://lab.invalid',
    allowsPipelineCapability: () => true,
    sensitivePaymentObservations: [],
    ...overrides,
  };
}

test('authz adapter resolve authRef, confirma BOLA e encadeia classificador de pagamento sem vazar PAN/CVV', async () => {
  const pan = '4111111111111111';
  const state = baseState({
    authzObjectMatrixConfig: {
      allowActive: true,
      requestBudget: 4,
      authContexts: {
        alice: { headers: { Authorization: 'Bearer token-a' } },
        bob: { headers: { Authorization: 'Bearer token-b' } },
      },
      cases: [{
        id: 'orders', endpointOrigin: 'https://lab.invalid',
        personaAId: 'alice', personaBId: 'bob', objectAId: 'a', objectBId: 'b',
        personaAAuthRef: 'alice', personaBAuthRef: 'bob',
        urlAOwn: 'https://lab.invalid/orders/a', urlBOwn: 'https://lab.invalid/orders/b',
        urlBReadsA: 'https://lab.invalid/orders/a', urlAnonymousReadsA: 'https://lab.invalid/orders/a',
        objectIdPath: 'id', ownerIdPath: 'owner',
      }],
    },
    fetchImpl: async (url, init) => {
      const auth = init.headers.Authorization || '';
      if (!auth) return new Response('{}', { status: 403 });
      if (url.endsWith('/b')) {
        return new Response(JSON.stringify({ id: 'b', owner: 'bob' }), { status: 200 });
      }
      return new Response(JSON.stringify({ id: 'a', owner: 'alice', card_number: pan, cvv: '123' }), { status: 200 });
    },
  });
  const authz = await moduleRunners.authz_object_matrix_v2(state);
  assert.equal(authz.findings.length, 1);
  assert.equal(state.sensitivePaymentObservations.length, 1);
  const payment = await moduleRunners.sensitive_payment_data(state);
  assert.equal(payment.findings.length, 1);
  assert.equal(payment.findings[0].paymentEvidence.pans[0].last4, '1111');
  assert.equal(state.sensitivePaymentObservations.length, 0);
  assert.doesNotMatch(JSON.stringify({ authz, payment }), /4111111111111111|"123"/);
});

test('object-key discovery alimenta template do proxy cloud e authRef fica somente em memória', async () => {
  const seen = [];
  const state = baseState({
    objectKeyCandidates: [{ key: 'owner/private/card.json' }],
    cloudObjectProxyAuthzConfig: {
      allowActive: true,
      requestBudget: 4,
      authContexts: {
        owner: { headers: { Authorization: 'Bearer owner-private' } },
        other: { headers: { Authorization: 'Bearer other-private' } },
      },
      caseTemplate: {
        id: 'cloud-object', endpointOrigin: 'https://lab.invalid',
        ownerAuthRef: 'owner', crossAuthRef: 'other',
        ownerUrl: 'https://lab.invalid/object?key={{objectKey}}',
        crossUrl: 'https://lab.invalid/object?key={{objectKey}}',
        missingControlUrl: 'https://lab.invalid/object?key=missing-fixture',
        urlShapedControlUrl: 'https://lab.invalid/object?key=http%3A%2F%2F127.0.0.1%2Fmetadata',
      },
    },
    fetchImpl: async (url, init) => {
      seen.push({ url, authorization: init.headers.Authorization });
      if (url.includes('missing-fixture') || url.includes('127.0.0.1')) {
        return new Response('<Code>NoSuchKey</Code>', { status: 404 });
      }
      return new Response('{"object":"same-private-object-fixture"}', { status: 200 });
    },
  });
  const result = await moduleRunners.cloud_object_proxy_authz(state);
  assert.equal(seen.length, 4);
  assert.equal(result.findings.length, 1);
  assert.doesNotMatch(JSON.stringify(result), /owner\/private|owner-private|other-private|same-private-object/);
});

test('adapter financeiro declarativo limita POST, confirma cleanup e contabiliza toda a rede', async () => {
  const calls = [];
  const state = baseState({
    financialIntegrityConfig: {
      url: 'https://lab.invalid/purchase', endpointOrigin: 'https://lab.invalid',
      displayedPrice: 100, displayedMinimum: 20, testAmounts: [0], requestBudget: 2,
      disposableAccountRef: 'disposable:fixture', allowMutatingActions: true, confirmedPlan: true,
      request: {
        method: 'POST', bodyTemplate: { amount: '{{amount}}', marker: '{{marker}}' },
        acceptedPath: 'accepted', persistedPath: 'persisted', acceptedAmountPath: 'amount', receiptRefPath: 'id',
      },
      cleanupRequest: {
        method: 'DELETE', urlTemplate: 'https://lab.invalid/purchase/{{receiptRef}}',
        confirmedStatuses: [204],
      },
    },
    fetchImpl: async (url, init) => {
      calls.push({ url, method: init.method });
      if (init.method === 'DELETE') return new Response(null, { status: 204 });
      const body = JSON.parse(init.body);
      return new Response(JSON.stringify({ accepted: true, persisted: true, amount: body.amount, id: 'private-receipt' }), { status: 201 });
    },
  });
  const result = await moduleRunners.financial_integrity_audit(state);
  assert.deepEqual(calls.map((row) => row.method), ['POST', 'DELETE']);
  assert.equal(result.attempted, 2);
  assert.equal(result.findings.length, 1);
  assert.doesNotMatch(JSON.stringify(result), /private-receipt/);
});

test('JWKS e JWT diff compartilham somente secretRef efêmera resolvível', async () => {
  const rawToken = jwt({ sub: 'alice', user_id: 'alice', role: 'user' });
  const state = createPipelineState({
    domain: 'lab.invalid', targetUrl: 'https://lab.invalid/', exactMatch: false,
    modules: ['jwt_jwks_audit', 'jwt_claim_authz_diff'], emit: () => {},
    manualEffectiveCapabilities: ['jwt_claim_authz_diff'],
    jwtClaimAuthzConfig: {
      url: 'https://lab.invalid/api/me', token: rawToken, allowActive: true,
      cases: [{ claim: 'user_id', value: 'bob', expectedIdentity: 'bob', identityPath: 'user.id' }],
    },
    fetchImpl: async (url, init = {}) => {
      if (new URL(url).pathname === '/api/me') {
        const sent = String(init.headers?.Authorization || '').replace(/^Bearer\s+/i, '');
        const payload = JSON.parse(Buffer.from(sent.split('.')[1] || '', 'base64url').toString() || '{}');
        if (sent !== jwt(payload)) return new Response('{"error":"invalid"}', { status: 401 });
        return new Response(JSON.stringify({ user: { id: payload.user_id } }), { status: 200 });
      }
      return new Response('{}', { status: 404 });
    },
  });
  try {
    const rows = await auditJwks({
      keys: [{ kty: 'oct', alg: 'HS256', kid: 'lab', k: Buffer.from('fixture-secret').toString('base64url') }],
    }, { onSecret: async (entry) => {
      const stored = await state.storeSensitiveEvidence(entry);
      state.latestJwtSecretRef = stored.secretRef;
      return stored;
    } });
    assert.match(rows[0].secretRef, /^memory:sha256:/);
    const result = await moduleRunners.jwt_claim_authz_diff(state);
    assert.equal(result.findings[0].type, 'jwt_claim_bola');
    assert.doesNotMatch(JSON.stringify({ rows, result }), /fixture-secret|eyJhbGci/);
  } finally {
    state.disposeSensitiveEvidence();
  }
});
