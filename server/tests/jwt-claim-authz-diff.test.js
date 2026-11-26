import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import {
  analyzeJwtClaimDiff,
  runJwtClaimAuthzDiff,
} from '../modules/jwt-claim-authz-diff.mjs';
import { auditJwks } from '../modules/jwt-jwks-audit.mjs';

function token(payload, secret = 'fixture-secret') {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT', kid: 'lab' })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = createHmac('sha256', secret).update(`${header}.${body}`).digest('base64url');
  return `${header}.${body}.${sig}`;
}

test('JWKS oct usa a secretRef retornada pelo sink e nunca inclui o segredo', async () => {
  const raw = 'fixture-jwt-secret-never-persist';
  let captured;
  const rows = await auditJwks({ keys: [{ kty: 'oct', alg: 'HS256', kid: 'lab', k: Buffer.from(raw).toString('base64url') }] }, {
    url: 'https://lab.invalid/jwks.json',
    async onSecret(value) {
      captured = value.value.toString();
      return { secretRef: `vault:sha256:${value.fingerprint}` };
    },
  });
  assert.equal(rows[0].state, 'confirmed');
  assert.match(rows[0].secretRef, /^vault:sha256:/);
  assert.equal(captured, raw);
  assert.doesNotMatch(JSON.stringify(rows), new RegExp(raw));
  assert.doesNotMatch(JSON.stringify(rows), new RegExp(Buffer.from(raw).toString('base64url')));
});

test('analisador exige controle de assinatura negado', () => {
  const result = analyzeJwtClaimDiff({
    original: { status: 200, identity: 'alice' },
    invalidControl: { status: 200, identity: 'alice' },
    mutations: [{ claim: 'user_id', value: 'bob', expectedIdentity: 'bob', observation: { status: 200, identity: 'bob' } }],
  });
  assert.equal(result.findings.length, 0);
  assert.equal(result.reason, 'invalid_signature_not_rejected');
});

test('runner confirma user_id por diferença semântica e não vaza JWT/secret', async () => {
  const rawToken = token({ sub: 'alice', user_id: 'alice', role: 'user' });
  const calls = [];
  const result = await runJwtClaimAuthzDiff({
    url: 'https://lab.invalid/api/me',
    token: rawToken,
    secretRef: 'memory:fixture',
    resolveSecret: async () => Buffer.from('fixture-secret'),
    allowActive: true,
    urlAllowed: (url) => new URL(url).origin === 'https://lab.invalid',
    cases: [{ claim: 'user_id', value: 'bob', expectedIdentity: 'bob', identityPath: 'user.id' }],
    transport: async ({ token: sent }) => {
      calls.push(sent);
      const payload = JSON.parse(Buffer.from(sent.split('.')[1], 'base64url').toString());
      const expected = token(payload);
      if (sent !== expected) return { status: 401, json: { error: 'invalid' }, text: 'invalid' };
      return { status: 200, json: { user: { id: payload.user_id } }, text: payload.user_id };
    },
  });
  assert.equal(calls.length, 3);
  assert.equal(result.findings[0].type, 'jwt_claim_bola');
  const serialized = JSON.stringify(result);
  assert.doesNotMatch(serialized, /fixture-secret/);
  assert.doesNotMatch(serialized, new RegExp(rawToken.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
});

test('runner confirma role somente quando operação restrita ganha efeito', async () => {
  const result = await runJwtClaimAuthzDiff({
    url: 'https://lab.invalid/api/admin-action',
    token: token({ sub: 'alice', role: 'user' }),
    secretRef: 'memory:fixture',
    resolveSecret: async () => Buffer.from('fixture-secret'),
    allowActive: true,
    cases: [{ claim: 'role', value: 'admin', kind: 'privilege', effectPath: 'changed' }],
    transport: async ({ token: sent }) => {
      const payload = JSON.parse(Buffer.from(sent.split('.')[1], 'base64url').toString());
      const valid = sent === token(payload);
      if (!valid) return { status: 401, json: { changed: false } };
      return payload.role === 'admin'
        ? { status: 200, json: { changed: true } }
        : { status: 403, json: { changed: false } };
    },
  });
  assert.equal(result.findings[0].type, 'jwt_claim_bfla');
});

test('método mutável é recusado antes do transporte', async () => {
  const calls = [];
  const result = await runJwtClaimAuthzDiff({
    url: 'https://lab.invalid/api/default',
    token: token({ sub: 'alice', role: 'user' }),
    secretRef: 'memory:fixture',
    resolveSecret: async () => Buffer.from('fixture-secret'),
    allowActive: true,
    cases: [{
      claim: 'role', value: 'admin', kind: 'privilege', effectPath: 'changed',
      method: 'POST', body: JSON.stringify({ operation: 'restricted' }), headers: { 'X-Case': 'role' },
    }],
    transport: async ({ token: sent, method, body, headers }) => {
      calls.push({ sent, method, body, headers });
      const payload = JSON.parse(Buffer.from(sent.split('.')[1], 'base64url').toString());
      const valid = sent === token(payload);
      if (!valid) return { status: 401, json: { changed: false } };
      return { status: payload.role === 'admin' ? 200 : 403, json: { changed: payload.role === 'admin' } };
    },
  });
  assert.equal(result.findings.length, 0);
  assert.equal(result.reason, 'non_read_only_method_rejected');
  assert.equal(calls.length, 0);
});

test('gate ativo e escopo impedem qualquer transporte', async () => {
  let calls = 0;
  const common = {
    url: 'https://outside.invalid/api/me',
    token: token({ sub: 'alice' }),
    secretRef: 'memory:fixture',
    resolveSecret: async () => Buffer.from('fixture-secret'),
    cases: [{ claim: 'sub', value: 'bob' }],
    transport: async () => { calls += 1; return { status: 200 }; },
  };
  const inactive = await runJwtClaimAuthzDiff(common);
  const outOfScope = await runJwtClaimAuthzDiff({ ...common, allowActive: true, urlAllowed: () => false });
  assert.equal(inactive.reason, 'active_not_authorized');
  assert.equal(outOfScope.reason, 'out_of_scope');
  assert.equal(calls, 0);
});
