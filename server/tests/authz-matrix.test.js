import test from 'node:test';
import assert from 'node:assert/strict';
import { buildAuthzPlan, runAuthzMatrix, analyzeAuthzResults, fingerprintBody } from '../modules/authz-matrix.mjs';

const personas = [
  { id: 'alice', expectedRole: 'user', headers: { Cookie: 'sid=alice' } },
  { id: 'bob', expectedRole: 'user', headers: { Cookie: 'sid=bob' } },
  { id: 'admin', expectedRole: 'admin', headers: { Cookie: 'sid=admin' } },
];

const requests = [
  { method: 'GET', path: '/api/me', perUser: true },
  { method: 'GET', path: '/api/admin/users', adminOnly: true },
  { method: 'GET', path: '/api/public/posts' },
];

test('authz: buildAuthzPlan multiplica request x persona', () => {
  const plan = buildAuthzPlan(requests, personas);
  assert.equal(plan.length, requests.length * personas.length);
});

test('authz: BOLA detection', async () => {
  const executor = (req, persona) => {
    if (req.path === '/api/me') return { status: 200, fingerprint: 'LEAK_FP', bodyLen: 50 };
    if (req.path === '/api/admin/users') return { status: persona.expectedRole === 'admin' ? 200 : 403, fingerprint: 'admin', bodyLen: 100 };
    return { status: 200, fingerprint: 'public', bodyLen: 30 };
  };
  const result = await runAuthzMatrix({ requests, personas, executor, concurrency: 1 });
  assert.ok(result.findings.find((f) => f.category === 'authz-bola'));
});

test('authz: PRIVESC detection', async () => {
  const executor = (req, persona) => {
    if (req.path === '/api/admin/users') return { status: 200, fingerprint: persona.id, bodyLen: 100 };
    return { status: 200, fingerprint: persona.id, bodyLen: 30 };
  };
  const result = await runAuthzMatrix({ requests, personas, executor });
  const privesc = result.findings.find((f) => f.category === 'authz-privesc');
  assert.ok(privesc);
  assert.equal(privesc.severity, 'critical');
});

test('authz: matriz limpa nao gera vuln', async () => {
  const executor = (req, persona) => {
    if (req.adminOnly) return { status: persona.expectedRole === 'admin' ? 200 : 403, fingerprint: persona.id, bodyLen: 100 };
    if (req.perUser) return { status: 200, fingerprint: persona.id, bodyLen: 50 };
    return { status: 200, fingerprint: 'public', bodyLen: 30 };
  };
  const result = await runAuthzMatrix({ requests, personas, executor });
  assert.equal(result.findings.length, 0);
});

test('authz: fingerprintBody normaliza timestamps e hex', () => {
  const a = fingerprintBody('{"ts":"2026-04-26T10:00:00Z","id":"abc1234567890abcdef0123456789abef"}');
  const b = fingerprintBody('{"ts":"2026-04-27T11:00:00Z","id":"deadbeef1234567890abcdef012345670"}');
  assert.equal(a, b);
});

test('authz: executor obrigatorio', async () => {
  await assert.rejects(() => runAuthzMatrix({ requests: [], personas: [] }), /executor/);
});
