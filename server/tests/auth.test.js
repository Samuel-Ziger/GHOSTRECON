/**
 * Auth + RBAC unit tests
 *
 * Cobertura:
 *   - API key valida / inválida / curta / role bad
 *   - JWT HS256 valido / expirado / alg=none rejeitado / role bad
 *   - requireAuth allowlist
 *   - requireScope allow/deny + escalada intrusiva
 *   - reconBodyIsIntrusive
 *   - audit log NDJSON é criado
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { createHmac, randomBytes } from 'crypto';

const KEY_OPERATOR = randomBytes(20).toString('base64url'); // 27 chars
const KEY_RED = randomBytes(20).toString('base64url');
const KEY_ADMIN = randomBytes(20).toString('base64url');
const JWT_SECRET = randomBytes(32).toString('base64url');

// O módulo lê env no initAuth — definir antes do import.
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'ghostrecon-auth-'));
process.env.AUTH_MODE = 'apikey';
process.env.AUTH_DISABLE = '0';
process.env.AUTH_API_KEYS = `${KEY_OPERATOR}:operator:test-op|${KEY_RED}:red:test-red|${KEY_ADMIN}:admin:test-adm`;
process.env.AUTH_JWT_SECRET = JWT_SECRET;
process.env.AUTH_AUDIT_DIR = TMP;

const {
  initAuth,
  requireAuth,
  requireScope,
  requireRole,
  reconBodyIsIntrusive,
  signJwtHs256,
  generateApiKey,
  ROLE_SCOPES,
  _authStateForTests,
} = await import('../modules/auth.js');

initAuth();

// ─── Helpers de mock req/res ────────────────────────────────────────────────
function makeReq({ headers = {}, url = '/api/x', method = 'POST', body = {}, ip = '10.0.0.1' } = {}) {
  return {
    headers: { 'user-agent': 'test', ...headers },
    socket: { remoteAddress: ip },
    body,
    url,
    originalUrl: url,
    method,
  };
}
function makeRes() {
  const res = {};
  res.statusCode = 200;
  res.body = null;
  res.status = (c) => { res.statusCode = c; return res; };
  res.json = (j) => { res.body = j; return res; };
  res.setHeader = () => res;
  res.send = (s) => { res.body = s; return res; };
  return res;
}
function callMw(mw, req) {
  return new Promise((resolve) => {
    const res = makeRes();
    let nextCalled = false;
    const result = mw(req, res, () => { nextCalled = true; resolve({ next: true, req, res }); });
    if (result && typeof result.then === 'function') {
      result.then(() => { if (!nextCalled) resolve({ next: false, req, res }); });
    } else {
      // sync — middleware either called next() or sent response
      setImmediate(() => { if (!nextCalled) resolve({ next: false, req, res }); });
    }
  });
}

// ─── Boot summary ───────────────────────────────────────────────────────────
test('initAuth registou 3 api keys + jwt HS256', () => {
  const s = _authStateForTests();
  assert.equal(s.ready, true);
  assert.equal(s.mode, 'apikey');
  assert.equal(s.disabled, false);
  assert.equal(s.apiKeys, 3);
  assert.equal(s.jwt.hs256, true);
});

test('ROLE_SCOPES tem expected role hierarchy', () => {
  assert.deepEqual(ROLE_SCOPES.viewer, ['recon.read']);
  assert.ok(ROLE_SCOPES.operator.includes('recon.run'));
  assert.ok(!ROLE_SCOPES.operator.includes('recon.intrusive'));
  assert.ok(ROLE_SCOPES.red.includes('recon.intrusive'));
  assert.deepEqual(ROLE_SCOPES.admin, ['*']);
});

// ─── requireAuth: API key ───────────────────────────────────────────────────
test('requireAuth: sem token → 401', async () => {
  const mw = requireAuth();
  const { next, res } = await callMw(mw, makeReq());
  assert.equal(next, false);
  assert.equal(res.statusCode, 401);
  assert.equal(res.body.error, 'auth required');
});

test('requireAuth: token inválido → 401', async () => {
  const mw = requireAuth();
  const r = makeReq({ headers: { authorization: 'Bearer chave-que-nao-existe-12345678' } });
  const { next, res } = await callMw(mw, r);
  assert.equal(next, false);
  assert.equal(res.statusCode, 401);
});

test('requireAuth: API key via X-API-Key → next + principal', async () => {
  const mw = requireAuth();
  const r = makeReq({ headers: { 'x-api-key': KEY_OPERATOR } });
  const { next, req } = await callMw(mw, r);
  assert.equal(next, true);
  assert.equal(req.principal.role, 'operator');
  assert.equal(req.principal.via, 'apikey');
});

test('requireAuth: API key via Bearer → next', async () => {
  const mw = requireAuth();
  const r = makeReq({ headers: { authorization: `Bearer ${KEY_RED}` } });
  const { next, req } = await callMw(mw, r);
  assert.equal(next, true);
  assert.equal(req.principal.role, 'red');
});

test('requireAuth: allowlist /api/health → next sem token', async () => {
  const mw = requireAuth({ allowlist: [/^\/api\/health$/] });
  const { next } = await callMw(mw, makeReq({ url: '/api/health', method: 'GET' }));
  assert.equal(next, true);
});

// ─── requireAuth: JWT ───────────────────────────────────────────────────────
test('JWT HS256 válido → autentica como red', async () => {
  const tok = signJwtHs256({
    sub: 'alice',
    role: 'red',
    exp: Math.floor(Date.now() / 1000) + 3600,
  });
  const mw = requireAuth();
  const r = makeReq({ headers: { authorization: `Bearer ${tok}` } });
  const { next, req } = await callMw(mw, r);
  assert.equal(next, true);
  assert.equal(req.principal.role, 'red');
  assert.equal(req.principal.via, 'jwt');
  assert.equal(req.principal.sub, 'alice');
});

test('JWT expirado → 401', async () => {
  const tok = signJwtHs256({
    sub: 'bob',
    role: 'operator',
    exp: Math.floor(Date.now() / 1000) - 60,
  });
  const mw = requireAuth();
  const r = makeReq({ headers: { authorization: `Bearer ${tok}` } });
  const { next, res } = await callMw(mw, r);
  assert.equal(next, false);
  assert.equal(res.statusCode, 401);
});

test('JWT alg=none → rejeitado', async () => {
  const enc = (o) =>
    Buffer.from(JSON.stringify(o), 'utf8').toString('base64')
      .replace(/=+$/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const tok = `${enc({ alg: 'none', typ: 'JWT' })}.${enc({ sub: 'mallory', role: 'admin' })}.`;
  const mw = requireAuth();
  const r = makeReq({ headers: { authorization: `Bearer ${tok}` } });
  const { next, res } = await callMw(mw, r);
  assert.equal(next, false);
  assert.equal(res.statusCode, 401);
});

test('JWT com role inválido → 401', async () => {
  const tok = signJwtHs256({
    sub: 'eve',
    role: 'superuser',
    exp: Math.floor(Date.now() / 1000) + 60,
  });
  const mw = requireAuth();
  const r = makeReq({ headers: { authorization: `Bearer ${tok}` } });
  const { next, res } = await callMw(mw, r);
  assert.equal(next, false);
  assert.equal(res.statusCode, 401);
});

test('JWT scopes não pode expandir além do role', async () => {
  // operator tenta reclamar recon.intrusive — deve ser filtrado
  const tok = signJwtHs256({
    sub: 'op',
    role: 'operator',
    scopes: ['recon.run', 'recon.intrusive'],
    exp: Math.floor(Date.now() / 1000) + 60,
  });
  const mw = requireAuth();
  const r = makeReq({ headers: { authorization: `Bearer ${tok}` } });
  const { req } = await callMw(mw, r);
  assert.ok(req.principal.scopes.includes('recon.run'));
  assert.ok(!req.principal.scopes.includes('recon.intrusive'));
});

test('JWT signature manipulada → 401', async () => {
  const tok = signJwtHs256({ sub: 'a', role: 'admin', exp: Math.floor(Date.now() / 1000) + 60 });
  const parts = tok.split('.');
  parts[2] = parts[2].slice(0, -2) + 'AA';
  const mw = requireAuth();
  const r = makeReq({ headers: { authorization: `Bearer ${parts.join('.')}` } });
  const { next, res } = await callMw(mw, r);
  assert.equal(next, false);
  assert.equal(res.statusCode, 401);
});

// ─── requireScope ───────────────────────────────────────────────────────────
test('requireScope: operator pode recon.run', async () => {
  const auth = requireAuth();
  const scope = requireScope('recon.run');
  const req = makeReq({ headers: { authorization: `Bearer ${KEY_OPERATOR}` } });
  await callMw(auth, req);
  const { next } = await callMw(scope, req);
  assert.equal(next, true);
});

test('requireScope: viewer NÃO pode recon.run → 403', async () => {
  // Forjar viewer via JWT (não temos api key viewer)
  const tok = signJwtHs256({
    sub: 'v', role: 'viewer', exp: Math.floor(Date.now() / 1000) + 60,
  });
  const auth = requireAuth();
  const scope = requireScope('recon.run');
  const req = makeReq({ headers: { authorization: `Bearer ${tok}` } });
  await callMw(auth, req);
  const { next, res } = await callMw(scope, req);
  assert.equal(next, false);
  assert.equal(res.statusCode, 403);
  assert.match(res.body.error, /missing scope/);
});

test('requireScope: escalada intrusiva — operator com módulos kali → 403', async () => {
  const auth = requireAuth();
  const scope = requireScope('recon.run', { intrusiveCheck: (req) => reconBodyIsIntrusive(req.body) });
  const req = makeReq({
    headers: { authorization: `Bearer ${KEY_OPERATOR}` },
    body: { domain: 'x.com', modules: ['kali_nmap'] },
  });
  await callMw(auth, req);
  const { next, res } = await callMw(scope, req);
  assert.equal(next, false);
  assert.equal(res.statusCode, 403);
  assert.match(res.body.error, /recon\.intrusive/);
});

test('requireScope: escalada intrusiva — red com módulos kali → allow', async () => {
  const auth = requireAuth();
  const scope = requireScope('recon.run', { intrusiveCheck: (req) => reconBodyIsIntrusive(req.body) });
  const req = makeReq({
    headers: { authorization: `Bearer ${KEY_RED}` },
    body: { domain: 'x.com', modules: ['kali_nmap'] },
  });
  await callMw(auth, req);
  const { next } = await callMw(scope, req);
  assert.equal(next, true);
});

test('requireRole: admin OK', async () => {
  const auth = requireAuth();
  const adm = requireRole('admin');
  const req = makeReq({ headers: { authorization: `Bearer ${KEY_ADMIN}` } });
  await callMw(auth, req);
  const { next } = await callMw(adm, req);
  assert.equal(next, true);
});

test('requireRole: red não satisfaz role admin → 403', async () => {
  const auth = requireAuth();
  const adm = requireRole('admin');
  const req = makeReq({ headers: { authorization: `Bearer ${KEY_RED}` } });
  await callMw(auth, req);
  const { next, res } = await callMw(adm, req);
  assert.equal(next, false);
  assert.equal(res.statusCode, 403);
});

// ─── reconBodyIsIntrusive ───────────────────────────────────────────────────
test('reconBodyIsIntrusive: kaliMode → true', () => {
  assert.equal(reconBodyIsIntrusive({ kaliMode: true }), true);
});
test('reconBodyIsIntrusive: opsecProfile aggressive → true', () => {
  assert.equal(reconBodyIsIntrusive({ opsecProfile: 'aggressive' }), true);
});
test('reconBodyIsIntrusive: módulos passivos → false', () => {
  assert.equal(reconBodyIsIntrusive({ modules: ['dns', 'probe', 'wayback'] }), false);
});
test('reconBodyIsIntrusive: módulo sqlmap → true', () => {
  assert.equal(reconBodyIsIntrusive({ modules: ['probe', 'sqlmap'] }), true);
});
test('reconBodyIsIntrusive: módulo cloud_bruteforce → true', () => {
  assert.equal(reconBodyIsIntrusive({ modules: ['cloud_bruteforce'] }), true);
});
test('reconBodyIsIntrusive: shannon_whitebox → true', () => {
  assert.equal(reconBodyIsIntrusive({ modules: ['shannon_whitebox'] }), true);
});

// ─── Audit log file is created ──────────────────────────────────────────────
test('audit log NDJSON é gerado em AUTH_AUDIT_DIR', async () => {
  const auth = requireAuth();
  const scope = requireScope('recon.run');
  // 1 deny
  const r1 = makeReq();
  await callMw(auth, r1);
  // 1 allow
  const r2 = makeReq({ headers: { authorization: `Bearer ${KEY_OPERATOR}` } });
  await callMw(auth, r2);
  await callMw(scope, r2);

  // Force flush — write streams são async
  await new Promise((r) => setTimeout(r, 50));
  const today = new Date().toISOString().slice(0, 10);
  const file = path.join(TMP, `audit-${today}.ndjson`);
  assert.ok(fs.existsSync(file), `esperava ${file}`);
  const lines = fs.readFileSync(file, 'utf8').trim().split('\n').filter(Boolean);
  assert.ok(lines.length >= 2);
  const parsed = lines.map((l) => JSON.parse(l));
  assert.ok(parsed.some((p) => p.decision === 'deny'));
  assert.ok(parsed.some((p) => p.decision === 'allow'));
});

// ─── generateApiKey ─────────────────────────────────────────────────────────
test('generateApiKey produz string com tamanho razoável', () => {
  const k = generateApiKey();
  assert.ok(k.length >= 40);
});
