import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  decodeJwt, analyzeJwt, forgeAlgNone, forgeHsConfusion, forgeKidTraversal,
  bruteforceSecret, adminPromoter,
} from '../modules/jwt-lab.mjs';

function b64url(s) {
  return Buffer.from(typeof s === 'string' ? s : JSON.stringify(s)).toString('base64')
    .replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function makeHs256(secret, header = { alg: 'HS256' }, payload = { sub: 'alice', role: 'user' }) {
  const h = b64url(header);
  const p = b64url(payload);
  const sig = crypto.createHmac('sha256', secret).update(`${h}.${p}`).digest()
    .toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
  return `${h}.${p}.${sig}`;
}

test('jwt: decodeJwt extrai header + payload', () => {
  const t = makeHs256('secret');
  const d = decodeJwt(t);
  assert.equal(d.header.alg, 'HS256');
  assert.equal(d.payload.sub, 'alice');
});

test('jwt: analyzeJwt detecta alg-none', () => {
  const t = `${b64url({ alg: 'none' })}.${b64url({ sub: 'a' })}.`;
  const r = analyzeJwt(t);
  assert.ok(r.findings.find((f) => f.issue === 'alg-none'));
});

test('jwt: analyzeJwt detecta sem expiração', () => {
  const t = makeHs256('s', { alg: 'HS256' }, { sub: 'a' });
  const r = analyzeJwt(t);
  assert.ok(r.findings.find((f) => f.issue === 'no-expiration'));
});

test('jwt: analyzeJwt detecta jku/x5u', () => {
  const t = `${b64url({ alg: 'RS256', jku: 'http://attacker' })}.${b64url({ sub: 'a' })}.x`;
  const r = analyzeJwt(t);
  assert.ok(r.findings.find((f) => f.issue === 'remote-key-url'));
});

test('jwt: forgeAlgNone produz token sem assinatura', () => {
  const orig = makeHs256('s', { alg: 'HS256', kid: '1' }, { sub: 'a', role: 'user' });
  const f = forgeAlgNone(orig, adminPromoter);
  const d = decodeJwt(f);
  assert.equal(d.header.alg, 'none');
  assert.equal(d.payload.role, 'admin');
  assert.equal(d.signature, '');
});

test('jwt: forgeHsConfusion assina com publicKey como secret HMAC', () => {
  const pub = '-----BEGIN PUBLIC KEY-----\nMIIBIjAN...\n-----END PUBLIC KEY-----';
  const orig = makeHs256('s', { alg: 'RS256' }, { sub: 'a', role: 'user' });
  const f = forgeHsConfusion(orig, pub, adminPromoter);
  const d = decodeJwt(f);
  assert.equal(d.header.alg, 'HS256');
  assert.equal(d.payload.role, 'admin');
});

test('jwt: forgeKidTraversal seta kid e assina com secret vazio', () => {
  const orig = makeHs256('s', { alg: 'HS256' }, { sub: 'a' });
  const f = forgeKidTraversal(orig, '../../../../dev/null', '');
  const d = decodeJwt(f);
  assert.equal(d.header.kid, '../../../../dev/null');
});

test('jwt: bruteforceSecret encontra secret na wordlist', () => {
  const t = makeHs256('admin');
  const r = bruteforceSecret(t, { wordlist: ['x', 'y', 'admin', 'z'] });
  assert.equal(r.found, true);
  assert.equal(r.secret, 'admin');
});

test('jwt: bruteforceSecret falha quando secret fora da wordlist', () => {
  const t = makeHs256('absurdly-long-secret-NOT-in-wordlist');
  const r = bruteforceSecret(t, { wordlist: ['x', 'y', 'admin'] });
  assert.equal(r.found, false);
});

test('jwt: bruteforceSecret recusa alg não-simétrico', () => {
  const t = `${b64url({ alg: 'RS256' })}.${b64url({ sub: 'a' })}.fakesig`;
  const r = bruteforceSecret(t, { wordlist: ['a'] });
  assert.equal(r.found, false);
  assert.ok(r.reason.includes('alg-not-symmetric'));
});

test('jwt: adminPromoter eleva role e flags', () => {
  const out = adminPromoter({ role: 'user', isAdmin: false, scope: 'read' });
  assert.equal(out.role, 'admin');
  assert.equal(out.isAdmin, true);
  assert.ok(out.scope.includes('admin'));
});
