import test from 'node:test';
import assert from 'node:assert/strict';
import { detectWaf, mutatePayload, tryWithMutations } from '../modules/payload-mutator.mjs';

test('mutator: detectWaf identifica Cloudflare via header', () => {
  const r = detectWaf({ status: 403, headers: { 'CF-Ray': 'abc-DFW' }, body: 'Attention Required' });
  assert.equal(r.vendor, 'cloudflare');
  assert.equal(r.blocked, true);
});

test('mutator: detectWaf identifica AWS WAF via body', () => {
  const r = detectWaf({ status: 403, headers: {}, body: 'Request blocked by AWS WAF rule' });
  assert.equal(r.vendor, 'aws-waf');
});

test('mutator: detectWaf null vendor para resposta limpa', () => {
  const r = detectWaf({ status: 200, headers: {}, body: 'ok' });
  assert.equal(r.vendor, null);
  assert.equal(r.blocked, false);
});

test('mutator: mutatePayload gera variações', () => {
  const v = mutatePayload('<script>alert(1)</script>');
  assert.ok(v.length >= 5);
  assert.ok(v.some((x) => /sCrIpT/.test(x)));
  assert.ok(v.some((x) => /%3C/.test(x)));
});

test('mutator: mutatePayload SQL inclui /**/ comments', () => {
  const v = mutatePayload("' UNION SELECT 1,2 FROM users --");
  assert.ok(v.some((x) => x.includes('/**/')));
});

test('mutator: tryWithMutations para no primeiro não-bloqueado', async () => {
  let calls = 0;
  const exec = async (variant) => {
    calls++;
    if (variant.includes('sCrIpT')) return { status: 200, body: 'ok', headers: {} };
    return { status: 403, body: 'blocked by cf', headers: { 'cf-ray': 'x' } };
  };
  const r = await tryWithMutations('<script>alert(1)</script>', exec, { maxAttempts: 8 });
  assert.equal(r.ok, true);
  assert.ok(/sCrIpT/.test(r.variant));
});

test('mutator: tryWithMutations exhausted quando tudo bloqueado', async () => {
  const exec = async () => ({ status: 403, body: 'blocked', headers: { 'cf-ray': 'x' } });
  const r = await tryWithMutations('xyz', exec, { maxAttempts: 3 });
  assert.equal(r.ok, false);
  assert.equal(r.exhausted, true);
});
