import test from 'node:test';
import assert from 'node:assert/strict';
import {
  mergeIdentityBodyFromEnv,
  normalizeIdentityOptions,
  shouldEnableIdentity,
  createIdentityController,
} from '../modules/identity-controller.mjs';

test('mergeIdentityBodyFromEnv accepts null-like', () => {
  const a = mergeIdentityBodyFromEnv(null);
  assert.equal(typeof a, 'object');
});

test('shouldEnableIdentity: module flag', () => {
  assert.equal(shouldEnableIdentity({ modules: ['identity_rotation'], identityBody: {} }), true);
});

test('shouldEnableIdentity: proxy pool implies on', () => {
  assert.equal(
    shouldEnableIdentity({ modules: [], identityBody: { proxyPool: ['http://127.0.0.1:9'] } }),
    true,
  );
});

test('normalizeIdentityOptions merges env-shaped body', () => {
  const n = normalizeIdentityOptions([], { enabled: true, proxyPool: [], behavior: false });
  assert.equal(n.enabled, true);
  assert.equal(n.behavior, false);
});

test('createIdentityController disabled uses plain fetch path stats', () => {
  const c = createIdentityController({ enabled: false, modules: [] });
  assert.equal(c.enabled, false);
  const s = c.getStats();
  assert.ok('backoffMul' in s);
});

test('identity-controller: normaliza host:port:user:pass para URL com auth', () => {
  const ctrl = createIdentityController({
    enabled: true,
    proxyPool: ['31.59.20.176:6754:alice:secret123'],
    modules: [],
  });
  const pool = ctrl.getProxyPool();
  assert.equal(pool.length, 1);
  assert.match(pool[0], /^http:\/\/alice:secret123@31\.59\.20\.176:6754\/$/);
});

test('identity-controller: aceita user:pass@host:port e host:port', () => {
  const ctrl = createIdentityController({
    enabled: true,
    proxyPool: ['bob:pw@198.23.239.134:6540', '127.0.0.1:8080'],
    modules: [],
  });
  const pool = ctrl.getProxyPool();
  assert.equal(pool.length, 2);
  assert.match(pool[0], /^http:\/\/bob:pw@198\.23\.239\.134:6540\/$/);
  assert.match(pool[1], /^http:\/\/127\.0\.0\.1:8080\/$/);
});

test('normalizeIdentityOptions: expõe rotação quando enviada no body', () => {
  const out = normalizeIdentityOptions([], {
    enabled: true,
    rotation: 'random',
    proxyPool: ['127.0.0.1:8080'],
  });
  assert.equal(out.enabled, true);
  assert.equal(out.rotation, 'random');
  assert.equal(out.proxyPool.length, 1);
});
