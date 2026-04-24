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
