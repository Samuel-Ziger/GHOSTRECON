import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createStableRequestPolicy,
  pickStealthUserAgent,
} from '../modules/request-policy.js';

test('stealth usa User-Agent estável para o mesmo plano', () => {
  const modules = ['stealth_requests', 'security_headers'];
  assert.equal(pickStealthUserAgent(modules), pickStealthUserAgent([...modules].reverse()));
});

test('política estável não repete nem troca identidade em 403', async () => {
  const calls = [];
  const policy = createStableRequestPolicy({
    modules: ['stealth_requests'],
    sleepImpl: async () => {},
    fetchImpl: async (_url, init) => {
      calls.push(init);
      return new Response('blocked', { status: 403 });
    },
  });
  const response = await policy.fetch('https://example.test/');
  assert.equal(response.status, 403);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].headers.get('user-agent'), policy.userAgent);
  assert.deepEqual(policy.stats(), {
    enabled: true,
    userAgent: policy.userAgent,
    requests: 1,
    retries: 0,
    identityRotations: 0,
  });
});

