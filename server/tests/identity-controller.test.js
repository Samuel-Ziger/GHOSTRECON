import test from 'node:test';
import assert from 'node:assert/strict';
import {
  mergeIdentityBodyFromEnv,
  normalizeIdentityOptions,
  resolveEffectiveIdentityConfig,
  shouldEnableIdentity,
  createIdentityController,
} from '../modules/identity-controller.mjs';

test('mergeIdentityBodyFromEnv accepts null-like', () => {
  const a = mergeIdentityBodyFromEnv(null);
  assert.equal(typeof a, 'object');
});

test('mergeIdentityBodyFromEnv accepts injected env and preserves explicit empty pool', () => {
  const env = { GHOSTRECON_PROXY_POOL: '127.0.0.1:8080' };
  assert.deepEqual(
    mergeIdentityBodyFromEnv({}, env).proxyPool,
    ['127.0.0.1:8080'],
  );
  assert.deepEqual(
    mergeIdentityBodyFromEnv({ proxyPool: [] }, env).proxyPool,
    [],
  );
});

test('shouldEnableIdentity: module flag', () => {
  assert.equal(
    shouldEnableIdentity({
      modules: ['identity_rotation'],
      identityBody: {},
      env: { GHOSTRECON_IDENTITY_ROTATION: '0' },
    }),
    true,
  );
});

test('shouldEnableIdentity: proxy pool implies on', () => {
  assert.equal(
    shouldEnableIdentity({ modules: [], identityBody: { proxyPool: ['http://127.0.0.1:9'] } }),
    true,
  );
});

test('shouldEnableIdentity: request explícito desliga módulo e ambiente', () => {
  assert.equal(
    shouldEnableIdentity({
      modules: ['identity_rotation'],
      identityBody: {
        enabled: false,
        proxyPool: ['http://127.0.0.1:9'],
      },
      env: { GHOSTRECON_IDENTITY_ROTATION: '1' },
    }),
    false,
  );
});

test('normalizeIdentityOptions merges env-shaped body', () => {
  const n = normalizeIdentityOptions(
    [],
    { enabled: true, proxyPool: [], behavior: false },
    { env: { GHOSTRECON_PROXY_POOL: '127.0.0.1:8080' } },
  );
  assert.equal(n.enabled, true);
  assert.equal(n.behavior, false);
  assert.equal(n.resolved, true);
  assert.deepEqual(n.proxyPool, []);
  assert.equal(Object.isFrozen(n), false);
});

test('resolveEffectiveIdentityConfig aplica request > módulo > env > defaults', () => {
  const env = {
    GHOSTRECON_IDENTITY_ROTATION: '1',
    GHOSTRECON_PROXY_POOL: '127.0.0.1:8080',
    GHOSTRECON_PROXY_ROTATION: 'random',
    GHOSTRECON_TOR_ISOLATE: '1',
  };
  const requestWins = resolveEffectiveIdentityConfig({
    modules: ['identity_rotation'],
    identityBody: {
      enabled: false,
      behavior: false,
      proxyPool: [],
      rotation: 'fixed',
      isolate: false,
    },
    env,
  });
  assert.equal(requestWins.enabled, false);
  assert.equal(requestWins.behavior, false);
  assert.deepEqual(requestWins.proxyPool, []);
  assert.equal(requestWins.rotation, 'fixed');
  assert.equal(requestWins.isolate, false);

  const moduleWins = resolveEffectiveIdentityConfig({
    modules: ['identity_rotation'],
    identityBody: {},
    env: { GHOSTRECON_IDENTITY_ROTATION: '0' },
  });
  assert.equal(moduleWins.enabled, true);

  const envWins = resolveEffectiveIdentityConfig({
    modules: [],
    identityBody: {},
    env,
  });
  assert.equal(envWins.enabled, true);
  assert.equal(envWins.rotation, 'fixed');
  assert.equal(envWins.isolate, true);
  assert.equal(envWins.proxyPool.length, 1);

  const defaults = resolveEffectiveIdentityConfig({
    modules: [],
    identityBody: {},
    env: {},
  });
  assert.equal(defaults.enabled, false);
  assert.equal(defaults.behavior, true);
  assert.deepEqual(defaults.proxyPool, []);
  assert.equal(defaults.rotation, 'fixed');
  assert.equal(defaults.isolate, false);
});

test('resolveEffectiveIdentityConfig retorna snapshot profundamente congelado', () => {
  const snapshot = resolveEffectiveIdentityConfig({
    modules: ['identity_rotation'],
    identityBody: { proxyPool: ['127.0.0.1:8080'] },
    env: {},
  });
  assert.equal(Object.isFrozen(snapshot), true);
  assert.equal(Object.isFrozen(snapshot.proxyPool), true);
  assert.equal(Object.isFrozen(snapshot.modules), true);
  assert.throws(() => snapshot.proxyPool.push('127.0.0.1:9090'), TypeError);
});

test('createIdentityController disabled uses plain fetch path stats', () => {
  const c = createIdentityController({ enabled: false, modules: [] });
  assert.equal(c.enabled, false);
  const s = c.getStats();
  assert.ok('backoffMul' in s);
});

test('createIdentityController não relê env quando recebe snapshot resolved', () => {
  const ctrl = createIdentityController({
    resolved: true,
    enabled: true,
    behavior: true,
    proxyPool: [],
    rotation: 'fixed',
    isolate: false,
    modules: [],
    env: {
      GHOSTRECON_PROXY_POOL: '127.0.0.1:8080',
      GHOSTRECON_PROXY_ROTATION: 'random',
      GHOSTRECON_TOR_ISOLATE: '1',
    },
  });
  assert.deepEqual(ctrl.getProxyPool(), []);
  assert.equal(ctrl.getStats().rotationStrategy, 'fixed');
  assert.equal(ctrl.getStats().isolate, false);
  assert.equal(ctrl.getStats().resolved, true);
});

test('createIdentityController preserva fallback de env para caller legado', () => {
  const ctrl = createIdentityController({
    enabled: true,
    modules: [],
    env: {
      GHOSTRECON_PROXY_POOL: '127.0.0.1:8080',
      GHOSTRECON_PROXY_ROTATION: 'fixed',
      GHOSTRECON_TOR_ISOLATE: '1',
    },
  });
  assert.equal(ctrl.getProxyPool().length, 1);
  assert.equal(ctrl.getStats().rotationStrategy, 'fixed');
  assert.equal(ctrl.getStats().isolate, true);
  assert.equal(ctrl.getStats().resolved, false);
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
  }, { env: {} });
  assert.equal(out.enabled, true);
  assert.equal(out.rotation, 'fixed');
  assert.equal(out.proxyPool.length, 1);
});

test('identity-controller não repete 403 nem consome o body antecipadamente', async () => {
  const requests = [];
  const ctrl = createIdentityController({
    enabled: true,
    resolved: true,
    behavior: true,
    proxyPool: [],
    rotation: 'round_robin',
    runId: 'run-stable',
    modules: [],
    fetchImpl: async (_url, init) => {
      requests.push(init);
      return new Response('<html>Attention Required cloudflare challenge-platform</html>', {
        status: 403,
        headers: { 'content-type': 'text/html' },
      });
    },
  });
  const response = await ctrl.fetchHtmlProbe('https://target.test/', { headers: {} });
  assert.equal(response.status, 403);
  assert.equal(requests.length, 1);
  assert.equal(ctrl.getStats().rotationStrategy, 'fixed');
  assert.equal(ctrl.getStats().captchaResponses, 0);
});

test('identity-controller reutiliza e encerra dispatcher HTTP', async () => {
  let created = 0;
  let closed = 0;
  const dispatcher = { close: async () => { closed += 1; } };
  const ctrl = createIdentityController({
    enabled: true,
    resolved: true,
    behavior: false,
    proxyPool: ['http://127.0.0.1:8080'],
    modules: [],
    httpProxyDispatcherFactory: async () => {
      created += 1;
      return dispatcher;
    },
    fetchImpl: async (_url, init) => {
      assert.equal(init.dispatcher, dispatcher);
      return new Response(null, { status: 204 });
    },
  });
  await ctrl.fetchHtmlProbe('https://target.test/');
  await ctrl.fetchHtmlProbe('https://target.test/again');
  assert.equal(created, 1);
  await ctrl.dispose();
  assert.equal(closed, 1);
  await assert.rejects(() => ctrl.fetchHtmlProbe('https://target.test/after'), /encerrado/);
});

test('identity-controller registra Retry-After sem retry imediato', async () => {
  let current = 1_000;
  const sleeps = [];
  const requests = [];
  const ctrl = createIdentityController({
    enabled: true,
    resolved: true,
    proxyPool: [],
    rotation: 'fixed',
    modules: [],
    now: () => current,
    sleepImpl: async (ms) => {
      sleeps.push(ms);
      current += ms;
    },
    fetchImpl: async (_url, init) => {
      requests.push(init);
      if (requests.length === 1) {
        return new Response('rate limited', { status: 429, headers: { 'retry-after': '2' } });
      }
      return new Response('ok', { status: 200 });
    },
  });
  assert.equal((await ctrl.fetchVerifyGet('https://target.test/a', {})).status, 429);
  assert.equal(requests.length, 1);
  assert.equal((await ctrl.fetchVerifyGet('https://target.test/b', {})).status, 200);
  assert.equal(requests.length, 2);
  assert.ok(sleeps.some((ms) => ms >= 2_000));
  assert.equal(requests[0].headers['User-Agent'], requests[1].headers['User-Agent']);
});

test('identity-controller cancela espera de backoff antes da próxima rede', async () => {
  const controller = new AbortController();
  let calls = 0;
  let releaseSleep;
  const ctrl = createIdentityController({
    enabled: true,
    resolved: true,
    proxyPool: [],
    modules: [],
    now: () => 1_000,
    sleepImpl: () => new Promise((resolve) => { releaseSleep = resolve; }),
    fetchImpl: async () => {
      calls += 1;
      return new Response('rate', { status: 429, headers: { 'retry-after': '30' } });
    },
  });
  await ctrl.fetchVerifyGet('https://target.test/first', {});
  const pending = ctrl.fetchVerifyGet('https://target.test/second', { signal: controller.signal });
  controller.abort(new Error('operator stop'));
  await assert.rejects(pending, /operator stop/);
  releaseSleep?.();
  assert.equal(calls, 1);
});
