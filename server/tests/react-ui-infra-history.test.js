import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createServer } from 'vite';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const vite = await createServer({
  root: ROOT,
  appType: 'custom',
  logLevel: 'silent',
  server: { middlewareMode: true },
});
after(async () => vite.close());

const {
  createInfraHistoryService,
  InfraHistoryRequestError,
  isInfraHistoryTarget,
} = await vite.ssrLoadModule('/frontend/src/features/infra-history/service.ts');

function storage(values = {}) {
  const map = new Map(Object.entries(values));
  return {
    getItem: (key) => map.get(key) ?? null,
    setItem: (key, value) => map.set(key, String(value)),
    removeItem: (key) => map.delete(key),
  };
}

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

test('auto-auth usa a base file://, persiste a chave e valida em /api/runs', async () => {
  const local = storage({ ghostrecon_api_base: 'http://127.0.0.1:4999///' });
  const calls = [];
  const signal = new AbortController().signal;
  const fetchImpl = async (url, init = {}) => {
    calls.push({ url: String(url), init });
    if (String(url).endsWith('/api/setup/auto-auth')) return json({ apiKey: 'a'.repeat(24) });
    if (String(url).endsWith('/api/runs')) return json({ runs: [{ id: 7 }] });
    throw new Error(`URL inesperada: ${url}`);
  };
  const service = createInfraHistoryService({
    fetchImpl,
    protocol: 'file:',
    storage: local,
  });

  const result = await service.autoAuth({ signal });
  assert.equal(result.skipped, false);
  assert.equal(result.persisted, true);
  assert.equal(result.authenticated, true);
  assert.equal(result.authTest.runCount, 1);
  assert.deepEqual(calls.map((call) => call.url), [
    'http://127.0.0.1:4999/api/setup/auto-auth',
    'http://127.0.0.1:4999/api/runs',
  ]);
  assert.equal(calls[0].init.signal, signal);
  assert.equal(calls[1].init.signal, signal);
  assert.equal(calls[1].init.headers['X-API-Key'], 'a'.repeat(24));
  assert.deepEqual(JSON.parse(local.getItem('ghostrecon_auth_json')), {
    ghostreconApiKey: 'a'.repeat(24),
    headers: {},
    cookie: '',
    programHeadersEnabled: false,
    programHeadersRaw: '',
  });

  const skipped = await service.autoAuth();
  assert.equal(skipped.skipped, true);
  assert.equal(skipped.apiKey, 'a'.repeat(24));
  assert.equal(calls.length, 2);
});

test('infra e histórico normalizam respostas e preservam auth/signal', async () => {
  const local = storage({
    ghostrecon_api_base: 'https://ghost.local/base/',
    ghostrecon_auth_json: JSON.stringify({ ghostreconApiKey: 'secret-key' }),
  });
  const calls = [];
  const signal = new AbortController().signal;
  const fetchImpl = async (url, init = {}) => {
    const href = String(url);
    calls.push({ url: href, init });
    if (href.endsWith('/api/auto-rag/status')) {
      return json({ ok: true, count: '3', counts: { lessons: '2', bad: 'x' }, recent: [{ id: 1 }] });
    }
    if (href.endsWith('/api/intel/example.com')) {
      return json({ target: 'EXAMPLE.COM', totalUnique: '2', items: [{ type: 'dns' }] });
    }
    if (href.endsWith('/api/tunnel/status')) {
      return json({ ok: true, active: 1, tor: 'active', openvpn: '' });
    }
    if (href.endsWith('/api/runs?limit=500')) {
      return json({ runs: [{ id: 7, target: 'example.com' }] });
    }
    if (href.endsWith('/api/runs/7')) {
      return json({ id: 7, target: 'example.com', stats: { endpoints: 2 } });
    }
    if (href.endsWith('/api/manual-validations/example.com')) {
      return json({
        target: 'example.com',
        items: [
          { fingerprint: 'ABC' },
          { fingerprint: 'abc' },
          { fingerprint: '' },
        ],
      });
    }
    if (href.endsWith('/api/ai/lmstudio-check')) {
      return json({ ok: true, model: 'local-model' });
    }
    throw new Error(`URL inesperada: ${url}`);
  };
  const service = createInfraHistoryService({ fetchImpl, protocol: 'file:', storage: local });

  assert.deepEqual(await service.autoRagStatus(signal), {
    ok: true,
    count: 3,
    counts: { lessons: 2, bad: 0 },
    recent: [{ id: 1 }],
    vault: 'auto-rag',
    partition: '',
  });
  assert.deepEqual(await service.intelCorpus(' EXAMPLE.COM ', signal), {
    target: 'example.com',
    totalUnique: 2,
    items: [{ type: 'dns' }],
  });
  assert.deepEqual(await service.tunnelStatus(signal), {
    ok: true,
    active: true,
    tor: 'active',
    openvpn: 'unknown',
  });
  assert.deepEqual((await service.listRuns(999, signal)).runs, [
    { id: 7, target: 'example.com' },
  ]);
  assert.equal((await service.runDetail('7', signal)).id, 7);
  const artifact = await service.downloadRun(7, signal);
  assert.equal(artifact.filename, 'ghostrecon_run_7.json');
  assert.equal(artifact.mimeType, 'application/json');
  assert.deepEqual(JSON.parse(artifact.content), artifact.run);
  const validations = await service.manualValidationFingerprints('Example.COM', signal);
  assert.deepEqual(validations.fingerprints, ['abc']);
  assert.deepEqual(await service.manualValidationFingerprints('invalid target', signal), {
    target: 'invalid target',
    items: [],
    fingerprints: [],
  });
  assert.equal((await service.lmStudioCheck(signal)).model, 'local-model');

  assert.equal(isInfraHistoryTarget('example.com'), true);
  assert.equal(isInfraHistoryTarget('invalid target'), false);
  assert.ok(calls.every((call) => call.url.startsWith('https://ghost.local/base/api/')));
  assert.ok(calls.every((call) => call.init.headers['X-API-Key'] === 'secret-key'));
  assert.ok(calls.every((call) => call.init.signal === signal));
});

test('mutações obtêm CSRF, enviam JSON e expõem erros normalizados', async () => {
  const local = storage({
    ghostrecon_auth_json: JSON.stringify({ ghostreconApiKey: 'admin-key' }),
  });
  const calls = [];
  const signal = new AbortController().signal;
  let csrfIndex = 0;
  const fetchImpl = async (url, init = {}) => {
    const href = String(url);
    calls.push({ url: href, init });
    if (href === '/api/csrf-token') {
      csrfIndex += 1;
      return json({ token: `csrf-${csrfIndex}` });
    }
    if (href === '/api/tool-path-refresh') {
      return json({
        ok: false,
        error: 'PATH_REFRESH_RESTART_REQUIRED',
        message: 'reinicie a stack',
      }, 409);
    }
    if (href === '/api/tunnel/enable') {
      return json({
        ok: true,
        run: { ok: true },
        status: { active: true, tor: 'active', openvpn: 'inactive' },
      });
    }
    if (href === '/api/tunnel/disable') {
      return json({ ok: false, error: 'PLAYBOOK_FAILED' });
    }
    throw new Error(`URL inesperada: ${url}`);
  };
  const service = createInfraHistoryService({ fetchImpl, protocol: 'http:', storage: local });

  await assert.rejects(
    service.refreshToolPath(signal),
    (error) => {
      assert.ok(error instanceof InfraHistoryRequestError);
      assert.equal(error.status, 409);
      assert.equal(error.code, 'PATH_REFRESH_RESTART_REQUIRED');
      assert.equal(error.endpoint, '/api/tool-path-refresh');
      assert.equal(error.message, 'reinicie a stack');
      return true;
    },
  );
  const enabled = await service.enableTunnel({ signal });
  assert.equal(enabled.action, 'enable');
  assert.equal(enabled.status.active, true);
  await assert.rejects(
    service.disableTunnel({ signal }),
    (error) => error instanceof InfraHistoryRequestError
      && error.code === 'PLAYBOOK_FAILED'
      && error.status === 200,
  );

  const posts = calls.filter((call) => call.init.method === 'POST');
  assert.equal(posts.length, 3);
  assert.deepEqual(posts.map((call) => call.init.headers['X-CSRF-Token']), [
    'csrf-1',
    'csrf-2',
    'csrf-3',
  ]);
  assert.ok(posts.every((call) => call.init.headers['X-API-Key'] === 'admin-key'));
  assert.ok(posts.every((call) => call.init.headers['Content-Type'] === 'application/json'));
  assert.ok(posts.every((call) => call.init.signal === signal));
  assert.equal(posts[0].init.body, '{}');
  assert.equal(posts[1].init.body, JSON.stringify({ dryRun: false }));
});

test('CSRF e auto-auth vazios preservam AbortSignal e falham com contexto', async () => {
  const signal = new AbortController().signal;
  const calls = [];
  const fetchImpl = async (url, init = {}) => {
    calls.push({ url: String(url), init });
    if (String(url).endsWith('/api/csrf-token')) return json({ token: 'token-direct' });
    return json({});
  };
  const service = createInfraHistoryService({
    fetchImpl,
    apiBase: () => 'http://127.0.0.1:4888',
    auth: () => ({ ghostreconApiKey: 'key', headers: {}, cookie: '' }),
  });

  assert.equal(await service.requestCsrfToken(signal), 'token-direct');
  assert.equal(calls[0].url, 'http://127.0.0.1:4888/api/csrf-token');
  assert.equal(calls[0].init.headers['X-API-Key'], 'key');
  assert.equal(calls[0].init.signal, signal);
  await assert.rejects(
    service.setupAutoAuth(signal),
    (error) => error instanceof InfraHistoryRequestError
      && error.code === 'AUTO_AUTH_KEY_EMPTY'
      && error.endpoint === '/api/setup/auto-auth',
  );
});
