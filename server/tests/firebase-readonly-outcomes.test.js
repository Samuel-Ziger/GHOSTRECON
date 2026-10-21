import test from 'node:test';
import assert from 'node:assert/strict';
import { runFirebaseAudit } from '../modules/firebase-audit.mjs';

const databaseURL = 'https://firebase.example.test';
const response = (body, status = 200, extra = {}) => ({ status, headers: {}, body, error: null, ...extra });

test('Firebase não trata HTML, JSON inválido ou resposta truncada como leitura pública', async () => {
  for (const fixture of [
    response(`<html>${'fixture'.repeat(100)}</html>`),
    response('{"data":'),
    response('{"data":true}', 200, { headers: { 'content-type': 'text/html' } }),
    response('{"data":true}', 200, { truncated: true }),
    response('', 200, { headers: { 'content-length': 100_000 } }),
  ]) {
    const result = await runFirebaseAudit({ databaseURL }, { requestImpl: async () => fixture });
    assert.deepEqual(result.findings, []);
    assert.ok(['invalid_response', 'response_too_large'].includes(result.summary.results.rtdbRead));
    assert.equal(result.summary.outcomes.rtdbRead.conclusive, false);
    assert.equal(result.summary.status, 'partial');
  }
});

test('Firebase distingue negação, ausência de dados, erro HTTP e falha de rede; nunca declara ok', async () => {
  for (const [fixture, state, conclusive] of [
    [response('{}', 403), 'access_denied', true],
    [response('{"error":"Permission denied"}'), 'access_denied', true],
    [response('null'), 'no_data_observed', true],
    [response('{}'), 'no_data_observed', true],
    [response('{}', 404), 'not_found', false],
    [response('{}', 429), 'rate_limited', false],
    [response('{}', 500), 'http_error', false],
    [response('', null, { error: 'connection closed' }), 'network_error', false],
    [response('', null, { error: 'timeout' }), 'timeout', false],
  ]) {
    const result = await runFirebaseAudit({ databaseURL }, { requestImpl: async () => fixture });
    assert.equal(result.summary.results.rtdbRead, state);
    assert.equal(result.summary.outcomes.rtdbRead.conclusive, conclusive);
    assert.deepEqual(result.findings, []);
  }
});

test('Firebase leitura anônima vira observação de baixo risco sem afirmar impacto ou vazar dados', async () => {
  const result = await runFirebaseAudit({
    databaseURL,
    apiKey: 'synthetic-public-config-key',
    firestoreUrl: 'https://firebase.example.test/documents',
    firestoreCollections: ['catalog'],
    storageUrl: 'https://firebase.example.test/storage',
  }, {
    requestImpl: async (url, options) => {
      assert.equal(options.method || 'GET', 'GET');
      if (url.includes('/documents/')) return response('{"documents":[{"name":"catalog/item","fields":{"private":"sensitive-fixture"}}]}');
      if (url.includes('/storage')) return response('{"items":[{"name":"personal-private-filename"}],"nextPageToken":"private-page-token"}');
      return response('{"sensitive-private-key":true}');
    },
  });
  assert.equal(result.findings.length, 3);
  for (const finding of result.findings) {
    assert.equal(finding.prio, 'low');
    assert.equal(finding.cvss, null);
    assert.equal(finding.meta.evidenceStatus, 'public_read_observed');
    assert.equal(finding.meta.impactVerified, false);
    assert.equal(finding.meta.assessment, 'candidate_requires_owner_review');
  }
  assert.equal(result.summary.critical, 0);
  assert.equal(result.summary.high, 0);
  assert.doesNotMatch(JSON.stringify(result), /sensitive-fixture|personal-private-filename|private-page-token|sensitive-private-key/);
});

test('Firebase configuração pública e RBAC no frontend não provam bypass', async () => {
  const result = await runFirebaseAudit({
    apiKey: 'synthetic-public-config-key',
    projectId: 'fixture-project',
    bundleText: 'router.beforeEach(() => hasRole("ADMIN")); // permissions.js',
  }, { requestImpl: async () => response('{}', 403) });
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].type, 'firebase_client_side_rbac');
  assert.equal(result.findings[0].prio, 'info');
  assert.equal(result.findings[0].meta.evidenceStatus, 'inventory');
  assert.equal(result.summary.results.rtdbRead, 'access_denied');
  assert.equal(result.summary.results.firestoreRead, 'no_observed_collections');
});

test('Firebase rejeita collections inválidas e preserva outcomes individuais de cobertura mista', async () => {
  const calls = [];
  const result = await runFirebaseAudit({
    apiKey: 'synthetic-public-config-key',
    firestoreUrl: 'https://firebase.example.test/documents',
    firestoreCollections: ['../users', 'users?x=1', '', null, 'public', 'denied', 'invalid', 'offline'],
  }, {
    requestImpl: async (url) => {
      calls.push(url);
      if (url.includes('/public?')) return response('{"documents":[{"name":"public/item"}]}');
      if (url.includes('/denied?')) return response('{}', 403);
      if (url.includes('/invalid?')) return response('{"documents":"not-a-document-array"}');
      return response('', null, { error: 'offline' });
    },
  });
  assert.equal(calls.length, 4);
  assert.equal(result.findings.length, 1);
  assert.equal(result.summary.results.firestoreRead, 'mixed_outcomes');
  assert.deepEqual(result.summary.outcomes.firestoreRead.collections.map(({ state }) => state), [
    'public_data_observed', 'access_denied', 'invalid_response', 'network_error',
  ]);
  assert.equal(result.summary.status, 'partial');
});

test('Firebase identifica Storage inválido e bloqueio de escopo sem declarar segurança', async () => {
  for (const body of ['<html>catch-all</html>', '{"items":[{"unexpected":true}]}', '{"items":"not-an-array"}']) {
    const result = await runFirebaseAudit({
      apiKey: 'synthetic-public-config-key',
      storageUrl: 'https://firebase.example.test/storage',
    }, { requestImpl: async () => response(body) });
    assert.equal(result.summary.results.storage, 'invalid_response');
    assert.deepEqual(result.findings, []);
  }
  let calls = 0;
  const result = await runFirebaseAudit({ databaseURL }, {
    urlAllowed: (url) => !url.includes('.json'),
    requestImpl: async () => { calls += 1; return response('{"data":true}'); },
  });
  assert.equal(calls, 0);
  assert.equal(result.summary.results.rtdbRead, 'out_of_scope');
  assert.equal(result.summary.status, 'partial');
});

test('Firebase deadline local chega ao request injetado mesmo com sinal pai ativo', async () => {
  const controller = new AbortController();
  let receivedSignal;
  const result = await runFirebaseAudit({ databaseURL }, {
    signal: controller.signal,
    requestTimeoutMs: 10,
    requestImpl: async (_url, { signal }) => {
      receivedSignal = signal;
      return new Promise((_resolve, reject) => {
        const guard = setTimeout(() => reject(new Error('fixture timeout failed')), 500);
        signal.addEventListener('abort', () => { clearTimeout(guard); reject(signal.reason); }, { once: true });
      });
    },
  });
  assert.equal(receivedSignal.aborted, true);
  assert.equal(controller.signal.aborted, false);
  assert.equal(result.summary.results.rtdbRead, 'timeout');
  assert.equal(result.summary.status, 'partial');
  assert.deepEqual(result.findings, []);
});

test('Firebase mantém razão de cancelamento do operador e não inicia outra leitura', async () => {
  const controller = new AbortController();
  const reason = new Error('operator cancellation fixture');
  let calls = 0;
  const running = runFirebaseAudit({
    databaseURL,
    apiKey: 'synthetic-public-config-key',
    storageUrl: 'https://firebase.example.test/storage',
  }, {
    signal: controller.signal,
    requestTimeoutMs: 100,
    requestImpl: async (_url, { signal }) => {
      calls += 1;
      controller.abort(reason);
      throw signal.reason;
    },
  });
  await assert.rejects(running, (error) => error === reason);
  assert.equal(calls, 1);
});
