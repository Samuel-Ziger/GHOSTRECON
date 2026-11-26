import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
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

const model = await vite.ssrLoadModule('/frontend/src/features/pages/vigolium-workbench/model.ts');
const serviceModule = await vite.ssrLoadModule('/frontend/src/features/pages/vigolium-workbench/service.ts');

test('modelo Workbench preserva query, envelopes, grupos, decode e curl', () => {
  assert.equal(model.buildQuery({ limit: 100, q: ' idor ', empty: '', nil: null }), 'limit=100&q=idor');
  assert.deepEqual(model.workbenchRows({ data: { data: [{ id: 1 }], total: 9 } }), {
    rows: [{ id: 1 }],
    total: 9,
  });
  assert.deepEqual(model.workbenchRows({ data: [{ id: 2 }] }), {
    rows: [{ id: 2 }],
    total: 1,
  });
  assert.deepEqual(model.groupBy([
    { host: 'b' }, { host: 'a' }, { host: 'b' },
  ], (item) => item.host), [
    ['b', [{ host: 'b' }, { host: 'b' }]],
    ['a', [{ host: 'a' }]],
  ]);
  assert.equal(model.safeDecode(btoa('GET / HTTP/1.1\r\nHost: a.test\r\n\r\n')), 'GET / HTTP/1.1\r\nHost: a.test\r\n\r\n');
  assert.equal(model.findingHost({ matched_at: ['https://api.example.test/a'] }), 'api.example.test');
  assert.match(model.curlFor({
    method: 'POST',
    url: 'https://api.example.test/items',
    raw_request: 'POST /items HTTP/1.1\r\nHost: api.example.test\r\nContent-Type: application/json\r\n\r\n{"id":1}',
  }), /curl -i -X POST[\s\S]*Content-Type: application\/json[\s\S]*--data/);
  assert.equal(model.REVIEW_TEMPLATES.auth.mode, 'audit');
  assert.equal(model.REVIEW_TEMPLATES.fp.mode, 'query');
});

test('serviço Workbench preserva file://, auth, CSRF e os quinze contratos HTTP', async () => {
  const requests = [];
  const storage = {
    getItem: (key) => key === 'ghostrecon_auth_json'
      ? JSON.stringify({ ghostreconApiKey: 'workbench-key' })
      : null,
  };
  const fetchImpl = async (url, init = {}) => {
    const parsed = new URL(String(url));
    requests.push({ url: parsed, init });
    if (parsed.pathname === '/api/csrf-token') {
      return new Response(JSON.stringify({ token: 'workbench-csrf' }), { status: 200 });
    }
    if (init.method === 'POST') {
      return new Response(JSON.stringify({ ok: true, report: { url: '/reports/imported.html' } }), { status: 200 });
    }
    if (parsed.pathname === '/api/vigolium/server/status') {
      return new Response(JSON.stringify({ ok: true, configured: true }), { status: 200 });
    }
    if (parsed.pathname === '/api/vigolium/modules') {
      return new Response(JSON.stringify({ modules: [{ id: 'idor' }], tags: ['access-control'] }), { status: 200 });
    }
    if (parsed.pathname === '/api/vigolium/reports') {
      return new Response(JSON.stringify({ reports: [{ file: 'report.html' }], total: 1 }), { status: 200 });
    }
    if (/\/(http-records|findings|oast-interactions|agent-sessions)\/[^/]+$/.test(parsed.pathname)) {
      return new Response(JSON.stringify({ data: { id: parsed.pathname.split('/').at(-1) } }), { status: 200 });
    }
    return new Response(JSON.stringify({ data: { data: [{ id: parsed.pathname }], total: 1 } }), { status: 200 });
  };
  const service = serviceModule.createVigoliumWorkbenchService({
    fetchImpl,
    locationLike: { protocol: 'file:' },
    storage,
  });

  assert.equal(service.apiUrl('/api/test'), 'http://127.0.0.1:3847/api/test');
  await service.status();
  await service.scans();
  await service.requests({ search: ' login ', method: 'POST' });
  assert.equal((await service.request('request/1')).id, 'request%2F1');
  await service.findings({ severity: 'high' });
  assert.equal((await service.finding('finding 1')).id, 'finding%201');
  await service.oast({ protocol: 'dns' });
  await service.oastDetail('oast-1');
  await service.agentSessions();
  await service.agentSession('agent-1');
  assert.equal((await service.modules({ q: 'idor', tag: 'access-control', kind: 'active' })).modules[0].id, 'idor');
  assert.equal((await service.reports()).reports[0].file, 'report.html');
  await service.runAgent('audit', { target: 'example.test' });
  await service.importReport({ sourcePath: '/tmp/report.html' });

  assert.equal(requests.length, 15);
  assert.equal(requests.filter(({ url }) => url.pathname === '/api/csrf-token').length, 1);
  assert.equal(requests.filter(({ init }) => init.method === 'POST').length, 2);
  assert.ok(requests.every(({ init }) => init.headers['X-API-Key'] === 'workbench-key'));
  assert.ok(requests.filter(({ init }) => init.method === 'POST').every(
    ({ init }) => init.headers['X-CSRF-Token'] === 'workbench-csrf',
  ));
  const recordsRequest = requests.find(({ url }) => url.pathname.endsWith('/http-records') && url.search);
  assert.equal(recordsRequest.url.searchParams.get('limit'), '100');
  assert.equal(recordsRequest.url.searchParams.get('search'), 'login');
  assert.equal(recordsRequest.url.searchParams.get('method'), 'POST');
  const agentPost = requests.find(({ url }) => url.pathname === '/api/vigolium/agent/audit');
  assert.deepEqual(JSON.parse(agentPost.init.body), { target: 'example.test' });
});

test('Workbench React nativa preserva 58 IDs e não executa scripts legados', async () => {
  const [component, hooks, service, auxiliary, inventoryText] = await Promise.all([
    fs.readFile(path.join(ROOT, 'frontend/src/features/pages/vigolium-workbench/VigoliumWorkbenchPage.tsx'), 'utf8'),
    fs.readFile(path.join(ROOT, 'frontend/src/features/pages/vigolium-workbench/hooks.ts'), 'utf8'),
    fs.readFile(path.join(ROOT, 'frontend/src/features/pages/vigolium-workbench/service.ts'), 'utf8'),
    fs.readFile(path.join(ROOT, 'frontend/src/features/pages/AuxiliaryPage.tsx'), 'utf8'),
    fs.readFile(path.join(ROOT, 'frontend/contracts/ui-inventory.json'), 'utf8'),
  ]);
  const baseline = JSON.parse(inventoryText).pages['vigolium-workbench.html'];
  const ids = [...component.matchAll(/\bid="([^"]+)"/g)].map((match) => match[1]);

  assert.equal(baseline.functionDeclarationCount, 46);
  assert.equal(baseline.inlineHandlers.onclick, 46);
  assert.equal(baseline.fetchCallCount, 3);
  assert.equal(new Set(ids).size, 58);
  assert.deepEqual([...new Set(ids)].sort(), [...baseline.domIds].sort());
  assert.match(component, /useVigoliumWorkbenchShell/);
  assert.match(hooks, /ghostreconNativeVigoliumWorkbench/);
  assert.match(hooks, /snapshotLegacyDocument/);
  assert.equal([...service.matchAll(/\bfetchImpl\(/g)].length, 3);
  assert.doesNotMatch(`${component}\n${hooks}`, /executeScripts|dangerouslySetInnerHTML/);
  assert.doesNotMatch(component, /\bonclick=/);
  assert.match(auxiliary, /'vigolium-workbench': VigoliumWorkbenchPage/);
  assert.match(auxiliary, /import \{ VigoliumWorkbenchPage \} from '.\/vigolium-workbench\/VigoliumWorkbenchPage'/);
});
