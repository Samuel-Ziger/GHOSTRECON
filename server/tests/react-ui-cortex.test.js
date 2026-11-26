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

const model = await vite.ssrLoadModule('/frontend/src/features/pages/cortex/model.ts');
const serviceModule = await vite.ssrLoadModule('/frontend/src/features/pages/cortex/service.ts');

test('modelo Cortex preserva demo, taxonomia, URL e textos educativos', () => {
  assert.equal(model.isCortexDemoLocation({ search: '?demo=1', hash: '' }), true);
  assert.equal(model.isCortexDemoLocation({ search: '', hash: '#demo' }), true);
  assert.equal(model.isCortexDemoLocation({ search: '', hash: '#9001' }), false);
  assert.equal(model.cloneDemoCategories().length, 4);
  assert.equal(model.cloneDemoLinks(9001).length, 2);
  const link = {
    target: 'example.test',
    snapshot: {
      type: 'xss',
      value: 'https://example.test/?q=x',
      owasp: [{ id: 'A03' }],
      mitre: [{ id: 'T1059' }],
    },
  };
  assert.equal(model.linkDisplayUrl(link), 'https://example.test/?q=x');
  assert.match(model.snippetFromLink(link), /A03, T1059/);
  assert.match(model.getCategoryTeach('IDOR').text, /outro utilizador/);
  assert.deepEqual(model.categoryTeach('XSS', 'Texto custom'), {
    headline: 'Sobre esta categoria',
    text: 'Texto custom',
  });
});

test('serviço Cortex preserva os cinco contratos HTTP, CSRF e file://', async () => {
  const requests = [];
  const responses = [
    { body: { items: [{ id: 7, title: 'XSS' }] } },
    { body: { category: { id: 7, title: 'XSS' }, links: [{ target: 'a.test' }] } },
    { body: { token: 'csrf-cortex' } },
    { body: { category: { id: 7, description: 'Nova' } } },
    { body: { token: 'csrf-cortex-2' } },
    { body: { ok: true } },
  ];
  const fetchImpl = async (url, init = {}) => {
    requests.push({ url: String(url), init });
    const current = responses.shift();
    return new Response(JSON.stringify(current?.body || {}), {
      status: current?.status || 200,
      headers: { 'Content-Type': 'application/json' },
    });
  };
  const service = serviceModule.createCortexService({
    fetchImpl,
    locationLike: { href: 'file:///tmp/cortex.html', protocol: 'file:' },
  });
  assert.equal(service.apiBase, 'http://127.0.0.1:3847');
  assert.equal((await service.listCategories()).length, 1);
  assert.equal((await service.getCategory(7)).links.length, 1);
  assert.equal((await service.saveCategoryDescription(7, 'Nova')).description, 'Nova');
  await service.saveValidation(
    { target: 'a.test', fingerprint: 'fp', snapshot: { type: 'xss' } },
    { notes: 'nota', marked: true },
  );

  assert.deepEqual(requests.map((request) => new URL(request.url).pathname), [
    '/api/brain/categories',
    '/api/brain/category/7',
    '/api/csrf-token',
    '/api/brain/categories/7/description',
    '/api/csrf-token',
    '/api/manual-validations',
  ]);
  assert.equal(requests[3].init.headers['X-CSRF-Token'], 'csrf-cortex');
  assert.equal(requests[5].init.headers['X-CSRF-Token'], 'csrf-cortex-2');
  assert.equal(JSON.parse(requests[5].init.body).snapshot.cortex_marked, true);
});

test('Cortex React nativo preserva os 35 IDs e não executa controller legado', async () => {
  const source = await fs.readFile(path.join(ROOT, 'frontend/src/features/pages/cortex/CortexPage.tsx'), 'utf8');
  const auxiliary = await fs.readFile(path.join(ROOT, 'frontend/src/features/pages/AuxiliaryPage.tsx'), 'utf8');
  const ids = [...source.matchAll(/\bid="([^"]+)"/g)].map((match) => match[1]);
  assert.equal(new Set(ids).size, 35);
  assert.match(source, /ghostreconNativeCortex/);
  assert.match(source, /createCortexService/);
  assert.match(source, /ResizeObserver/);
  assert.match(source, /onPointerDown/);
  assert.doesNotMatch(source, /executeScripts/);
  assert.match(auxiliary, /import \{ CortexPage \} from '.\/cortex\/CortexPage'/);
  assert.doesNotMatch(auxiliary, /function CortexPage\(/);
});
