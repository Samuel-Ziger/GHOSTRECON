import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createServer } from 'vite';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const vite = await createServer({ root: ROOT, appType: 'custom', logLevel: 'silent', server: { middlewareMode: true } });
after(async () => vite.close());

const model = await vite.ssrLoadModule('/frontend/src/features/pages/report/model.ts');
const serviceModule = await vite.ssrLoadModule('/frontend/src/features/pages/report/service.ts');

test('modelo Reporte preserva alvo, import, fingerprint, filtros e exports', async () => {
  assert.equal(model.normalizeTarget('https://WWW.Example.com:443/a?q=1'), 'www.example.com');
  assert.equal(model.targetUsableForApi('www.example.com'), true);
  assert.equal(model.deriveTargetFromFindings([{ url: 'https://api.example.test/v1' }]), 'api.example.test');
  const finding = model.normalizeImportedFinding({ type: 'xss', priority: 'high', value: '<x>', url: 'HTTPS://A.TEST/?b=2&a=1' });
  const hydrated = await model.ensureFindingFingerprint('a.test', finding);
  assert.match(hydrated.fingerprint, /^[a-f0-9]{64}$/);
  assert.equal(model.applySubset([hydrated, { type: 'sqli', prio: 'low' }], 'high').length, 1);
  assert.equal(model.isDorkFinding({ type: 'endpoint', meta: 'GHDB search dork' }), true);
  const markdown = model.buildReportMarkdown('a.test', [hydrated], new Set([hydrated.fingerprint]), { [hydrated.fingerprint]: 'confirmado' });
  assert.match(markdown, /Relatório GHOSTRECON/);
  assert.match(markdown, /confirmado/);
  assert.match(model.buildReportHtml(markdown), /<!doctype html>/);
});

test('serviço Reporte preserva API base, auth, CSRF e doze contratos HTTP', async () => {
  const requests = [];
  const responseBodies = [
    { ai: { openrouter: true } },
    { items: [{ fingerprint: 'a'.repeat(64) }] },
    { runs: [{ id: 7, target: 'a.test' }] },
    { target: 'a.test', findings: [{ type: 'xss', value: 'x' }] },
    { token: 'csrf-1' }, { ok: true },
    { items: [{ id: 2, title: 'XSS' }] },
    { token: 'csrf-2' }, { id: 3, ok: true },
    { token: 'csrf-3' }, { ok: true },
    { token: 'csrf-4' }, { ok: true, openrouter: { ok: true } },
    { token: 'csrf-5' }, { ok: true, id: 'handoff-1' },
  ];
  const storage = { getItem: (key) => key === 'ghostrecon_api_base' ? 'http://127.0.0.1:3999/' : key === 'ghostrecon_auth_json' ? '{"ghostreconApiKey":"k"}' : null };
  const fetchImpl = async (url, init = {}) => {
    requests.push({ url: String(url), init });
    return new Response(JSON.stringify(responseBodies.shift() || {}), { status: 200, headers: { 'Content-Type': 'application/json' } });
  };
  const service = serviceModule.createReportService({ fetchImpl, locationLike: { protocol: 'file:' }, storage });
  assert.equal(service.apiBase, 'http://127.0.0.1:3999');
  await service.capabilities();
  assert.equal((await service.loadValidations('a.test')).length, 1);
  assert.equal((await service.loadLatestRun('a.test')).runId, 7);
  await service.persistValidation({ target: 'a.test', fingerprint: 'a'.repeat(64), validated: true, finding: { type: 'xss' }, notes: 'ok' });
  assert.equal((await service.listBrainCategories())[0].id, 2);
  assert.equal(await service.createBrainCategory('IDOR'), 3);
  await service.linkBrain('a.test', 'a'.repeat(64), 3);
  await service.generateAi('a.test', [{ type: 'xss' }], true);
  assert.equal(await service.annotationHandoff({ target: 'a.test' }), 'handoff-1');
  assert.ok(requests.every((request) => request.init.headers?.['X-API-Key'] === 'k'));
  assert.equal(requests.filter((request) => request.init.method === 'POST').length, 5);
  assert.ok(requests.filter((request) => request.init.method === 'POST').every((request) => request.init.headers['X-CSRF-Token']));
});

test('Reporte React nativo preserva IDs e não executa controller legado', async () => {
  const source = await fs.readFile(path.join(ROOT, 'frontend/src/features/pages/report/ReportPage.tsx'), 'utf8');
  const auxiliary = await fs.readFile(path.join(ROOT, 'frontend/src/features/pages/AuxiliaryPage.tsx'), 'utf8');
  const baseline = [
    'reporteBgGhostGrad', 'reporteBgGhostSheen', 'headLine', 'targetMismatchBanner', 'btnReload', 'btnAi',
    'btnToggleDorks', 'btnAnotacao', 'countLine', 'reporteLivePill', 'list', 'msg', 'reportJsonDockWrap',
    'reportJsonDockTab', 'reportJsonDockPanel', 'reportJsonDockClose', 'reportJsonPanelToggle', 'reportJsonPanelWrap',
    'reportImportJson', 'reportImportFile', 'reportImportApply', 'reportImportClearField', 'brainModal',
    'brainModalHead', 'brainModalBody', 'brainModalActions', 'footHint', 'brainNewWrap', 'brainNewTitle',
    'brainNewCreate', 'brainChipsHost', 'brainSave', 'brainCancel', 'brainYes', 'brainNo',
  ];
  for (const id of baseline) assert.match(source, new RegExp(`id="${id}"`), id);
  assert.match(source, /ghostreconNativeReport/);
  assert.match(source, /BroadcastChannel/);
  assert.match(source, /createReportService/);
  assert.doesNotMatch(source, /executeScripts/);
  assert.match(auxiliary, /import \{ ReportPage \} from '.\/report\/ReportPage'/);
  assert.doesNotMatch(auxiliary, /function ReportPage\(/);
});
