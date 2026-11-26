import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createServer } from 'vite';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const vite = await createServer({ root: ROOT, appType: 'custom', logLevel: 'silent', server: { middlewareMode: true } });
after(async () => vite.close());

const runForm = await vite.ssrLoadModule('/frontend/src/features/run-form/model.ts');
const { consumeReconNdjson } = await vite.ssrLoadModule('/frontend/src/features/run-form/stream-dispatcher.ts');
const { createRunFormStore } = await vite.ssrLoadModule('/frontend/src/features/run-form/store.tsx');
const { createExecutionStore } = await vite.ssrLoadModule('/frontend/src/features/execution/store.tsx');

function fakeForm(values, selectedModules = []) {
  const controls = new Map(Object.entries(values).map(([id, data]) => [id, typeof data === 'object' ? { ...data } : { value: data }]));
  return {
    getElementById: (id) => controls.get(id) || null,
    querySelector: () => null,
    querySelectorAll: (selector) => selector.includes('input.mod')
      ? selectedModules.map((value) => ({ value, checked: true }))
      : [],
  };
}

test('modelo RUN normaliza fila e cascata fora de escopo', () => {
  assert.equal(runForm.normalizeTargetKey('HTTPS://Example.COM:443/path'), 'example.com');
  assert.equal(runForm.normalizeTargetKey('[2001:db8::1]'), '2001:db8::1');
  assert.deepEqual(runForm.collectRunTargets({
    target: 'https://root.example/path', batchMode: true,
    batchText: 'next.example\nhttps://NEXT.example/a; third.example',
  }).targets, ['https://root.example/path', 'next.example', 'third.example']);
  const rules = runForm.parseCascadeOutOfScopeRules('*.dev.root.example\nhttps://cdn.root.example/a');
  assert.deepEqual(runForm.extractCascadeSubdomains([
    { type: 'subdomain', value: 'api.root.example' },
    { type: 'subdomain', value: 'a.dev.root.example' },
    { type: 'subdomain', value: 'cdn.root.example' },
    { type: 'subdomain', value: 'outside.example' },
  ], 'root.example', new Set(), rules), ['api.root.example']);
});

test('projeção RUN compõe auth, OPSEC, infra, Tor, Vigolium e módulos', async () => {
  const template = await fs.readFile(path.join(ROOT, 'frontend/templates/index.html'), 'utf8');
  assert.equal((template.match(/<input\b[^>]*class="[^"]*\bmod\b[^"]*"[^>]*>/g) || []).length, 88);
  const projection = runForm.projectRunForm(fakeForm({
    domainInput: { value: 'root.example' }, batchModeToggle: { checked: true }, batchDomainsInput: { value: 'next.example' },
    reconProfileSelect: { value: 'deep' }, includeFrameSevenToggle: { checked: true }, frameSevenAuthToggle: { checked: true },
    modAiReports: { checked: true }, engagementIdInput: { value: 'eng-1' }, engagementOperatorInput: { value: 'operator' },
    projectNameInput: { value: 'project' }, manualAuthorizationBasisSelect: { value: 'lab' }, manualAuthorizationToggle: { checked: false },
    navigatorModeToggle: { checked: true }, navegationExecToggle: { checked: true }, anonModeToggle: { checked: true },
    anonTorToggle: { checked: true }, identityBodyEnabledToggle: { checked: true }, identityProxyPoolInput: { value: '' },
    kaliModeToggle: { checked: true }, outOfScopeInput: { value: '*.old.root.example' }, vigoliumEngineSelect: { value: 'both' },
    vigoliumStrategySelect: { value: 'deep' }, vigoliumPreferPathToggle: { checked: true }, vigoliumUseCodexToggle: { checked: true },
    vigoliumAuthFileInput: { value: 'admin.yml,user.yml' }, vigoliumAuthEntriesInput: { value: 'admin:Cookie:a\nuser:Cookie:b' },
    vigoliumHtmlReportToggle: { checked: true }, vigoliumAuditModeSelect: { value: 'deep' },
  }, ['out_of_scope', 'vigolium_audit', 'identity_rotation']), {
    aiOptions: { aiPrimaryCloud: 'openrouter', aiUseOpenrouter: true }, kaliAvailable: true,
    pipelineAuth: { headers: { Authorization: 'Bearer test' }, cookie: 'sid=1' },
  });
  const body = runForm.buildManualReconBody(projection, 'api.root.example');
  assert.deepEqual(body.modules, ['out_of_scope', 'vigolium_audit', 'identity_rotation', 'navegation']);
  assert.equal(body.profile, 'deep');
  assert.equal(body.opsecProfile, 'standard');
  assert.equal(body.vigoliumAgent, 'audit');
  assert.equal(body.aiOpenrouterOnly, true);
  assert.deepEqual(body.identity.proxyPool, ['socks5h://127.0.0.1:9050']);
  assert.deepEqual(body.vigoliumAuthFiles, ['admin.yml', 'user.yml']);
});

test('stores controlados recebem campos e sequência NDJSON completa', async () => {
  const formStore = createRunFormStore({
    target: '', batchMode: false, batchDomains: '', profile: 'standard',
    modules: { subdomains: true, sqlmap: false, vigolium_audit: false },
  });
  formStore.setTarget('root.example');
  formStore.setBatchMode(true);
  formStore.setProfile('deep');
  formStore.replaceModules(['sqlmap', 'vigolium_audit']);
  assert.deepEqual(formStore.getSelectedModules(), ['sqlmap', 'vigolium_audit']);

  const executionStore = createExecutionStore();
  const response = new Response([
    JSON.stringify({ type: 'log', msg: 'started', level: 'info' }),
    JSON.stringify({ type: 'pipe', name: 'probe', state: 'active' }),
    JSON.stringify({ type: 'progress', pct: 42 }),
    JSON.stringify({ type: 'stats', stats: { endpoints: 3 } }),
    JSON.stringify({ type: 'finding', finding: { type: 'endpoint', value: '/api' } }),
    JSON.stringify({ type: 'auto_session', phase: 'completed' }),
  ].join('\n') + '\n', { status: 200 });
  const outcome = await consumeReconNdjson(response, { executionStore, requireAutoTerminal: true });
  assert.equal(outcome.status, 'completed');
  assert.equal(executionStore.getState().events.length, 6);
  assert.equal(executionStore.getState().logs[0].message, 'started');
  assert.equal(executionStore.getState().pipeline.progress, 42);
  assert.equal(executionStore.getState().findings[0].value, '/api');
});

test('CockpitPage monta target/fila/perfil e 88 módulos como controles React', async () => {
  const page = await fs.readFile(path.join(ROOT, 'frontend/src/features/cockpit/CockpitPage.tsx'), 'utf8');
  const controls = await fs.readFile(path.join(ROOT, 'frontend/src/features/run-form/RunFormControls.tsx'), 'utf8');
  const controller = await fs.readFile(path.join(ROOT, 'frontend/templates/index.html'), 'utf8');
  assert.match(page, /<RunFormStoreProvider store=\{runFormStore\}>/);
  assert.match(page, /<NativeRunFormControl element=\{element\}/);
  assert.match(controls, /props\.checked = Boolean\(state\.modules\[module\]\)/);
  assert.match(controls, /props\.value = module/);
  assert.match(controller, /runForm\.project\(document/);
  assert.match(controller, /runForm\.buildBody\(runProjection, host\)/);
  assert.match(controller, /runForm\?\.consumeStream/);
  assert.doesNotMatch(controller, /const makeStreamBody = \(host\) => \{/);
  assert.doesNotMatch(controller, /const reader = res\.body\.getReader\(\)/);
});
