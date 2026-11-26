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
  apiUrl,
  buildApiHeaders,
  parseProgramHeaders,
  readOptionalAuthConfig,
  resolveApiBase,
  toPipelineAuth,
} = await vite.ssrLoadModule('/frontend/src/services/api-client.ts');
const { NdjsonDecoder } = await vite.ssrLoadModule('/frontend/src/services/ndjson.ts');
const {
  findingMatchesFilter,
  findingMatchesSearch,
  selectFindings,
} = await vite.ssrLoadModule('/frontend/src/features/findings/model.ts');
const {
  createPipelineState,
  formatElapsed,
  pipelineReducer,
} = await vite.ssrLoadModule('/frontend/src/features/pipeline/model.ts');
const {
  createExecutionStore,
  executionSelectors,
} = await vite.ssrLoadModule('/frontend/src/features/execution/store.tsx');
const { createNativeCockpitServices } = await vite.ssrLoadModule(
  '/frontend/src/features/cockpit/native-services.ts',
);
const { createManualReconService } = await vite.ssrLoadModule(
  '/frontend/src/features/manual-recon/service.ts',
);
const {
  AUTO_TERMINAL_PHASES,
  autoUiTerminalStatusText,
  createAutoForgeService,
} = await vite.ssrLoadModule('/frontend/src/features/auto-forge/service.ts');
const {
  createVigoliumService,
  mergeUniqueCsv,
  mergeUniqueLines,
  moduleSelectionForPreset,
  vigoliumAuthEntry,
  vigoliumGuardrailMessages,
} = await vite.ssrLoadModule('/frontend/src/features/vigolium/service.ts');

function storage(values = {}) {
  const map = new Map(Object.entries(values));
  return {
    getItem: (key) => map.get(key) ?? null,
    setItem: (key, value) => map.set(key, value),
    removeItem: (key) => map.delete(key),
  };
}

test('API/auth nativos preservam file://, headers privados e separação pipeline', () => {
  const authStorage = storage({
    ghostrecon_api_base: 'http://127.0.0.1:3999///',
    ghostrecon_auth_json: JSON.stringify({
      ghostreconApiKey: 'test-key',
      headers: { Authorization: 'Bearer test', 'X-Research': 'yes' },
      cookie: 'sid=test',
    }),
  });
  const base = resolveApiBase({ protocol: 'file:', storage: authStorage });
  assert.equal(base, 'http://127.0.0.1:3999');
  assert.equal(resolveApiBase({ protocol: 'http:', storage: authStorage }), '');
  assert.equal(apiUrl('api/runs', base), 'http://127.0.0.1:3999/api/runs');
  const auth = readOptionalAuthConfig(authStorage);
  assert.equal(auth?.ghostreconApiKey, 'test-key');
  assert.deepEqual(toPipelineAuth(auth), {
    headers: { Authorization: 'Bearer test', 'X-Research': 'yes' },
    cookie: 'sid=test',
  });
  assert.deepEqual(buildApiHeaders({ auth, csrfToken: 'csrf', json: true }), {
    'Content-Type': 'application/json',
    'X-API-Key': 'test-key',
    'X-CSRF-Token': 'csrf',
  });
  assert.deepEqual(parseProgramHeaders('X-One: 1\nmalformed\nX-Two: value:with:colon'), {
    'X-One': '1',
    'X-Two': 'value:with:colon',
  });
});

test('decoder NDJSON preserva chunks incompletos e reporta linha inválida', () => {
  const decoder = new NdjsonDecoder();
  assert.deepEqual(decoder.push('{"type":"log"'), []);
  const frames = decoder.push(',"msg":"ok"}\nnot-json\n{"type":"done"}');
  assert.equal(frames.length, 2);
  assert.equal(frames[0].ok && frames[0].value.type, 'log');
  assert.equal(frames[1].ok, false);
  const tail = decoder.finish();
  assert.equal(tail.length, 1);
  assert.equal(tail[0].ok && tail[0].value.type, 'done');
});

test('modelo de findings preserva dorks, Vigolium, subfinder, busca e ordenação', () => {
  const findings = [
    { type: 'dork', value: 'site:example', __idx: 0 },
    { type: 'param', value: 'id', __idx: 2 },
    { type: 'endpoint', value: '/api', __idx: 1 },
    { type: 'subdomain', value: 'a.example', meta: 'tool=subfinder', __idx: 3 },
    { type: 'xss', value: 'reflected', sourceEngine: 'Vigolium', __idx: 4 },
  ];
  assert.equal(findingMatchesFilter(findings[0], 'all'), false);
  assert.equal(findingMatchesFilter(findings[0], 'dorks'), true);
  assert.equal(findingMatchesFilter(findings[3], 'subfinder'), true);
  assert.equal(findingMatchesFilter(findings[4], 'vigolium'), true);
  assert.equal(findingMatchesSearch(findings[2], 'API'), true);
  assert.deepEqual(selectFindings(findings).map((finding) => finding.type), [
    'endpoint', 'param', 'xss', 'subdomain',
  ]);
});

test('reducer de pipeline preserva aliases, baseline de stats e progresso', () => {
  let state = createPipelineState();
  state = pipelineReducer(state, { type: 'node', name: 'validate', state: 'active' });
  state = pipelineReducer(state, { type: 'detail', name: 'validate', current: 2, total: 5, label: 'scope' });
  state = pipelineReducer(state, { type: 'progress', value: 140 });
  state = pipelineReducer(state, {
    type: 'stats',
    value: { subs: 3, high: 1 },
    baseline: { subs: 7, high: 2 },
  });
  assert.equal(state.currentNode, 'input');
  assert.equal(state.nodes.input.detail, '2/5');
  assert.equal(state.progress, 100);
  assert.equal(state.stats.subs, 10);
  assert.equal(state.stats.high, 3);
  assert.equal(formatElapsed(125_000), '2:05');
});

test('execution store sincroniza alvo, fila/cascata, pipeline, findings e snapshots NDJSON', () => {
  const store = createExecutionStore({ target: 'initial.example' });
  let notifications = 0;
  const unsubscribe = store.subscribe(() => { notifications += 1; });

  store.resetRun({ target: 'root.example' });
  store.setBatchTargets(['root.example', 'next.example']);
  store.setBatchPosition({ index: 1, total: 2 });
  store.setCascade({
    index: 2,
    rootHost: 'root.example',
    subHost: 'api.root.example',
    total: 3,
  });
  store.setTarget('api.root.example');
  store.pipeline({ type: 'node', name: 'validate', state: 'active' });
  store.pipeline({ type: 'detail', name: 'validate', current: 2, total: 5, label: 'scope' });
  store.pipeline({ type: 'stat', name: 'endpoints', value: 4 });
  store.setProgressDetail('2/5 - scope');
  store.addFinding({ type: 'endpoint', value: '/api', fingerprint: 'fp-1' });
  store.addFinding({ type: 'dork', value: 'site:root.example', fingerprint: 'fp-2' });
  store.setFilter('endpoint');
  store.setSearch('/api');
  store.setManualFingerprints(new Set(['fp-1', 'fp-1']));
  const coverage = { counts: { totalFindings: 2 } };
  const bundle = { runId: 42, reconCoverage: coverage };
  store.setCoverage(coverage);
  store.setLastPipelineBundle(bundle);

  const state = store.getState();
  assert.equal(executionSelectors.target(state), 'api.root.example');
  assert.deepEqual(executionSelectors.batchTargets(state), ['root.example', 'next.example']);
  assert.deepEqual(executionSelectors.batchPosition(state), { index: 1, total: 2 });
  assert.deepEqual(executionSelectors.cascade(state), {
    index: 2,
    rootHost: 'root.example',
    subHost: 'api.root.example',
    total: 3,
  });
  assert.equal(executionSelectors.pipeline(state).currentNode, 'input');
  assert.equal(executionSelectors.stats(state).endpoints, 4);
  assert.equal(executionSelectors.progressDetail(state), '2/5 - scope');
  assert.equal(executionSelectors.findings(state)[0].__idx, 0);
  assert.deepEqual(executionSelectors.manualFingerprints(state), ['fp-1']);
  assert.equal(executionSelectors.coverage(state), coverage);
  assert.equal(executionSelectors.lastPipelineBundle(state), bundle);

  store.dismissFingerprint('fp-1');
  assert.deepEqual(store.getState().findings.map((finding) => finding.fingerprint), ['fp-2']);
  assert.ok(notifications >= 16);
  unsubscribe();

  store.resetRun({ target: 'fresh.example' });
  assert.equal(store.getState().target, 'fresh.example');
  assert.deepEqual(store.getState().findings, []);
  assert.equal(store.getState().coverage, null);
  assert.equal(store.getState().lastPipelineBundle, null);
});

test('ponte do cockpit executa os serviços nativos e contabiliza delegações', async () => {
  const authStorage = storage({
    ghostrecon_api_base: 'http://127.0.0.1:3999/',
    ghostrecon_auth_json: JSON.stringify({ headers: { Authorization: 'Bearer bridge' } }),
  });
  const services = createNativeCockpitServices({
    fetch: globalThis.fetch,
    location: { protocol: 'file:' },
    localStorage: authStorage,
  });

  assert.equal(services.api.url('/api/runs'), 'http://127.0.0.1:3999/api/runs');
  assert.deepEqual(services.api.readPipelineAuth(), {
    headers: { Authorization: 'Bearer bridge' },
    cookie: '',
  });
  assert.deepEqual(
    services.findings.select([
      { type: 'dork', value: 'site:example', __idx: 0 },
      { type: 'endpoint', value: '/api', __idx: 1 },
    ]),
    [{ type: 'endpoint', value: '/api', __idx: 1 }],
  );
  services.pipeline.reduce({ type: 'node', name: 'vigolium_engine', state: 'active' });
  services.pipeline.reduce({ type: 'progress', value: 130 });
  assert.equal(services.pipeline.getState().currentNode, 'vigolium_dast');
  assert.equal(services.pipeline.getState().progress, 100);
  const decoder = services.ndjson.createDecoder();
  assert.equal(decoder.push('{"type":"done"}\n')[0].ok, true);
  assert.deepEqual(
    await services.infraHistory.manualValidationFingerprints('invalid target'),
    { target: 'invalid target', items: [], fingerprints: [] },
  );

  assert.deepEqual(services.calls, {
    api: 2,
    autoForge: 0,
    ndjson: 1,
    findings: 1,
    infraHistory: 1,
    manualRecon: 0,
    pipeline: 2,
    runForm: 0,
    vigolium: 0,
  });
});

test('modelo Vigolium preserva presets, credenciais e guardrails', () => {
  assert.equal(mergeUniqueLines('admin:Cookie:a\nuser:Cookie:b', [
    'ADMIN:cookie:A',
    'guest:Cookie:c',
  ]), 'admin:Cookie:a\nuser:Cookie:b\nguest:Cookie:c');
  assert.equal(mergeUniqueCsv('idor,authz', ['IDOR', 'bola']), 'idor,authz,bola');
  assert.equal(vigoliumAuthEntry('admin', 'sid=abc'), 'admin:Cookie:sid=abc');
  assert.equal(
    vigoliumAuthEntry('user', 'Authorization: Bearer token'),
    'user:Header:Authorization: Bearer token',
  );
  assert.deepEqual(
    moduleSelectionForPreset(['subdomains', 'sqlmap', 'vigolium_dast'], 'smart-fast'),
    ['subdomains'],
  );
  assert.deepEqual(
    moduleSelectionForPreset(['subdomains', 'kali_ffuf', 'out_of_scope'], 'full'),
    ['subdomains'],
  );
  const blockers = vigoliumGuardrailMessages({
    modules: ['vigolium_autopilot'],
    source: '',
    useCodex: true,
    moduleTags: '',
    only: '',
    codexInstalled: false,
  });
  assert.ok(blockers.some((item) => item.level === 'block' && /tags/.test(item.text)));
  assert.ok(blockers.some((item) => item.level === 'warn' && /PATH/.test(item.text)));
  assert.deepEqual(vigoliumGuardrailMessages({ modules: ['subdomains'] }), []);
});

test('serviço Vigolium persiste perfil e consulta capabilities/catalogo com auth', async () => {
  const requests = [];
  const profileStorage = storage();
  const responses = [
    new Response(JSON.stringify({ ok: true, tools: { nmap: true }, vigolium: { installed: true } })),
    new Response(JSON.stringify({ ok: true, counts: { total: 1 }, modules: [{ id: 'idor' }] })),
  ];
  const service = createVigoliumService({
    apiBase: () => 'http://127.0.0.1:3999',
    auth: () => ({ ghostreconApiKey: 'vig-key', headers: {}, cookie: '' }),
    fetchImpl: async (url, options = {}) => {
      requests.push({ url: String(url), options });
      return responses.shift();
    },
    storage: profileStorage,
    now: () => new Date('2026-11-18T12:00:00.000Z'),
  });
  const saved = service.saveProfile({
    engine: 'both',
    strategy: 'deep',
    dast: true,
    source: '/tmp/src',
    moduleTags: 'idor,bola',
  });
  assert.equal(saved.savedAt, '2026-11-18T12:00:00.000Z');
  assert.equal(service.loadProfile().engine, 'both');
  assert.equal(service.loadProfile().moduleTags, 'idor,bola');
  const capabilities = await service.capabilities();
  const catalog = await service.catalog({ q: 'idor', tag: 'access-control', limit: 500 });
  assert.equal(capabilities.tools.nmap, true);
  assert.equal(catalog.modules[0].id, 'idor');
  assert.deepEqual(requests.map((request) => new URL(request.url).pathname), [
    '/api/capabilities',
    '/api/vigolium/modules',
  ]);
  assert.equal(new URL(requests[1].url).searchParams.get('limit'), '100');
  assert.equal(new URL(requests[1].url).searchParams.get('q'), 'idor');
  assert.equal(requests[0].options.headers['X-API-Key'], 'vig-key');
  assert.equal(service.clearProfile(), true);
  assert.equal(service.loadProfile(), null);
});

test('transporte Manual Recon sela autorização, aprova o plano e abre o stream', async () => {
  const requests = [];
  const responses = [
    new Response(JSON.stringify({ token: 'csrf-preflight' }), { status: 200 }),
    new Response(JSON.stringify({ ok: true, engagement: { id: 'MANUAL-test' } }), { status: 200 }),
    new Response(JSON.stringify({
      ok: true,
      requiresApproval: true,
      approval: { approvalId: 'approval-1' },
      plan: {
        target: 'example.test',
        hash: 'plan-hash',
        intrusiveModules: ['sqlmap'],
        expandedModules: ['sqlmap'],
      },
    }), { status: 200 }),
    new Response(JSON.stringify({ ok: true }), { status: 200 }),
    new Response(JSON.stringify({ token: 'csrf-stream' }), { status: 200 }),
    new Response('{"type":"done"}\n', { status: 200 }),
  ];
  const fetchImpl = async (url, options = {}) => {
    requests.push({ url: String(url), options });
    return responses.shift();
  };
  const events = [];
  const service = createManualReconService({
    apiBase: () => 'http://127.0.0.1:3999',
    auth: () => ({ ghostreconApiKey: 'key', headers: {}, cookie: '' }),
    fetchImpl,
  });
  const result = await service.openStream({
    domain: 'example.test',
    modules: ['sqlmap'],
    exactMatch: false,
    outOfScope: ['admin.example.test'],
    operator: 'tester',
  }, {
    authorizationRequested: true,
    authorizationBasis: 'program_scope',
    onTemporaryAuthorization: (id) => events.push(['authorization', id]),
    onAuthorizationConsumed: () => events.push(['consumed']),
    onPlanAuthorized: ({ plan }) => events.push(['plan', plan.hash]),
  });

  assert.equal(result.response.status, 200);
  assert.equal(result.approvedBody.engagementId, 'MANUAL-test');
  assert.equal(result.approvedBody.confirmActive, true);
  assert.deepEqual(result.approvedBody.manualApproval, {
    approvalId: 'approval-1',
    planHash: 'plan-hash',
  });
  assert.deepEqual(events, [
    ['authorization', 'MANUAL-test'],
    ['consumed'],
    ['plan', 'plan-hash'],
  ]);
  assert.deepEqual(requests.map((request) => new URL(request.url).pathname), [
    '/api/csrf-token',
    '/api/engagements/manual-authorization',
    '/api/recon/preflight',
    '/api/recon/approval',
    '/api/csrf-token',
    '/api/recon/stream',
  ]);
  assert.equal(requests[1].options.headers['X-API-Key'], 'key');
  assert.equal(requests[1].options.headers['X-CSRF-Token'], 'csrf-preflight');
  assert.equal(requests[5].options.headers['X-CSRF-Token'], 'csrf-stream');
  assert.deepEqual(JSON.parse(requests[1].options.body), {
    target: 'example.test',
    authorizationConfirmed: true,
    basis: 'program_scope',
    includeSubdomains: true,
    exclusions: ['admin.example.test'],
    operator: 'tester',
  });
  assert.equal(JSON.parse(requests[5].options.body).manualApproval.planHash, 'plan-hash');
});

test('Auto nativo abre stream com CSRF/auth e persiste a sessão iniciada', async () => {
  const requests = [];
  const responses = [
    new Response(JSON.stringify({ token: 'csrf-auto' }), { status: 200 }),
    new Response('{"type":"auto_session","phase":"started"}\n', { status: 200 }),
  ];
  const autoStorage = storage();
  const service = createAutoForgeService({
    apiBase: () => 'http://127.0.0.1:3999',
    auth: () => ({ ghostreconApiKey: 'auto-key', headers: {}, cookie: '' }),
    fetchImpl: async (url, options = {}) => {
      requests.push({ url: String(url), options });
      return responses.shift();
    },
    storage: autoStorage,
  });
  const controller = new AbortController();
  const response = await service.openStream({
    domain: 'example.test',
    mode: 'balanced',
    resumeSessionId: 'resume-1',
  }, controller.signal);
  assert.equal(response.status, 200);
  assert.deepEqual(requests.map((request) => new URL(request.url).pathname), [
    '/api/csrf-token',
    '/api/recon/auto/stream',
  ]);
  assert.equal(requests[1].options.headers['X-API-Key'], 'auto-key');
  assert.equal(requests[1].options.headers['X-CSRF-Token'], 'csrf-auto');
  assert.equal(requests[1].options.signal, controller.signal);
  assert.deepEqual(JSON.parse(requests[1].options.body), {
    domain: 'example.test',
    mode: 'balanced',
    resumeSessionId: 'resume-1',
  });

  const summary = service.summarizeEvent({
    type: 'auto_session',
    phase: 'started',
    sessionId: 'AUTO-123',
    mode: 'balanced',
  });
  assert.equal(summary.sessionId, 'AUTO-123');
  assert.equal(service.lastSessionId(), 'AUTO-123');
  assert.equal(autoStorage.getItem('ghostrecon.auto.lastSessionId'), 'AUTO-123');
});

test('Auto nativo lista snapshots e confirma terminal sem renovar deadline', async () => {
  let clock = 1_000;
  const responses = [
    new Response(JSON.stringify({ ok: true, sessions: [
      { sessionId: 'A', resumable: true },
      { sessionId: 'B', resumable: false },
    ] }), { status: 200 }),
    new Response(JSON.stringify({ ok: true, session: { status: 'running' } }), { status: 200 }),
    new Response(JSON.stringify({ ok: true, source: 'snapshot', session: { status: 'partial' } }), { status: 200 }),
  ];
  const service = createAutoForgeService({
    apiBase: () => '',
    auth: () => null,
    fetchImpl: async () => responses.shift(),
    now: () => clock,
    sleep: async (milliseconds) => { clock += milliseconds; },
  });
  assert.equal((await service.listResumableSessions()).length, 2);
  const terminal = await service.waitForTerminal('AUTO-123', { timeoutMs: 2_000, intervalMs: 250 });
  assert.equal(terminal.status, 'partial');
  assert.equal(terminal.source, 'snapshot');
  assert.equal(AUTO_TERMINAL_PHASES.has(terminal.status), true);
  assert.equal(autoUiTerminalStatusText(terminal.status), 'AUTO PARCIAL');
  assert.equal(autoUiTerminalStatusText('interrupted'), 'AUTO CANCELADO');
});

test('Auto/Forge nativo preserva aprovação, cancelamento, lifecycle e verdict', async () => {
  const requests = [];
  const json = (value) => new Response(JSON.stringify(value), { status: 200 });
  const responses = [
    json({ token: 'csrf-approval' }), json({ ok: true }),
    json({ token: 'csrf-cancel' }), json({ ok: true, status: 'cancel_requested' }),
    json({ ok: true, items: [{ forgeId: 'F1' }] }),
    json({ ok: true, item: { forgeId: 'F1', state: 'active' } }),
    json({ token: 'csrf-life' }), json({ ok: true, status: 'canary' }),
    json({ token: 'csrf-verdict' }), json({ ok: true, status: 'active' }),
  ];
  const service = createAutoForgeService({
    apiBase: () => '',
    auth: () => null,
    fetchImpl: async (url, options = {}) => {
      requests.push({ url: String(url, 'http://local'), options });
      return responses.shift();
    },
  });
  await service.respondApproval('AUTO-1', 'approval-1', true);
  await service.requestCancel('AUTO-1');
  assert.equal((await service.listForge())[0].forgeId, 'F1');
  assert.equal((await service.inspectForge('F1')).state, 'active');
  await service.lifecycleForge('F1', 'canary', 'teste autorizado', 10);
  await service.decideForge('F1', 'approve', 'revisado', 'ENG-1');

  const paths = requests.map((request) => new URL(request.url, 'http://local').pathname);
  assert.ok(paths.includes('/api/recon/auto/AUTO-1/approval'));
  assert.ok(paths.includes('/api/recon/auto/AUTO-1/cancel'));
  assert.ok(paths.includes('/api/auto-forge/F1/lifecycle'));
  assert.ok(paths.includes('/api/auto-forge/F1/verdict'));
  const posted = requests.filter((request) => request.options.method === 'POST');
  assert.deepEqual(JSON.parse(posted[0].options.body), {
    approvalId: 'approval-1',
    approved: true,
    reason: 'operador confirmou',
  });
  assert.deepEqual(JSON.parse(posted[2].options.body), {
    action: 'canary',
    reason: 'teste autorizado',
    percentage: 10,
  });
  assert.deepEqual(JSON.parse(posted[3].options.body), {
    decision: 'approve',
    reason: 'revisado',
    engagementId: 'ENG-1',
  });
  await assert.rejects(
    () => service.decideForge('F1', 'approve', 'sem engagement'),
    /engagement autorizado/,
  );
});

test('sumário Auto nativo preserva estados recuperáveis, motores e Forge', () => {
  const service = createAutoForgeService({
    apiBase: () => '',
    auth: () => null,
    fetchImpl: globalThis.fetch,
  });
  assert.deepEqual(service.summarizeEvent({
    type: 'phase_outcome', phase: 'probe', status: 'failed', recoverable: true, error: 'timeout',
  }), {
    message: 'AUTO fase probe: failed — timeout (pipeline continuou)',
    level: 'warn',
  });
  assert.match(service.summarizeEvent({
    type: 'auto_forge_status', forgeId: 'F1', status: 'active', pipelineEnabled: true,
  }).message, /pipeline=ativo/);
  assert.equal(service.summarizeEvent({ type: 'engine_timeout', engine: 'vigolium' }).level, 'warn');
  assert.equal(service.summarizeEvent({
    type: 'auto_session', phase: 'budget_exceeded', error: 'limite',
  }).terminalPhase, 'budget_exceeded');
});

test('polling Auto nativo respeita AbortSignal sem continuar requests', async () => {
  let calls = 0;
  const controller = new AbortController();
  controller.abort(new DOMException('cancelado', 'AbortError'));
  const service = createAutoForgeService({
    apiBase: () => '',
    auth: () => null,
    fetchImpl: async () => {
      calls += 1;
      return new Response(JSON.stringify({ ok: true, session: { status: 'running' } }));
    },
  });
  await assert.rejects(
    () => service.waitForTerminal('AUTO-ABORT', { signal: controller.signal }),
    /cancelado/,
  );
  assert.equal(calls, 0);
});

test('transporte Manual Recon preserva erros detalhados do checklist', async () => {
  const responses = [
    new Response(JSON.stringify({ token: 'csrf' }), { status: 200 }),
    new Response(JSON.stringify({
      ok: false,
      error: 'plano recusado',
      checklist: { errors: ['escopo inválido', 'módulo bloqueado'] },
    }), { status: 400 }),
  ];
  const service = createManualReconService({
    apiBase: () => '',
    auth: () => null,
    fetchImpl: async () => responses.shift(),
  });
  await assert.rejects(
    service.prepareApproval({ domain: 'example.test' }),
    /plano recusado: escopo inválido \| módulo bloqueado/,
  );
});
