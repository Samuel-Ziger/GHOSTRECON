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

const { createExecutionStore } = await vite.ssrLoadModule(
  '/frontend/src/features/execution/store.tsx',
);
const exportsModule = await vite.ssrLoadModule(
  '/frontend/src/features/exports-integrations/service.ts',
);

function memoryStorage(initial = {}) {
  const values = new Map(Object.entries(initial));
  return {
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, String(value)),
    removeItem: (key) => values.delete(key),
    values,
  };
}

function populatedStore() {
  const store = createExecutionStore({ target: 'api.example.test' });
  store.setBatchTargets(['api.example.test', 'www.example.test']);
  store.pipeline({
    type: 'stats',
    value: { subs: 2, endpoints: 5, params: 3, secrets: 1, dorks: 4, high: 2 },
  });
  store.replaceFindings([
    {
      type: 'sqli',
      prio: 'high',
      score: 97,
      value: 'id',
      url: 'https://api.example.test/users?id=1',
      meta: 'response changed',
      fingerprint: 'fp-high',
      risk: { why: 'database access', next: 'manual compare' },
      provenance: { how: '**probe**', relation: 'same host' },
      verification: {
        classification: 'confirmed',
        evidence: {
          requestSnippet: 'r'.repeat(900),
          responseSnippet: 's'.repeat(1900),
          evidenceHash: 'sha256:one',
        },
      },
    },
    {
      type: 'idor',
      prio: 'critical',
      score: 92,
      value: '/users/2',
      fingerprint: 'fp-critical',
    },
    { type: 'endpoint', prio: 'med', value: '/health', fingerprint: 'fp-med' },
  ]);
  store.setManualFingerprints(['fp-critical']);
  store.setCoverage({ counts: { totalFindings: 3 } });
  store.setLastPipelineBundle({
    runId: 91,
    storage: { sqlite: true },
    correlation: { groups: 1 },
    reportTemplates: ['technical'],
  });
  return store;
}

test('exports JSON preservam previews, subsets, nomes e bundle da plataforma', () => {
  const store = populatedStore();
  const state = store.getState();
  const high = exportsModule.filterFindingsForSubset(
    state.findings,
    'high',
    state.manualFingerprints,
  );
  const validated = exportsModule.filterFindingsForSubset(
    state.findings,
    'validated',
    state.manualFingerprints,
  );
  assert.deepEqual(high.map((finding) => finding.fingerprint), ['fp-high', 'fp-critical']);
  assert.deepEqual(validated.map((finding) => finding.fingerprint), ['fp-critical']);

  const artifact = exportsModule.buildJsonExport(state, {
    findings: high,
    now: 1_700_000_000_000,
    projectName: 'Lab',
    subset: 'high',
  });
  assert.equal(artifact.filename, 'ghostrecon_high_fila_2_1700000000000.json');
  assert.equal(artifact.payload.projectName, 'Lab');
  assert.equal(artifact.payload.subsetFilter, 'high');
  assert.equal(artifact.payload.findings.length, 2);
  assert.equal(artifact.payload.findings[0].verification.requestSnippetPreview.length, 800);
  assert.equal(artifact.payload.findings[0].verification.responseSnippetPreview.length, 1800);

  const platform = exportsModule.buildPlatformExport(state, {
    now: 1_700_000_000_000,
    projectName: 'Lab',
  });
  assert.equal(platform.filename, 'ghostrecon_platform_api.example.test_1700000000000.json');
  assert.equal(platform.payload.schemaVersion, 2);
  assert.equal(platform.payload.runId, 91);
  assert.deepEqual(platform.payload.severityHistogram, { high: 1, med: 1, low: 1 });
  assert.deepEqual(platform.payload.reconCoverage, { counts: { totalFindings: 3 } });
});

test('exports Markdown técnico/bounty e TXT preservam evidência e nomes de fila', () => {
  const state = populatedStore().getState();
  const technical = exportsModule.buildMarkdownExport(state, 'technical', 1_700_000_000_000);
  const bounty = exportsModule.buildMarkdownExport(state, 'bounty', 1_700_000_000_000);
  const plain = exportsModule.buildTextExport(state, 1_700_000_000_000);

  assert.equal(technical.filename, 'ghostrecon_fila_2_1700000000000.md');
  assert.match(technical.content, /relatório técnico/);
  assert.match(technical.content, /database access/);
  assert.match(technical.content, /https:\/\/api\.example\.test\/users/);
  assert.equal(bounty.filename, 'ghostrecon_bounty_fila_2_1700000000000.md');
  assert.match(bounty.content, /Found 2 prioritized issue\(s\)/);
  assert.equal(plain.filename, 'ghostrecon_fila_2_1700000000000.txt');
  assert.match(plain.content, /TODOS OS ACHADOS/);
  assert.match(plain.content, /manual compare/);
});

test('URLs externas respeitam overrides e defaults originais', () => {
  const location = {
    href: 'http://127.0.0.1:3847/',
    hostname: '127.0.0.1',
    port: '3847',
    protocol: 'http:',
  };
  assert.equal(
    exportsModule.resolveGhostDeskUrl(location, memoryStorage()),
    'http://127.0.0.1:5173/',
  );
  assert.equal(
    exportsModule.resolveGhostAssistantUrl(location, memoryStorage()),
    'http://127.0.0.1:8000/gui/',
  );
  assert.equal(
    exportsModule.resolveGhostDeskUrl(
      location,
      memoryStorage({ ghostrecon_ghostdesk_url: '/desk' }),
    ),
    'http://127.0.0.1:3847/desk',
  );
  assert.equal(
    exportsModule.resolveGhostAssistantUrl(
      location,
      memoryStorage({ ghostrecon_ghost_ui_url: 'https://ghost.example/gui' }),
    ),
    'https://ghost.example/gui',
  );
});

test('Reporte e GhostMap preservam popup síncrono, storage, nomes e BroadcastChannel', async () => {
  const store = populatedStore();
  const localStorage = memoryStorage();
  const sessionStorage = memoryStorage();
  const opened = [];
  const channels = [];
  class FakeBroadcastChannel {
    constructor(name) {
      this.name = name;
      this.messages = [];
      channels.push(this);
    }
    postMessage(message) { this.messages.push(message); }
    close() { this.closed = true; }
  }
  const elements = {
    domainInput: { value: 'input.example.test' },
    runBtn: { disabled: true },
    kaliModeToggle: { checked: true },
    mitreMapBtn: {
      disabled: true,
      title: '',
      classList: { toggle() {} },
    },
    projectNameInput: { value: 'Lab' },
  };
  const fakeWindow = {
    BroadcastChannel: FakeBroadcastChannel,
    URL: globalThis.URL,
    __ghostreconExecutionStore: store,
    __kaliScanAvailable: true,
    crypto: { randomUUID: () => 'session-1' },
    fetch: globalThis.fetch,
    localStorage,
    sessionStorage,
    location: {
      href: 'http://127.0.0.1:3847/',
      hostname: '127.0.0.1',
      origin: 'http://127.0.0.1:3847',
      port: '3847',
      protocol: 'http:',
    },
    open(url, name, features) {
      opened.push({ url, name, features });
      return {};
    },
    setTimeout: globalThis.setTimeout,
    clearTimeout: globalThis.clearTimeout,
  };
  const fakeDocument = {
    getElementById: (id) => elements[id] || null,
    createElement: () => ({ click() {} }),
  };
  const service = exportsModule.createExportsIntegrationsService({
    windowRef: fakeWindow,
    documentRef: fakeDocument,
    executionStore: store,
    now: () => 1_700_000_000_000,
  });

  const reportPromise = service.openReportePageWithSubset(null, 'ghostrecon_reporte');
  assert.equal(opened.length, 1, 'popup precisa abrir antes do primeiro await');
  assert.equal(opened[0].name, 'ghostrecon_reporte');
  await reportPromise;
  const payload = JSON.parse(sessionStorage.getItem('ghostrecon_reporte_payload'));
  assert.equal(payload.target, 'api.example.test');
  assert.equal(payload.findings.length, 3);
  assert.equal(
    localStorage.getItem('ghostrecon_reporte_payload_shared'),
    sessionStorage.getItem('ghostrecon_reporte_payload'),
  );

  assert.equal(service.ensureGhostmapLiveChannel(), true);
  assert.equal(channels[0].name, 'ghostrecon-mitre-session-1');
  assert.equal(localStorage.getItem('ghostrecon_mitre_live_session_id'), 'session-1');
  assert.deepEqual(channels[0].messages[0], {
    type: 'target',
    domain: 'api.example.test',
    kaliMode: true,
  });
  service.openMitreMapPage('ghostrecon_ghostmap');
  assert.equal(opened.at(-1).name, 'ghostrecon_ghostmap');
  assert.match(opened.at(-1).url, /\/ghostmap\/ghostrecon#session-1$/);
  service.cleanup();
});
