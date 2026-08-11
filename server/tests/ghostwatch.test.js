import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import {
  applyDomainsToWatchlist,
  buildGhostwatchAlertPayload,
  buildGhostwatchRunBody,
  canTrustedApprove,
  isLoopbackServerUrl,
  latestRunsByTarget,
  normalizeTargetForGhostwatch,
  normalizeDiffForGhostwatch,
  parseDomainsFile,
  resolveApiKeyRole,
  resolveOutOfScope,
  runOneSweep,
  sanitizeGhostwatchModules,
  selectGhostwatchTargets,
} from '../modules/cli/commands/ghostwatch.mjs';
import { summarizeDiff } from '../modules/diff-engine.mjs';

test('ghostwatch: latestRunsByTarget keeps newest id per target', () => {
  const latest = latestRunsByTarget([
    { id: 1, target: 'example.com' },
    { id: 3, target: 'api.example.com' },
    { id: 2, target: 'example.com' },
  ]);
  assert.equal(latest.get('example.com').id, 2);
  assert.equal(latest.get('api.example.com').id, 3);
});

test('ghostwatch: selectGhostwatchTargets skips disabled watchlist entries', () => {
  const latest = latestRunsByTarget([
    { id: 10, target: 'a.example.com' },
    { id: 11, target: 'b.example.com' },
  ]);
  const targets = selectGhostwatchTargets({
    latestRuns: latest,
    watchlist: {
      'b.example.com': { target: 'b.example.com', enabled: false },
      'c.example.com': { target: 'c.example.com', enabled: true },
    },
  });
  assert.deepEqual(targets.map((x) => x.target), ['a.example.com', 'c.example.com']);
});

test('ghostwatch: selectGhostwatchTargets accepts URL in onlyTarget', () => {
  const latest = latestRunsByTarget([{ id: 10, target: 'nenlucosmeticos.com' }]);
  const targets = selectGhostwatchTargets({
    latestRuns: latest,
    watchlist: {
      'nenlucosmeticos.com': { target: 'nenlucosmeticos.com', enabled: true },
    },
    onlyTarget: 'https://nenlucosmeticos.com/',
  });
  assert.deepEqual(targets.map((x) => x.target), ['nenlucosmeticos.com']);
});

test('ghostwatch: normalizeTargetForGhostwatch normalizes URLs', () => {
  assert.equal(normalizeTargetForGhostwatch('https://NenluCosmeticos.com/'), 'nenlucosmeticos.com');
});

test('ghostwatch: normalizeDiffForGhostwatch maps prio/value to diff-engine fields', () => {
  const diff = normalizeDiffForGhostwatch({
    target: 'example.com',
    baselineId: 1,
    newerId: 2,
    added: [{ prio: 'high', type: 'secret', value: 'GitHub token exposed', url: 'https://example.com/app.js' }],
    removed: [],
  });
  const summary = summarizeDiff(diff, { minSeverity: 'high', onlyNew: true });
  assert.equal(summary.addedCount, 1);
  assert.equal(summary.notableAdded[0].severity, 'high');
  assert.equal(summary.notableAdded[0].title, 'GitHub token exposed');
});

test('ghostwatch: alert payload is Discord-friendly markdown', () => {
  const payload = buildGhostwatchAlertPayload('example.com', {
    baselineId: 1,
    newerId: 2,
    addedCount: 1,
    addedBySeverity: { high: 1 },
    newHosts: ['api.example.com'],
    notableAdded: [{ severity: 'high', title: 'Admin exposed' }],
  });
  assert.equal(payload.source, 'ghostwatch');
  assert.match(payload.content, /GhostWatch/);
  assert.match(payload.content, /Admin exposed/);
});

test('ghostwatch: sanitizeGhostwatchModules removes only Tor/Navigator/proxychains', () => {
  assert.deepEqual(
    sanitizeGhostwatchModules([
      'subdomains',
      'kali_proxychains',
      'shannon_whitebox',
      'pentestgpt_validate',
      'vigolium_audit',
      'http',
      'navigator',
      'tor',
    ]),
    ['subdomains', 'shannon_whitebox', 'pentestgpt_validate', 'vigolium_audit', 'http'],
  );
});

test('ghostwatch: resolveOutOfScope merges baseline, watchlist and cli exclusions', () => {
  assert.deepEqual(
    resolveOutOfScope({
      baseline: { stats: { outOfScope: ['dev.example.com'] } },
      cfg: { outOfScope: ['*.legacy.example.com'] },
      opts: { 'out-of-scope': ['shop.example.com', 'dev.example.com'] },
    }),
    ['dev.example.com', '*.legacy.example.com', 'shop.example.com'],
  );
});

test('ghostwatch: parseDomainsFile ignora comentarios e invalidados', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostwatch-domains-'));
  const file = path.join(dir, 'domains.txt');
  try {
    await fs.writeFile(file, '# comment\n\nexemplo.com\nhttps://Alvo2.com/path\n#skip\n\n', 'utf8');
    assert.deepEqual(await parseDomainsFile(file), ['exemplo.com', 'alvo2.com']);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('ghostwatch: applyDomainsToWatchlist register/enable/disable e lista vazia', async () => {
  const state = {
    targets: {
      'old.example.com': { target: 'old.example.com', enabled: true, registeredAt: '2020-01-01T00:00:00.000Z' },
    },
  };
  const empty = await applyDomainsToWatchlist({ state, domains: [] });
  assert.equal(empty.skippedEmpty, true);
  assert.equal(state.targets['old.example.com'].enabled, true);

  const result = await applyDomainsToWatchlist({
    state,
    domains: ['novo.example.com'],
    playbook: 'full-recon',
  });
  assert.equal(result.skippedEmpty, false);
  assert.equal(state.targets['novo.example.com'].enabled, true);
  assert.equal(state.targets['old.example.com'].enabled, false);
  assert.deepEqual(result.registered, ['novo.example.com']);
  assert.deepEqual(result.disabled, ['old.example.com']);
});

test('ghostwatch: buildGhostwatchRunBody liga engines full', () => {
  const body = buildGhostwatchRunBody({
    target: 'lab.example.test',
    modules: ['http', 'subdomains'],
    runCfg: { kali: true, profile: 'aggressive', playbook: 'full-recon' },
    opts: {
      'opsec-profile': 'aggressive',
      'confirm-active': true,
      engine: 'both',
      strategy: 'deep',
      'vigolium-use-codex': true,
      'include-frameseven': true,
    },
    outOfScope: [],
  });
  assert.equal(body.engine, 'both');
  assert.equal(body.strategy, 'deep');
  assert.equal(body.vigoliumUseCodex, true);
  assert.equal(body.includeFrameSeven, true);
  assert.equal(body.frameSevenAuth, false);
  assert.equal(body.navigatorMode, false);
  assert.equal(body.tor.required, false);
});

test('ghostwatch: trusted-operator gates allow/deny', () => {
  assert.equal(isLoopbackServerUrl('http://127.0.0.1:3847'), true);
  assert.equal(isLoopbackServerUrl('http://evil.example:3847'), false);

  const apiKey = 'test-key-with-enough-length-0123456789';
  const env = {
    GHOSTWATCH_TRUSTED_OPERATOR: '1',
    GHOSTRECON_API_KEY: apiKey,
    AUTH_API_KEYS: `${apiKey}:admin:vps`,
  };
  assert.equal(resolveApiKeyRole(env), 'admin');

  const denied = canTrustedApprove({
    env: { ...env, GHOSTWATCH_TRUSTED_OPERATOR: '0' },
    serverUrl: 'http://127.0.0.1:3847',
    target: 'lab.example.test',
    watchlist: { 'lab.example.test': { target: 'lab.example.test', enabled: true } },
    confirmActive: true,
  });
  assert.equal(denied.ok, false);

  const outside = canTrustedApprove({
    env,
    serverUrl: 'http://127.0.0.1:3847',
    target: 'lab.example.test',
    watchlist: {},
    confirmActive: true,
  });
  assert.equal(outside.ok, false);

  const ok = canTrustedApprove({
    env,
    serverUrl: 'http://127.0.0.1:3847',
    target: 'lab.example.test',
    watchlist: { 'lab.example.test': { target: 'lab.example.test', enabled: true } },
    confirmActive: true,
  });
  assert.equal(ok.ok, true);
});

test('ghostwatch: sem trusted-operator bloqueia plano intrusivo', async () => {
  const stateDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostwatch-approval-'));
  const calls = [];
  let streamed = false;
  try {
    await fs.mkdir(stateDir, { recursive: true });
    await fs.writeFile(path.join(stateDir, 'ghostwatch.json'), JSON.stringify({
      version: 1,
      targets: {
        'lab.example.test': { target: 'lab.example.test', enabled: true, registeredAt: '2020-01-01T00:00:00.000Z' },
      },
      seenFingerprints: {},
      lastRunByTarget: {},
      history: [],
    }), 'utf8');

    const client = {
      baseUrl: 'http://127.0.0.1:3847',
      async listRuns() {
        return [{ id: 10, target: 'lab.example.test', stats: {} }];
      },
      async postJson(pathname, body) {
        calls.push(pathname);
        assert.equal(pathname, '/api/recon/preflight');
        return {
          ok: true,
          requiresApproval: true,
          plan: {
            hash: 'c'.repeat(64),
            target: body.domain,
            intrusiveModules: ['kali_active'],
          },
          approval: { approvalId: 'approval-ghostwatch-fixture' },
        };
      },
      async streamRecon() {
        streamed = true;
        assert.fail('GhostWatch não pode iniciar stream intrusivo sem trusted-operator');
      },
    };
    const code = await runOneSweep({
      client,
      stateDir,
      log() {},
      env: { GHOSTWATCH_TRUSTED_OPERATOR: '0' },
      ensureCve: async () => ({ status: 'skip', detail: 'test' }),
      opts: {
        target: 'lab.example.test',
        modules: ['headers'],
        playbook: '',
        profile: 'deep',
        kali: true,
        'opsec-profile': 'aggressive',
        'confirm-active': true,
        'out-of-scope': [],
        'limit-runs': 10,
        'max-targets': 0,
        'dry-run': false,
        timeout: 30,
        format: 'table',
        webhook: '',
        'min-severity': 'medium',
        'only-new': true,
        'sync-domains': false,
        'update-cve': false,
        engine: 'both',
        strategy: 'deep',
        'vigolium-use-codex': true,
        'include-frameseven': true,
        bootstrap: false,
        server: 'http://127.0.0.1:3847',
      },
    });
    assert.equal(code, 5);
    assert.deepEqual(calls, ['/api/recon/preflight']);
    assert.equal(streamed, false);
  } finally {
    await fs.rm(stateDir, { recursive: true, force: true });
  }
});

test('ghostwatch: trusted-operator aprova e inicia stream', async () => {
  const stateDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostwatch-trusted-'));
  const calls = [];
  let streamed = false;
  const apiKey = 'trusted-key-with-enough-length-0123456789';
  try {
    await fs.mkdir(stateDir, { recursive: true });
    await fs.writeFile(path.join(stateDir, 'ghostwatch.json'), JSON.stringify({
      version: 1,
      targets: {
        'lab.example.test': { target: 'lab.example.test', enabled: true, registeredAt: '2020-01-01T00:00:00.000Z' },
      },
      seenFingerprints: {},
      lastRunByTarget: {},
      history: [],
    }), 'utf8');

    const client = {
      baseUrl: 'http://127.0.0.1:3847',
      async listRuns() {
        return [{ id: 10, target: 'lab.example.test', stats: {} }];
      },
      async postJson(pathname, body) {
        calls.push(pathname);
        if (pathname === '/api/recon/preflight') {
          return {
            ok: true,
            requiresApproval: true,
            plan: {
              hash: 'a'.repeat(64),
              target: body.domain,
              intrusiveModules: ['kali_nuclei'],
            },
            approval: { approvalId: 'approval-trusted' },
          };
        }
        if (pathname === '/api/recon/approval') {
          assert.equal(body.approved, true);
          assert.equal(body.approvalId, 'approval-trusted');
          return { ok: true, approval: { status: 'approved' } };
        }
        throw new Error(`unexpected ${pathname}`);
      },
      async streamRecon(body) {
        streamed = true;
        assert.equal(body.manualApproval.approvalId, 'approval-trusted');
        assert.equal(body.includeFrameSeven, true);
        assert.equal(body.vigoliumUseCodex, true);
        assert.equal(body.engine, 'both');
      },
      async diffRuns() {
        return { error: 'skip' };
      },
    };

    const code = await runOneSweep({
      client,
      stateDir,
      log() {},
      env: {
        GHOSTWATCH_TRUSTED_OPERATOR: '1',
        GHOSTRECON_API_KEY: apiKey,
        AUTH_API_KEYS: `${apiKey}:red:vps`,
      },
      ensureCve: async () => ({ status: 'ok', detail: 'fresh' }),
      opts: {
        target: 'lab.example.test',
        modules: ['headers'],
        playbook: '',
        profile: 'aggressive',
        kali: true,
        'opsec-profile': 'aggressive',
        'confirm-active': true,
        'out-of-scope': [],
        'limit-runs': 10,
        'max-targets': 0,
        'dry-run': false,
        timeout: 30,
        format: 'table',
        webhook: '',
        'min-severity': 'medium',
        'only-new': true,
        'sync-domains': false,
        'update-cve': true,
        engine: 'both',
        strategy: 'deep',
        'vigolium-use-codex': true,
        'include-frameseven': true,
        bootstrap: false,
        server: 'http://127.0.0.1:3847',
      },
    });
    assert.equal(code, 0);
    assert.deepEqual(calls, ['/api/recon/preflight', '/api/recon/approval']);
    assert.equal(streamed, true);
  } finally {
    await fs.rm(stateDir, { recursive: true, force: true });
  }
});

test('ghostwatch: CVE hook roda antes do loop e nao aborta em warn', async () => {
  const stateDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostwatch-cve-'));
  let cveCalled = false;
  try {
    const code = await runOneSweep({
      stateDir,
      log() {},
      ensureCve: async () => {
        cveCalled = true;
        return { status: 'warn', detail: 'collect_failed_keep_old' };
      },
      client: {
        baseUrl: 'http://127.0.0.1:3847',
        async listRuns() {
          return [];
        },
      },
      opts: {
        'sync-domains': false,
        'update-cve': true,
        'limit-runs': 10,
        'max-targets': 0,
        format: 'table',
        'dry-run': true,
      },
    });
    assert.equal(code, 0);
    assert.equal(cveCalled, true);
  } finally {
    await fs.rm(stateDir, { recursive: true, force: true });
  }
});

test('ghostwatch: falha de preflight tambem encerra com codigo seguro', async () => {
  const stateDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostwatch-preflight-'));
  let listCalls = 0;
  try {
    await fs.mkdir(stateDir, { recursive: true });
    await fs.writeFile(path.join(stateDir, 'ghostwatch.json'), JSON.stringify({
      version: 1,
      targets: {
        'lab.example.test': { target: 'lab.example.test', enabled: true, registeredAt: '2020-01-01T00:00:00.000Z' },
      },
      seenFingerprints: {},
      lastRunByTarget: {},
      history: [],
    }), 'utf8');

    const code = await runOneSweep({
      stateDir,
      log() {},
      ensureCve: async () => ({ status: 'skip', detail: 'test' }),
      client: {
        baseUrl: 'http://127.0.0.1:3847',
        async listRuns() {
          listCalls += 1;
          return [{ id: 20, target: 'lab.example.test', stats: {} }];
        },
        async postJson() {
          throw new Error('preflight HTTP 403');
        },
        async streamRecon() {
          assert.fail('stream não pode iniciar após falha de preflight');
        },
      },
      opts: {
        target: 'lab.example.test',
        modules: ['headers'],
        playbook: '',
        profile: 'standard',
        kali: false,
        'opsec-profile': 'standard',
        'confirm-active': false,
        'out-of-scope': [],
        'limit-runs': 10,
        'max-targets': 0,
        'dry-run': false,
        timeout: 30,
        format: 'table',
        webhook: '',
        'min-severity': 'medium',
        'only-new': true,
        'sync-domains': false,
        'update-cve': false,
        engine: 'node',
        strategy: 'lite',
        'vigolium-use-codex': false,
        'include-frameseven': false,
        bootstrap: false,
        server: 'http://127.0.0.1:3847',
      },
    });
    assert.equal(code, 5);
    assert.equal(listCalls, 1);
    const state = JSON.parse(
      await fs.readFile(path.join(stateDir, 'ghostwatch.json'), 'utf8'),
    );
    assert.equal(state.history[0].targets[0].preflightFailed, true);
  } finally {
    await fs.rm(stateDir, { recursive: true, force: true });
  }
});
