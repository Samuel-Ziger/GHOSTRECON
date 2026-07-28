import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import {
  buildGhostwatchAlertPayload,
  latestRunsByTarget,
  normalizeTargetForGhostwatch,
  normalizeDiffForGhostwatch,
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

test('ghostwatch: sanitizeGhostwatchModules removes VPS-forbidden modules', () => {
  assert.deepEqual(
    sanitizeGhostwatchModules([
      'subdomains',
      'kali_proxychains',
      'shannon_whitebox',
      'pentestgpt_validate',
      'vigolium_audit',
      'http',
    ]),
    ['subdomains', 'http'],
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

test('ghostwatch: plano intrusivo exige aprovação externa e nunca inicia stream', async () => {
  const stateDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostwatch-approval-'));
  const calls = [];
  let streamed = false;
  try {
    const client = {
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
        assert.fail('GhostWatch não pode iniciar stream intrusivo sem aprovação humana');
      },
    };
    const code = await runOneSweep({
      client,
      stateDir,
      log() {},
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
      },
    });
    assert.equal(code, 5);
    assert.deepEqual(calls, ['/api/recon/preflight']);
    assert.equal(streamed, false);

    const state = JSON.parse(
      await fs.readFile(path.join(stateDir, 'ghostwatch.json'), 'utf8'),
    );
    assert.match(
      state.lastRunByTarget['lab.example.test'].errors[0],
      /approval_required/,
    );
    assert.equal(
      state.history[0].targets[0].approvalRequired.planHash,
      'c'.repeat(64),
    );
  } finally {
    await fs.rm(stateDir, { recursive: true, force: true });
  }
});

test('ghostwatch: cliente não contém endpoint de autoaprovação', async () => {
  const source = await fs.readFile(
    new URL('../modules/cli/commands/ghostwatch.mjs', import.meta.url),
    'utf8',
  );
  assert.match(source, /\/api\/recon\/preflight/);
  assert.doesNotMatch(source, /\/api\/recon\/approval/);
});

test('ghostwatch: falha de preflight também encerra com código seguro', async () => {
  const stateDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostwatch-preflight-'));
  let listCalls = 0;
  try {
    const code = await runOneSweep({
      stateDir,
      log() {},
      client: {
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
