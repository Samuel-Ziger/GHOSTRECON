import test from 'node:test';
import assert from 'node:assert/strict';

import {
  buildGhostwatchAlertPayload,
  latestRunsByTarget,
  normalizeDiffForGhostwatch,
  resolveOutOfScope,
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
