import test from 'node:test';
import assert from 'node:assert/strict';
import { summarizeDiff, shouldAlert, normalizeSeverity } from '../modules/diff-engine.mjs';

const mkFinding = (sev, title, host) => ({
  severity: sev,
  title,
  category: 'test',
  evidence: { target: host, host },
});

test('summarizeDiff: counts by severity', () => {
  const diff = {
    target: 'example.com',
    baselineId: 1,
    newerId: 2,
    added: [
      mkFinding('high', 'x', 'api.example.com'),
      mkFinding('medium', 'y', 'api.example.com'),
      mkFinding('low', 'z', 'blog.example.com'),
    ],
    removed: [mkFinding('low', 'old', 'api.example.com')],
  };
  const s = summarizeDiff(diff, { minSeverity: 'low' });
  assert.equal(s.addedCount, 3);
  assert.equal(s.removedCount, 1);
  assert.equal(s.addedBySeverity.high, 1);
  assert.equal(s.addedBySeverity.medium, 1);
  assert.equal(s.addedBySeverity.low, 1);
});

test('summarizeDiff: minSeverity filters out low', () => {
  const diff = {
    target: 'example.com',
    added: [mkFinding('high', 'x'), mkFinding('low', 'y')],
    removed: [],
  };
  const s = summarizeDiff(diff, { minSeverity: 'high' });
  assert.equal(s.addedCount, 1);
  assert.equal(s.addedBySeverity.high, 1);
  assert.equal(s.addedBySeverity.low, undefined);
});

test('summarizeDiff: fingerprint estável', () => {
  const diff = {
    target: 'example.com',
    added: [mkFinding('high', 'x', 'a.com'), mkFinding('medium', 'y', 'b.com')],
    removed: [],
  };
  const fp1 = summarizeDiff(diff, {}).fingerprint;
  // trocar ordem não muda fingerprint
  const diff2 = { ...diff, added: diff.added.slice().reverse() };
  const fp2 = summarizeDiff(diff2, {}).fingerprint;
  assert.equal(fp1, fp2);
  assert.equal(fp1.length, 16);
});

test('summarizeDiff: fingerprint muda com novo finding', () => {
  const a = summarizeDiff({ target: 'x', added: [mkFinding('high', 'x')], removed: [] }).fingerprint;
  const b = summarizeDiff({
    target: 'x',
    added: [mkFinding('high', 'x'), mkFinding('high', 'y')],
    removed: [],
  }).fingerprint;
  assert.notEqual(a, b);
});

test('shouldAlert: respeita seenFingerprints quando onlyNew', () => {
  const summary = {
    addedCount: 1,
    newHosts: [],
    fingerprint: 'deadbeef',
    onlyNew: true,
  };
  assert.equal(shouldAlert(summary, { seenFingerprints: new Set() }), true);
  assert.equal(shouldAlert(summary, { seenFingerprints: new Set(['deadbeef']) }), false);
});

test('shouldAlert: sem onlyNew alerta mesmo se visto', () => {
  const summary = { addedCount: 2, newHosts: [], fingerprint: 'x', onlyNew: false };
  assert.equal(shouldAlert(summary, { seenFingerprints: new Set(['x']) }), true);
});

test('shouldAlert: false quando sem added nem novos hosts', () => {
  const summary = { addedCount: 0, newHosts: [], fingerprint: 'x' };
  assert.equal(shouldAlert(summary), false);
});

test('normalizeSeverity maps aliases', () => {
  assert.equal(normalizeSeverity('crit'), 'critical');
  assert.equal(normalizeSeverity('HIGH'), 'high');
  assert.equal(normalizeSeverity(''), 'info');
});
