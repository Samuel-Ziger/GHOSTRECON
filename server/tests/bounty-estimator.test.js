import test from 'node:test';
import assert from 'node:assert/strict';
import { estimateBounty, prioritize, summarizeValue, PROGRAM_TIERS } from '../modules/bounty-estimator.mjs';

test('estimator: critical RCE em VIP tier rende muito', () => {
  const e = estimateBounty({ severity: 'critical', category: 'rce' }, { tier: 'vip' });
  assert.ok(e.expectedPayout >= 5000);
  assert.equal(e.recommendation, 'go-now');
});

test('estimator: low XSS basic tier baixo', () => {
  const e = estimateBounty({ severity: 'low', category: 'xss' }, { tier: 'basic' });
  assert.ok(e.expectedPayout <= 100);
});

test('estimator: info → skip', () => {
  const e = estimateBounty({ severity: 'info', category: 'security-headers' });
  assert.equal(e.recommendation, 'skip');
});

test('estimator: prioritize ordena por ratio desc', () => {
  const findings = [
    { severity: 'low', category: 'xss' },
    { severity: 'critical', category: 'rce' },
    { severity: 'medium', category: 'security-headers' },
  ];
  const r = prioritize(findings, { tier: 'standard' });
  assert.equal(r[0].finding.category, 'rce');
});

test('estimator: summarizeValue agrega', () => {
  const s = summarizeValue([
    { severity: 'critical', category: 'rce' },
    { severity: 'high', category: 'sqli' },
    { severity: 'info', category: 'security-headers' },
  ], { tier: 'plus' });
  assert.ok(s.totalExpected > 0);
  assert.ok(s.byRecommendation['go-now'] >= 1 || s.byRecommendation['priority'] >= 1);
});

test('estimator: PROGRAM_TIERS coerentes (basic < vip < enterprise)', () => {
  assert.ok(PROGRAM_TIERS.basic < PROGRAM_TIERS.vip);
  assert.ok(PROGRAM_TIERS.vip < PROGRAM_TIERS.enterprise);
});

test('estimator: chain-* multiplier usado quando categoria começa com chain-', () => {
  const e = estimateBounty({ severity: 'critical', category: 'chain-ato' }, { tier: 'plus' });
  assert.ok(e.expectedPayout > 0);
});
