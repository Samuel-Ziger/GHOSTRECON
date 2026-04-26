import test from 'node:test';
import assert from 'node:assert/strict';
import { uniqueMarker, buildPayloads, buildVerificationPlan, evaluateEvidence } from '../modules/dom-xss-verify.mjs';

test('domxss: uniqueMarker tem prefixo determinístico', () => {
  const m = uniqueMarker('seed');
  assert.ok(m.startsWith('__GR_XSS_'));
  assert.equal(m.length, '__GR_XSS_'.length + 10 + 2); // _XX..._
});

test('domxss: buildPayloads inclui marker em cada payload', () => {
  const { marker, payloads } = buildPayloads('test');
  assert.ok(payloads.length >= 5);
  for (const p of payloads) assert.ok(p.payload.includes(marker));
});

test('domxss: buildVerificationPlan multiplica por param/url/payload', () => {
  const plan = buildVerificationPlan({
    urls: ['https://x.com/a', 'https://x.com/b'], params: ['q'], maxPerUrl: 3,
  });
  assert.equal(plan.length, 6); // 2 urls × 1 param × 3 payloads
  assert.ok(plan[0].url.includes('q='));
});

test('domxss: evaluateEvidence emite finding HIGH quando marker em sink real', () => {
  const plan = buildVerificationPlan({ urls: ['https://x.com/'], params: ['q'], maxPerUrl: 2 });
  const reports = plan.map((slot) => ({
    evidence: [{ sink: 'innerHTML', value: `xx ${slot.marker} yy` }],
  }));
  const findings = evaluateEvidence(plan, reports);
  assert.ok(findings.length >= 2);
  assert.ok(findings.every((f) => f.category === 'xss-dom-confirmed'));
});

test('domxss: evaluateEvidence dialog hit conta como confirmado', () => {
  const plan = buildVerificationPlan({ urls: ['https://x.com/'], params: ['q'], maxPerUrl: 1 });
  const reports = plan.map((slot) => ({ evidence: [{ sink: 'dialog', value: slot.marker }] }));
  const findings = evaluateEvidence(plan, reports);
  assert.equal(findings[0].severity, 'high');
});

test('domxss: marker em console-only é apenas reflexão (low)', () => {
  const plan = buildVerificationPlan({ urls: ['https://x.com/'], params: ['q'], maxPerUrl: 1 });
  const reports = plan.map((slot) => ({ evidence: [{ sink: 'console', value: slot.marker }] }));
  const findings = evaluateEvidence(plan, reports);
  assert.equal(findings[0].category, 'xss-dom-reflected');
  assert.equal(findings[0].severity, 'low');
});
