import test from 'node:test';
import assert from 'node:assert/strict';
import { applyRiskExplanations, explainFindingRisk } from '../modules/risk-explainer.mjs';

test('explainFindingRisk reconhece secrets', () => {
  const risk = explainFindingRisk({ type: 'secret', prio: 'high', value: 'token' });
  assert.equal(risk.confidence, 'high');
  assert.match(risk.why, /credenciais|tokens/i);
});

test('applyRiskExplanations adiciona contexto sem sobrescrever existente', () => {
  const findings = [
    { type: 'panel', value: '/admin', prio: 'med' },
    { type: 'intel', value: 'x', risk: { why: 'custom' } },
  ];
  const out = applyRiskExplanations(findings);
  assert.equal(out.changed, 1);
  assert.ok(findings[0].risk?.why);
  assert.equal(findings[1].risk.why, 'custom');
});
