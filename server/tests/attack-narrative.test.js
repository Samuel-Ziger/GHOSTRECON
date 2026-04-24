/**
 * Attack narrative — classificação por fase + cenários nomeados.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { narrate, narrativeToMarkdown, buildAttackPath, matchScenarios, PHASES, SCENARIOS } from '../modules/attack-narrative.mjs';

const sampleRun = {
  id: 10,
  target: 'acme.com',
  findings: [
    { severity: 'critical', category: 'rce', title: 'Remote Code Execution via upload' },
    { severity: 'high', category: 'sqli', title: 'SQL Injection em /search' },
    { severity: 'high', category: 'exposure', title: 'API key exposed em .env' },
    { severity: 'medium', category: 'auth-surface', title: 'Login /wp-admin aberto' },
    { severity: 'low', category: 'recon', title: 'Subdomain api.acme.com' },
    { severity: 'info', category: 'info', title: 'Server banner nginx' },
  ],
};

test('narrative: classifica findings em fases', () => {
  const nar = narrate(sampleRun);
  const execution = nar.phases.find((p) => p.id === 'execution');
  assert.equal(execution.findings.length, 1);
  assert.ok(execution.findings[0].title.includes('RCE') || execution.findings[0].title.includes('Code'));
  const injection = nar.phases.find((p) => p.id === 'injection');
  assert.ok(injection.findings.length >= 1);
});

test('narrative: score prioriza critical/high', () => {
  const nar = narrate(sampleRun);
  const execution = nar.phases.find((p) => p.id === 'execution');
  const recon = nar.phases.find((p) => p.id === 'recon');
  assert.ok(execution.score >= recon.score);
});

test('narrative: includeInfo=false filtra info findings', () => {
  const narNoInfo = narrate(sampleRun, { includeInfo: false });
  assert.equal(narNoInfo.totalFindings, 5); // 6 - 1 info
  const narWithInfo = narrate(sampleRun, { includeInfo: true });
  assert.equal(narWithInfo.totalFindings, 6);
});

test('narrative: OWASP → phase direto', () => {
  const r = { findings: [{ severity: 'high', category: 'x', owasp: ['A03:2021'], title: 'y' }] };
  const nar = narrate(r);
  const inj = nar.phases.find((p) => p.id === 'injection');
  assert.equal(inj.findings.length, 1);
});

test('narrative: markdown inclui storyline + fases', () => {
  const nar = narrate(sampleRun);
  const md = narrativeToMarkdown(nar);
  assert.ok(md.includes('# Attack narrative'));
  assert.ok(md.includes('Storyline'));
  assert.ok(md.includes('Execution'));
});

test('narrative: buildAttackPath identifica preconditions e impacts', () => {
  const ap = buildAttackPath(narrate(sampleRun));
  assert.ok(ap.preconditions.length > 0);
  assert.ok(ap.impacts.length > 0);
  assert.ok(ap.story.includes('1.'));
});

test('narrative: matchScenarios retorna matches por padrão', () => {
  const nar = narrate(sampleRun);
  const matches = matchScenarios(nar);
  assert.ok(matches.length > 0);
  // 'initial-access-admin' deve bater por wp-admin
  assert.ok(matches.some((m) => m.id === 'initial-access-admin'));
});

test('narrative: SCENARIOS tem campos mínimos', () => {
  for (const sc of Object.values(SCENARIOS)) {
    assert.ok(sc.id);
    assert.ok(sc.label);
    assert.ok(sc.triggers);
    assert.ok(Array.isArray(sc.recommendedNext));
  }
});

test('narrative: PHASES ordenadas', () => {
  for (let i = 1; i < PHASES.length; i++) {
    assert.ok(PHASES[i].order > PHASES[i - 1].order);
  }
});
