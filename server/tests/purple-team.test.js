/**
 * Purple team — origem annotation + control library + Sigma export.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  annotateOrigin, filterByOrigin, buildSigmaForFinding, sigmaToYaml,
  exportPurpleTeamReport, CONTROL_LIBRARY,
} from '../modules/purple-team.mjs';

test('purple: annotateOrigin adiciona metadata', () => {
  const f = annotateOrigin({ severity: 'high' }, { origin: 'simulated-lab', by: 'op1' });
  assert.equal(f.origin, 'simulated-lab');
  assert.equal(f.origin_meta.by, 'op1');
});

test('purple: annotateOrigin rejeita origem inválida', () => {
  assert.throws(() => annotateOrigin({}, { origin: 'bogus' }), /inválida/);
});

test('purple: filterByOrigin filtra corretamente', () => {
  const all = [
    { severity: 'a', origin: 'observed-prod' },
    { severity: 'b', origin: 'simulated-lab' },
    { severity: 'c' }, // default: observed-prod
  ];
  const prod = filterByOrigin(all, ['observed-prod']);
  assert.equal(prod.length, 2);
});

test('purple: CONTROL_LIBRARY tem categorias principais', () => {
  for (const k of ['rce', 'sqli', 'xss', 'ssrf', 'oauth-redirect', 'secrets-leak']) {
    assert.ok(CONTROL_LIBRARY[k], `missing ${k}`);
    assert.ok(CONTROL_LIBRARY[k].control);
    assert.ok(Array.isArray(CONTROL_LIBRARY[k].logSources));
  }
});

test('purple: buildSigmaForFinding gera objeto com campos Sigma', () => {
  const f = { category: 'rce', title: 'RCE', evidence: { url: 'http://x' } };
  const sig = buildSigmaForFinding(f);
  assert.ok(sig.title);
  assert.ok(sig.id.startsWith('ghostrecon-rce-'));
  assert.equal(sig.status, 'experimental');
  assert.ok(sig.detection.selection);
  assert.equal(sig.level, 'critical');
});

test('purple: buildSigmaForFinding retorna null para categoria sem detecção', () => {
  const f = { category: 'security-headers' };
  assert.equal(buildSigmaForFinding(f), null);
});

test('purple: sigmaToYaml produz YAML parseável (manual)', () => {
  const sig = buildSigmaForFinding({ category: 'xss', title: 'XSS' });
  const yaml = sigmaToYaml(sig);
  assert.ok(yaml.includes('title:'));
  assert.ok(yaml.includes('detection:'));
  assert.ok(yaml.includes('selection:'));
  assert.ok(yaml.includes('level: medium'));
});

test('purple: exportPurpleTeamReport inclui controle e Sigma por finding', () => {
  const run = {
    id: 1, target: 'x.com',
    findings: [
      { severity: 'high', category: 'sqli', title: 'SQLi', description: 'bad', evidence: { target: 'x.com' } },
      { severity: 'low', category: 'security-headers', title: 'CSP ausente' },
    ],
  };
  const md = exportPurpleTeamReport(run, { minSeverity: 'low' });
  assert.ok(md.includes('Purple team report'));
  assert.ok(md.includes('Controle sugerido'));
  assert.ok(md.includes('prepared statements')); // controle SQLi
  assert.ok(md.includes('Regra Sigma'));
});

test('purple: exportPurpleTeamReport respeita minSeverity', () => {
  const run = { id: 1, target: 'x.com', findings: [{ severity: 'info', category: 'rce', title: 'x' }] };
  const md = exportPurpleTeamReport(run, { minSeverity: 'high' });
  assert.ok(!md.includes('## [INFO]'));
});
