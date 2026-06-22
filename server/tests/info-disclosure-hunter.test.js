import test from 'node:test';
import assert from 'node:assert/strict';
import {
  infoDisclosureFindingFromRow,
  infoDisclosureModulesForRun,
  mapInfoDisclosureJsonToFindings,
} from '../modules/kali-scan.js';

test('InfoHunter modules: errors fica fora por padrao', () => {
  assert.deepEqual(infoDisclosureModulesForRun(), ['headers', 'files', 'listing', 'comments', 'metadata']);
  assert.deepEqual(infoDisclosureModulesForRun({ includeErrors: true }), [
    'headers',
    'files',
    'listing',
    'comments',
    'metadata',
    'errors',
  ]);
});

test('InfoHunter row vira finding info_disclosure com severidade preservada', () => {
  const finding = infoDisclosureFindingFromRow({
    modulo: 'files',
    severidade: 'CRITICAL',
    titulo: '.env exposto',
    url: 'https://example.test/.env',
    evidencia: 'DB_PASSWORD=secret',
  });
  assert.equal(finding.type, 'info_disclosure');
  assert.equal(finding.prio, 'high');
  assert.equal(finding.score, 96);
  assert.equal(finding.value, '.env exposto');
  assert.equal(finding.url, 'https://example.test/.env');
  assert.match(finding.meta, /scanner=infohunter_br/);
  assert.match(finding.meta, /module=files/);
  assert.match(finding.meta, /severity=CRITICAL/);
});

test('InfoHunter JSON mapper deduplica e usa URL alvo como fallback', () => {
  const json = {
    achados: [
      {
        modulo: 'headers',
        severidade: 'LOW',
        titulo: 'Server header divulga versao',
        url: '',
        evidencia: 'Server: nginx/1.25.0',
      },
      {
        modulo: 'headers',
        severidade: 'LOW',
        titulo: 'Server header divulga versao',
        url: '',
        evidencia: 'Server: nginx/1.25.0',
      },
    ],
  };
  const findings = mapInfoDisclosureJsonToFindings(json, { targetUrl: 'https://example.test/' });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].prio, 'low');
  assert.equal(findings[0].url, 'https://example.test/');
});
