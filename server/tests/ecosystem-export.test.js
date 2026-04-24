/**
 * Ecosystem export — Obsidian, SIEM payload, naabu/httpx/ffuf normalizers.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  exportToObsidian, normalizeRunForSiem,
  normalizeNaabu, normalizeHttpx, normalizeFfuf, normalizeAuto,
} from '../modules/ecosystem-export.mjs';

const sampleRun = {
  id: 42,
  target: 'example.com',
  createdAt: '2026-04-24T10:00:00Z',
  modules: ['crtsh', 'http'],
  findings: [
    { severity: 'high', category: 'rce', title: 'RCE', description: 'bad', evidence: { target: 'example.com', url: 'http://example.com/x' } },
    { severity: 'low', category: 'info', title: 'banner', description: 'nginx' },
  ],
};

test('obsidian: gera index, run e finding files', () => {
  const eng = { id: 'ENG-1', client: 'acme', scopeDomains: ['*.example.com'], roeSigned: true };
  const { files } = exportToObsidian({ engagement: eng, runs: [sampleRun] });
  const paths = files.map((f) => f.path);
  assert.ok(paths.some((p) => p.includes('engagements/ENG-1/index.md')));
  assert.ok(paths.some((p) => p.includes('engagements/ENG-1/runs/run-42-example.com.md')));
  assert.ok(paths.some((p) => p.includes('engagements/ENG-1/findings/')));
  assert.ok(paths.some((p) => p.includes('targets/example.com.md')));
});

test('obsidian: frontmatter YAML válido nas notas', () => {
  const { files } = exportToObsidian({ engagement: { id: 'X' }, runs: [sampleRun] });
  const runFile = files.find((f) => f.path.includes('runs/'));
  assert.ok(runFile.content.startsWith('---\n'));
  assert.ok(runFile.content.includes('run_id: 42'));
  assert.ok(runFile.content.includes('engagement: X'));
  assert.ok(runFile.content.includes('target: example.com'));
});

test('obsidian: wikilinks entre run e findings', () => {
  const { files } = exportToObsidian({ runs: [sampleRun] });
  const runFile = files.find((f) => f.path.endsWith('run-42-example.com.md'));
  assert.ok(runFile.content.includes('[['));
});

test('siem: normalizeRunForSiem produz schema v1', () => {
  const p = normalizeRunForSiem(sampleRun, { engagement: { id: 'ENG-1', client: 'acme' }, operator: 'op1' });
  assert.equal(p.schema, 'ghostrecon.run.v1');
  assert.equal(p.engagement.id, 'ENG-1');
  assert.equal(p.operator, 'op1');
  assert.equal(p.run.id, 42);
  assert.equal(p.findings.length, 2);
  assert.ok(p.findings[0].signature.startsWith('sig-'));
  assert.equal(p.summary.total, 2);
  assert.equal(p.summary.bySeverity.high, 1);
});

test('siem: signature dedupe estável para findings idênticos', () => {
  const p = normalizeRunForSiem(sampleRun);
  const sig1 = p.findings[0].signature;
  const p2 = normalizeRunForSiem(sampleRun);
  assert.equal(sig1, p2.findings[0].signature);
});

test('normalizeNaabu: porta aberta → finding info', () => {
  const f = normalizeNaabu({ host: 'acme.com', ip: '1.2.3.4', port: 22, timestamp: 'x' });
  assert.equal(f.source, 'naabu');
  assert.equal(f.severity, 'info');
  assert.equal(f.evidence.port, 22);
  assert.ok(f.title.includes('22'));
});

test('normalizeNaabu: JSON string parseável', () => {
  const f = normalizeNaabu('{"host":"x","port":80,"ip":"1.1.1.1"}');
  assert.equal(f.severity, 'info');
});

test('normalizeHttpx: endpoint sensível → medium', () => {
  const f = normalizeHttpx({ url: 'https://x.com/admin', status_code: 200, title: 'Admin' });
  assert.equal(f.severity, 'medium');
  assert.equal(f.category, 'http-surface');
});

test('normalizeHttpx: endpoint comum → info', () => {
  const f = normalizeHttpx({ url: 'https://x.com/public', status_code: 200, title: 'Home' });
  assert.equal(f.severity, 'info');
});

test('normalizeFfuf: path quente → high', () => {
  const f = normalizeFfuf({ url: 'https://x.com/.env', status: 200, length: 500, input: '.env' });
  assert.equal(f.severity, 'high');
  assert.equal(f.category, 'content-discovery');
});

test('normalizeFfuf: path banal → info/low', () => {
  const f = normalizeFfuf({ url: 'https://x.com/static.css', status: 404, length: 0, input: 'static.css' });
  assert.equal(f.severity, 'info');
});

test('normalizeAuto: detecta shape httpx', () => {
  const f = normalizeAuto({ url: 'https://x.com/', status_code: 200, webserver: 'nginx' });
  assert.equal(f.source, 'httpx');
});

test('normalizeAuto: detecta shape naabu', () => {
  const f = normalizeAuto({ host: 'x.com', ip: '1.1.1.1', port: 443 });
  assert.equal(f.source, 'naabu');
});

test('normalizeAuto: input desconhecido retorna null', () => {
  assert.equal(normalizeAuto({ totally: 'unknown' }), null);
  assert.equal(normalizeAuto('not json'), null);
});
