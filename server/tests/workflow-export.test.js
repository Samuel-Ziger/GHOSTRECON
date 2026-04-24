import test from 'node:test';
import assert from 'node:assert/strict';
import { exportToMarkdown, exportToGithubIssues } from '../modules/workflow-export.mjs';

const sampleRun = {
  id: 42,
  target: 'example.com',
  findings: [
    {
      severity: 'high',
      category: 'security-headers',
      title: 'CSP ausente',
      description: 'A resposta não inclui Content-Security-Policy.',
      owasp: ['A05:2021'],
      evidence: { target: 'example.com', url: 'https://example.com/' },
    },
    {
      severity: 'low',
      category: 'info',
      title: 'Server banner',
      description: 'nginx 1.18.0',
      evidence: { target: 'example.com' },
    },
  ],
};

test('exportToMarkdown: filtra por severidade', () => {
  const md = exportToMarkdown(sampleRun, { minSeverity: 'medium' });
  assert.ok(md.includes('CSP ausente'));
  assert.ok(!md.includes('Server banner'));
  assert.ok(md.includes('example.com'));
  assert.ok(md.includes('run #42'));
});

test('exportToMarkdown: inclui OWASP e run header', () => {
  const md = exportToMarkdown(sampleRun, { minSeverity: 'low' });
  assert.ok(md.includes('A05:2021'));
  assert.ok(md.includes('## ['));
});

test('exportToGithubIssues: dry-run não faz requests', async () => {
  const res = await exportToGithubIssues(sampleRun, {
    repo: 'owner/name',
    token: 'fake',
    minSeverity: 'low',
    dryRun: true,
  });
  assert.equal(res.dryRun, true);
  assert.equal(res.preview.length, 2);
  assert.ok(res.preview[0].labels.includes('ghostrecon'));
  assert.ok(res.preview[0].labels.some((l) => l.startsWith('severity:')));
});

test('exportToGithubIssues: title formato correto', async () => {
  const res = await exportToGithubIssues(sampleRun, {
    repo: 'o/n', token: 'x', minSeverity: 'high', dryRun: true,
  });
  assert.equal(res.preview.length, 1);
  assert.ok(/^\[HIGH\]/.test(res.preview[0].title));
});
