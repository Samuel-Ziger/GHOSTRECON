/**
 * Workflow export — integrações Linear e Jira em modo dry-run.
 * Valida shape do preview (prioridade, labels, campos Jira obrigatórios).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { exportToLinear, exportToJira } from '../modules/workflow-export.mjs';

const sampleRun = {
  id: 7,
  target: 'acme.com',
  findings: [
    {
      severity: 'critical',
      category: 'rce',
      title: 'Remote Code Execution via file upload',
      description: 'Upload endpoint aceita .php.',
      owasp: ['A03:2021'],
      mitre: 'T1190',
      cve: ['CVE-2024-1234'],
      evidence: { target: 'acme.com', url: 'https://acme.com/upload' },
    },
    {
      severity: 'high',
      category: 'xss',
      title: 'Reflected XSS em search',
      description: 'Parametro q reflete sem sanitização.',
      evidence: { target: 'acme.com', url: 'https://acme.com/search?q=x' },
    },
    {
      severity: 'low',
      category: 'info',
      title: 'Server banner',
      description: 'nginx 1.18.0',
      evidence: { target: 'acme.com' },
    },
  ],
};

// ============================================================================
// Linear
// ============================================================================

test('linear: dry-run retorna preview sem fazer requests', async () => {
  const res = await exportToLinear(sampleRun, {
    teamId: 'TEAM-abc',
    token: 'lin_api_fake',
    minSeverity: 'medium',
    dryRun: true,
  });
  assert.equal(res.dryRun, true);
  assert.equal(res.preview.length, 2); // low filtrado
  assert.equal(res.created.length, 0);
  assert.equal(res.errors.length, 0);
});

test('linear: priority mapping (critical=1, high=2, medium=3, low=4)', async () => {
  const res = await exportToLinear(sampleRun, {
    teamId: 'T1', token: 'x', minSeverity: 'low', dryRun: true,
  });
  const byTitle = Object.fromEntries(res.preview.map((p) => [p.title, p.priority]));
  const critTitle = Object.keys(byTitle).find((t) => t.startsWith('[CRITICAL]'));
  const highTitle = Object.keys(byTitle).find((t) => t.startsWith('[HIGH]'));
  const lowTitle = Object.keys(byTitle).find((t) => t.startsWith('[LOW]'));
  assert.equal(byTitle[critTitle], 1);
  assert.equal(byTitle[highTitle], 2);
  assert.equal(byTitle[lowTitle], 4);
});

test('linear: titles carregam severidade e teamId', async () => {
  const res = await exportToLinear(sampleRun, {
    teamId: 'GR-1', token: 'x', minSeverity: 'high', dryRun: true,
  });
  assert.equal(res.preview.length, 2);
  for (const p of res.preview) {
    assert.equal(p.teamId, 'GR-1');
    assert.ok(p.title.match(/^\[(CRITICAL|HIGH)\]/));
  }
});

// ============================================================================
// Jira
// ============================================================================

test('jira: dry-run preview inclui fields obrigatórios', async () => {
  const res = await exportToJira(sampleRun, {
    baseUrl: 'https://acme.atlassian.net',
    project: 'SEC',
    user: 'user@acme.com',
    token: 'fake',
    minSeverity: 'medium',
    dryRun: true,
  });
  assert.equal(res.dryRun, true);
  assert.equal(res.preview.length, 2);
  const p = res.preview[0];
  assert.equal(p.fields.project.key, 'SEC');
  assert.equal(p.fields.issuetype.name, 'Bug');
  assert.ok(p.fields.summary.startsWith('['));
  assert.ok(Array.isArray(p.fields.labels));
  assert.ok(p.fields.labels.includes('ghostrecon'));
});

test('jira: priority mapping (critical→Highest, high→High, low→Low)', async () => {
  const res = await exportToJira(sampleRun, {
    baseUrl: 'https://x.atlassian.net', project: 'P', user: 'u', token: 't',
    minSeverity: 'low', dryRun: true,
  });
  const priorities = res.preview.map((p) => p.fields.priority.name);
  assert.ok(priorities.includes('Highest'));
  assert.ok(priorities.includes('High'));
  assert.ok(priorities.includes('Low'));
});

test('jira: labels incluem severity-<level>', async () => {
  const res = await exportToJira(sampleRun, {
    baseUrl: 'https://x.atlassian.net', project: 'P', user: 'u', token: 't',
    minSeverity: 'critical', dryRun: true,
  });
  assert.equal(res.preview.length, 1);
  assert.ok(res.preview[0].fields.labels.includes('severity-critical'));
});

test('jira: description inclui OWASP/MITRE/CVE do finding', async () => {
  const res = await exportToJira(sampleRun, {
    baseUrl: 'https://x.atlassian.net', project: 'P', user: 'u', token: 't',
    minSeverity: 'critical', dryRun: true,
  });
  const desc = res.preview[0].fields.description;
  assert.ok(desc.includes('A03:2021'));
  assert.ok(desc.includes('T1190'));
  assert.ok(desc.includes('CVE-2024-1234'));
});
