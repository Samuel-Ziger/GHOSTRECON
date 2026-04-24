/**
 * Engagement mode — ROE metadata, checklist, op-report.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import {
  upsertEngagement, getEngagement, listEngagements, closeEngagement,
  attachRunToEngagement, preRunChecklist, buildOperationalReport,
} from '../modules/engagement.mjs';

function isolate() {
  const dir = path.join(os.tmpdir(), `gr-eng-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`);
  process.env.GHOSTRECON_ENGAGEMENT_DIR = dir;
  process.chdir(os.tmpdir());
  return dir;
}

test('engagement: upsert + list + get', async () => {
  isolate();
  await upsertEngagement({ id: 'ENG-001', client: 'acme', scopeDomains: ['*.acme.com'] });
  const list = await listEngagements();
  assert.ok(list.find((e) => e.id === 'ENG-001'));
  const e = await getEngagement('ENG-001');
  assert.equal(e.client, 'acme');
  assert.deepEqual(e.scopeDomains, ['*.acme.com']);
});

test('engagement: close marca status e closedAt', async () => {
  isolate();
  await upsertEngagement({ id: 'E', client: 'x' });
  const closed = await closeEngagement('E', { reason: 'done' });
  assert.equal(closed.status, 'closed');
  assert.ok(closed.closedAt);
});

test('engagement: attachRun registra no histórico', async () => {
  isolate();
  await upsertEngagement({ id: 'E2' });
  await attachRunToEngagement('E2', { runId: 7, target: 'acme.com', by: 'op1' });
  const e = await getEngagement('E2');
  assert.equal(e.runs.length, 1);
  assert.equal(e.runs[0].by, 'op1');
});

test('engagement: preRunChecklist bloqueia out-of-scope', () => {
  const eng = {
    id: 'E', status: 'active', roeSigned: true,
    scopeDomains: ['*.acme.com'], scopeIps: [], exclusions: [],
  };
  const r = preRunChecklist({ engagement: eng, target: 'evil.com' });
  assert.equal(r.ok, false);
  assert.ok(r.errors.some((x) => /fora do escopo/.test(x)));
});

test('engagement: preRunChecklist bloqueia exclusions', () => {
  const eng = {
    status: 'active', roeSigned: true,
    scopeDomains: ['*.acme.com'], exclusions: ['staging.acme.com'],
  };
  const r = preRunChecklist({ engagement: eng, target: 'staging.acme.com' });
  assert.equal(r.ok, false);
  assert.ok(r.errors.some((x) => /exclusions/.test(x)));
});

test('engagement: preRunChecklist bloqueia CLOSED', () => {
  const eng = { id: 'E', status: 'closed', closedAt: '2024-01-01', scopeDomains: [], roeSigned: true };
  const r = preRunChecklist({ engagement: eng, target: 'acme.com' });
  assert.equal(r.ok, false);
  assert.ok(r.errors.some((x) => /CLOSED/.test(x)));
});

test('engagement: preRunChecklist warn em módulos intrusivos', () => {
  const r = preRunChecklist({ engagement: null, target: 'acme.com', modules: ['crtsh', 'sqlmap', 'nuclei'] });
  assert.ok(r.warnings.some((w) => /INTRUSIVOS/.test(w)));
  assert.deepEqual(r.intrusiveModules.sort(), ['nuclei', 'sqlmap']);
});

test('engagement: preRunChecklist respeita janela de tempo', () => {
  const past = new Date(Date.now() - 3600_000).toISOString();
  const eng = {
    status: 'active', roeSigned: true,
    scopeDomains: ['*.acme.com'],
    window: { startsAt: past, endsAt: past },
  };
  const r = preRunChecklist({ engagement: eng, target: 'sub.acme.com' });
  assert.equal(r.ok, false);
  assert.ok(r.errors.some((x) => /janela/.test(x)));
});

test('engagement: buildOperationalReport gera markdown', async () => {
  isolate();
  const e = await upsertEngagement({
    id: 'E3', client: 'acme', scopeDomains: ['*.acme.com'],
    roeUrl: 'https://example.com/roe.pdf', roeSigned: true,
    escalationContact: { name: 'Alice', email: 'alice@acme.com', phone: '123' },
  });
  const md = buildOperationalReport(e, { runs: [{ modules: ['crtsh'], findings: [{ severity: 'high' }] }] });
  assert.ok(md.includes('Operational Report'));
  assert.ok(md.includes('acme'));
  assert.ok(md.includes('Alice'));
  assert.ok(md.includes('high=1'));
});
