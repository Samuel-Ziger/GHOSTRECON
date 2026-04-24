/**
 * Replay + tabletop rerank.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import { replayNdjson, replayNdjsonSync, tabletopRerank } from '../modules/replay-tabletop.mjs';

function tmp() {
  return path.join(os.tmpdir(), `gr-rep-${Date.now()}-${Math.random().toString(36).slice(2, 8)}.ndjson`);
}

test('replay: replayNdjsonSync lê todos os eventos', () => {
  const f = tmp();
  fsSync.writeFileSync(f, '{"t":1}\n{"t":2}\n{"t":3}\n');
  const seen = [];
  const r = replayNdjsonSync(f, (e) => seen.push(e));
  assert.equal(r.replayed, 3);
  assert.deepEqual(seen, [{ t: 1 }, { t: 2 }, { t: 3 }]);
});

test('replay: replayNdjsonSync ignora linhas malformadas', () => {
  const f = tmp();
  fsSync.writeFileSync(f, '{"ok":1}\n{oops\n{"ok":2}\n');
  const seen = [];
  const r = replayNdjsonSync(f, (e) => seen.push(e));
  assert.equal(r.replayed, 2);
});

test('replay: replayNdjson async com speed=Infinity instantâneo', async () => {
  const f = tmp();
  await fs.writeFile(f, '{"at":"2026-01-01T00:00:00Z"}\n{"at":"2026-01-01T00:00:10Z"}\n', 'utf8');
  const seen = [];
  const start = Date.now();
  await replayNdjson(f, (e) => seen.push(e), { speed: Infinity });
  const dur = Date.now() - start;
  assert.equal(seen.length, 2);
  assert.ok(dur < 500, `replay deveria ser rápido, durou ${dur}ms`);
});

test('replay: limit corta eventos', async () => {
  const f = tmp();
  await fs.writeFile(f, Array.from({ length: 10 }, (_, i) => JSON.stringify({ i })).join('\n'), 'utf8');
  const seen = [];
  const r = await replayNdjson(f, (e) => seen.push(e), { speed: Infinity, limit: 3 });
  assert.equal(r.replayed, 3);
  assert.equal(seen.length, 3);
});

// ============================================================================
// Tabletop
// ============================================================================

const sampleRun = {
  id: 1, target: 'acme.com',
  findings: [
    { severity: 'high', category: 'rce', title: 'RCE', evidence: { target: 'prod.acme.com' } },
    { severity: 'medium', category: 'xss', title: 'XSS', evidence: { target: 'staging.acme.com' } },
    { severity: 'low', category: 'info-banner', title: 'Banner', evidence: { target: 'acme.com' } },
    { severity: 'info', category: 'oidc-config', title: 'PKCE', evidence: { target: 'idp.acme.com' } },
  ],
};

test('tabletop: bumpSeverity eleva severidade', () => {
  const r = tabletopRerank(sampleRun, {
    bountyContext: { bumpSeverity: { rce: 'critical' } },
  });
  const rce = r.findings.find((f) => f.category === 'rce');
  assert.equal(rce.severity, 'critical');
  assert.equal(rce.rerank.originalSeverity, 'high');
});

test('tabletop: dropIfCategory filtra findings', () => {
  const r = tabletopRerank(sampleRun, {
    bountyContext: { dropIfCategory: ['info-banner'] },
  });
  assert.equal(r.kept, 3);
  assert.equal(r.dropped, 1);
  assert.ok(!r.findings.find((f) => f.category === 'info-banner'));
});

test('tabletop: excludeHosts remove por host', () => {
  const r = tabletopRerank(sampleRun, {
    bountyContext: { excludeHosts: ['staging.*'] },
  });
  assert.ok(!r.findings.find((f) => f.evidence?.target?.startsWith('staging')));
});

test('tabletop: onlyHosts filtra apenas matches', () => {
  const r = tabletopRerank(sampleRun, {
    bountyContext: { onlyHosts: ['*.acme.com'] },
  });
  // só subdomains válidos permanecem
  assert.ok(r.kept >= 2);
  for (const f of r.findings) {
    assert.ok(f.evidence?.target?.endsWith('.acme.com'));
  }
});

test('tabletop: weightByCategory afeta score ordering', () => {
  const r = tabletopRerank(sampleRun, {
    bountyContext: { weightByCategory: { 'oidc-config': 10 } },
  });
  // findings ordenados por score desc
  for (let i = 1; i < r.findings.length; i++) {
    assert.ok(r.findings[i - 1].rerank.score >= r.findings[i].rerank.score);
  }
});

test('tabletop: summary por severidade', () => {
  const r = tabletopRerank(sampleRun, {});
  assert.equal(r.summary.high, 1);
  assert.equal(r.summary.medium, 1);
  assert.equal(r.summary.low, 1);
  assert.equal(r.summary.info, 1);
});

test('tabletop: sem bountyContext é no-op (kept=total)', () => {
  const r = tabletopRerank(sampleRun);
  assert.equal(r.kept, r.total);
  assert.equal(r.dropped, 0);
});
