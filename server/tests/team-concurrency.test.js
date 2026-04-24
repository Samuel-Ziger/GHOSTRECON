/**
 * Team concurrency — locks + trail + diff.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs/promises';
import {
  acquireLock, releaseLock, forceReleaseLock, listLocks, withLock,
  recordAction, listTrail, diffByOperator,
} from '../modules/team-concurrency.mjs';

function isolate() {
  const dir = path.join(os.tmpdir(), `gr-team-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`);
  process.env.GHOSTRECON_TEAM_DIR = dir;
  process.chdir(os.tmpdir());
  return dir;
}

test('team: acquireLock primeiro operador ganha', async () => {
  isolate();
  const a = await acquireLock('acme.com', { operator: 'op1', ttlMs: 60_000 });
  assert.equal(a.ok, true);
  assert.ok(a.token);
});

test('team: acquireLock segundo bate e recebe heldBy', async () => {
  isolate();
  await acquireLock('acme.com', { operator: 'op1' });
  const b = await acquireLock('acme.com', { operator: 'op2' });
  assert.equal(b.ok, false);
  assert.equal(b.heldBy, 'op1');
});

test('team: releaseLock libera o slot', async () => {
  isolate();
  const a = await acquireLock('acme.com', { operator: 'op1' });
  const ok = await releaseLock('acme.com', a.token);
  assert.equal(ok, true);
  const c = await acquireLock('acme.com', { operator: 'op2' });
  assert.equal(c.ok, true);
});

test('team: releaseLock com token errado falha', async () => {
  isolate();
  await acquireLock('acme.com', { operator: 'op1' });
  const ok = await releaseLock('acme.com', 'wrong-token');
  assert.equal(ok, false);
});

test('team: TTL expirado libera automaticamente no próximo acquire', async () => {
  isolate();
  await acquireLock('a.com', { operator: 'op1', ttlMs: 1 });
  await new Promise((r) => setTimeout(r, 10));
  const b = await acquireLock('a.com', { operator: 'op2' });
  assert.equal(b.ok, true);
});

test('team: forceReleaseLock', async () => {
  isolate();
  await acquireLock('a.com', { operator: 'op1' });
  const ok = await forceReleaseLock('a.com');
  assert.equal(ok, true);
  const locks = await listLocks();
  assert.equal(locks.length, 0);
});

test('team: withLock auto-release em sucesso', async () => {
  isolate();
  const result = await withLock('a.com', async () => 'ok', { operator: 'op1' });
  assert.equal(result, 'ok');
  const locks = await listLocks();
  assert.equal(locks.length, 0);
});

test('team: withLock auto-release em erro', async () => {
  isolate();
  await assert.rejects(() => withLock('a.com', async () => { throw new Error('boom'); }, { operator: 'op1' }), /boom/);
  const locks = await listLocks();
  assert.equal(locks.length, 0);
});

test('team: withLock propaga ELOCKED', async () => {
  isolate();
  await acquireLock('a.com', { operator: 'op1' });
  await assert.rejects(() => withLock('a.com', async () => 'x', { operator: 'op2' }), (e) => e.code === 'ELOCKED');
});

test('team: trail — recordAction + listTrail', async () => {
  isolate();
  await recordAction({ operator: 'op1', target: 'x.com', action: 'run-start', runId: 10 });
  await recordAction({ operator: 'op2', target: 'x.com', action: 'evidence-captured', runId: 10 });
  const t = await listTrail({ target: 'x.com' });
  assert.equal(t.length, 2);
});

test('team: trail — diffByOperator agrega', async () => {
  isolate();
  await recordAction({ operator: 'op1', target: 'x.com', action: 'run-start', runId: 1 });
  await recordAction({ operator: 'op2', target: 'x.com', action: 'finding-validated', runId: 1 });
  await recordAction({ operator: 'op1', target: 'x.com', action: 'evidence-captured', runId: 1 });
  const d = await diffByOperator({ target: 'x.com' });
  assert.equal(Object.keys(d.byOperator).length, 2);
  assert.equal(d.byOperator.op1.counts['run-start'], 1);
  assert.equal(d.byOperator.op1.counts['evidence-captured'], 1);
  assert.equal(d.byOperator.op2.counts['finding-validated'], 1);
  assert.deepEqual(d.runs, [1]);
});

test('team: trail persiste NDJSON append-only', async () => {
  const dir = isolate();
  await recordAction({ operator: 'x', target: 't.com', action: 'a' });
  await recordAction({ operator: 'x', target: 't.com', action: 'b' });
  const raw = await fs.readFile(path.join(dir, 'trail.jsonl'), 'utf8');
  const lines = raw.split('\n').filter(Boolean);
  assert.equal(lines.length, 2);
  const second = JSON.parse(lines[1]);
  assert.equal(second.action, 'b');
});
