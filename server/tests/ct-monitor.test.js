import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { monitorCt, classifyNewSubs } from '../modules/ct-monitor.mjs';

function isolate() {
  const dir = path.join(os.tmpdir(), `gr-ct-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`);
  process.env.GHOSTRECON_CT_DIR = dir;
  return dir;
}

test('ct: monitorCt primeira execução popula state e emite findings', async () => {
  isolate();
  const fakeSource = async () => ['api.acme.com', 'admin.acme.com', 'www.acme.com'];
  const r = await monitorCt('acme.com', { source: fakeSource });
  assert.equal(r.fresh.length, 3);
  assert.equal(r.findings.length, 3);
});

test('ct: monitorCt segunda execução só emite novos', async () => {
  isolate();
  const src1 = async () => ['a.acme.com', 'b.acme.com'];
  await monitorCt('acme.com', { source: src1 });
  const src2 = async () => ['a.acme.com', 'b.acme.com', 'c.acme.com'];
  const r = await monitorCt('acme.com', { source: src2 });
  assert.deepEqual(r.fresh, ['c.acme.com']);
});

test('ct: monitorCt sem novos = sem findings', async () => {
  isolate();
  const src = async () => ['a.acme.com'];
  await monitorCt('acme.com', { source: src });
  const r = await monitorCt('acme.com', { source: src });
  assert.equal(r.fresh.length, 0);
  assert.equal(r.findings.length, 0);
});

test('ct: classifyNewSubs marca hot subs', () => {
  const r = classifyNewSubs(['admin.x.com', 'foo.x.com', 'jenkins.x.com']);
  assert.equal(r.find((x) => x.sub === 'admin.x.com').hot, true);
  assert.equal(r.find((x) => x.sub === 'jenkins.x.com').severity, 'medium');
  assert.equal(r.find((x) => x.sub === 'foo.x.com').hot, false);
});

test('ct: monitorCt apex obrigatório', async () => {
  await assert.rejects(() => monitorCt('', { source: async () => [] }), /apex/);
});
