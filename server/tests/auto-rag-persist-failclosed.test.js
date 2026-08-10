import test from 'node:test';
import assert from 'node:assert/strict';
import {
  isDurableRagRequired,
  evaluateRagPersist,
  assertDurableRagPersist,
} from '../auto-agent/rag-persist-guard.mjs';

test('isDurableRagRequired: default off, aceita 1/true/on', () => {
  assert.equal(isDurableRagRequired({}), false);
  assert.equal(isDurableRagRequired({ GHOSTRECON_AUTO_RAG_REQUIRED: '0' }), false);
  assert.equal(isDurableRagRequired({ GHOSTRECON_AUTO_RAG_REQUIRED: 'false' }), false);
  assert.equal(isDurableRagRequired({ GHOSTRECON_AUTO_RAG_REQUIRED: '1' }), true);
  assert.equal(isDurableRagRequired({ GHOSTRECON_AUTO_RAG_REQUIRED: 'true' }), true);
  assert.equal(isDurableRagRequired({ GHOSTRECON_AUTO_RAG_REQUIRED: 'on' }), true);
});

test('evaluateRagPersist classifica sucesso, erro, skip, ausência', () => {
  assert.deepEqual(evaluateRagPersist({ filePath: '/x/y.md', filename: 'y.md' }), { ok: true, reason: null });
  assert.equal(evaluateRagPersist({ error: 'EACCES' }).ok, false);
  assert.match(evaluateRagPersist({ error: 'EACCES' }).reason, /rag_write_error/);
  assert.equal(evaluateRagPersist({ skipped: true, reason: 'rag_file_limit' }).ok, false);
  assert.match(evaluateRagPersist({ skipped: true, reason: 'rag_file_limit' }).reason, /rag_skipped: rag_file_limit/);
  assert.equal(evaluateRagPersist(null).ok, false);
  assert.match(evaluateRagPersist(null).reason, /rag_disabled_or_absent/);
  assert.equal(evaluateRagPersist({}).ok, false);
  assert.match(evaluateRagPersist({}).reason, /rag_unknown_result/);
});

test('default (sem flag): erro de RAG não é fatal e não emite auto_persist_failed', () => {
  const emitted = [];
  const result = assertDurableRagPersist(
    { error: 'disco cheio' },
    { env: {}, captureEmit: (e) => emitted.push(e), sessionId: 's1', requestRunId: 'r1', stage: 'plan' },
  );
  assert.deepEqual(result, { error: 'disco cheio' });
  assert.equal(emitted.length, 0);
});

test('required + erro: emite auto_persist_failed (rag_plan) e lança AUTO_RAG_PERSIST_FAILED', () => {
  const emitted = [];
  assert.throws(
    () => assertDurableRagPersist(
      { error: 'disco cheio' },
      {
        env: { GHOSTRECON_AUTO_RAG_REQUIRED: '1' },
        captureEmit: (e) => emitted.push(e),
        sessionId: 's1',
        requestRunId: 'r1',
        stage: 'plan',
      },
    ),
    (err) => err.code === 'AUTO_RAG_PERSIST_FAILED' && /plan/.test(err.message),
  );
  assert.equal(emitted.length, 1);
  assert.equal(emitted[0].type, 'auto_persist_failed');
  assert.equal(emitted[0].stage, 'rag_plan');
  assert.equal(emitted[0].sessionId, 's1');
  assert.match(emitted[0].error, /rag_write_error/);
});

test('required + skip de capacidade: fail-closed', () => {
  const emitted = [];
  assert.throws(
    () => assertDurableRagPersist(
      { skipped: true, reason: 'rag_file_limit' },
      { env: { GHOSTRECON_AUTO_RAG_REQUIRED: '1' }, captureEmit: (e) => emitted.push(e), stage: 'evaluation' },
    ),
    (err) => err.code === 'AUTO_RAG_PERSIST_FAILED',
  );
  assert.equal(emitted[0].stage, 'rag_evaluation');
  assert.match(emitted[0].error, /rag_skipped/);
});

test('required + RAG desabilitado (null): fail-closed por contradição de config', () => {
  assert.throws(
    () => assertDurableRagPersist(null, { env: { GHOSTRECON_AUTO_RAG_REQUIRED: '1' } }),
    (err) => err.code === 'AUTO_RAG_PERSIST_FAILED' && /rag_disabled_or_absent/.test(err.message),
  );
});

test('required + sucesso: retorna resultado sem emitir nem lançar', () => {
  const emitted = [];
  const ok = { filePath: '/data/auto-rag/decisions/x.md', filename: 'x.md' };
  const result = assertDurableRagPersist(ok, {
    env: { GHOSTRECON_AUTO_RAG_REQUIRED: '1' },
    captureEmit: (e) => emitted.push(e),
  });
  assert.deepEqual(result, ok);
  assert.equal(emitted.length, 0);
});
