import test from 'node:test';
import assert from 'node:assert/strict';

import {
  autoEngineTimeouts,
  autoSessionLimits,
  createAutoSession,
  intersectAutoSessionLimits,
} from '../auto-agent/session-store.mjs';

test('limites padrão reservam 30 min ao pipeline e 90 min ao NeuroSploit', () => {
  assert.equal(autoSessionLimits({}).sessionTimeoutMs, 2 * 60 * 60_000);
  assert.equal(autoEngineTimeouts({}).pipelineTimeoutMs, 30 * 60_000);
});

test('resume determinístico preserva iteração/deadline e descarta estado do Council', async () => {
  const deadline = new Date(Date.now() + 120_000).toISOString();
  const session = createAutoSession({
    sessionId: 'resume-limits-1',
    requestRunId: 'run-limits-1',
    target: 'example.test',
    restoredState: {
      startedAt: new Date(Date.now() - 60_000).toISOString(),
      deadlineAt: deadline,
      iteration: 2,
      limits: {
        maxIterations: 3,
        sessionTimeoutMs: 600_000,
      },
      // Campos históricos são legíveis no arquivo, mas não reativados.
      providers: ['codex'],
      agentCalls: 9,
      costUsd: 3.5,
      usage: { codex: { calls: 9 } },
    },
  });

  try {
    assert.equal(session.state.iteration, 2);
    assert.equal(session.state.deadlineAt, deadline);
    assert.equal(session.limits.maxIterations, 3);
    assert.equal(Object.hasOwn(session.state, 'providers'), false);
    assert.equal(Object.hasOwn(session.state, 'agentCalls'), false);
    assert.equal(Object.hasOwn(session.state, 'costUsd'), false);
    assert.equal(Object.hasOwn(session.state, 'usage'), false);
    session.assertActive();
  } finally {
    await session.close('cancelled');
  }
});

test('assertActive falha quando deadlineAt já passou', async () => {
  const session = createAutoSession({
    sessionId: 'resume-limits-2',
    requestRunId: 'run-limits-2',
    target: 'example.test',
    restoredState: {
      deadlineAt: new Date(Date.now() - 1_000).toISOString(),
      limits: {
        maxIterations: 3,
        sessionTimeoutMs: 1_800_000,
      },
    },
  });
  try {
    assert.throws(() => session.assertActive(), /limite de tempo/);
  } finally {
    await session.close('cancelled');
  }
});

test('intersectAutoSessionLimits escolhe limites determinísticos mais restritivos', () => {
  const out = intersectAutoSessionLimits(
    { sessionTimeoutMs: 100_000, maxIterations: 2 },
    { sessionTimeoutMs: 50_000, maxIterations: 3 },
  );
  assert.deepEqual(out, {
    sessionTimeoutMs: 50_000,
    maxIterations: 2,
  });
});
