import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createAutoSession,
  intersectAutoSessionLimits,
} from '../auto-agent/session-store.mjs';

test('resume preserva agentCalls/costUsd e usa deadlineAt absoluto', () => {
  const past = new Date(Date.now() - 60_000).toISOString();
  const deadline = new Date(Date.now() + 120_000).toISOString();
  const session = createAutoSession({
    sessionId: 'resume-budget-1',
    requestRunId: 'run-budget-1',
    target: 'example.test',
    env: {
      GHOSTRECON_AUTO_MAX_AGENT_CALLS: '20',
      GHOSTRECON_AUTO_MAX_COST_USD: '50',
      GHOSTRECON_AUTO_SESSION_TIMEOUT_MS: '1800000',
    },
    restoredState: {
      startedAt: past,
      deadlineAt: deadline,
      agentCalls: 9,
      costUsd: 3.5,
      usage: { codex: { calls: 9, costUsd: 3.5 } },
      iteration: 2,
      limits: {
        maxIterations: 3,
        sessionTimeoutMs: 600_000,
        agentTimeoutMs: 60_000,
        maxAgentCalls: 10,
        maxContextChars: 50_000,
        maxCostUsd: 5,
      },
    },
  });

  assert.equal(session.state.agentCalls, 9);
  assert.equal(session.state.costUsd, 3.5);
  assert.equal(session.state.iteration, 2);
  assert.equal(session.state.deadlineAt, deadline);
  assert.equal(session.limits.maxAgentCalls, 10);
  assert.equal(session.limits.maxCostUsd, 5);
  session.assertActive();
  assert.throws(() => {
    // Já está em 9; max 10 → uma chamada ok, a seguinte estoura.
    session.reserveAgentCall('codex');
    session.reserveAgentCall('codex');
  }, /limite de chamadas/);
});

test('assertActive falha quando deadlineAt já passou', () => {
  const session = createAutoSession({
    sessionId: 'resume-budget-2',
    requestRunId: 'run-budget-2',
    target: 'example.test',
    restoredState: {
      deadlineAt: new Date(Date.now() - 1_000).toISOString(),
      agentCalls: 0,
      costUsd: 0,
      limits: {
        maxIterations: 3,
        sessionTimeoutMs: 1_800_000,
        agentTimeoutMs: 60_000,
        maxAgentCalls: 12,
        maxContextChars: 120_000,
        maxCostUsd: 10,
      },
    },
  });
  assert.throws(() => session.assertActive(), /limite de tempo/);
});

test('intersectAutoSessionLimits escolhe o mais restritivo', () => {
  const out = intersectAutoSessionLimits(
    { maxAgentCalls: 4, maxCostUsd: 2, sessionTimeoutMs: 100_000, maxIterations: 2, agentTimeoutMs: 10_000, maxContextChars: 20_000 },
    { maxAgentCalls: 12, maxCostUsd: 10, sessionTimeoutMs: 50_000, maxIterations: 3, agentTimeoutMs: 60_000, maxContextChars: 120_000 },
  );
  assert.equal(out.maxAgentCalls, 4);
  assert.equal(out.maxCostUsd, 2);
  assert.equal(out.sessionTimeoutMs, 50_000);
  assert.equal(out.maxIterations, 2);
});
