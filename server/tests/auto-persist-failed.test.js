import test from 'node:test';
import assert from 'node:assert/strict';

import {
  sessionTerminalFromEvaluation,
  terminalStatus,
} from '../auto-agent/orchestrator.mjs';

test('auto_persist_failed é o contrato de falha de snapshot terminal', () => {
  // Contrato estável para NDJSON/UI: falha de persistência no catch terminal
  // não pode ser silenciosa (ver orchestrator catch → auto_persist_failed).
  const event = {
    type: 'auto_persist_failed',
    stage: 'terminal_snapshot',
    sessionId: 'session-fixture',
    requestRunId: 'run-fixture',
    error: 'EACCES',
  };
  assert.equal(event.type, 'auto_persist_failed');
  assert.equal(event.stage, 'terminal_snapshot');
  assert.ok(event.error);
});

test('terminalStatus distingue cancelamento de falha genérica', () => {
  const session = {
    signal: {
      aborted: true,
      reason: Object.assign(new Error('operator_cancelled'), { name: 'AbortError' }),
    },
  };
  const cancelled = terminalStatus(session.signal.reason, session);
  assert.equal(cancelled.status, 'cancelled');
  const failed = terminalStatus(new Error('boom'), { signal: { aborted: false } });
  assert.equal(failed.status, 'failed');
});

test('falha na avaliação nunca vira completed', () => {
  assert.equal(sessionTerminalFromEvaluation({ status: 'failed' }), 'failed');
  assert.equal(sessionTerminalFromEvaluation({ status: 'partial' }), 'partial');
  assert.equal(sessionTerminalFromEvaluation({ status: 'completed' }), 'completed');
});
