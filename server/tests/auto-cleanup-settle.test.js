import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough, Writable } from 'node:stream';

import { createAutoSession } from '../auto-agent/session-store.mjs';
import { CodexAppServerClient } from '../auto-agent/providers/codex-app-server.mjs';
import { execFileClosedStdin } from '../auto-agent/providers/codex.mjs';
import { loadAutoRedactionPolicy, redactAutoText } from '../auto-agent/redaction.mjs';
import { sessionTerminalFromEvaluation } from '../auto-agent/orchestrator.mjs';

test('session.close falha fechado quando resource não assenta', async () => {
  const session = createAutoSession({
    sessionId: 'session-cleanup-fail01',
    requestRunId: 'run-cleanup-fail01',
    target: 'example.test',
  });
  session.resources.push({
    async close() {
      const error = new Error('resource_unterminated');
      error.code = 'PROCESS_UNTERMINATED';
      throw error;
    },
  });
  const state = await session.close('completed');
  assert.equal(state.status, 'failed');
  assert.equal(state.cleanupFailed, true);
  assert.match(state.error || '', /cleanup_failed|resource_unterminated/);
});

test('Codex App Server close aguarda exit e falha se ignorar kill', async () => {
  const stdout = new PassThrough();
  const stderr = new PassThrough();
  const signals = [];
  const proc = new EventEmitter();
  proc.stdout = stdout;
  proc.stderr = stderr;
  proc.pid = 424242;
  proc.stdin = new Writable({ write(_c, _e, cb) { cb(); } });
  proc.kill = (signalName) => {
    signals.push(signalName);
    // Ignora TERM/KILL — simula provider zumbi.
    return true;
  };
  const client = new CodexAppServerClient({
    root: process.cwd(),
    env: {},
    spawnImpl: () => proc,
  });
  await assert.rejects(
    client.close(new Error('cancel')),
    (error) => error?.code === 'CODEX_APP_SERVER_UNTERMINATED',
  );
  assert.ok(signals.includes('SIGTERM'));
  assert.ok(signals.includes('SIGKILL'));
});

test('execFileClosedStdin marca PROCESS_UNTERMINATED se close não chega', {
  skip: process.platform === 'win32' ? 'process groups POSIX' : false,
}, async () => {
  await assert.rejects(
    execFileClosedStdin(
      process.execPath,
      ['-e', 'process.on("SIGTERM",()=>{}); setInterval(()=>{}, 1000)'],
      { timeout: 30, killGraceMs: 50 },
    ),
    (error) => error?.code === 'PROCESS_UNTERMINATED' || error?.code === 'ETIMEDOUT',
  );
});

test('política de redação extra via env é consumida', () => {
  const policy = loadAutoRedactionPolicy({
    GHOSTRECON_AUTO_REDACT_EXTRA: 'acme-lab-token,short,xx',
  });
  assert.equal(policy.source, 'env:GHOSTRECON_AUTO_REDACT_EXTRA');
  assert.deepEqual(policy.extras, ['acme-lab-token']);
  const redacted = redactAutoText('prefix acme-lab-token suffix', {
    GHOSTRECON_AUTO_REDACT_EXTRA: 'acme-lab-token',
  });
  assert.match(redacted, /\[REDACTED\]/);
  assert.doesNotMatch(redacted, /acme-lab-token/);
});

test('recordUsage sem cost marca budgetVerifiable=false', () => {
  const session = createAutoSession({
    sessionId: 'session-budget-verify01',
    requestRunId: 'run-budget-verify01',
    target: 'example.test',
  });
  assert.equal(session.state.budgetVerifiable, true);
  session.recordUsage('openrouter', { prompt_tokens: 10, completion_tokens: 2 });
  assert.equal(session.state.budgetVerifiable, false);
  assert.equal(session.state.usage.openrouter.costEstimated, true);
});

test('sessionTerminalFromEvaluation mapeia failed/partial', () => {
  assert.equal(sessionTerminalFromEvaluation({ status: 'failed' }), 'failed');
  assert.equal(sessionTerminalFromEvaluation({ status: 'partial' }), 'partial');
  assert.equal(sessionTerminalFromEvaluation({ status: 'completed' }), 'completed');
  assert.equal(sessionTerminalFromEvaluation({ status: 'unknown' }), 'failed');
});
