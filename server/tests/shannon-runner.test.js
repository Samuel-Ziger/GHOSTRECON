import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {
  waitForShannonWorkflowEnd,
  workflowLogPath,
  shannonReportPath,
  extractTemporalWebUiUrl,
  runShannonOnClone,
} from '../modules/shannon-runner.js';

test('workflowLogPath junta workspaces e workspace id', () => {
  const p = workflowLogPath('/tmp/shannon', 'ghostrecon-test-1');
  assert.equal(p, path.join('/tmp/shannon', 'workspaces', 'ghostrecon-test-1', 'workflow.log'));
});

test('shannonReportPath aponta para comprehensive_security_assessment_report.md', () => {
  const p = shannonReportPath('/clone/repo');
  assert.match(p, /comprehensive_security_assessment_report\.md$/);
});

test('waitForShannonWorkflowEnd detecta COMPLETED', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-shannon-'));
  const ws = 'test-ws-1';
  const dir = path.join(root, 'workspaces', ws);
  await fs.mkdir(dir, { recursive: true });
  const logFile = path.join(dir, 'workflow.log');
  await fs.writeFile(logFile, 'line1\nWorkflow COMPLETED\n', 'utf8');
  process.env.GHOSTRECON_SHANNON_WORKFLOW_TIMEOUT_MS = '8000';
  const r = await waitForShannonWorkflowEnd(root, ws, null);
  assert.equal(r.outcome, 'completed');
  assert.match(r.tail, /COMPLETED/);
});

test('extractTemporalWebUiUrl captura Web UI do Shannon (localhost:8233)', () => {
  const seen = new Set();
  const buf = `  Monitor:\n    Web UI:  http://localhost:8233/namespaces/default/workflows/wf-abc\n`;
  const u = extractTemporalWebUiUrl(buf, seen);
  assert.equal(u, 'http://localhost:8233/namespaces/default/workflows/wf-abc');
  assert.equal(extractTemporalWebUiUrl(buf, seen), null);
});

test('extractTemporalWebUiUrl suporta 127.0.0.1:8233', () => {
  const seen = new Set();
  const u = extractTemporalWebUiUrl('x http://127.0.0.1:8233/y z', seen);
  assert.equal(u, 'http://127.0.0.1:8233/y');
});

test('waitForShannonWorkflowEnd detecta FAILED', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-shannon-'));
  const ws = 'test-ws-2';
  await fs.mkdir(path.join(root, 'workspaces', ws), { recursive: true });
  await fs.writeFile(path.join(root, 'workspaces', ws, 'workflow.log'), 'Workflow FAILED\n', 'utf8');
  process.env.GHOSTRECON_SHANNON_WORKFLOW_TIMEOUT_MS = '8000';
  const r = await waitForShannonWorkflowEnd(root, ws, null);
  assert.equal(r.outcome, 'failed');
});

test('waitForShannonWorkflowEnd rejeita sinal já cancelado sem iniciar polling', async () => {
  const controller = new AbortController();
  controller.abort(new Error('parar polling'));
  await assert.rejects(
    waitForShannonWorkflowEnd('/tmp/shannon', 'never-read', null, {
      signal: controller.signal,
      pollIntervalMs: 1,
    }),
    (error) => error?.name === 'AbortError' && error?.code === 'PROCESS_ABORTED',
  );
});

test('runShannonOnClone remove tarefa cancelada da fila antes de iniciar subprocesso', async () => {
  let releaseFirst;
  let firstStarted;
  const firstReady = new Promise((resolve) => {
    firstStarted = resolve;
  });
  const firstProcess = new Promise((resolve) => {
    releaseFirst = resolve;
  });
  let processCalls = 0;
  const processRunner = async () => {
    processCalls += 1;
    if (processCalls === 1) {
      firstStarted();
      return firstProcess;
    }
    return { code: 0, stdout: '', stderr: '' };
  };
  const common = {
    ghostRoot: '/tmp/ghostrecon-test',
    domain: 'example.test',
    clonePath: '/tmp/clone-test',
    processRunner,
    waitForWorkflowImpl: async () => ({
      outcome: 'completed',
      logPath: '/tmp/workflow.log',
      tail: '',
    }),
    readReportImpl: async () => ({
      ok: true,
      path: '/tmp/report.md',
      content: 'ok',
      bytes: 2,
    }),
  };

  const first = runShannonOnClone({ ...common, repoFullName: 'acme/first' });
  await firstReady;

  const controller = new AbortController();
  const second = runShannonOnClone({
    ...common,
    repoFullName: 'acme/second',
    signal: controller.signal,
  });
  controller.abort(new Error('cancelar tarefa na fila'));
  await assert.rejects(
    second,
    (error) => error?.name === 'AbortError' && error?.code === 'PROCESS_ABORTED',
  );

  releaseFirst({ code: 0, stdout: '', stderr: '' });
  await first;
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(processCalls, 1);
});
