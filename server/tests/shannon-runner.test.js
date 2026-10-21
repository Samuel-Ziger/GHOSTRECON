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
  extractTemporalWorkflowId,
  cancelShannonWorkflow,
  readShannonComprehensiveReport,
  extractShannonFindings,
  buildShannonChildEnv,
  runShannonOnClone,
} from '../modules/shannon-runner.js';

test('buildShannonChildEnv usa allowlist e remove segredos alheios ao motor', () => {
  const env = buildShannonChildEnv({
    PATH: '/safe/bin',
    HOME: '/tmp/operator',
    OPENAI_API_KEY: 'explicit-provider-key',
    DATABASE_URL: 'postgres://secret',
    JWT_SECRET: 'must-not-leak',
    SHANNON_PIPELINE_TESTING: '1',
  });
  assert.equal(env.PATH, '/safe/bin');
  assert.equal(env.OPENAI_API_KEY, 'explicit-provider-key');
  assert.equal(env.SHANNON_PIPELINE_TESTING, '1');
  assert.equal(env.SHANNON_LOCAL, '1');
  assert.equal(env.DATABASE_URL, undefined);
  assert.equal(env.JWT_SECRET, undefined);
});

test('Shannon não rebaixa processo sem término confirmado a resultado recuperável', async () => {
  const error = Object.assign(new Error('fixture process unterminated'), { code: 'PROCESS_UNTERMINATED', fatal: true });
  await assert.rejects(runShannonOnClone({
    ghostRoot: '/fixture', domain: 'example.test', clonePath: '/fixture/repo',
    processRunner: async () => { throw error; },
  }), (failure) => failure === error && failure.code === 'PROCESS_UNTERMINATED');
  await assert.rejects(cancelShannonWorkflow({
    workflowId: 'wf-fixture', processRunner: async () => { throw error; },
  }), (failure) => failure === error);
});

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

test('runShannonOnClone tenta cancelar workflow observado quando o start expira', async () => {
  let cancelArgs = null;
  const result = await runShannonOnClone({
    ghostRoot: '/tmp/ghostrecon-test',
    domain: 'example.test',
    clonePath: '/tmp/clone-test',
    repoFullName: 'acme/app',
    processRunner: async (_binary, _args, options) => {
      options.onStdout('http://localhost:8233/namespaces/default/workflows/wf-timeout-fixture\n');
      const error = new Error('timeout fixture');
      error.code = 'PROCESS_TIMEOUT';
      throw error;
    },
    cancelWorkflowImpl: async (args) => {
      cancelArgs = args;
      return { attempted: true, requested: true, confirmed: false };
    },
  });
  assert.equal(result.ok, false);
  assert.equal(result.cleanup.requested, true);
  assert.equal(result.cleanup.confirmed, false);
  assert.equal(cancelArgs.reason, 'ghostrecon_start_timeout');
  assert.equal(cancelArgs.workflowId, 'wf-timeout-fixture');
  assert.match(cancelArgs.workspaceId, /^ghostrecon-example\.test-/);
});

test('cancelShannonWorkflow não confunde pedido aceito com término observado', async () => {
  let seenArgs;
  const result = await cancelShannonWorkflow({
    workflowId: 'wf-real-id',
    processRunner: async (_command, args, options) => {
      seenArgs = args;
      assert.equal(options.timeoutMs, 30_000);
      assert.equal(options.signal.aborted, false);
      return { code: 0, stdout: '', stderr: '' };
    },
  });
  assert.equal(seenArgs[0], 'workflow');
  assert.equal(seenArgs[1], 'cancel');
  assert.equal(result.requested, true);
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, 'cancellation_requested_terminal_unobserved');
});

test('cancelShannonWorkflow nunca adivinha workflow ID pelo workspace', async () => {
  let calls = 0;
  const result = await cancelShannonWorkflow({
    workspaceId: 'not-a-workflow-id',
    processRunner: async () => { calls += 1; return { code: 0 }; },
  });
  assert.equal(calls, 0);
  assert.equal(result.attempted, false);
  assert.equal(result.requested, false);
  assert.equal(result.confirmed, false);
  assert.equal(extractTemporalWorkflowId('http://localhost:8233/'), null);
});

test('cancelShannonWorkflow mantém erro/timeout explícitos e redige os detalhes', async () => {
  const result = await cancelShannonWorkflow({
    workflowId: 'wf-fixture',
    processRunner: async () => ({ code: 0, timedOut: true, stderr: 'Authorization: Bearer secret-fixture-token' }),
  });
  assert.equal(result.requested, false);
  assert.equal(result.confirmed, false);
  assert.doesNotMatch(result.error, /secret-fixture-token/);
});

test('runShannonOnClone captura ID por chunks com UI/espelho desligados', async (t) => {
  const oldUi = process.env.GHOSTRECON_SHANNON_OPEN_TEMPORAL_UI;
  const oldMirror = process.env.GHOSTRECON_SHANNON_MIRROR_CLI;
  t.after(() => {
    if (oldUi === undefined) delete process.env.GHOSTRECON_SHANNON_OPEN_TEMPORAL_UI;
    else process.env.GHOSTRECON_SHANNON_OPEN_TEMPORAL_UI = oldUi;
    if (oldMirror === undefined) delete process.env.GHOSTRECON_SHANNON_MIRROR_CLI;
    else process.env.GHOSTRECON_SHANNON_MIRROR_CLI = oldMirror;
  });
  process.env.GHOSTRECON_SHANNON_OPEN_TEMPORAL_UI = '0';
  process.env.GHOSTRECON_SHANNON_MIRROR_CLI = '0';
  let observedId = null;
  const result = await runShannonOnClone({
    ghostRoot: '/tmp/ghostrecon-test', domain: 'example.test', clonePath: '/tmp/fixture-clone',
    processRunner: async (_command, _args, options) => {
      options.onStdout('Web UI: http://localhost:8233/namespaces/default/workflows/wf-part');
      options.onStdout('ial-id?token=secret-fixture\n');
      return { code: 0, stdout: '', stderr: '' };
    },
    waitForWorkflowImpl: async () => ({ outcome: 'timeout' }),
    cancelWorkflowImpl: async ({ workflowId }) => {
      observedId = workflowId;
      return { attempted: true, requested: true, confirmed: false };
    },
  });
  assert.equal(observedId, 'wf-partial-id');
  assert.equal(result.cleanup.confirmed, false);
});

test('runShannonOnClone cancela ao perder estado e não declara conclusão', async () => {
  let reason = null;
  const result = await runShannonOnClone({
    ghostRoot: '/tmp/ghostrecon-test', domain: 'example.test', clonePath: '/tmp/fixture-clone',
    processRunner: async () => ({ code: 0, stdout: '', stderr: '' }),
    waitForWorkflowImpl: async () => ({ outcome: 'unavailable', reason: 'workflow_log_unreadable' }),
    cancelWorkflowImpl: async (args) => {
      reason = args.reason;
      return { attempted: false, requested: false, confirmed: false };
    },
    readReportImpl: async () => assert.fail('Não deve importar relatório sem término observado'),
  });
  assert.equal(result.ok, false);
  assert.equal(result.outcome, 'unavailable');
  assert.equal(reason, 'ghostrecon_workflow_state_unavailable');
});

test('runShannonOnClone redige espelho, linhas extensas e fragmentos de chave privada', async (t) => {
  const oldMirror = process.env.GHOSTRECON_SHANNON_MIRROR_CLI;
  process.env.GHOSTRECON_SHANNON_MIRROR_CLI = '1';
  t.after(() => {
    if (oldMirror === undefined) delete process.env.GHOSTRECON_SHANNON_MIRROR_CLI;
    else process.env.GHOSTRECON_SHANNON_MIRROR_CLI = oldMirror;
  });
  const events = [];
  const logs = [];
  const result = await runShannonOnClone({
    ghostRoot: '/tmp/ghostrecon-test', domain: 'example.test', clonePath: '/tmp/fixture-clone',
    emit: (event) => events.push(event),
    log: (line) => logs.push(line),
    processRunner: async (_command, _args, options) => {
      options.onStdout('Authorization: Bearer confidential-fixture\n');
      options.onStdout('-----BEGIN PRIVATE KEY-----\n');
      options.onStdout('fixture-private-body\n-----END PRIVATE KEY-----\n');
      options.onStdout('oversize-fixture'.repeat(2000));
      options.onStdout('\nnormal line\n');
      return { code: 1, stdout: 'password=secret-fixture-value', stderr: '' };
    },
  });
  const publicText = JSON.stringify({ events, logs, detail: result.detail });
  assert.doesNotMatch(publicText, /confidential-fixture|fixture-private-body|oversize-fixture|secret-fixture-value|fixture-clone/);
  assert.match(publicText, /REDACTED/);
  assert.match(publicText, /normal line/);
  assert.ok(publicText.length < 5000);
});

test('readShannonComprehensiveReport limita leitura e redige antes de devolver conteúdo', async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-shannon-report-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const oldLimit = process.env.GHOSTRECON_SHANNON_REPORT_MAX_CHARS;
  process.env.GHOSTRECON_SHANNON_REPORT_MAX_CHARS = '256';
  t.after(() => {
    if (oldLimit === undefined) delete process.env.GHOSTRECON_SHANNON_REPORT_MAX_CHARS;
    else process.env.GHOSTRECON_SHANNON_REPORT_MAX_CHARS = oldLimit;
  });
  const reportFile = shannonReportPath(root);
  await fs.mkdir(path.dirname(reportFile), { recursive: true });
  const content = 'Authorization: Bearer secret-report-fixture\n' + 'evidence '.repeat(20_000);
  await fs.writeFile(reportFile, content);
  const report = await readShannonComprehensiveReport(root);
  assert.equal(report.ok, true);
  assert.equal(report.bytes, Buffer.byteLength(content));
  assert.equal(report.truncated, true);
  assert.ok(report.content.length < 350);
  assert.doesNotMatch(report.content, /secret-report-fixture/);
});

test('leitores Shannon recusam symlinks finais e diferenciam estado indisponível', async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-shannon-links-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const unrelated = path.join(root, 'unrelated-fixture.txt');
  await fs.writeFile(unrelated, 'private unrelated fixture\nWorkflow COMPLETED\n');
  const reportFile = shannonReportPath(root);
  await fs.mkdir(path.dirname(reportFile), { recursive: true });
  await fs.symlink(unrelated, reportFile);
  assert.equal((await readShannonComprehensiveReport(root)).ok, false);
  const logFile = workflowLogPath(root, 'fixture');
  await fs.mkdir(path.dirname(logFile), { recursive: true });
  await fs.symlink(unrelated, logFile);
  const result = await waitForShannonWorkflowEnd(root, 'fixture', null);
  assert.equal(result.outcome, 'unavailable');
  assert.equal(result.reason, 'workflow_log_unreadable');
});

test('workflow.log grande usa cauda limitada e não publica conteúdo bruto', async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-shannon-log-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const logFile = workflowLogPath(root, 'fixture');
  await fs.mkdir(path.dirname(logFile), { recursive: true });
  await fs.writeFile(logFile, `${'private fixture data\n'.repeat(20_000)}Workflow COMPLETED\n`);
  const logs = [];
  const result = await waitForShannonWorkflowEnd(root, 'fixture', (line) => logs.push(line));
  assert.equal(result.outcome, 'completed');
  assert.equal(result.logTruncated, true);
  assert.equal(result.tail, 'Workflow COMPLETED');
  assert.doesNotMatch(JSON.stringify({ logs, result }), /private fixture data/);
});

test('extractShannonFindings redige evidência e mantém status de candidato IA', () => {
  const findings = extractShannonFindings('## HIGH Fixture issue\nFile: src/app.js\nAuthorization: Bearer secret-finding-fixture');
  assert.equal(findings.length, 1);
  assert.equal(findings[0].meta.evidenceStatus, 'candidate_ai_report');
  assert.doesNotMatch(JSON.stringify(findings), /secret-finding-fixture/);
});

test('runShannonOnClone propaga cancelamento durante start e espera do workflow', async () => {
  for (const phase of ['start', 'workflow']) {
    const controller = new AbortController();
    const cancellation = new Error('cancelar fixture');
    cancellation.name = 'AbortError';
    cancellation.code = 'PROCESS_ABORTED';
    let cancelArgs;
    await assert.rejects(runShannonOnClone({
      ghostRoot: '/tmp/ghostrecon-test', domain: 'example.test', clonePath: '/tmp/fixture-clone',
      signal: controller.signal,
      processRunner: async (_command, _args, options) => {
        options.onStdout('http://localhost:8233/namespaces/default/workflows/wf-abort-fixture');
        if (phase === 'start') {
          controller.abort();
          throw cancellation;
        }
        return { code: 0, stdout: 'http://localhost:8233/namespaces/default/workflows/wf-abort-fixture', stderr: '' };
      },
      waitForWorkflowImpl: async () => {
        controller.abort();
        throw cancellation;
      },
      cancelWorkflowImpl: async (args) => {
        cancelArgs = args;
        return { attempted: true, requested: true, confirmed: false };
      },
    }), (error) => error === cancellation && error.cleanup.requested && !error.cleanup.confirmed);
    assert.equal(cancelArgs.workflowId, 'wf-abort-fixture');
    assert.equal(cancelArgs.reason, 'ghostrecon_operator_cancelled');
  }
});
