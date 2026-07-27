import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { runWithProcessExecutionContext } from '../lib/process-execution-context.mjs';
import { runProcess } from '../modules/module-runner.mjs';
import { runPipelinePhases } from '../pipeline/phase-executor.mjs';

const LONG_RUNNING_CHILD =
  'process.on("SIGTERM",()=>{}); setInterval(()=>{}, 1000)';

function makeAutoState(events, signal = null) {
  return {
    autoModeExecution: true,
    subprocessKillGraceMs: 20,
    subprocessCloseGraceMs: 200,
    signal,
    emit(event) {
      events.push(event);
    },
    log(msg, level = 'info') {
      events.push({ type: 'log', msg, level });
    },
    throwIfAborted() {
      if (this.signal?.aborted) throw this.signal.reason || new Error('cancelado');
    },
  };
}

function processIsRunning(pid) {
  try {
    process.kill(pid, 0);
    const stat = readFileSync(`/proc/${pid}/stat`, 'utf8');
    return stat.split(' ')[2] !== 'Z';
  } catch {
    return false;
  }
}

async function waitUntilStopped(pid, timeoutMs = 1_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (!processIsRunning(pid)) return true;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  return !processIsRunning(pid);
}

test('fase Auto propaga AbortSignal implicitamente ao runProcess e segue após close', async () => {
  const events = [];
  const order = [];
  const state = makeAutoState(events);

  await runPipelinePhases(
    state,
    [
      {
        name: 'subprocess_phase',
        run: async () => {
          await runProcess(process.execPath, ['-e', LONG_RUNNING_CHILD], {
            timeoutMs: 5_000,
            label: 'fixture subprocess',
          });
        },
      },
      {
        name: 'next',
        run: async () => {
          order.push('next');
        },
      },
    ],
    {
      enabled: true,
      continueOnPhaseError: true,
      phaseTimeouts: { subprocess_phase: 40, next: 500 },
      phaseSettleGraceMs: 600,
    },
  );

  assert.deepEqual(order, ['next']);
  const outcome = events.find(
    (event) => event.type === 'phase_outcome' && event.phase === 'subprocess_phase',
  );
  assert.equal(outcome?.status, 'timeout');
  assert.equal(outcome?.settled, true);
  assert.equal(outcome?.recoverable, true);
});

test(
  'contexto Auto encerra o grupo POSIX com TERM seguido de KILL e não deixa neto ativo',
  { skip: process.platform === 'win32' },
  async () => {
    const controller = new AbortController();
    const parentScript = `
      const { spawn } = require('node:child_process');
      const { writeSync } = require('node:fs');
      const child = spawn(process.execPath, ['-e', ${JSON.stringify(LONG_RUNNING_CHILD)}], {
        stdio: 'ignore'
      });
      writeSync(1, String(child.pid));
      process.on('SIGTERM', () => {});
      setInterval(() => {}, 1000);
    `;
    const stopTimer = setTimeout(
      () => controller.abort(new Error('operator stop fixture')),
      350,
    );
    let descendantPid = null;

    try {
      await assert.rejects(
        runWithProcessExecutionContext(
          {
            signal: controller.signal,
            managedProcessGroup: true,
            killGraceMs: 20,
            closeGraceMs: 300,
          },
          () =>
            runProcess(process.execPath, ['-e', parentScript], {
              timeoutMs: 5_000,
              label: 'process tree fixture',
            }),
        ),
        (error) => {
          assert.equal(error.code, 'PROCESS_ABORTED');
          assert.equal(error.result?.cancelled, true);
          descendantPid = Number.parseInt(error.result?.stdout || '', 10);
          return true;
        },
      );

      assert.equal(Number.isSafeInteger(descendantPid), true);
      assert.equal(await waitUntilStopped(descendantPid), true);
    } finally {
      clearTimeout(stopTimer);
      if (Number.isSafeInteger(descendantPid) && processIsRunning(descendantPid)) {
        try {
          process.kill(descendantPid, 'SIGKILL');
        } catch {
          // best-effort de limpeza da fixture
        }
      }
    }
  },
);

test('RUN manual continua fora do contexto automático', async () => {
  const result = await runProcess(
    process.execPath,
    ['-e', 'require("node:fs").writeSync(1, "manual")'],
    { timeoutMs: 1_000 },
  );

  assert.equal(result.code, 0);
  assert.equal(result.stdout, 'manual');
  assert.equal('cancelled' in result, false);
});

for (const code of [
  'PROCESS_UNTERMINATED',
  'FRAMESEVEN_PROCESS_UNTERMINATED',
  'VIGOLIUM_BINARY_IDENTITY_MISMATCH',
]) {
  test(`pipeline não libera próxima fase após ${code}`, async () => {
    const events = [];
    const order = [];
    const state = makeAutoState(events);
    const fatal = new Error('subprocesso sem confirmação de encerramento');
    fatal.code = code;
    fatal.recoverable = false;

    await assert.rejects(
      runPipelinePhases(
        state,
        [
          {
            name: 'unterminated',
            run: async () => {
              throw fatal;
            },
          },
          {
            name: 'must_not_run',
            run: async () => {
              order.push('must_not_run');
            },
          },
        ],
        {
          enabled: true,
          continueOnPhaseError: true,
          phaseTimeouts: { unterminated: 500, must_not_run: 500 },
        },
      ),
      (error) => error === fatal,
    );

    assert.deepEqual(order, []);
    const outcome = events.find(
      (event) => event.type === 'phase_outcome' && event.phase === 'unterminated',
    );
    assert.equal(outcome?.status, 'failed');
    assert.equal(outcome?.settled, true);
    assert.equal(outcome?.recoverable, false);
  });
}

test('pipeline mantém fail-closed quando PROCESS_UNTERMINATED chega durante a graça do timeout', async () => {
  const events = [];
  const order = [];
  const state = makeAutoState(events);
  const fatal = new Error('subprocesso continuou ativo após o timeout da fase');
  fatal.code = 'PROCESS_UNTERMINATED';
  fatal.recoverable = false;

  await assert.rejects(
    runPipelinePhases(
      state,
      [
        {
          name: 'late_unterminated',
          run: (phaseState) => new Promise((_resolve, reject) => {
            phaseState.signal.addEventListener('abort', () => {
              setTimeout(() => reject(fatal), 20);
            }, { once: true });
          }),
        },
        {
          name: 'must_not_run',
          run: async () => {
            order.push('must_not_run');
          },
        },
      ],
      {
        enabled: true,
        continueOnPhaseError: true,
        phaseTimeouts: { late_unterminated: 5, must_not_run: 500 },
        phaseSettleGraceMs: 100,
      },
    ),
    (error) => error === fatal,
  );

  assert.deepEqual(order, []);
  const outcome = events.find(
    (event) => event.type === 'phase_outcome' && event.phase === 'late_unterminated',
  );
  assert.equal(outcome?.status, 'timeout');
  assert.equal(outcome?.settled, false);
  assert.equal(outcome?.recoverable, false);
});

test('pipeline mantém Vigolium identity mismatch fatal quando chega durante a graça do timeout', async () => {
  const events = [];
  const order = [];
  const state = makeAutoState(events);
  const fatal = new Error('Vigolium binary identity changed');
  fatal.code = 'VIGOLIUM_BINARY_IDENTITY_MISMATCH';

  await assert.rejects(
    runPipelinePhases(
      state,
      [
        {
          name: 'late_identity_mismatch',
          run: (phaseState) => new Promise((_resolve, reject) => {
            phaseState.signal.addEventListener('abort', () => {
              setTimeout(() => reject(fatal), 20);
            }, { once: true });
          }),
        },
        {
          name: 'must_not_run',
          run: async () => {
            order.push('must_not_run');
          },
        },
      ],
      {
        enabled: true,
        continueOnPhaseError: true,
        phaseTimeouts: { late_identity_mismatch: 5, must_not_run: 500 },
        phaseSettleGraceMs: 100,
      },
    ),
    (error) => error === fatal,
  );

  assert.deepEqual(order, []);
  const outcome = events.find(
    (event) => event.type === 'phase_outcome'
      && event.phase === 'late_identity_mismatch',
  );
  assert.equal(outcome?.status, 'timeout');
  assert.equal(outcome?.settled, true);
  assert.equal(outcome?.recoverable, false);
});
