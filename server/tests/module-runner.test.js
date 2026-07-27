import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';

import {
  createCappedOutputCollector,
  mapPool,
  readResponseSnippet,
  runProcess,
} from '../modules/module-runner.mjs';

function fakeChild(onKill = () => true) {
  const child = new EventEmitter();
  child.pid = 42_424;
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.kill = (signal) => onKill(signal, child);
  return child;
}

test('createCappedOutputCollector limita stdout em modo head', () => {
  const c = createCappedOutputCollector({ maxBytes: 5, mode: 'head', marker: '[cut]' });
  c.append('abcdefghi');
  assert.equal(c.toString(), 'abcde[cut]');
  assert.deepEqual(c.stats(), { totalBytes: 9, capturedBytes: 5, truncated: true });
});

test('createCappedOutputCollector preserva tail quando configurado', () => {
  const c = createCappedOutputCollector({ maxBytes: 5, mode: 'tail', marker: '[cut]' });
  c.append('abc');
  c.append('defghi');
  assert.equal(c.toString(), 'efghi[cut]');
});

test('mapPool preserva ordem dos resultados', async () => {
  const out = await mapPool([3, 1, 2], 2, async (n) => {
    await new Promise((r) => setTimeout(r, 5 * n));
    return n * 2;
  });
  assert.deepEqual(out, [6, 2, 4]);
});

test('mapPool aplica timeout por item', async () => {
  await assert.rejects(
    () => mapPool([1], 1, () => new Promise((r) => setTimeout(r, 50)), { timeoutMs: 5, label: 'teste' }),
    /teste timeout/,
  );
});

test('runProcess limita stdout capturado', async () => {
  const r = await runProcess(process.execPath, ['-e', 'require("node:fs").writeSync(1, "abcdefghi")'], {
    timeoutMs: 10_000,
    stdoutMaxBytes: 5,
  });
  assert.equal(r.code, 0);
  assert.equal(r.stdout, 'abcde\n[ghostrecon: stdout truncated]\n');
  assert.equal(r.stdoutStats.truncated, true);
});

test('runProcess entrega stdin limitado sem expor o payload no resultado', async () => {
  const secretFixture = 'cookie=fixture-secret';
  const r = await runProcess(
    process.execPath,
    ['-e', 'const fs=require("node:fs");fs.writeSync(1,fs.readFileSync(0))'],
    {
      timeoutMs: 10_000,
      input: secretFixture,
      stdinMaxBytes: 128,
    },
  );

  assert.equal(r.code, 0);
  assert.equal(r.stdout, secretFixture);
  assert.equal('input' in r, false);
  assert.equal(JSON.stringify({ cmd: r.cmd, args: r.args }).includes(secretFixture), false);
});

test('runProcess recusa stdin acima do limite antes de iniciar subprocesso', async () => {
  let spawned = false;
  await assert.rejects(
    runProcess('fixture', [], {
      input: '12345',
      stdinMaxBytes: 4,
      spawnImpl() {
        spawned = true;
        throw new Error('não deve iniciar');
      },
    }),
    (error) => error?.code === 'PROCESS_STDIN_TOO_LARGE',
  );
  assert.equal(spawned, false);
});

for (const terminationKind of ['timeout', 'abort']) {
  test(`runProcess falha fechado quando ${terminationKind} não recebe exit/close após KILL`, async () => {
    const signals = [];
    const controller = new AbortController();
    const keepEventLoopAlive = setInterval(() => {}, 1_000);
    try {
      const pending = runProcess('fixture-unterminated', [], {
        timeoutMs: terminationKind === 'timeout' ? 5 : 5_000,
        signal: terminationKind === 'abort' ? controller.signal : null,
        killGraceMs: 10,
        closeGraceMs: 50,
        spawnImpl: () => fakeChild((signal) => {
          signals.push(signal);
          return true;
        }),
      });
      if (terminationKind === 'abort') {
        controller.abort(new Error('operator stop fixture'));
      }
      await assert.rejects(
        pending,
        (error) => {
          assert.equal(error?.code, 'PROCESS_UNTERMINATED');
          assert.equal(error?.fatal, true);
          assert.equal(error?.recoverable, false);
          assert.equal(error?.unterminated, true);
          assert.equal(error?.terminationKind, terminationKind);
          assert.equal(error?.result?.terminationConfirmed, false);
          assert.equal(error?.result?.unterminated, true);
          assert.equal(error?.result?.timedOut, terminationKind === 'timeout');
          assert.equal(Boolean(error?.result?.cancelled), terminationKind === 'abort');
          return true;
        },
      );
      assert.deepEqual(signals, ['SIGTERM', 'SIGKILL']);
    } finally {
      clearInterval(keepEventLoopAlive);
    }
  });
}

test('runProcess só retorna timeout recuperável depois que close confirma o encerramento', async () => {
  const signals = [];
  const keepEventLoopAlive = setInterval(() => {}, 1_000);
  let result;
  try {
    result = await runProcess('fixture-confirmed-timeout', [], {
      timeoutMs: 5,
      rejectOnTimeout: false,
      killGraceMs: 10,
      closeGraceMs: 100,
      spawnImpl: () => fakeChild((signal, child) => {
        signals.push(signal);
        if (signal === 'SIGKILL') queueMicrotask(() => child.emit('close', null, signal));
        return true;
      }),
    });
  } finally {
    clearInterval(keepEventLoopAlive);
  }

  assert.deepEqual(signals, ['SIGTERM', 'SIGKILL']);
  assert.equal(result.timedOut, true);
  assert.equal(result.terminationConfirmed, true);
  assert.equal(result.unterminated, undefined);
});

test('runProcess aceita exit como confirmação e não envia KILL após o filho encerrar com TERM', async () => {
  const signals = [];
  const keepEventLoopAlive = setInterval(() => {}, 1_000);
  let result;
  try {
    result = await runProcess('fixture-exit-after-term', [], {
      timeoutMs: 5,
      rejectOnTimeout: false,
      killGraceMs: 10,
      closeGraceMs: 50,
      spawnImpl: () => fakeChild((signal, child) => {
        signals.push(signal);
        if (signal === 'SIGTERM') queueMicrotask(() => child.emit('exit', null, signal));
        return true;
      }),
    });
  } finally {
    clearInterval(keepEventLoopAlive);
  }

  assert.deepEqual(signals, ['SIGTERM']);
  assert.equal(result.timedOut, true);
  assert.equal(result.terminationConfirmed, true);
  assert.equal(result.signal, 'SIGTERM');
});

test('readResponseSnippet le apenas prefixo do body', async () => {
  const res = new Response('abcdefghi');
  assert.equal(await readResponseSnippet(res, 4), 'abcd');
});
