import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  frameSevenChildEnv,
  inspectFrameSevenBinaryIdentity,
  resolveFrameSevenBinary,
  runFrameSeven,
  redactFrameSevenOutput,
} from '../integrations/frameseven-adapter.mjs';
import {
  cleanupFrameSevenAuthContext,
  consumeFrameSevenAuthSecret,
  createFrameSevenAuthContext,
  getFrameSevenAuthContext,
  loadFrameSevenAuthSession,
  markFrameSevenAuthReady,
} from '../integrations/frameseven-auth-context.mjs';
import {
  openFrameSevenRegularFile,
  readFrameSevenRegularFile,
  readAndMergeFrameSevenReport,
  readFrameSevenReportAccessMetadata,
  serializeFrameSevenMergedFindings,
} from '../integrations/frameseven-report.mjs';
import {
  getFrameSevenApproval,
  openFrameSevenPublicReport,
  publicFrameSevenReportUrl,
  readFrameSevenPublicReport,
  readFrameSevenReportAccess,
  requestFrameSevenApproval,
  resolveFrameSevenReportPath,
  resolveFrameSevenApproval,
  runIntegratedFrameSeven,
} from '../integrations/frameseven-runner.mjs';

const FRAMESEVEN_RECON_TOOLS_V1 = 'recon,cve';
const FRAMESEVEN_OFFENSIVE_TOOLS_V1 = [
  'recon',
  'access',
  'redirect',
  'misconfig',
  'cve',
  'crawler',
  'content',
  'subdomain',
  'ports',
  'nmap',
  'bannergrab',
].join(',');

function fakeProcess(onInput, onKill) {
  const child = new EventEmitter();
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.stdin = {
    write: (value) => onInput?.(value, child),
    end: () => {},
  };
  child.kill = (signal) => {
    if (onKill) return onKill(signal, child);
    child.emit('exit', null, signal || 'SIGTERM');
    return true;
  };
  return child;
}

async function tempRoot(t) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-frameseven-test-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const binary = resolveFrameSevenBinary(root, {});
  await fs.mkdir(path.dirname(binary), { recursive: true });
  await fs.writeFile(binary, 'fixture-binary');
  await fs.chmod(binary, 0o755);
  return root;
}

async function sealedIdentity(root, env = {}) {
  return inspectFrameSevenBinaryIdentity(resolveFrameSevenBinary(root, env));
}

async function runSealedFrameSeven(options) {
  return runFrameSeven({
    ...options,
    expectedBinaryIdentity: options.expectedBinaryIdentity
      || await sealedIdentity(options.root, options.env || {}),
  });
}

test('FrameSeven report URL usa rota protegida e o resolver bloqueia traversal/symlink', async (t) => {
  const root = await tempRoot(t);
  const outputDir = path.join(root, 'reports', 'frameseven-safe-report');
  const reportPath = path.join(outputDir, 'public-report.html');
  const outside = path.join(root, 'outside.html');
  await fs.mkdir(outputDir, { recursive: true });
  await Promise.all([
    fs.writeFile(reportPath, '<html>fixture</html>'),
    fs.writeFile(outside, '<html>outside</html>'),
  ]);
  await fs.symlink(outside, path.join(outputDir, 'public-report.json'));

  assert.equal(
    publicFrameSevenReportUrl(root, outputDir),
    '/api/frameseven/reports/frameseven-safe-report/report.html',
  );
  assert.equal(
    await resolveFrameSevenReportPath(root, 'frameseven-safe-report', 'report.html'),
    reportPath,
  );
  const opened = await openFrameSevenPublicReport(
    root,
    'frameseven-safe-report',
    'report.html',
  );
  assert.equal(await opened.handle.readFile({ encoding: 'utf8' }), '<html>fixture</html>');
  await opened.handle.close();
  assert.equal(
    (await readFrameSevenPublicReport(
      root,
      'frameseven-safe-report',
      'report.html',
    )).body.toString('utf8'),
    '<html>fixture</html>',
  );
  assert.equal(
    await resolveFrameSevenReportPath(root, 'frameseven-safe-report', 'report.json'),
    null,
  );
  assert.equal(
    await resolveFrameSevenReportPath(root, 'frameseven-safe-report', 'report.pdf'),
    null,
  );
  assert.equal(
    await resolveFrameSevenReportPath(root, '../frameseven-safe-report', 'report.html'),
    null,
  );
  assert.equal(
    await resolveFrameSevenReportPath(root, 'frameseven-safe-report', 'session-v1.json'),
    null,
  );
});

test('unauthenticated FrameSeven never receives auth browser flags and emits real lifecycle events', async (t) => {
  const root = await tempRoot(t);
  const events = [];
  let receivedArgs;
  const result = await runSealedFrameSeven({
    root,
    target: 'https://example.com',
    outputDir: 'reports/unauthenticated',
    authBrowser: false,
    emit: (event) => events.push(event),
    spawnImpl: (_binary, args) => {
      receivedArgs = args;
      const child = fakeProcess();
      queueMicrotask(() => {
        child.stdout.write(`report directory: ${root}/reports/unauthenticated\n`);
        child.emit('exit', 0, null);
      });
      return child;
    },
  });
  assert.equal(result.code, 0);
  assert.equal(receivedArgs.includes('-auth-browser'), false);
  assert.equal(receivedArgs.includes('-auth-session-out'), false);
  assert.equal(receivedArgs[receivedArgs.indexOf('-tools') + 1], FRAMESEVEN_RECON_TOOLS_V1);
  assert.equal(receivedArgs.includes('all'), false);
  assert.equal(receivedArgs.includes('-active-scan'), false);
  assert.deepEqual(events.filter((event) => event.type.startsWith('engine_')).map((event) => event.type), [
    'engine_started',
    'engine_progress',
    'engine_done',
  ]);
  assert.equal(events.some((event) => JSON.stringify(event).includes(root)), false);
  if (process.platform !== 'win32') {
    const mode = (await fs.stat(result.outputDir)).mode & 0o777;
    assert.equal(mode, 0o700);
  }
});

test('FrameSeven offensive profile requires explicit approval before spawn', async (t) => {
  const root = await tempRoot(t);
  let spawnCalls = 0;

  await assert.rejects(
    runSealedFrameSeven({
      root,
      target: 'https://example.com',
      outputDir: 'reports/offensive-without-approval',
      tools: FRAMESEVEN_OFFENSIVE_TOOLS_V1,
      spawnImpl: () => {
        spawnCalls += 1;
        return fakeProcess();
      },
    }),
    (error) => {
      assert.equal(error?.code, 'FRAMESEVEN_OFFENSIVE_APPROVAL_REQUIRED');
      return true;
    },
  );
  assert.equal(spawnCalls, 0);
});

test('approved FrameSeven offensive profile is explicit and never enables active-scan', async (t) => {
  const root = await tempRoot(t);
  let receivedArgs = null;

  const result = await runSealedFrameSeven({
    root,
    target: 'https://example.com',
    outputDir: 'reports/offensive-approved',
    tools: FRAMESEVEN_OFFENSIVE_TOOLS_V1,
    offensiveApproved: true,
    spawnImpl: (_binary, args) => {
      receivedArgs = args;
      const child = fakeProcess();
      queueMicrotask(() => child.emit('exit', 0, null));
      return child;
    },
  });

  assert.equal(result.code, 0);
  assert.equal(receivedArgs[receivedArgs.indexOf('-tools') + 1], FRAMESEVEN_OFFENSIVE_TOOLS_V1);
  assert.equal(receivedArgs.includes('all'), false);
  assert.equal(receivedArgs.includes('-active-scan'), false);
});

test('FrameSeven subprocess receives only the explicit runtime environment allowlist', async (t) => {
  const root = await tempRoot(t);
  let receivedOptions;
  let receivedArgs;
  await runSealedFrameSeven({
    root,
    target: 'https://example.com',
    outputDir: 'reports/safe-env',
    env: {
      PATH: '/fixture/bin',
      HOME: '/fixture/home',
      DISPLAY: ':99',
      GHOSTRECON_FRAMESEVEN_BIN: resolveFrameSevenBinary(root, {}),
      GITHUB_TOKEN: 'ghp_should_not_reach_child',
      OPENROUTER_API_KEY: 'secret-provider-key',
      SHODAN_API_KEY: 'secret-shodan-key',
      HTTP_PROXY: 'http://user:password@proxy.test',
    },
    timeout: '99h',
    toolTimeout: '999h',
    concurrency: 5_000,
    rate: Number.POSITIVE_INFINITY,
    spawnImpl: (_binary, args, options) => {
      receivedArgs = args;
      receivedOptions = options;
      const child = fakeProcess();
      queueMicrotask(() => child.emit('exit', 0, null));
      return child;
    },
  });

  assert.deepEqual(receivedOptions.env, {
    PATH: '/fixture/bin',
    HOME: '/fixture/home',
    DISPLAY: ':99',
  });
  assert.deepEqual(frameSevenChildEnv({
    PATH: '/fixture/bin',
    GITHUB_TOKEN: 'secret',
  }), { PATH: '/fixture/bin' });
  assert.equal(receivedArgs[receivedArgs.indexOf('-timeout') + 1], '300000ms');
  assert.equal(receivedArgs[receivedArgs.indexOf('-tool-timeout') + 1], '1800000ms');
  assert.equal(receivedArgs[receivedArgs.indexOf('-concurrency') + 1], '50');
  assert.equal(receivedArgs[receivedArgs.indexOf('-rate') + 1], '100');
});

test('FrameSeven rejeita outputDir fora da raiz protegida de reports', async (t) => {
  const root = await tempRoot(t);
  await assert.rejects(
    runSealedFrameSeven({
      root,
      target: 'https://example.com',
      outputDir: path.join(root, '..', 'outside-report'),
    }),
    /dentro de reports/,
  );
});

test('FrameSeven rejects a binary replaced after its identity was approved and never spawns it', async (t) => {
  const root = await tempRoot(t);
  const binary = resolveFrameSevenBinary(root, {});
  const expectedBinaryIdentity = await inspectFrameSevenBinaryIdentity(binary);
  await fs.writeFile(binary, 'replaced-after-approval');
  await fs.chmod(binary, 0o755);
  let spawned = false;

  await assert.rejects(
    runFrameSeven({
      root,
      target: 'https://example.com',
      outputDir: 'reports/replaced-binary',
      expectedBinaryIdentity,
      spawnImpl: () => {
        spawned = true;
        return fakeProcess();
      },
    }),
    /identity mismatch/i,
  );
  assert.equal(spawned, false);
});

test('authenticated FrameSeven waits for captured session approval, shares it once, then releases the scan', async (t) => {
  const root = await tempRoot(t);
  const order = [];
  const events = [];
  let receivedArgs;
  let writes = 0;
  await runSealedFrameSeven({
    root,
    target: 'https://example.com',
    outputDir: 'reports/authenticated',
    authBrowser: true,
    approvalId: 'approval-1',
    emit: (event) => events.push(event),
    waitForAuth: async () => {
      order.push('approved');
      return true;
    },
    beforeScan: async (auth) => {
      order.push('ghostrecon-vigolium');
      assert.equal(auth.cookie, 'sid=secret');
      assert.equal(auth.headers.Authorization, 'Bearer secret-token');
      const file = receivedArgs[receivedArgs.indexOf('-auth-session-out') + 1];
      await assert.rejects(fs.access(file));
    },
    spawnImpl: (_binary, args) => {
      receivedArgs = args;
      const child = fakeProcess((_value, proc) => {
        writes += 1;
        order.push('frameseven');
        proc.emit('exit', 0, null);
      });
      queueMicrotask(async () => {
        const file = args[args.indexOf('-auth-session-out') + 1];
        await fs.writeFile(file, JSON.stringify({
          version: 'v1',
          target: 'https://example.com/',
          cookies: ['sid=secret'],
          headers: { Authorization: 'Bearer secret-token' },
          endpoints: ['https://example.com/api/me'],
        }), { mode: 0o600 });
        child.stdout.write('FRAMESEVEN_AUTH_');
        child.stdout.write('READY_V1\n');
      });
      return child;
    },
  });
  assert.equal(receivedArgs.includes('-auth-browser'), true);
  assert.equal(writes, 1);
  assert.deepEqual(order, ['approved', 'ghostrecon-vigolium', 'frameseven']);
  assert.deepEqual(
    events.filter((event) => ['auth_ready', 'auth_required', 'auth_confirmed'].includes(event.type)).map((event) => event.type),
    ['auth_ready', 'auth_required', 'auth_confirmed'],
  );
  assert.equal(events.find((event) => event.type === 'auth_required')?.approvalId, 'approval-1');
  assert.equal(events.at(-1)?.type, 'engine_done');
  const authFile = receivedArgs[receivedArgs.indexOf('-auth-session-out') + 1];
  await assert.rejects(fs.access(authFile));
});

test('FrameSeven scan timeout starts after auth work, escalates TERM to KILL, and removes temporary files', async (t) => {
  const root = await tempRoot(t);
  const events = [];
  const signals = [];
  let authFile;
  let beforeScanFinished = false;
  await assert.rejects(
    runSealedFrameSeven({
      root,
      target: 'https://example.com',
      outputDir: 'reports/timeout',
      authBrowser: true,
      runTimeoutMs: 5,
      killGraceMs: 5,
      emit: (event) => events.push(event),
      waitForAuth: async () => true,
      beforeScan: async () => {
        await new Promise((resolve) => setTimeout(resolve, 20));
        beforeScanFinished = true;
      },
      spawnImpl: (_binary, args) => {
        authFile = args[args.indexOf('-auth-session-out') + 1];
        const child = fakeProcess(null, (signal, proc) => {
          assert.equal(beforeScanFinished, true);
          signals.push(signal);
          if (signal === 'SIGKILL') proc.emit('exit', null, signal);
          return true;
        });
        queueMicrotask(async () => {
          await fs.writeFile(authFile, JSON.stringify({
            version: 'v1',
            target: 'https://example.com/',
            cookies: [],
            headers: {},
            endpoints: [],
          }), { mode: 0o600 });
          child.stdout.write('FRAMESEVEN_AUTH_READY_V1\n');
        });
        return child;
      },
    }),
    /timeout/,
  );
  assert.deepEqual(signals, ['SIGTERM', 'SIGKILL']);
  assert.equal(events.at(-1)?.type, 'engine_timeout');
  assert.equal(events.at(-1)?.timeout, true);
  await assert.rejects(fs.access(path.dirname(authFile)));
});

for (const stopKind of ['timeout', 'abort']) {
  test(`FrameSeven falha fechado quando ${stopKind} não recebe exit/close após KILL`, async (t) => {
    const root = await tempRoot(t);
    const events = [];
    const signals = [];
    const controller = new AbortController();

    await assert.rejects(
      runSealedFrameSeven({
        root,
        target: 'https://example.com',
        outputDir: `reports/unterminated-${stopKind}`,
        signal: stopKind === 'abort' ? controller.signal : undefined,
        runTimeoutMs: stopKind === 'timeout' ? 5 : 5_000,
        killGraceMs: 3,
        reapTimeoutMs: 10,
        emit: (event) => events.push(event),
        spawnImpl: () => {
          const child = fakeProcess(null, (signalName) => {
            signals.push(signalName);
            return true;
          });
          if (stopKind === 'abort') {
            queueMicrotask(() => controller.abort(new Error('operator stop fixture')));
          }
          return child;
        },
      }),
      (error) => {
        assert.equal(error?.code, 'FRAMESEVEN_PROCESS_UNTERMINATED');
        assert.equal(error?.fatal, true);
        assert.equal(error?.recoverable, false);
        assert.equal(error?.unterminated, true);
        assert.equal(error?.requestedStatus, stopKind === 'timeout' ? 'timeout' : 'cancelled');
        return true;
      },
    );

    assert.deepEqual(signals, ['SIGTERM', 'SIGKILL']);
    assert.equal(events.at(-1)?.type, 'engine_failed');
    assert.equal(events.at(-1)?.phase, 'termination');
    assert.equal(events.at(-1)?.unterminated, true);
    assert.equal(events.at(-1)?.recoverable, false);
    assert.equal(
      events.some((event) => event.type === (stopKind === 'timeout'
        ? 'engine_timeout'
        : 'engine_cancelled')),
      false,
    );
  });
}

for (const stage of ['auth_capture', 'approval', 'before_scan']) {
  test(`FrameSeven ${stage} timeout is finite, aborts the stage, kills the tree, and cleans auth files`, async (t) => {
    const root = await tempRoot(t);
    const events = [];
    const signals = [];
    let authFile;
    let stageWasAborted = false;
    const options = {
      root,
      target: 'https://example.com',
      outputDir: `reports/timeout-${stage}`,
      authBrowser: true,
      authCaptureTimeoutMs: stage === 'auth_capture' ? 5 : 100,
      approvalTimeoutMs: stage === 'approval' ? 5 : 100,
      beforeScanTimeoutMs: stage === 'before_scan' ? 5 : 100,
      killGraceMs: 3,
      reapTimeoutMs: 50,
      emit: (event) => events.push(event),
      waitForAuth: stage === 'approval'
        ? ({ signal: stageSignal }) => new Promise((_resolve, reject) => {
            stageSignal.addEventListener('abort', () => {
              stageWasAborted = true;
              reject(stageSignal.reason);
            }, { once: true });
          })
        : async () => true,
      beforeScan: stage === 'before_scan'
        ? (_auth, { signal: stageSignal }) => new Promise((_resolve, reject) => {
            stageSignal.addEventListener('abort', () => {
              stageWasAborted = true;
              reject(stageSignal.reason);
            }, { once: true });
          })
        : async () => {},
      spawnImpl: (_binary, args) => {
        authFile = args[args.indexOf('-auth-session-out') + 1];
        const child = fakeProcess(null, (signalName, proc) => {
          signals.push(signalName);
          if (signalName === 'SIGKILL') proc.emit('exit', null, signalName);
          return true;
        });
        if (stage !== 'auth_capture') {
          queueMicrotask(async () => {
            await fs.writeFile(authFile, JSON.stringify({
              version: 'v1',
              target: 'https://example.com/',
              cookies: [],
              headers: {},
              endpoints: [],
            }), { mode: 0o600 });
            child.stdout.write('FRAMESEVEN_AUTH_READY_V1\n');
          });
        }
        return child;
      },
    };

    await assert.rejects(runSealedFrameSeven(options), /timeout/i);
    assert.deepEqual(signals, ['SIGTERM', 'SIGKILL']);
    assert.equal(events.at(-1)?.type, 'engine_timeout');
    assert.equal(events.at(-1)?.phase, stage);
    if (stage !== 'auth_capture') assert.equal(stageWasAborted, true);
    await assert.rejects(fs.access(path.dirname(authFile)));
  });
}

test('FrameSeven non-zero exit is reported as a failed engine', async (t) => {
  const root = await tempRoot(t);
  const events = [];
  await assert.rejects(
    runSealedFrameSeven({
      root,
      target: 'https://example.com',
      outputDir: 'reports/failed',
      emit: (event) => events.push(event),
      spawnImpl: () => {
        const child = fakeProcess();
        queueMicrotask(() => child.emit('exit', 2, null));
        return child;
      },
    }),
    /encerrou \(2\)/,
  );
  assert.deepEqual(events.map((event) => event.type), ['engine_started', 'engine_failed']);
  assert.equal(events.at(-1)?.timeout, false);
});

test('FrameSeven exit 1 is recoverable when CLI v1 preserved a report', async (t) => {
  const root = await tempRoot(t);
  const outputDir = path.join(root, 'reports', 'partial');
  const events = [];
  const result = await runSealedFrameSeven({
    root,
    target: 'https://example.com',
    outputDir,
    emit: (event) => events.push(event),
    spawnImpl: () => {
      const child = fakeProcess();
      queueMicrotask(async () => {
        await fs.writeFile(path.join(outputDir, 'report.json'), JSON.stringify({
          schema_version: 'v1',
          target: 'https://example.com/',
          surface: { endpoints: [] },
          findings: [{ title: 'Recovered', module: 'recon', severity: 'INFO' }],
          errors: [{ module: 'crawler', message: 'bounded tool error' }],
        }));
        child.emit('exit', 1, null);
      });
      return child;
    },
  });
  assert.equal(result.status, 'partial');
  assert.equal(result.recoverable, true);
  assert.equal(events.at(-1)?.type, 'engine_partial');
  assert.equal(events.at(-1)?.recoverable, true);
});

test('FrameSeven deferDoneEvent leaves the final success event to the report merger', async (t) => {
  const root = await tempRoot(t);
  const events = [];
  const result = await runSealedFrameSeven({
    root,
    target: 'https://example.com',
    outputDir: 'reports/deferred',
    deferDoneEvent: true,
    emit: (event) => events.push(event),
    spawnImpl: () => {
      const child = fakeProcess();
      queueMicrotask(() => child.emit('exit', 0, null));
      return child;
    },
  });
  assert.equal(result.status, 'done');
  assert.deepEqual(events.map((event) => event.type), ['engine_started']);
});

test('FrameSeven abort emits cancelled and cleans the authenticated context directory', async (t) => {
  const root = await tempRoot(t);
  const controller = new AbortController();
  const events = [];
  let authFile;
  let notifySpawned;
  const spawned = new Promise((resolve) => {
    notifySpawned = resolve;
  });
  const run = runSealedFrameSeven({
    root,
    target: 'https://example.com',
    outputDir: 'reports/cancelled',
    authBrowser: true,
    signal: controller.signal,
    emit: (event) => events.push(event),
    spawnImpl: (_binary, args) => {
      authFile = args[args.indexOf('-auth-session-out') + 1];
      notifySpawned();
      return fakeProcess();
    },
  });
  await spawned;
  controller.abort(new Error('operator cancelled'));
  await assert.rejects(run, /operator cancelled/);
  assert.equal(events.at(-1)?.type, 'engine_cancelled');
  await assert.rejects(fs.access(path.dirname(authFile)));
});

test('FrameSeven auth context is single-use and expires without exposing its secret', async (t) => {
  const context = createFrameSevenAuthContext({ target: 'https://example.com', ttlMs: 50 });
  t.after(() => cleanupFrameSevenAuthContext(context.contextId));
  assert.equal(markFrameSevenAuthReady(context.contextId, { cookie: 'sid=secret' }), true);
  assert.deepEqual(consumeFrameSevenAuthSecret(context.contextId), { cookie: 'sid=secret' });
  assert.equal(consumeFrameSevenAuthSecret(context.contextId), null);
  const metadata = getFrameSevenAuthContext(context.contextId);
  assert.equal(metadata.status, 'consumed');
  assert.equal(Object.hasOwn(metadata, 'secret'), false);

  const expiring = createFrameSevenAuthContext({ target: 'https://example.com', ttlMs: 5 });
  await new Promise((resolve) => setTimeout(resolve, 15));
  assert.equal(getFrameSevenAuthContext(expiring.contextId), null);
});

test('FrameSeven auth context rejects routing, framing, malformed, injected, and oversized headers', async (t) => {
  const invalidHeaders = [
    { Host: 'evil.example' },
    { Connection: 'keep-alive' },
    { 'Content-Length': '4' },
    { Cookie: 'sid=must-use-cookie-array' },
    { 'Transfer-Encoding': 'chunked' },
    { 'Bad Header': 'value' },
    { 'X-Test': 'safe\r\nInjected: true' },
    { 'X-Test': `x${'a'.repeat(64 * 1024)}` },
  ];

  for (const [index, headers] of invalidHeaders.entries()) {
    const context = createFrameSevenAuthContext({ target: 'https://example.com/' });
    const file = path.join(await tempRoot(t), `session-${index}.json`);
    await fs.writeFile(file, JSON.stringify({
      version: 'v1',
      target: 'https://example.com/',
      cookies: [],
      headers,
      endpoints: [],
    }), { mode: 0o600 });
    await assert.rejects(
      loadFrameSevenAuthSession(context.contextId, file),
      /header/i,
    );
    await cleanupFrameSevenAuthContext(context.contextId, file);
  }
});

test('FrameSeven rejects URL userinfo in targets, captured endpoints, and reports', async (t) => {
  const root = await tempRoot(t);
  await assert.rejects(
    runSealedFrameSeven({
      root,
      target: 'https://user:password@example.com/',
      spawnImpl: () => fakeProcess(),
    }),
    /userinfo/i,
  );
  assert.throws(
    () => createFrameSevenAuthContext({ target: 'https://user:password@example.com/' }),
    /userinfo/i,
  );

  const context = createFrameSevenAuthContext({ target: 'https://example.com/' });
  const file = path.join(root, 'session-userinfo.json');
  await fs.writeFile(file, JSON.stringify({
    version: 'v1',
    target: 'https://example.com/',
    cookies: [],
    headers: {},
    endpoints: ['https://user:password@example.com/private'],
  }), { mode: 0o600 });
  await assert.rejects(loadFrameSevenAuthSession(context.contextId, file), /userinfo/i);
  await cleanupFrameSevenAuthContext(context.contextId, file);

  const outputDir = path.join(root, 'report-userinfo');
  await fs.mkdir(outputDir);
  await fs.writeFile(path.join(outputDir, 'report.json'), JSON.stringify({
    schema_version: 'v1',
    target: 'https://user:password@example.com/',
    findings: [],
  }));
  await assert.rejects(
    readAndMergeFrameSevenReport({ outputDir, target: 'https://example.com/' }),
    /target/i,
  );
});

test('FrameSeven auth loader refuses symlinks and consumes the protected file once', async (t) => {
  const root = await tempRoot(t);
  const real = path.join(root, 'real-session.json');
  const link = path.join(root, 'linked-session.json');
  await fs.writeFile(real, JSON.stringify({
    version: 'v1',
    target: 'https://example.com/',
    cookies: ['sid=secret'],
    headers: {},
    endpoints: [],
  }), { mode: 0o600 });
  await fs.symlink(real, link);
  const linkedContext = createFrameSevenAuthContext({ target: 'https://example.com/' });
  await assert.rejects(
    loadFrameSevenAuthSession(linkedContext.contextId, link),
    /ELOOP|symbolic|invalid/i,
  );
  await cleanupFrameSevenAuthContext(linkedContext.contextId, link);

  const file = path.join(root, 'consumed-session.json');
  await fs.writeFile(file, JSON.stringify({
    version: 'v1',
    target: 'https://example.com/',
    cookies: ['sid=secret'],
    headers: {},
    endpoints: [],
  }), { mode: 0o600 });
  const context = createFrameSevenAuthContext({
    target: 'https://example.com/',
    filePath: file,
  });
  await assert.rejects(
    loadFrameSevenAuthSession(context.contextId, path.join(root, 'different-session.json')),
    /bound context/i,
  );
  assert.equal(await loadFrameSevenAuthSession(context.contextId, file), true);
  await assert.rejects(fs.access(file));
  assert.equal((await consumeFrameSevenAuthSecret(context.contextId))?.cookie, 'sid=secret');
  assert.equal(consumeFrameSevenAuthSecret(context.contextId), null);
});

test('FrameSeven report normalizer redacts and merges findings for every caller', async (t) => {
  const root = await tempRoot(t);
  const outputDir = path.join(root, 'frame-report');
  await fs.mkdir(outputDir);
  await fs.writeFile(path.join(outputDir, 'report.json'), JSON.stringify({
    schema_version: 'v1',
    target: 'https://example.com/',
    surface: {
      endpoints: ['https://example.com/search', 'https://outside.example/path'],
      params: [{ name: 'id', endpoint: 'https://example.com/search?id=1', method: 'GET' }],
      sensitive_files: ['/robots.txt'],
    },
    findings: [
      {
        module: 'XSS Scanner',
        severity: 'high',
        title: 'Authorization: Bearer abcdefgh123456',
        description: 'Reflected input',
        evidence: {
          request: 'GET /search?id=2 HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer request-secret',
          response: 'HTTP/1.1 200 OK\r\nSet-Cookie: sid=response-secret\r\nX-Private: private-only-marker-7f09',
          extracted: 'password=hunter2',
        },
        owasp: 'A03:2025',
        cwe: 'CWE-79',
        cvss: 7.2,
        confidence: 0.85,
        next_steps: ['Encode output'],
      },
      {
        module: 'headers',
        severity: 'low',
        title: 'Missing browser header',
        endpoint: 'https://example.com/',
      },
    ],
  }));

  const merged = await readAndMergeFrameSevenReport({
    outputDir,
    target: 'https://example.com/',
    existingFindings: [{
      type: 'xss_scanner',
      prio: 'low',
      score: 30,
      value: 'older signal',
      url: 'https://example.com/search?id=1',
      evidence: 'older evidence',
      sourceEngine: 'ghostrecon',
      moduleId: 'xss_scanner',
    }],
    accessMetadata: {
      ownerSub: 'alice',
      engagementId: 'ENG-FRAMESEVEN',
      authenticated: true,
      privateReport: true,
    },
  });

  assert.equal(merged.incomingFindings.length, 2);
  assert.equal(merged.outputCount, 2);
  assert.equal(merged.mergedCount, 1);
  assert.equal(merged.newFindings.length, 2);
  assert.deepEqual(merged.endpoints, [
    'https://example.com/search',
    'https://example.com/search?id=1',
    'https://example.com/robots.txt',
  ]);
  assert.equal(merged.newFindings[0].sourceEngine, 'frameseven');
  assert.equal(merged.newFindings[0].url, 'https://example.com/search?id=2');
  assert.equal(merged.newFindings[0].value.includes('abcdefgh123456'), false);
  assert.equal(merged.newFindings[0].evidence.includes('request-secret'), false);
  assert.equal(merged.newFindings[0].evidence.includes('response-secret'), false);
  assert.equal(merged.newFindings[0].evidence.includes('hunter2'), false);
  assert.deepEqual(
    merged.newFindings[0].meta.sources.map((source) => source.engine).sort(),
    ['frameseven', 'ghostrecon'],
  );
  assert.equal(merged.newFindings[0].meta.evidence.length, 2);
  const serialized = serializeFrameSevenMergedFindings(merged.newFindings);
  assert.equal(serialized[0].module, 'xss_scanner');
  assert.equal(serialized[0].endpoint, 'https://example.com/search?id=2');

  const publicSources = await Promise.all([
    'public-report.json',
    'public-report.html',
    'public-report.md',
  ].map((fileName) => readFrameSevenRegularFile(path.join(outputDir, fileName), {
    encoding: 'utf8',
  })));
  const publicText = publicSources.join('\n');
  for (const secret of [
    'abcdefgh123456',
    'request-secret',
    'response-secret',
    'hunter2',
    'private-only-marker-7f09',
    'sid=',
  ]) {
    assert.equal(publicText.includes(secret), false, secret);
  }
  const metadata = await readFrameSevenReportAccessMetadata(outputDir);
  assert.deepEqual({
    ownerSub: metadata.ownerSub,
    engagementId: metadata.engagementId,
    origin: metadata.origin,
    authenticated: metadata.authenticated,
    private: metadata.private,
  }, {
    ownerSub: 'alice',
    engagementId: 'ENG-FRAMESEVEN',
    origin: 'https://example.com',
    authenticated: true,
    private: true,
  });
  if (process.platform !== 'win32') {
    for (const fileName of [
      'public-report.json',
      'public-report.html',
      'public-report.md',
      'report-access.json',
    ]) {
      assert.equal((await fs.stat(path.join(outputDir, fileName))).mode & 0o777, 0o600);
    }
  }
});

test('FrameSeven safe report readers reject symlinks and keep reading the originally opened descriptor', async (t) => {
  const root = await tempRoot(t);
  const outputDir = path.join(root, 'reports', 'safe-fd');
  const reportPath = path.join(outputDir, 'report.json');
  const replacement = path.join(root, 'replacement.json');
  await fs.mkdir(outputDir, { recursive: true });
  await fs.writeFile(reportPath, '{"safe":"original"}');
  await fs.writeFile(replacement, '{"secret":"outside"}');

  const opened = await openFrameSevenRegularFile(reportPath);
  await fs.rename(reportPath, path.join(outputDir, 'old-report.json'));
  await fs.symlink(replacement, reportPath);
  assert.equal(await opened.handle.readFile({ encoding: 'utf8' }), '{"safe":"original"}');
  await opened.handle.close();
  await assert.rejects(
    readFrameSevenRegularFile(reportPath, { encoding: 'utf8' }),
    /ELOOP|symbolic|invalid/i,
  );

  const metadataTarget = path.join(outputDir, 'report-access.json');
  await fs.symlink(replacement, metadataTarget);
  await assert.rejects(
    readFrameSevenReportAccessMetadata(outputDir),
    /ELOOP|symbolic|invalid|metadata/i,
  );
});

test('FrameSeven malformed report is a hard merge error for callers to classify as partial', async (t) => {
  const root = await tempRoot(t);
  const outputDir = path.join(root, 'invalid-frame-report');
  await fs.mkdir(outputDir);
  await fs.writeFile(path.join(outputDir, 'report.json'), '{"findings":');

  await assert.rejects(
    readAndMergeFrameSevenReport({ outputDir, target: 'https://example.com/' }),
    /report JSON is invalid/i,
  );

  await fs.writeFile(path.join(outputDir, 'report.json'), JSON.stringify({
    schema_version: 'v2',
    target: 'https://example.com/',
    findings: [],
  }));
  await assert.rejects(
    readAndMergeFrameSevenReport({ outputDir, target: 'https://example.com/' }),
    /schema_version must be v1/i,
  );
});

test('FrameSeven approval wait resolves once and abort removes the pending approval', async () => {
  const controller = new AbortController();
  const approved = requestFrameSevenApproval('approval-once', { signal: controller.signal, timeoutMs: 100 });
  assert.equal(resolveFrameSevenApproval('approval-once', true), true);
  assert.equal(resolveFrameSevenApproval('approval-once', true), false);
  assert.equal(await approved, true);

  const cancelled = requestFrameSevenApproval('approval-cancelled', { signal: controller.signal, timeoutMs: 100 });
  controller.abort();
  assert.equal(await cancelled, false);
  assert.equal(resolveFrameSevenApproval('approval-cancelled', true), false);

  const owned = requestFrameSevenApproval('approval-owned', {
    timeoutMs: 100,
    ownerSub: 'alice',
  });
  assert.equal(getFrameSevenApproval('approval-owned')?.ownerSub, 'alice');
  assert.equal(resolveFrameSevenApproval('approval-owned', true, {
    principal: { sub: 'bob' },
  }), false);
  assert.equal(resolveFrameSevenApproval('approval-owned', true, {
    principal: { sub: 'alice' },
  }), true);
  assert.equal(await owned, true);
});

test('integrated FrameSeven skips an unavailable binary without skipping the GhostRecon pipeline', async (t) => {
  const root = await tempRoot(t);
  const events = [];
  let pipelineCalled = false;
  const result = await runIntegratedFrameSeven({
    root,
    target: 'https://example.com',
    requestId: 'unavailable',
    env: { GHOSTRECON_FRAMESEVEN_BIN: path.join(root, 'missing-frame-seven') },
    emit: (event) => events.push(event),
    pipeline: async () => {
      pipelineCalled = true;
    },
  });
  assert.equal(result.status, 'skipped');
  assert.equal(pipelineCalled, true);
  assert.deepEqual(events.map((event) => event.type), [
    'engine_unavailable',
    'engine_skipped',
    'engine_started',
    'engine_done',
  ]);
});

test('integrated FrameSeven fails closed when an approved binary disappears before execution', async (t) => {
  const root = await tempRoot(t);
  const binary = resolveFrameSevenBinary(root, {});
  const expectedBinaryIdentity = await inspectFrameSevenBinaryIdentity(binary);
  await fs.rm(binary);
  let pipelineCalled = false;
  await assert.rejects(
    runIntegratedFrameSeven({
      root,
      target: 'https://example.com',
      requestId: 'missing-after-approval',
      expectedBinaryIdentity,
      pipeline: async () => {
        pipelineCalled = true;
      },
    }),
    /identity mismatch/i,
  );
  assert.equal(pipelineCalled, false);
});

test('integrated FrameSeven reports partial when the scanner exits but its report cannot be parsed', async (t) => {
  const root = await tempRoot(t);
  const binary = path.join(root, 'FrameSeven', 'bin', 'frameseven', 'cli', 'v1');
  const outputDir = path.join(root, 'frame-output');
  await fs.mkdir(path.dirname(binary), { recursive: true });
  await fs.writeFile(binary, 'fixture');
  await fs.chmod(binary, 0o755);
  await fs.mkdir(outputDir);
  await fs.writeFile(path.join(outputDir, 'report.json'), '{"findings":');
  const events = [];

  const result = await runIntegratedFrameSeven({
    root,
    target: 'https://example.com/',
    requestId: 'invalid-report',
    expectedBinaryIdentity: await sealedIdentity(root),
    emit: (event) => events.push(event),
    pipeline: async () => {},
    runFrameSevenImpl: async () => ({
      engine: 'frameseven',
      status: 'done',
      code: 0,
      outputDir,
    }),
  });

  assert.equal(result.status, 'partial');
  assert.equal(result.reportMerge.status, 'failed');
  assert.equal(events.some((event) => event.type === 'engine_partial'
    && event.phase === 'report_merge'), true);
  assert.equal(events.some((event) => event.type === 'error'
    && event.recoverable === true), true);
});

test('integrated FrameSeven emits done only after bounded report merge and hides local paths', async (t) => {
  const root = await tempRoot(t);
  const binary = path.join(root, 'FrameSeven', 'bin', 'frameseven', 'cli', 'v1');
  const outputDir = path.join(root, 'reports', 'integrated-success');
  await fs.mkdir(path.dirname(binary), { recursive: true });
  await fs.writeFile(binary, 'fixture');
  await fs.chmod(binary, 0o755);
  await fs.mkdir(outputDir, { recursive: true });
  await fs.writeFile(path.join(outputDir, 'report.json'), JSON.stringify({
    schema_version: 'v1',
    target: 'https://example.com/',
    surface: { endpoints: [] },
    findings: [{
      title: 'Header issue',
      module: 'misconfig',
      severity: 'LOW',
      evidence: {
        request: 'GET / HTTP/1.1\r\nHost: example.com',
        extracted: 'missing: Content-Security-Policy',
      },
    }],
  }));
  const events = [];
  let mergeCall;
  const result = await runIntegratedFrameSeven({
    root,
    target: 'https://example.com/',
    requestId: 'valid-report',
    expectedBinaryIdentity: await sealedIdentity(root),
    ownerSub: 'alice',
    engagementId: 'ENG-INTEGRATED',
    emit: (event) => events.push(event),
    pipeline: async () => {},
    runFrameSevenImpl: async (options) => {
      assert.equal(options.deferDoneEvent, true);
      return {
        engine: 'frameseven',
        status: 'done',
        code: 0,
        outputDir,
      };
    },
    runProcessImpl: async (cmd, args, options) => {
      mergeCall = { cmd, args, options };
      return { ok: true, code: 0, stdout: '', stderr: '' };
    },
  });

  assert.equal(result.status, 'done');
  assert.equal(mergeCall.cmd, binary);
  assert.equal(mergeCall.options.signal, undefined);
  assert.equal(mergeCall.options.rejectOnTimeout, true);
  assert.equal(events.filter((event) => event.type === 'engine_done'
    && event.engine === 'frameseven').length, 1);
  assert.equal(events.some((event) => event.type === 'engine_partial'
    && event.engine === 'frameseven'), false);
  assert.equal(events.some((event) => JSON.stringify(event).includes(root)), false);
  assert.equal(events.find((event) => event.type === 'dedupe_summary')?.reportUrl,
    '/api/frameseven/reports/integrated-success/report.html');
  const access = await readFrameSevenReportAccess(root, 'integrated-success');
  assert.equal(access.ownerSub, 'alice');
  assert.equal(access.engagementId, 'ENG-INTEGRATED');
  assert.equal(access.authenticated, false);
  assert.equal(access.private, false);
  assert.equal(
    await openFrameSevenPublicReport(root, 'integrated-success', 'report.pdf'),
    null,
  );
  assert.equal(
    await openFrameSevenPublicReport(root, 'integrated-success', 'report-access.json'),
    null,
  );
});

test('integrated FrameSeven rejects a binary swapped after the approved scan and before report merge', async (t) => {
  const root = await tempRoot(t);
  const binary = resolveFrameSevenBinary(root, {});
  const expectedBinaryIdentity = await sealedIdentity(root);
  const outputDir = path.join(root, 'reports', 'integrated-binary-swap');
  await fs.mkdir(outputDir, { recursive: true });
  await fs.writeFile(path.join(outputDir, 'report.json'), JSON.stringify({
    schema_version: 'v1',
    target: 'https://example.com/',
    surface: { endpoints: [] },
    findings: [],
  }));
  let mergeSpawned = false;

  await assert.rejects(
    runIntegratedFrameSeven({
      root,
      target: 'https://example.com/',
      requestId: 'binary-swap',
      expectedBinaryIdentity,
      pipeline: async () => {},
      runFrameSevenImpl: async () => {
        await fs.writeFile(binary, 'replacement-after-approved-run');
        await fs.chmod(binary, 0o755);
        return {
          engine: 'frameseven',
          status: 'done',
          code: 0,
          outputDir,
        };
      },
      runProcessImpl: async () => {
        mergeSpawned = true;
        return { ok: true, code: 0, stdout: '', stderr: '' };
      },
    }),
    /identity mismatch/i,
  );
  assert.equal(mergeSpawned, false);
});

test('integrated authenticated FrameSeven writes private access metadata without session secrets', async (t) => {
  const root = await tempRoot(t);
  const outputDir = path.join(root, 'reports', 'integrated-auth-private');
  await fs.mkdir(outputDir, { recursive: true });
  await fs.writeFile(path.join(outputDir, 'report.json'), JSON.stringify({
    schema_version: 'v1',
    target: 'https://example.com/',
    surface: { endpoints: [] },
    findings: [{
      title: 'private-authenticated-marker',
      module: 'auth',
      severity: 'INFO',
      evidence: {
        request: 'GET /private HTTP/1.1\r\nAuthorization: Bearer private-token',
        response: 'Set-Cookie: sid=private-cookie',
      },
    }],
  }));
  await runIntegratedFrameSeven({
    root,
    target: 'https://example.com/',
    authBrowser: true,
    requestId: 'auth-private',
    ownerSub: 'alice',
    engagementId: 'ENG-AUTH',
    expectedBinaryIdentity: await sealedIdentity(root),
    pipeline: async () => {},
    runFrameSevenImpl: async (options) => {
      assert.equal(options.authBrowser, true);
      assert.equal(typeof options.beforeScan, 'function');
      return {
        engine: 'frameseven',
        status: 'done',
        code: 0,
        outputDir,
      };
    },
    runProcessImpl: async () => ({ ok: true, code: 0, stdout: '', stderr: '' }),
  });
  const access = await readFrameSevenReportAccess(root, 'integrated-auth-private');
  assert.equal(access.authenticated, true);
  assert.equal(access.private, true);
  assert.equal(access.ownerSub, 'alice');
  assert.equal(access.engagementId, 'ENG-AUTH');
  const publicReport = await openFrameSevenPublicReport(
    root,
    'integrated-auth-private',
    'report.json',
  );
  const publicText = await publicReport.handle.readFile({ encoding: 'utf8' });
  await publicReport.handle.close();
  for (const secret of [
    'private-authenticated-marker',
    'private-token',
    'private-cookie',
  ]) {
    assert.equal(publicText.includes(secret), false, secret);
  }
});

test('integrated authenticated before-scan deadline propagates its abort signal into the pipeline', async (t) => {
  const root = await tempRoot(t);
  const events = [];
  let pipelineAborted = false;
  let authFile;
  await assert.rejects(
    runIntegratedFrameSeven({
      root,
      target: 'https://example.com/',
      authBrowser: true,
      requestId: 'auth-before-scan-timeout',
      ownerSub: 'alice',
      expectedBinaryIdentity: await sealedIdentity(root),
      beforeScanTimeoutMs: 5,
      approvalTimeoutMs: 100,
      authCaptureTimeoutMs: 100,
      killGraceMs: 3,
      reapTimeoutMs: 50,
      emit: (event) => {
        events.push(event);
        if (event.type === 'auth_required') {
          setTimeout(() => resolveFrameSevenApproval(event.approvalId, true, {
            principal: { sub: 'alice' },
          }), 0);
        }
      },
      pipeline: (_auth, _emit, { signal: stageSignal } = {}) => new Promise((_resolve, reject) => {
        stageSignal.addEventListener('abort', () => {
          pipelineAborted = true;
          reject(stageSignal.reason);
        }, { once: true });
      }),
      runFrameSevenImpl: (options) => runFrameSeven({
        ...options,
        spawnImpl: (_binary, args) => {
          authFile = args[args.indexOf('-auth-session-out') + 1];
          const child = fakeProcess(null, (signalName, proc) => {
            if (signalName === 'SIGKILL') proc.emit('exit', null, signalName);
            return true;
          });
          queueMicrotask(async () => {
            await fs.writeFile(authFile, JSON.stringify({
              version: 'v1',
              target: 'https://example.com/',
              cookies: [],
              headers: {},
              endpoints: [],
            }), { mode: 0o600 });
            child.stdout.write('FRAMESEVEN_AUTH_READY_V1\n');
          });
          return child;
        },
      }),
    }),
    /timeout/i,
  );
  assert.equal(pipelineAborted, true);
  assert.equal(events.some((event) => event.type === 'engine_timeout'
    && event.phase === 'before_scan'), true);
  await assert.rejects(fs.access(path.dirname(authFile)));
});

test('integrated FrameSeven preserves findings from recoverable exit 1 and finishes partial', async (t) => {
  const root = await tempRoot(t);
  const binary = path.join(root, 'FrameSeven', 'bin', 'frameseven', 'cli', 'v1');
  const outputDir = path.join(root, 'reports', 'integrated-partial');
  await fs.mkdir(path.dirname(binary), { recursive: true });
  await fs.writeFile(binary, 'fixture');
  await fs.chmod(binary, 0o755);
  await fs.mkdir(outputDir, { recursive: true });
  await fs.writeFile(path.join(outputDir, 'report.json'), JSON.stringify({
    schema_version: 'v1',
    target: 'https://example.com/',
    surface: { endpoints: [] },
    findings: [{ title: 'Recovered finding', module: 'recon', severity: 'INFO' }],
    errors: [{ module: 'crawler', message: 'request timeout' }],
  }));
  const events = [];
  const result = await runIntegratedFrameSeven({
    root,
    target: 'https://example.com/',
    requestId: 'partial-report',
    expectedBinaryIdentity: await sealedIdentity(root),
    emit: (event) => events.push(event),
    pipeline: async () => {},
    runFrameSevenImpl: async () => ({
      engine: 'frameseven',
      status: 'partial',
      recoverable: true,
      code: 1,
      outputDir,
    }),
    runProcessImpl: async () => ({ ok: true, code: 0, stdout: '', stderr: '' }),
  });

  assert.equal(result.status, 'partial');
  assert.equal(result.reportMerge.findings, 1);
  assert.equal(result.reportMerge.reportErrors, 1);
  assert.equal(events.some((event) => event.type === 'finding'
    && event.finding?.value === 'Recovered finding'), true);
  assert.equal(events.filter((event) => event.type === 'engine_partial'
    && event.engine === 'frameseven').length, 1);
  assert.equal(events.some((event) => event.type === 'engine_done'
    && event.engine === 'frameseven'), false);
});

test('integrated FrameSeven propagates report-merge cancellation instead of downgrading it to partial', async (t) => {
  const root = await tempRoot(t);
  const binary = path.join(root, 'FrameSeven', 'bin', 'frameseven', 'cli', 'v1');
  const outputDir = path.join(root, 'reports', 'integrated-cancelled');
  await fs.mkdir(path.dirname(binary), { recursive: true });
  await fs.writeFile(binary, 'fixture');
  await fs.chmod(binary, 0o755);
  await fs.mkdir(outputDir, { recursive: true });
  await fs.writeFile(path.join(outputDir, 'report.json'), JSON.stringify({
    schema_version: 'v1',
    target: 'https://example.com/',
    surface: { endpoints: [] },
    findings: [],
  }));
  const controller = new AbortController();
  const events = [];
  await assert.rejects(
    runIntegratedFrameSeven({
      root,
      target: 'https://example.com/',
      requestId: 'cancelled-merge',
      expectedBinaryIdentity: await sealedIdentity(root),
      signal: controller.signal,
      emit: (event) => events.push(event),
      pipeline: async () => {},
      runFrameSevenImpl: async () => ({
        engine: 'frameseven',
        status: 'done',
        code: 0,
        outputDir,
      }),
      runProcessImpl: async () => {
        controller.abort(new Error('operator cancelled report merge'));
        const error = new Error('FrameSeven report merge cancelado');
        error.name = 'AbortError';
        error.code = 'PROCESS_ABORTED';
        throw error;
      },
    }),
    /cancelado/i,
  );
  assert.equal(events.filter((event) => event.type === 'engine_cancelled'
    && event.engine === 'frameseven').length, 1);
  assert.equal(events.some((event) => event.type === 'engine_partial'
    && event.engine === 'frameseven'), false);
});

test('integrated FrameSeven fails closed when report merge cannot confirm subprocess termination', async (t) => {
  const root = await tempRoot(t);
  const outputDir = path.join(root, 'reports', 'integrated-unterminated-merge');
  await fs.mkdir(outputDir, { recursive: true });
  await fs.writeFile(path.join(outputDir, 'report.json'), JSON.stringify({
    schema_version: 'v1',
    target: 'https://example.com/',
    surface: { endpoints: [] },
    findings: [],
  }));
  const events = [];

  await assert.rejects(
    runIntegratedFrameSeven({
      root,
      target: 'https://example.com/',
      requestId: 'unterminated-merge',
      expectedBinaryIdentity: await sealedIdentity(root),
      emit: (event) => events.push(event),
      pipeline: async () => {},
      runFrameSevenImpl: async () => ({
        engine: 'frameseven',
        status: 'done',
        code: 0,
        outputDir,
      }),
      runProcessImpl: async () => {
        const error = new Error('merge child did not terminate');
        error.code = 'PROCESS_UNTERMINATED';
        error.unterminated = true;
        error.recoverable = false;
        throw error;
      },
    }),
    (error) => {
      assert.equal(error?.code, 'PROCESS_UNTERMINATED');
      assert.equal(error?.fatal, true);
      assert.equal(error?.recoverable, false);
      assert.equal(error?.unterminated, true);
      return true;
    },
  );

  assert.equal(events.some((event) => event.type === 'engine_failed'
    && event.engine === 'frameseven'
    && event.phase === 'report_merge'
    && event.unterminated === true
    && event.recoverable === false), true);
  assert.equal(events.some((event) => event.type === 'engine_partial'
    && event.engine === 'frameseven'), false);
});

test('cockpit approvals use the authenticated helper and Auto requires a terminal session event', async () => {
  const html = await fs.readFile(new URL('../../public/index.html', import.meta.url), 'utf8');
  const reconRoute = await fs.readFile(new URL('../routes/recon-stream.mjs', import.meta.url), 'utf8');
  assert.match(html, /onclick="handleAutoModeButton\(\)"/);
  assert.match(html, /id="includeFrameSevenToggle"/);
  assert.match(html, /id="autoIncludeFrameSevenToggle"/);
  assert.match(html, /id="autoIncludeVigoliumToggle"/);
  assert.doesNotMatch(html, /id="(?:includeFrameSevenToggle|autoIncludeFrameSevenToggle)"[^>]*\bchecked\b/);
  assert.doesNotMatch(html, /id="autoIncludeVigoliumToggle"[^>]*\bchecked\b/);
  assert.doesNotMatch(html, /id="autoHexstrikeToggle"[^>]*\bchecked\b/);
  assert.match(html, /const frameSevenAuth = includeFrameSeven &&/);
  assert.match(html, /includeFrameSeven,\s*frameSevenAuth,\s*includeVigolium,\s*vigoliumUseCodex,/);
  assert.match(html, /function postAutoApiJson\(pathname, body\)[\s\S]*autoApiHeaders\(true\)/);
  assert.match(html, /postAutoApiJson\(`\/api\/recon\/auto\/\$\{encodeURIComponent\(ev\.sessionId\)\}\/approval`/);
  assert.match(html, /postAutoApiJson\(`\/api\/recon\/frameseven\/\$\{encodeURIComponent\(ev\.approvalId\)\}\/approval`/);
  assert.match(html, /a\.limits\?\.modules/);
  assert.match(html, /Limites:\\n\$\{limitsText\}/);
  assert.match(html, /consumeReconStreamFromResponse\(res, 0, null, null, \{ requireAutoTerminal: true \}\)/);
  assert.match(reconRoute, /const includeFrameSeven = req\.body\?\.includeFrameSeven === true/);
  assert.match(reconRoute, /if \(includeFrameSeven\) \{[\s\S]*runIntegratedFrameSeven/);
  assert.match(reconRoute, /\{ signal: stageSignal \} = \{\}/);
  assert.match(reconRoute, /signal: stageSignal \|\| controller\.signal/);
  assert.doesNotMatch(reconRoute, /\[\.\.\.modules,\s*'vigolium_dast',\s*'vigolium_audit'\]/);
});

test('FrameSeven output redacts headers, bearer tokens, and passwords', () => {
  const output = redactFrameSevenOutput('Authorization: Bearer abc.def\nCookie: sid=secret\npassword=hunter2');
  assert.equal(output.includes('abc.def'), false);
  assert.equal(output.includes('sid=secret'), false);
  assert.equal(output.includes('hunter2'), false);
});
