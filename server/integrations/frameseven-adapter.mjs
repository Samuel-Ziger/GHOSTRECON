import { spawn } from 'node:child_process';
import path from 'node:path';
import fs from 'node:fs/promises';
import { constants as fsConstants } from 'node:fs';
import { createHash } from 'node:crypto';
import os from 'node:os';
import {
  createFrameSevenAuthContext,
  loadFrameSevenAuthSession,
  consumeFrameSevenAuthSecret,
  cleanupFrameSevenAuthContext,
} from './frameseven-auth-context.mjs';
import { openFrameSevenRegularFile } from './frameseven-report.mjs';
import {
  FRAMESEVEN_RECON_TOOLS_ARG_V1,
  resolveFrameSevenToolProfileV1,
} from './frameseven-policy.mjs';

const DEFAULT_RUN_TIMEOUT_MS = 30 * 60_000;
const DEFAULT_AUTH_CAPTURE_TIMEOUT_MS = 10 * 60_000;
const DEFAULT_AUTH_APPROVAL_TIMEOUT_MS = 10 * 60_000;
const DEFAULT_BEFORE_SCAN_TIMEOUT_MS = 30 * 60_000;
const DEFAULT_KILL_GRACE_MS = 2_000;
const DEFAULT_REAP_TIMEOUT_MS = 10_000;
const MAX_STAGE_TIMEOUT_MS = 2 * 60 * 60_000;
const MAX_KILL_GRACE_MS = 30_000;
const MAX_REAP_TIMEOUT_MS = 60_000;
const FRAMESEVEN_ENV_ALLOWLIST = Object.freeze([
  'PATH',
  'HOME',
  'LANG',
  'LANGUAGE',
  'LC_ALL',
  'LC_CTYPE',
  'TMPDIR',
  'TMP',
  'TEMP',
  'TZ',
  'DISPLAY',
  'WAYLAND_DISPLAY',
  'XAUTHORITY',
  'DBUS_SESSION_BUS_ADDRESS',
  'XDG_RUNTIME_DIR',
  'XDG_CONFIG_HOME',
  'XDG_CACHE_HOME',
  'SSL_CERT_FILE',
  'SSL_CERT_DIR',
  'USERPROFILE',
  'APPDATA',
  'LOCALAPPDATA',
  'SYSTEMROOT',
  'WINDIR',
  'COMSPEC',
  'PATHEXT',
]);

function safeTarget(value) {
  const url = new URL(String(value || ''));
  if (!['http:', 'https:'].includes(url.protocol)
    || url.username
    || url.password) {
    throw new Error('FrameSeven exige alvo HTTP(S) sem userinfo');
  }
  return url.toString();
}

function asError(value, fallback) {
  if (value instanceof Error) return value;
  return new Error(String(value || fallback));
}

function boundedTimeout(value, fallback, maximum = MAX_STAGE_TIMEOUT_MS) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 1) return fallback;
  return Math.min(maximum, Math.floor(parsed));
}

function boundedPositiveInteger(value, fallback, maximum) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 1) return fallback;
  return Math.min(maximum, Math.floor(parsed));
}

function boundedDurationArgument(value, fallback, maximumMs) {
  const match = String(value || '').trim().match(/^(\d+)(ms|s|m|h)$/i);
  if (!match) return fallback;
  const multiplier = {
    ms: 1,
    s: 1_000,
    m: 60_000,
    h: 60 * 60_000,
  }[match[2].toLowerCase()];
  const milliseconds = Number(match[1]) * multiplier;
  if (!Number.isSafeInteger(milliseconds) || milliseconds < 1) return fallback;
  if (milliseconds > maximumMs) return `${maximumMs}ms`;
  return `${match[1]}${match[2].toLowerCase()}`;
}

function identityMismatch(message) {
  const error = new Error(`FrameSeven binary identity mismatch: ${message}`);
  error.code = 'FRAMESEVEN_BINARY_IDENTITY_MISMATCH';
  return error;
}

function safeInteger(value) {
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : null;
}

/**
 * Fingerprints the exact regular file opened with O_NOFOLLOW. Hash and metadata
 * come from the same descriptor so callers can seal this value in an approved
 * plan and reject a later executable swap.
 */
export async function inspectFrameSevenBinaryIdentity(binaryPath) {
  const resolved = path.resolve(String(binaryPath || ''));
  const noFollow = Number(fsConstants.O_NOFOLLOW || 0);
  let handle;
  try {
    handle = await fs.open(resolved, fsConstants.O_RDONLY | noFollow);
    const before = await handle.stat();
    if (!before.isFile()) throw identityMismatch('not a regular file');
    if (process.platform !== 'win32' && (before.mode & 0o111) === 0) {
      throw identityMismatch('file is not executable');
    }
    const hash = createHash('sha256');
    const buffer = Buffer.allocUnsafe(64 * 1024);
    let position = 0;
    while (position < before.size) {
      const { bytesRead } = await handle.read(
        buffer,
        0,
        Math.min(buffer.length, before.size - position),
        position,
      );
      if (bytesRead <= 0) break;
      hash.update(buffer.subarray(0, bytesRead));
      position += bytesRead;
    }
    const after = await handle.stat();
    if (
      position !== before.size
      || before.dev !== after.dev
      || before.ino !== after.ino
      || before.size !== after.size
      || before.mtimeMs !== after.mtimeMs
    ) {
      throw identityMismatch('file changed during fingerprint');
    }
    return Object.freeze({
      algorithm: 'sha256',
      sha256: hash.digest('hex'),
      size: after.size,
      dev: safeInteger(after.dev),
      ino: safeInteger(after.ino),
      mtimeMs: Number.isFinite(after.mtimeMs) ? after.mtimeMs : null,
      mode: safeInteger(after.mode),
    });
  } catch (error) {
    if (error?.code === 'FRAMESEVEN_BINARY_IDENTITY_MISMATCH') throw error;
    const wrapped = identityMismatch(error?.code || error?.message || 'unavailable');
    wrapped.cause = error;
    throw wrapped;
  } finally {
    await handle?.close().catch(() => {});
  }
}

export function assertFrameSevenBinaryIdentity(actual, expected) {
  if (
    !expected
    || expected.algorithm !== 'sha256'
    || !/^[a-f0-9]{64}$/i.test(String(expected.sha256 || ''))
    || safeInteger(expected.size) == null
  ) {
    throw identityMismatch('approved identity is missing or invalid');
  }
  if (
    actual?.algorithm !== 'sha256'
    || actual.sha256 !== String(expected.sha256).toLowerCase()
    || actual.size !== Number(expected.size)
  ) {
    throw identityMismatch('sha256 or size changed after approval');
  }
  for (const key of ['dev', 'ino', 'mode']) {
    if (expected[key] != null && actual[key] !== Number(expected[key])) {
      throw identityMismatch(`${key} changed after approval`);
    }
  }
  if (expected.mtimeMs != null && actual.mtimeMs !== Number(expected.mtimeMs)) {
    throw identityMismatch('mtimeMs changed after approval');
  }
  return true;
}

export async function validateFrameSevenBinaryIdentity(
  binaryPath,
  expected,
  { inspectImpl = inspectFrameSevenBinaryIdentity } = {},
) {
  const actual = await inspectImpl(binaryPath);
  assertFrameSevenBinaryIdentity(actual, expected);
  return actual;
}

function signalChildTree(child, signalName, killImpl = process.kill) {
  const pid = Number(child?.pid);
  if (process.platform !== 'win32' && Number.isInteger(pid) && pid > 0) {
    try {
      killImpl(-pid, signalName);
      return true;
    } catch {
      // O processo pode ter encerrado entre a checagem e o sinal.
    }
  }
  try {
    return child?.kill?.(signalName) !== false;
  } catch {
    return false;
  }
}

export function redactFrameSevenOutput(value, { paths = [] } = {}) {
  let output = String(value || '')
    .replace(/(^|[\r\n])\s*(authorization|authentication|cookie|set-cookie|x-(?:auth|access)-token|x-api-key|x-csrf-token)\s*:\s*[^\r\n]*/gi, '$1$2: [REDACTED]')
    .replace(/((?:access|refresh|auth|session|csrf)[_-]?token|password|passwd)\s*[=:]\s*([^\s,;]+)/gi, '$1=[REDACTED]')
    .replace(/\bBearer\s+[A-Za-z0-9._~+\/-]+=*/gi, 'Bearer [REDACTED]');
  for (const sensitivePath of paths) {
    const candidate = String(sensitivePath || '');
    if (candidate) output = output.split(candidate).join('[LOCAL_PATH]');
  }
  return output;
}

export function resolveFrameSevenBinary(root, env = process.env) {
  return String(env.GHOSTRECON_FRAMESEVEN_BIN || path.join(root, 'FrameSeven', 'bin', 'frameseven', 'cli', 'v1'));
}

export function frameSevenChildEnv(env = process.env) {
  const source = env && typeof env === 'object' ? env : {};
  return Object.fromEntries(FRAMESEVEN_ENV_ALLOWLIST
    .filter((key) => typeof source[key] === 'string' && source[key])
    .map((key) => [key, source[key]]));
}

/** Executes FrameSeven with argument arrays only; credentials are never accepted here. */
export async function runFrameSeven({
  root,
  target,
  outputDir,
  authBrowser = false,
  approvalId = null,
  tools = FRAMESEVEN_RECON_TOOLS_ARG_V1,
  offensiveApproved = false,
  timeout = '30s',
  toolTimeout = '5m',
  concurrency = 10,
  rate = 100,
  runTimeoutMs = DEFAULT_RUN_TIMEOUT_MS,
  authCaptureTimeoutMs = DEFAULT_AUTH_CAPTURE_TIMEOUT_MS,
  approvalTimeoutMs = DEFAULT_AUTH_APPROVAL_TIMEOUT_MS,
  beforeScanTimeoutMs = DEFAULT_BEFORE_SCAN_TIMEOUT_MS,
  killGraceMs = DEFAULT_KILL_GRACE_MS,
  reapTimeoutMs = DEFAULT_REAP_TIMEOUT_MS,
  expectedBinaryIdentity = null,
  signal,
  emit = () => {},
  deferDoneEvent = false,
  waitForAuth = null,
  beforeScan = null,
  env = process.env,
  spawnImpl = spawn,
  killImpl = process.kill,
  inspectBinaryIdentityImpl = inspectFrameSevenBinaryIdentity,
} = {}) {
  const url = safeTarget(target);
  const toolProfile = resolveFrameSevenToolProfileV1(tools);
  if (toolProfile.offensive && offensiveApproved !== true) {
    const error = new Error(
      'Perfil ofensivo FrameSeven exige aprovação explícita do plano efetivo',
    );
    error.code = 'FRAMESEVEN_OFFENSIVE_APPROVAL_REQUIRED';
    throw error;
  }
  const reportsRoot = path.resolve(root, 'reports');
  const out = path.resolve(root, outputDir || path.join('reports', `frameseven-${Date.now()}`));
  const outputRelative = path.relative(reportsRoot, out);
  if (
    !outputRelative
    || outputRelative.startsWith('..')
    || path.isAbsolute(outputRelative)
    || outputRelative.split(path.sep).length !== 1
    || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$/.test(outputRelative)
  ) {
    throw new Error('FrameSeven outputDir deve ficar dentro de reports/');
  }
  await fs.mkdir(reportsRoot, { recursive: true, mode: 0o700 });
  const reportsStat = await fs.lstat(reportsRoot);
  if (!reportsStat.isDirectory() || reportsStat.isSymbolicLink()) {
    throw new Error('FrameSeven reports/ deve ser um diretório local real');
  }
  const existingOutput = await fs.lstat(out).catch((error) => {
    if (error?.code === 'ENOENT') return null;
    throw error;
  });
  if (existingOutput && (!existingOutput.isDirectory() || existingOutput.isSymbolicLink())) {
    throw new Error('FrameSeven outputDir existente é inválido');
  }
  await fs.mkdir(out, { recursive: true, mode: 0o700 });
  if (process.platform !== 'win32') await fs.chmod(out, 0o700);

  const args = [
    '-url', url,
    '-tools', toolProfile.tools,
    '-timeout', boundedDurationArgument(timeout, '30s', 5 * 60_000),
    '-tool-timeout', boundedDurationArgument(toolTimeout, '5m', 30 * 60_000),
    '-concurrency', String(boundedPositiveInteger(concurrency, 10, 50)),
    '-rate', String(boundedPositiveInteger(rate, 100, 500)),
    '-verbose',
    '-out', out,
  ];
  let authContext = null;
  let authDir = null;
  let authFile = null;
  if (authBrowser) {
    authDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-frameseven-'));
    await fs.chmod(authDir, 0o700);
    authFile = path.join(authDir, 'session-v1.json');
    authContext = createFrameSevenAuthContext({ target: url, filePath: authFile });
    args.push('-auth-browser', '-auth-session-out', authFile, '-auth-wait-after-capture');
  }

  const cleanupAuth = async () => {
    if (authContext) await cleanupFrameSevenAuthContext(authContext.contextId, authFile);
    if (authDir) await fs.rm(authDir, { recursive: true, force: true }).catch(() => {});
  };

  if (signal?.aborted) {
    await cleanupAuth();
    const error = asError(signal.reason, 'FrameSeven cancelado');
    const message = redactFrameSevenOutput(error.message, {
      paths: [root, out, authDir, authFile].filter(Boolean),
    });
    emit({
      type: 'engine_cancelled',
      engine: 'frameseven',
      target: url,
      error: message,
    });
    throw new Error(message, { cause: error });
  }

  const binary = resolveFrameSevenBinary(root, env);
  const redactionPaths = [root, out, binary, authDir, authFile].filter(Boolean);
  const publicError = (error, fallback = 'FrameSeven falhou') => redactFrameSevenOutput(
    asError(error, fallback).message,
    { paths: redactionPaths },
  );
  let child;
  try {
    // Deliberately immediately before spawn: the expected value must have been
    // sealed by the catalog/preflight and included in the approved plan.
    await validateFrameSevenBinaryIdentity(binary, expectedBinaryIdentity, {
      inspectImpl: inspectBinaryIdentityImpl,
    });
    child = spawnImpl(binary, args, {
      cwd: root,
      env: frameSevenChildEnv(env),
      stdio: [authBrowser ? 'pipe' : 'ignore', 'pipe', 'pipe'],
      windowsHide: true,
      detached: process.platform !== 'win32',
    });
  } catch (error) {
    await cleanupAuth();
    const failure = asError(error, 'FrameSeven não iniciou');
    emit({
      type: 'engine_failed',
      engine: 'frameseven',
      target: url,
      error: publicError(failure),
      phase: 'spawn',
    });
    const wrapped = new Error(publicError(failure), { cause: failure });
    if (failure.code) wrapped.code = failure.code;
    throw wrapped;
  }

  emit({
    type: 'engine_started',
    engine: 'frameseven',
    target: url,
    authBrowser,
    toolProfile: toolProfile.id,
    tools: toolProfile.tools,
  });

  return new Promise((resolve, reject) => {
    let stdout = '';
    let stdoutMarkerTail = '';
    let stderr = '';
    let settled = false;
    let authFlowStarted = false;
    let scanReleased = !authBrowser;
    let stopIntent = null;
    let activeStageController = null;
    let authCaptureTimer = null;
    let runTimer = null;
    let killTimer = null;
    let reapTimer = null;
    let terminalObserved = false;

    const clearTimers = () => {
      if (authCaptureTimer) clearTimeout(authCaptureTimer);
      authCaptureTimer = null;
      if (runTimer) clearTimeout(runTimer);
      runTimer = null;
      if (killTimer) clearTimeout(killTimer);
      killTimer = null;
      if (reapTimer) clearTimeout(reapTimer);
      reapTimer = null;
    };

    const cleanup = async () => {
      clearTimers();
      signal?.removeEventListener('abort', abort);
      child.stdout?.off?.('data', onStdout);
      child.stderr?.off?.('data', onStderr);
      child.off?.('error', onChildError);
      child.off?.('exit', onChildExit);
      child.off?.('close', onChildClose);
      child.stdin?.end?.();
      activeStageController?.abort(new Error('FrameSeven stage closed'));
      activeStageController = null;
      await cleanupAuth();
    };

    const settle = (status, value) => {
      if (settled) return;
      settled = true;
      const recoverable = status === 'done' || status === 'partial';
      const error = recoverable ? null : asError(value, 'FrameSeven falhou');
      const publicFailure = error
        ? new Error(publicError(error), { cause: error })
        : null;
      if (publicFailure && error?.code) publicFailure.code = error.code;
      if (publicFailure && error?.name === 'AbortError') publicFailure.name = 'AbortError';
      if (publicFailure && error?.fatal === true) publicFailure.fatal = true;
      if (publicFailure && error?.recoverable === false) publicFailure.recoverable = false;
      if (publicFailure && error?.unterminated === true) publicFailure.unterminated = true;
      if (publicFailure && error?.requestedStatus) {
        publicFailure.requestedStatus = error.requestedStatus;
      }
      if (publicFailure && error?.phase) publicFailure.phase = error.phase;
      if (status === 'done') {
        if (!deferDoneEvent) {
          emit({ type: 'engine_done', engine: 'frameseven', target: url, code: value.code });
        }
      } else if (status === 'partial') {
        if (!deferDoneEvent) {
          emit({
            type: 'engine_partial',
            engine: 'frameseven',
            target: url,
            code: value.code,
            phase: 'scan',
            recoverable: true,
          });
        }
      } else if (status === 'cancelled') {
        emit({
          type: 'engine_cancelled',
          engine: 'frameseven',
          target: url,
          error: publicError(error),
        });
      } else if (status === 'timeout') {
        emit({
          type: 'engine_timeout',
          engine: 'frameseven',
          target: url,
          error: publicError(error),
          timeout: true,
          phase: stopIntent?.phase || 'scan',
        });
      } else if (status === 'unterminated') {
        emit({
          type: 'engine_failed',
          engine: 'frameseven',
          target: url,
          error: publicError(error),
          timeout: false,
          phase: 'termination',
          unterminated: true,
          recoverable: false,
          requestedStatus: stopIntent?.status || null,
        });
      } else {
        emit({
          type: 'engine_failed',
          engine: 'frameseven',
          target: url,
          error: publicError(error),
          timeout: false,
          phase: stopIntent?.phase || status,
        });
      }
      void cleanup().finally(() => {
        if (recoverable) resolve(value);
        else reject(publicFailure);
      });
    };

    const settleUnterminated = () => {
      if (settled || terminalObserved || !stopIntent) return;
      const error = new Error(
        `FrameSeven não confirmou encerramento após SIGTERM/SIGKILL `
          + `(${boundedTimeout(reapTimeoutMs, DEFAULT_REAP_TIMEOUT_MS, MAX_REAP_TIMEOUT_MS)}ms `
          + 'aguardando exit/close)',
        { cause: stopIntent.error },
      );
      error.code = 'FRAMESEVEN_PROCESS_UNTERMINATED';
      error.fatal = true;
      error.recoverable = false;
      error.unterminated = true;
      error.requestedStatus = stopIntent.status;
      error.phase = stopIntent.phase;
      settle('unterminated', error);
    };

    const requestStop = (status, value, phase = 'scan') => {
      if (settled || stopIntent) return;
      stopIntent = {
        status,
        error: asError(value, 'FrameSeven interrompido'),
        phase,
      };
      activeStageController?.abort(stopIntent.error);
      const grace = boundedTimeout(killGraceMs, DEFAULT_KILL_GRACE_MS, MAX_KILL_GRACE_MS);
      const reapLimit = boundedTimeout(reapTimeoutMs, DEFAULT_REAP_TIMEOUT_MS, MAX_REAP_TIMEOUT_MS);
      killTimer = setTimeout(() => {
        signalChildTree(child, 'SIGKILL', killImpl);
        // SIGKILL normally produces exit/close. The bounded reap guard may
        // reject the run, but it must never claim that cleanup completed when
        // the process did not confirm termination.
        reapTimer = setTimeout(settleUnterminated, reapLimit);
      }, grace);
      signalChildTree(child, 'SIGTERM', killImpl);
    };

    const runBoundedStage = async (phase, timeoutMs, callback) => {
      const controller = new AbortController();
      activeStageController = controller;
      const fallback = phase === 'approval'
        ? DEFAULT_AUTH_APPROVAL_TIMEOUT_MS
        : DEFAULT_BEFORE_SCAN_TIMEOUT_MS;
      const limit = boundedTimeout(timeoutMs, fallback);
      const timeoutError = new Error(`FrameSeven timeout após ${limit}ms na fase ${phase}`);
      timeoutError.code = 'FRAMESEVEN_STAGE_TIMEOUT';
      timeoutError.phase = phase;
      let timer;
      let abortListener;
      try {
        const deadline = new Promise((_, rejectStage) => {
          abortListener = () => rejectStage(asError(controller.signal.reason, 'FrameSeven stage cancelled'));
          controller.signal.addEventListener('abort', abortListener, { once: true });
          timer = setTimeout(() => {
            controller.abort(timeoutError);
          }, limit);
        });
        return await Promise.race([
          Promise.resolve().then(() => callback(controller.signal)),
          deadline,
        ]);
      } finally {
        if (timer) clearTimeout(timer);
        if (abortListener) controller.signal.removeEventListener('abort', abortListener);
        if (activeStageController === controller) activeStageController = null;
        if (!controller.signal.aborted) controller.abort(new Error(`FrameSeven ${phase} completed`));
      }
    };

    const handleAuthReady = async () => {
      try {
        const loaded = await loadFrameSevenAuthSession(authContext.contextId, authFile);
        if (!loaded) throw new Error('FrameSeven authentication context expired');
        if (authCaptureTimer) clearTimeout(authCaptureTimer);
        authCaptureTimer = null;
        if (settled || stopIntent) return;

        emit({ type: 'auth_ready', engine: 'frameseven', contextId: authContext.contextId, target: url });
        emit({
          type: 'auth_required',
          engine: 'frameseven',
          target: url,
          approvalId: approvalId || undefined,
          contextId: authContext.contextId,
          message: 'Autenticação capturada. Confirme para compartilhar a sessão temporária e iniciar as auditorias.',
        });
        const approved = await runBoundedStage(
          'approval',
          approvalTimeoutMs,
          (stageSignal) => (typeof waitForAuth === 'function'
            ? waitForAuth({
                contextId: authContext.contextId,
                target: url,
                approvalId,
                signal: stageSignal,
              })
            : false),
        );
        if (!approved) throw new Error('FrameSeven authentication refused by operator');
        if (settled || stopIntent) return;

        const secret = consumeFrameSevenAuthSecret(authContext.contextId);
        if (!secret) throw new Error('FrameSeven authentication context unavailable or already consumed');
        emit({ type: 'auth_confirmed', engine: 'frameseven', contextId: authContext.contextId, target: url });
        if (typeof beforeScan === 'function') {
          await runBoundedStage(
            'before_scan',
            beforeScanTimeoutMs,
            (stageSignal) => beforeScan(secret, {
              contextId: authContext.contextId,
              target: url,
              signal: stageSignal,
            }),
          );
        }
        if (settled || stopIntent) return;

        scanReleased = true;
        startRunTimer();
        child.stdin?.write('\n');
      } catch (error) {
        const timeout = error?.code === 'FRAMESEVEN_STAGE_TIMEOUT';
        requestStop(timeout ? 'timeout' : 'failed', error, error?.phase || 'authentication');
      }
    };

    const onStdout = (chunk) => {
      const raw = String(chunk);
      const line = redactFrameSevenOutput(raw, { paths: redactionPaths });
      stdout = `${stdout}${line}`.slice(-64_000);
      const visibleLine = line.replace(/FRAMESEVEN_AUTH_READY_V1/g, '').trimEnd();
      if (visibleLine) emit({ type: 'engine_progress', engine: 'frameseven', stream: 'stdout', line: visibleLine });

      stdoutMarkerTail = `${stdoutMarkerTail}${raw}`.slice(-256);
      if (authBrowser && stdoutMarkerTail.includes('FRAMESEVEN_AUTH_READY_V1') && !authFlowStarted) {
        authFlowStarted = true;
        void handleAuthReady();
      }
    };

    const onStderr = (chunk) => {
      const line = redactFrameSevenOutput(chunk, { paths: redactionPaths });
      stderr = `${stderr}${line}`.slice(-32_000);
      const visibleLine = line.trimEnd();
      if (visibleLine) emit({ type: 'engine_progress', engine: 'frameseven', stream: 'stderr', line: visibleLine });
    };

    const abort = () => requestStop(
      'cancelled',
      signal?.reason || new Error('FrameSeven cancelado'),
      authBrowser && !scanReleased ? 'authentication' : 'scan',
    );
    const runLimit = boundedTimeout(runTimeoutMs, DEFAULT_RUN_TIMEOUT_MS);
    const startRunTimer = () => {
      if (runTimer || settled || stopIntent) return;
      runTimer = setTimeout(
        () => {
          const error = new Error(`FrameSeven timeout após ${runLimit}ms de varredura`);
          error.code = 'FRAMESEVEN_STAGE_TIMEOUT';
          error.phase = 'scan';
          requestStop('timeout', error, 'scan');
        },
        runLimit,
      );
    };

    child.stdout?.on('data', onStdout);
    child.stderr?.on('data', onStderr);
    signal?.addEventListener('abort', abort, { once: true });
    if (signal?.aborted) abort();
    if (!authBrowser) {
      startRunTimer();
    } else {
      const captureLimit = boundedTimeout(
        authCaptureTimeoutMs,
        DEFAULT_AUTH_CAPTURE_TIMEOUT_MS,
      );
      authCaptureTimer = setTimeout(() => {
        const error = new Error(`FrameSeven timeout após ${captureLimit}ms aguardando captura autenticada`);
        error.code = 'FRAMESEVEN_STAGE_TIMEOUT';
        error.phase = 'auth_capture';
        requestStop('timeout', error, 'auth_capture');
      }, captureLimit);
    }
    const handleChildTerminal = (code, exitSignal) => {
      if (terminalObserved || settled) return;
      terminalObserved = true;
      void (async () => {
        if (stopIntent) {
          settle(stopIntent.status, stopIntent.error);
          return;
        }
        if (code === 0 && (!authBrowser || (authFlowStarted && scanReleased))) {
          settle('done', {
            engine: 'frameseven',
            status: 'done',
            toolProfile: toolProfile.id,
            tools: toolProfile.tools,
            code,
            signal: exitSignal,
            outputDir: out,
            stdout,
            stderr,
          });
          return;
        }
        if (code === 1 && (!authBrowser || (authFlowStarted && scanReleased))) {
          const reportAvailable = await openFrameSevenRegularFile(path.join(out, 'report.json'))
            .then(async (opened) => {
              const available = opened.size > 0;
              await opened.handle.close().catch(() => {});
              return available;
            })
            .catch(() => false);
          if (reportAvailable) {
            settle('partial', {
              engine: 'frameseven',
              status: 'partial',
              toolProfile: toolProfile.id,
              tools: toolProfile.tools,
              recoverable: true,
              code,
              signal: exitSignal,
              outputDir: out,
              stdout,
              stderr,
            });
            return;
          }
        }
        const reason = code === 0 && authBrowser
          ? 'FrameSeven encerrou sem concluir a captura autenticada'
          : `FrameSeven encerrou (${code ?? exitSignal})`;
        settle('failed', new Error(reason));
      })().catch((error) => settle('failed', error));
    };
    function onChildError(error) {
      if (stopIntent) {
        // Falha ao sinalizar ou outro evento `error` não confirma que o filho
        // encerrou. O guard de reap exige exit/close antes de assentar.
        return;
      }
      if (!Number.isInteger(Number(child?.pid)) || Number(child.pid) <= 0) {
        settle('failed', error);
        return;
      }
      requestStop('failed', error, 'runtime');
    }
    function onChildExit(code, exitSignal) {
      handleChildTerminal(code, exitSignal);
    }
    function onChildClose(code, closeSignal) {
      handleChildTerminal(code, closeSignal);
    }
    child.on('error', onChildError);
    child.on('exit', onChildExit);
    child.on('close', onChildClose);
  });
}
