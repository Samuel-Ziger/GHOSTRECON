import { spawn } from 'node:child_process';
import { getProcessExecutionContext } from '../lib/process-execution-context.mjs';

export function positiveIntEnv(name, fallback, { min = 1, max = Number.MAX_SAFE_INTEGER } = {}) {
  const n = Number(process.env[name]);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, Math.floor(n)));
}

export function createCappedOutputCollector({
  maxBytes = 1024 * 1024,
  mode = 'head',
  encoding = 'utf8',
  marker = '\n[ghostrecon: output truncated]\n',
} = {}) {
  const limit = Math.max(0, Number(maxBytes) || 0);
  const chunks = [];
  let capturedBytes = 0;
  let totalBytes = 0;
  let truncated = false;

  const appendHead = (buf) => {
    if (capturedBytes >= limit) {
      truncated = true;
      return;
    }
    const remaining = limit - capturedBytes;
    if (buf.length <= remaining) {
      chunks.push(buf);
      capturedBytes += buf.length;
      return;
    }
    chunks.push(buf.subarray(0, remaining));
    capturedBytes += remaining;
    truncated = true;
  };

  const appendTail = (buf) => {
    if (limit <= 0) {
      truncated = true;
      return;
    }
    if (buf.length >= limit) {
      chunks.length = 0;
      chunks.push(buf.subarray(buf.length - limit));
      capturedBytes = limit;
      truncated = true;
      return;
    }
    chunks.push(buf);
    capturedBytes += buf.length;
    while (capturedBytes > limit && chunks.length) {
      const over = capturedBytes - limit;
      const first = chunks[0];
      if (first.length <= over) {
        chunks.shift();
        capturedBytes -= first.length;
      } else {
        chunks[0] = first.subarray(over);
        capturedBytes -= over;
      }
      truncated = true;
    }
  };

  return {
    append(chunk) {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk ?? ''), encoding);
      totalBytes += buf.length;
      if (buf.length === 0) return;
      if (mode === 'tail') appendTail(buf);
      else appendHead(buf);
    },
    toString() {
      const text = Buffer.concat(chunks, capturedBytes).toString(encoding);
      return truncated ? `${text}${marker}` : text;
    },
    stats() {
      return { totalBytes, capturedBytes, truncated };
    },
  };
}

export async function mapPool(items, concurrency, fn, opts = {}) {
  const list = Array.isArray(items) ? items : [];
  const width = Math.max(1, Math.min(Number(concurrency) || 1, list.length || 1));
  const results = new Array(list.length);
  const { timeoutMs = 0, label = 'mapPool item' } = opts;
  let next = 0;

  async function runOne(item, idx) {
    if (!timeoutMs || timeoutMs <= 0) return fn(item, idx);
    let timer = null;
    try {
      return await Promise.race([
        fn(item, idx),
        new Promise((_, reject) => {
          timer = setTimeout(() => reject(new Error(`${label} timeout (${timeoutMs}ms)`)), timeoutMs);
        }),
      ]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  async function worker() {
    while (next < list.length) {
      const idx = next++;
      results[idx] = await runOne(list[idx], idx);
    }
  }

  await Promise.all(Array.from({ length: width }, () => worker()));
  return results;
}

export function runProcess(cmd, args = [], opts = {}) {
  const executionContext = getProcessExecutionContext();
  const {
    timeoutMs = 60_000,
    spawnOpts = {},
    stdoutMaxBytes = positiveIntEnv('GHOSTRECON_TOOL_STDOUT_MAX_BYTES', 16 * 1024 * 1024, {
      max: 128 * 1024 * 1024,
    }),
    stderrMaxBytes = positiveIntEnv('GHOSTRECON_TOOL_STDERR_MAX_BYTES', 2 * 1024 * 1024, {
      max: 32 * 1024 * 1024,
    }),
    rejectOnError = true,
    rejectOnTimeout = true,
    wrapCommand = null,
    label = cmd,
    signal: explicitSignal = null,
    rejectOnAbort = true,
    killGraceMs: explicitKillGraceMs = null,
    closeGraceMs: explicitCloseGraceMs = null,
    spawnImpl = spawn,
    onStdout = null,
    onStderr = null,
    input = null,
    stdinMaxBytes = 1024 * 1024,
  } = opts;
  const hasInput = input !== null && input !== undefined;
  if (hasInput && !Buffer.isBuffer(input) && typeof input !== 'string') {
    return Promise.reject(new TypeError(`${label} input deve ser string ou Buffer`));
  }
  const inputBuffer = hasInput
    ? (Buffer.isBuffer(input) ? input : Buffer.from(input, 'utf8'))
    : null;
  const inputLimit = Math.max(0, Number(stdinMaxBytes) || 0);
  if (inputBuffer && inputBuffer.length > inputLimit) {
    const error = new Error(`${label} input excede limite (${inputBuffer.length} > ${inputLimit} bytes)`);
    error.code = 'PROCESS_STDIN_TOO_LARGE';
    return Promise.reject(error);
  }
  const inheritedSignal = executionContext?.signal ?? null;
  const signal = explicitSignal ?? inheritedSignal;
  const managedProcessGroup =
    executionContext?.managedProcessGroup === true && process.platform !== 'win32';
  const killGraceMs = Math.max(
    10,
    Math.min(
      30_000,
      Number(explicitKillGraceMs ?? executionContext?.killGraceMs) || 250,
    ),
  );
  const closeGraceMs = Math.max(
    50,
    Math.min(
      30_000,
      Number(explicitCloseGraceMs ?? executionContext?.closeGraceMs) || 1_000,
    ),
  );

  let finalCmd = cmd;
  let finalArgs = Array.isArray(args) ? args : [];
  if (typeof wrapCommand === 'function') {
    const wrapped = wrapCommand(finalCmd, finalArgs);
    if (wrapped?.refuse) return Promise.reject(new Error(wrapped.reason || `${finalCmd} refused`));
    finalCmd = wrapped?.cmd || finalCmd;
    finalArgs = Array.isArray(wrapped?.args) ? wrapped.args : finalArgs;
  }

  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      const cause = signal.reason instanceof Error ? signal.reason : null;
      const error = new Error(
        `${label} cancelado${cause?.message ? `: ${cause.message}` : ''}`,
        cause ? { cause } : undefined,
      );
      error.name = 'AbortError';
      error.code = 'PROCESS_ABORTED';
      reject(error);
      return;
    }

    let child;
    try {
      child = spawnImpl(finalCmd, finalArgs, {
        ...spawnOpts,
        // O payload de stdin nunca entra em argv, no resultado ou nos logs.
        // Quando presente, force pipes também para stdout/stderr, necessários
        // para aplicar os limites de saída deste runner.
        stdio: hasInput ? ['pipe', 'pipe', 'pipe'] : (spawnOpts.stdio || ['ignore', 'pipe', 'pipe']),
        ...(managedProcessGroup ? { detached: true } : {}),
      });
    } catch (error) {
      reject(error);
      return;
    }
    const out = createCappedOutputCollector({
      maxBytes: stdoutMaxBytes,
      mode: 'head',
      marker: '\n[ghostrecon: stdout truncated]\n',
    });
    const err = createCappedOutputCollector({
      maxBytes: stderrMaxBytes,
      mode: 'tail',
      marker: '\n[ghostrecon: stderr truncated]\n',
    });
    let settled = false;
    let termination = null;
    let timeoutTimer = null;
    let killTimer = null;
    let closeTimer = null;
    let exitFallbackTimer = null;
    let terminalObserved = false;
    let exitObserved = null;

    const collectStdout = (data) => {
      out.append(data);
      if (typeof onStdout === 'function') {
        try {
          onStdout(data);
        } catch {
          // Telemetria de streaming não pode alterar o ciclo de vida do filho.
        }
      }
    };
    const collectStderr = (data) => {
      err.append(data);
      if (typeof onStderr === 'function') {
        try {
          onStderr(data);
        } catch {
          // Telemetria de streaming não pode alterar o ciclo de vida do filho.
        }
      }
    };

    const cleanup = () => {
      if (timeoutTimer) clearTimeout(timeoutTimer);
      if (killTimer) clearTimeout(killTimer);
      if (closeTimer) clearTimeout(closeTimer);
      if (exitFallbackTimer) clearTimeout(exitFallbackTimer);
      timeoutTimer = null;
      killTimer = null;
      closeTimer = null;
      exitFallbackTimer = null;
      signal?.removeEventListener('abort', onAbort);
      child.stdout?.removeListener('data', collectStdout);
      child.stderr?.removeListener('data', collectStderr);
      child.stdin?.removeListener('error', onStdinError);
      child.removeListener('error', onError);
      child.removeListener('exit', onExit);
      child.removeListener('close', onClose);
    };

    const finish = (result) => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve(result);
    };
    const fail = (error) => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(error);
    };
    const resultFor = (extra = {}) => ({
      code: extra.code ?? null,
      signal: extra.signal ?? null,
      ok: extra.ok ?? extra.code === 0,
      stdout: out.toString(),
      stderr: err.toString(),
      stdoutStats: out.stats(),
      stderrStats: err.stats(),
      timedOut: Boolean(extra.timedOut),
      ...(extra.cancelled ? { cancelled: true } : {}),
      ...(extra.terminationConfirmed !== undefined
        ? { terminationConfirmed: Boolean(extra.terminationConfirmed) }
        : {}),
      ...(extra.unterminated ? { unterminated: true } : {}),
      cmd: finalCmd,
      args: finalArgs,
    });

    const signalChild = (killSignal) => {
      if (!child.pid) return false;
      try {
        if (managedProcessGroup) process.kill(-child.pid, killSignal);
        else child.kill(killSignal);
        return true;
      } catch {
        try {
          child.kill(killSignal);
          return true;
        } catch {
          return false;
        }
      }
    };

    const terminationResult = ({
      code = null,
      signal: terminalSignal = null,
      confirmed = false,
      unterminated = false,
    } = {}) =>
      resultFor({
        code: termination?.kind === 'timeout' ? 124 : code,
        signal: terminalSignal,
        ok: false,
        timedOut: termination?.kind === 'timeout',
        cancelled: termination?.kind === 'abort',
        terminationConfirmed: confirmed,
        unterminated,
      });

    const settleTermination = ({ code = null, signal: terminalSignal = null } = {}) => {
      const result = terminationResult({
        code,
        signal: terminalSignal,
        confirmed: true,
      });
      if (termination?.kind === 'timeout') {
        const error = new Error(`${label} timeout (${timeoutMs}ms)`);
        error.code = 'PROCESS_TIMEOUT';
        error.result = result;
        if (rejectOnTimeout) fail(error);
        else finish(result);
        return;
      }

      if (termination?.kind === 'error') {
        const original = termination.reason instanceof Error
          ? termination.reason
          : new Error(`${label} falhou`);
        original.result = result;
        if (rejectOnError) fail(original);
        else {
          finish({
            ...result,
            stderr: `${result.stderr}\n${original.message}`.trim(),
          });
        }
        return;
      }

      const cause = termination?.reason instanceof Error ? termination.reason : null;
      const error = new Error(
        `${label} cancelado${cause?.message ? `: ${cause.message}` : ''}`,
        cause ? { cause } : undefined,
      );
      error.name = 'AbortError';
      error.code = 'PROCESS_ABORTED';
      error.result = result;
      if (rejectOnAbort) fail(error);
      else finish(result);
    };

    const failUnterminated = () => {
      if (settled || terminalObserved || exitObserved || !termination) return;
      const result = terminationResult({
        confirmed: false,
        unterminated: true,
      });
      const cause = termination.reason instanceof Error
        ? termination.reason
        : termination.kind === 'timeout'
          ? new Error(`${label} timeout (${timeoutMs}ms)`)
          : null;
      const error = new Error(
        `${label} não confirmou encerramento após SIGTERM/SIGKILL `
          + `(${closeGraceMs}ms aguardando exit/close)`,
        cause ? { cause } : undefined,
      );
      error.code = 'PROCESS_UNTERMINATED';
      error.fatal = true;
      error.recoverable = false;
      error.unterminated = true;
      error.terminationKind = termination.kind;
      error.result = result;
      fail(error);
    };

    const requestTermination = (kind, reason = null) => {
      if (settled || termination) return;
      termination = { kind, reason };
      if (timeoutTimer) {
        clearTimeout(timeoutTimer);
        timeoutTimer = null;
      }

      signalChild('SIGTERM');
      killTimer = setTimeout(() => {
        killTimer = null;
        signalChild('SIGKILL');
        closeTimer = setTimeout(() => {
          closeTimer = null;
          failUnterminated();
        }, closeGraceMs);
        closeTimer.ref?.();
      }, killGraceMs);
      killTimer.ref?.();
    };

    function onAbort() {
      requestTermination('abort', signal?.reason);
    }

    function onStdinError() {
      // EPIPE é esperado quando o filho encerra antes de consumir todo o
      // payload. O exit code/close continua sendo a fonte do resultado.
    }

    function onError(error) {
      if (termination) {
        // Um evento `error` (por exemplo, falha ao enviar um sinal) não prova
        // que o processo terminou. Aguarde obrigatoriamente exit/close; o
        // limite de reap produzirá PROCESS_UNTERMINATED se isso não ocorrer.
        return;
      }
      if (Number.isInteger(Number(child?.pid)) && Number(child.pid) > 0) {
        requestTermination('error', error);
        return;
      }
      const result = resultFor({ code: -1, ok: false });
      if (rejectOnError) fail(error);
      else finish({ ...result, stderr: `${result.stderr}\n${error?.message || error}`.trim() });
    }

    function onTerminal(code, closeSignal) {
      if (terminalObserved || settled) return;
      terminalObserved = true;
      if (termination) {
        settleTermination({ code, signal: closeSignal });
        return;
      }
      finish(resultFor({ code, signal: closeSignal, ok: code === 0, timedOut: false }));
    }

    function onExit(code, exitSignal) {
      if (terminalObserved || settled || exitObserved) return;
      exitObserved = { code, signal: exitSignal };
      // `exit` confirma que o processo acabou, mas `close` é a fronteira que
      // garante o escoamento de stdout/stderr. Aguarde close por um intervalo
      // limitado; se uma implementação quebrada nunca o emitir, exit ainda é
      // confirmação suficiente para assentar sem declarar unterminated.
      if (killTimer) {
        clearTimeout(killTimer);
        killTimer = null;
      }
      if (closeTimer) {
        clearTimeout(closeTimer);
        closeTimer = null;
      }
      exitFallbackTimer = setTimeout(
        () => {
          exitFallbackTimer = null;
          onTerminal(exitObserved.code, exitObserved.signal);
        },
        closeGraceMs,
      );
      exitFallbackTimer.ref?.();
    }

    function onClose(code, closeSignal) {
      onTerminal(code, closeSignal);
    }

    child.stdout?.on('data', collectStdout);
    child.stderr?.on('data', collectStderr);
    child.stdin?.on('error', onStdinError);
    child.on('error', onError);
    child.on('exit', onExit);
    child.on('close', onClose);
    signal?.addEventListener('abort', onAbort, { once: true });
    // Fecha a janela entre a checagem anterior ao spawn e o registro do
    // listener. AbortSignal não reenvia eventos que já ocorreram.
    if (signal?.aborted) onAbort();
    if (hasInput && !termination && !settled) {
      try {
        child.stdin?.end(inputBuffer);
      } catch {
        // O fechamento do processo produzirá o resultado terminal.
      }
    }

    timeoutTimer = !termination && !settled ? setTimeout(
      () => requestTermination('timeout'),
      Math.max(1, Number(timeoutMs) || 60_000),
    ) : null;
    timeoutTimer.unref?.();
  });
}

export async function readResponseSnippet(res, maxBytes) {
  const limit = Math.max(0, Number(maxBytes) || 0);
  if (!res?.body || limit <= 0) return '';

  const chunks = [];
  let total = 0;
  const reader = res.body.getReader?.();
  if (!reader) {
    const buf = await res.arrayBuffer();
    const slice = buf.byteLength > limit ? buf.slice(0, limit) : buf;
    return new TextDecoder('utf-8', { fatal: false }).decode(slice);
  }

  try {
    while (total < limit) {
      const { done, value } = await reader.read();
      if (done) break;
      const buf = Buffer.from(value);
      const remaining = limit - total;
      if (buf.length <= remaining) {
        chunks.push(buf);
        total += buf.length;
      } else {
        chunks.push(buf.subarray(0, remaining));
        total += remaining;
        break;
      }
    }
    if (total >= limit) await reader.cancel().catch(() => {});
  } finally {
    try {
      reader.releaseLock?.();
    } catch {
      // ignore
    }
  }

  return Buffer.concat(chunks, total).toString('utf8');
}
