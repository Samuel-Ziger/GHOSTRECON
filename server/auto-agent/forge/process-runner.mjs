import { runWithProcessExecutionContext } from '../../lib/process-execution-context.mjs';
import { runProcess } from '../../modules/module-runner.mjs';

export function throwIfForgeAborted(signal) {
  if (!signal?.aborted) return;
  if (signal.reason instanceof Error) throw signal.reason;
  const error = new Error(signal.reason ? String(signal.reason) : 'Forge cancelado');
  error.name = 'AbortError';
  error.code = 'PROCESS_ABORTED';
  throw error;
}

export function isForgeAbort(error, signal = null) {
  return Boolean(
    signal?.aborted
    || error?.name === 'AbortError'
    || error?.code === 'PROCESS_ABORTED'
    || error?.code === 'AUTO_FORGE_CANCELLED',
  );
}

/**
 * Runner único para CLIs do Forge. O caminho padrão usa grupo POSIX destacado
 * e encerramento TERM→KILL. Um execFile injetado é tratado como fronteira
 * confiável de teste/integração e recebe o AbortSignal explicitamente.
 */
export async function runForgeCommand(command, args, {
  cwd,
  env,
  timeoutMs,
  maxBuffer = 8 * 1024 * 1024,
  signal = null,
  execFileImpl = null,
  label = 'Forge subprocess',
} = {}) {
  throwIfForgeAborted(signal);
  if (typeof execFileImpl === 'function') {
    const operation = Promise.resolve().then(() => execFileImpl(command, args, {
      cwd,
      env,
      timeout: timeoutMs,
      maxBuffer,
      windowsHide: true,
      signal: signal || undefined,
    }));
    if (!signal) return operation;
    return new Promise((resolve, reject) => {
      const onAbort = () => {
        try {
          throwIfForgeAborted(signal);
        } catch (error) {
          reject(error);
        }
      };
      signal.addEventListener('abort', onAbort, { once: true });
      operation.then(resolve, reject).finally(() => {
        signal.removeEventListener('abort', onAbort);
      });
      if (signal.aborted) onAbort();
    });
  }

  return runWithProcessExecutionContext(
    {
      signal,
      managedProcessGroup: true,
      killGraceMs: 250,
      closeGraceMs: 1_000,
    },
    async () => {
      const result = await runProcess(command, args, {
        timeoutMs,
        signal,
        label,
        stdoutMaxBytes: maxBuffer,
        stderrMaxBytes: Math.min(maxBuffer, 2 * 1024 * 1024),
        spawnOpts: {
          cwd,
          env,
          windowsHide: true,
        },
      });
      return { stdout: result.stdout, stderr: result.stderr };
    },
  );
}
