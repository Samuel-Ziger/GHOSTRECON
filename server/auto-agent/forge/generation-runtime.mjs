import { spawn } from 'node:child_process';

import { redactAutoText } from '../redaction.mjs';

export function redactForgeContext(value) {
  return redactAutoText(value);
}

export function codexForgeEnv(env = process.env) {
  const allowed = [
    'PATH', 'HOME', 'USER', 'LOGNAME', 'SHELL', 'LANG', 'LC_ALL', 'TERM',
    'TMPDIR', 'TEMP', 'TMP', 'CODEX_HOME', 'XDG_CONFIG_HOME', 'XDG_CACHE_HOME',
    'HTTPS_PROXY', 'HTTP_PROXY', 'ALL_PROXY', 'NO_PROXY',
  ];
  const out = {};
  for (const key of allowed) if (env[key] != null) out[key] = env[key];
  for (const [key, value] of Object.entries(env)) {
    if (/^CODEX_[A-Z0-9_]+$/.test(key)) out[key] = value;
  }
  if (/^(1|true|yes)$/i.test(String(env.GHOSTRECON_CODEX_INHERIT_OPENAI_KEY || ''))) {
    if (env.OPENAI_API_KEY) out.OPENAI_API_KEY = env.OPENAI_API_KEY;
  }
  return out;
}

export function claudeForgeEnv(env = process.env) {
  const allowed = [
    'PATH', 'HOME', 'USER', 'LOGNAME', 'SHELL', 'LANG', 'LC_ALL', 'TERM',
    'TMPDIR', 'TEMP', 'TMP', 'XDG_CONFIG_HOME', 'XDG_CACHE_HOME',
  ];
  const out = {};
  for (const key of allowed) if (env[key] != null) out[key] = env[key];
  if (/^(1|true|yes)$/i.test(String(env.GHOSTRECON_CLAUDE_INHERIT_API_KEY || ''))
      && env.ANTHROPIC_API_KEY) {
    out.ANTHROPIC_API_KEY = env.ANTHROPIC_API_KEY;
  }
  return out;
}

/** Subprocess helper retained for Forge CLI integration tests and adapters. */
export function execFileClosedStdin(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const detached = process.platform !== 'win32';
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: options.env,
      windowsHide: options.windowsHide,
      stdio: [options.input == null ? 'ignore' : 'pipe', 'pipe', 'pipe'],
      detached,
    });
    const chunks = { stdout: [], stderr: [] };
    const maxBuffer = Number(options.maxBuffer || 1024 * 1024);
    let size = 0;
    let settled = false;
    let timer = null;
    let killTimer = null;
    let forceSettleTimer = null;
    let terminationError = null;
    const killGraceMs = Math.max(100, Math.min(10_000, Number(options.killGraceMs || 1_500)));
    const signalProcess = (signalName) => {
      const pid = Number(child.pid);
      if (detached && Number.isInteger(pid) && pid > 1 && pid !== process.pid) {
        try {
          process.kill(-pid, signalName);
          return;
        } catch {
          // O processo pode já ter terminado; tente o handle individual.
        }
      }
      try { child.kill(signalName); } catch { /* já encerrado */ }
    };
    const finish = (error = null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      clearTimeout(killTimer);
      clearTimeout(forceSettleTimer);
      options.signal?.removeEventListener('abort', onAbort);
      const stdout = Buffer.concat(chunks.stdout).toString(options.encoding || 'utf8');
      const stderr = Buffer.concat(chunks.stderr).toString(options.encoding || 'utf8');
      if (error) {
        error.stdout = stdout;
        error.stderr = stderr;
        reject(error);
      } else resolve({ stdout, stderr });
    };
    const terminate = (error) => {
      if (settled || terminationError) return;
      terminationError = error;
      signalProcess(options.killSignal || 'SIGTERM');
      killTimer = setTimeout(() => signalProcess('SIGKILL'), killGraceMs);
      forceSettleTimer = setTimeout(() => {
        finish(Object.assign(
          new Error(terminationError?.message || 'processo filho não encerrou após SIGKILL'),
          { code: 'PROCESS_UNTERMINATED', killed: true, cause: terminationError || undefined },
        ));
      }, killGraceMs + 2_000);
      killTimer.unref?.();
      forceSettleTimer.unref?.();
    };
    const collect = (stream) => (chunk) => {
      size += chunk.length;
      chunks[stream].push(chunk);
      if (size > maxBuffer) {
        terminate(Object.assign(new Error('stdout/stderr excedeu maxBuffer'), {
          code: 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER',
        }));
      }
    };
    child.stdout.on('data', collect('stdout'));
    child.stderr.on('data', collect('stderr'));
    child.once('error', finish);
    child.once('close', (code, childSignal) => {
      if (terminationError) finish(terminationError);
      else if (code === 0) finish();
      else finish(Object.assign(
        new Error(`Command failed: ${command} (exit ${code ?? 'unknown'})`),
        { code, signal: childSignal },
      ));
    });
    const onAbort = () => {
      terminate(options.signal?.reason || Object.assign(new Error('The operation was aborted'), {
        name: 'AbortError',
      }));
    };
    options.signal?.addEventListener('abort', onAbort, { once: true });
    if (options.signal?.aborted) onAbort();
    if (options.input != null && !settled) child.stdin.end(String(options.input));
    timer = !settled && options.timeout > 0 ? setTimeout(() => {
      terminate(Object.assign(new Error(`Command timed out after ${options.timeout}ms`), {
        code: 'ETIMEDOUT',
        killed: true,
      }));
    }, options.timeout) : null;
    timer?.unref?.();
  });
}
