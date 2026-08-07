import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { normalizeAndValidateAgentDecision, parseAgentDecisionText } from '../decision-contract.mjs';
import { availableCatalogIds, availableEvidenceRefs, buildAgentPrompt } from './shared.mjs';

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
          // Pode já ter encerrado; tentamos o handle individual abaixo.
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
      // Só libera a Promise sem evento `close` como PROCESS_UNTERMINATED —
      // nunca finge sucesso/timeout limpo com PID potencialmente vivo.
      forceSettleTimer = setTimeout(() => {
        const unterminated = Object.assign(
          new Error(terminationError?.message || 'processo filho não encerrou após SIGKILL'),
          {
            code: 'PROCESS_UNTERMINATED',
            killed: true,
            cause: terminationError || undefined,
          },
        );
        finish(unterminated);
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
      else finish(Object.assign(new Error(`Command failed: ${command} (exit ${code ?? 'unknown'})`), { code, signal: childSignal }));
    });
    const onAbort = () => {
      terminate(options.signal?.reason || Object.assign(new Error('The operation was aborted'), {
        name: 'AbortError',
      }));
    };
    options.signal?.addEventListener('abort', onAbort, { once: true });
    if (options.signal?.aborted) onAbort();
    if (options.input != null && !settled) {
      child.stdin.end(String(options.input));
    }
    timer = !settled && options.timeout > 0 ? setTimeout(() => {
      terminate(Object.assign(new Error(`Command timed out after ${options.timeout}ms`), {
        code: 'ETIMEDOUT',
        killed: true,
      }));
    }, options.timeout) : null;
    timer?.unref?.();
  });
}

const execFileDefault = execFileClosedStdin;
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DECISION_SCHEMA = path.join(__dirname, '..', 'schemas', 'decision.schema.json');

export function codexChildEnv(env) {
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

export async function decideWithCodex({
  target,
  mode,
  catalog,
  ragContext,
  root,
  role = 'planner',
  iteration = 1,
  peerDecisions = [],
  observationBundle = null,
  env = process.env,
  execFileImpl = execFileDefault,
  signal,
  maxContextChars = 120_000,
  allowIntrusive = false,
  autonomyLevel = 'observation',
} = {}) {
  const timeoutMs = Math.max(30_000, Math.min(900_000, Number(env.GHOSTRECON_CODEX_TIMEOUT_MS || 240_000)));
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-codex-'));
  const outputFile = path.join(tmpDir, 'decision.json');
  const prompt = buildAgentPrompt({
    target, mode, catalog, ragContext, role, iteration, peerDecisions,
    observationBundle, maxContextChars, allowIntrusive, autonomyLevel,
  });
  const args = [
    'exec',
    '--json',
    '--sandbox', 'read-only',
    '--output-schema', DECISION_SCHEMA,
    '--output-last-message', outputFile,
    '--cd', root,
    '--ephemeral',
    '-',
  ];
  const startedAt = Date.now();
  try {
    const result = await execFileImpl(String(env.GHOSTRECON_CODEX_COMMAND || 'codex'), args, {
      cwd: root,
      env: codexChildEnv(env),
      timeout: timeoutMs,
      maxBuffer: 8 * 1024 * 1024,
      windowsHide: true,
      signal,
      input: prompt,
    });
    const output = await fs.readFile(outputFile, 'utf8').catch(() => '');
    const rawParsed = parseAgentDecisionText(output || result?.stdout || '');
    const validated = normalizeAndValidateAgentDecision(rawParsed, {
      repairEnvelope: true,
      repairOptions: { objective: `authorized_recon:${target || 'target'}` },
      catalogModuleIds: availableCatalogIds(catalog, { allowIntrusive, autonomyLevel }),
      availableEvidenceRefs: availableEvidenceRefs({ ragContext, observationBundle }),
    });
    if (!validated.ok) throw new Error(`decisão Codex rejeitada: ${validated.errors.join('; ')}`);
    return {
      ok: true,
      provider: 'codex',
      role,
      iteration,
      mode: 'exec',
      latencyMs: Date.now() - startedAt,
      decision: validated.decision,
      transport: {
        command: 'codex exec', sandbox: 'read-only', ephemeral: true, promptTransport: 'stdin',
        repaired: rawParsed?.action == null || rawParsed?.objective == null || rawParsed?.confidence == null,
      },
    };
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true }).catch(() => {});
  }
}
