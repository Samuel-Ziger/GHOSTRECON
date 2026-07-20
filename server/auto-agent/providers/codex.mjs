import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { parseAgentDecisionText, validateAgentDecision } from '../decision-contract.mjs';
import { availableCatalogIds, availableEvidenceRefs, buildAgentPrompt } from './shared.mjs';

export function execFileClosedStdin(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: options.env,
      windowsHide: options.windowsHide,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const chunks = { stdout: [], stderr: [] };
    const maxBuffer = Number(options.maxBuffer || 1024 * 1024);
    let size = 0;
    let settled = false;
    let timer = null;
    const finish = (error = null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      options.signal?.removeEventListener('abort', onAbort);
      const stdout = Buffer.concat(chunks.stdout).toString(options.encoding || 'utf8');
      const stderr = Buffer.concat(chunks.stderr).toString(options.encoding || 'utf8');
      if (error) {
        error.stdout = stdout;
        error.stderr = stderr;
        reject(error);
      } else resolve({ stdout, stderr });
    };
    const collect = (stream) => (chunk) => {
      size += chunk.length;
      chunks[stream].push(chunk);
      if (size > maxBuffer) {
        child.kill(options.killSignal || 'SIGTERM');
        finish(Object.assign(new Error('stdout/stderr excedeu maxBuffer'), { code: 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER' }));
      }
    };
    child.stdout.on('data', collect('stdout'));
    child.stderr.on('data', collect('stderr'));
    child.once('error', finish);
    child.once('close', (code, childSignal) => {
      if (code === 0) finish();
      else finish(Object.assign(new Error(`Command failed: ${command} ${args.join(' ')}`), { code, signal: childSignal }));
    });
    const onAbort = () => {
      child.kill(options.killSignal || 'SIGTERM');
      finish(options.signal?.reason || Object.assign(new Error('The operation was aborted'), { name: 'AbortError' }));
    };
    options.signal?.addEventListener('abort', onAbort, { once: true });
    if (options.signal?.aborted) onAbort();
    timer = options.timeout > 0 ? setTimeout(() => {
      child.kill(options.killSignal || 'SIGTERM');
      finish(Object.assign(new Error(`Command timed out after ${options.timeout}ms`), { code: 'ETIMEDOUT', killed: true }));
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
} = {}) {
  const timeoutMs = Math.max(30_000, Math.min(900_000, Number(env.GHOSTRECON_CODEX_TIMEOUT_MS || 240_000)));
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-codex-'));
  const outputFile = path.join(tmpDir, 'decision.json');
  const args = [
    'exec',
    '--json',
    '--sandbox', 'read-only',
    '--output-schema', DECISION_SCHEMA,
    '--output-last-message', outputFile,
    '--cd', root,
    '--ephemeral',
    buildAgentPrompt({ target, mode, catalog, ragContext, role, iteration, peerDecisions, observationBundle, maxContextChars }),
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
    });
    const output = await fs.readFile(outputFile, 'utf8').catch(() => '');
    const parsed = parseAgentDecisionText(output || result?.stdout || '');
    const catalogModuleIds = availableCatalogIds(catalog);
    const validated = validateAgentDecision(parsed, {
      catalogModuleIds,
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
      transport: { command: 'codex exec', sandbox: 'read-only', ephemeral: true },
    };
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true }).catch(() => {});
  }
}
