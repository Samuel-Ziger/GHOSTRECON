import { spawn } from 'node:child_process';
import path from 'node:path';
import fs from 'node:fs/promises';
import os from 'node:os';
import { createFrameSevenAuthContext, loadFrameSevenAuthSession, consumeFrameSevenAuthSecret, cleanupFrameSevenAuthContext } from './frameseven-auth-context.mjs';

function safeTarget(value) {
  const url = new URL(String(value || ''));
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('FrameSeven exige alvo HTTP(S)');
  return url.toString();
}

export function redactFrameSevenOutput(value) {
  return String(value || '')
    .replace(/(^|[\r\n])\s*(authorization|authentication|cookie|set-cookie|x-(?:auth|access)-token|x-api-key|x-csrf-token)\s*:\s*[^\r\n]*/gi, '$1$2: [REDACTED]')
    .replace(/((?:access|refresh|auth|session|csrf)[_-]?token|password|passwd)\s*[=:]\s*([^\s,;]+)/gi, '$1=[REDACTED]')
    .replace(/\bBearer\s+[A-Za-z0-9._~+\/-]+=*/gi, 'Bearer [REDACTED]');
}

export function resolveFrameSevenBinary(root, env = process.env) {
  return String(env.GHOSTRECON_FRAMESEVEN_BIN || path.join(root, 'FrameSeven', 'bin', 'frameseven', 'cli', 'v1'));
}

/** Executes FrameSeven with argument arrays only; credentials are never accepted here. */
export async function runFrameSeven({ root, target, outputDir, authBrowser = false, tools = 'all', timeout = '30s', toolTimeout = '5m', concurrency = 10, rate = 100, signal, emit = () => {}, waitForAuth = null, beforeScan = null, env = process.env, spawnImpl = spawn } = {}) {
  const url = safeTarget(target);
  const out = path.resolve(root, outputDir || path.join('reports', `frameseven-${Date.now()}`));
  await fs.mkdir(out, { recursive: true });
  const args = ['-url', url, '-tools', String(tools), '-timeout', String(timeout), '-tool-timeout', String(toolTimeout), '-concurrency', String(concurrency), '-rate', String(rate), '-verbose', '-out', out];
  let authContext = null;
  let authFile = null;
  if (authBrowser) {
    authContext = createFrameSevenAuthContext({ target: url });
    const authDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-frameseven-'));
    await fs.chmod(authDir, 0o700);
    authFile = path.join(authDir, 'session-v1.json');
    args.push('-auth-browser', '-auth-session-out', authFile, '-auth-wait-after-capture');
  }
  const binary = resolveFrameSevenBinary(root, env);
  emit({ type: 'engine_started', engine: 'frameseven', target: url, authBrowser, outputDir: out });
  return new Promise((resolve, reject) => {
    const child = spawnImpl(binary, args, { cwd: root, env, stdio: [authBrowser ? 'pipe' : 'ignore', 'pipe', 'pipe'], windowsHide: true });
    let stdout = '';
    let stderr = '';
    let settled = false;
    let pipelineStarted = false;
    const cleanup = async () => {
      if (authContext) await cleanupFrameSevenAuthContext(authContext.contextId, authFile);
      if (authFile) await fs.rm(path.dirname(authFile), { recursive: true, force: true }).catch(() => {});
      signal?.removeEventListener('abort', abort);
    };
    const finish = (fn, value) => { if (settled) return; settled = true; clearTimeout(timer); void cleanup().finally(() => fn(value)); };
    const timer = setTimeout(() => { child.kill?.('SIGTERM'); finish(reject, new Error('FrameSeven timeout')); }, 30 * 60_000);
    child.stdout?.on('data', (chunk) => {
      const rawLine = String(chunk); const line = redactFrameSevenOutput(rawLine); stdout = `${stdout}${line}`.slice(-64_000);
      emit({ type: 'engine_progress', engine: 'frameseven', stream: 'stdout', line: line.replace(/FRAMESEVEN_AUTH_READY_V1/g, '').trimEnd() });
      if (authBrowser && rawLine.includes('FRAMESEVEN_AUTH_READY_V1') && !pipelineStarted) {
        pipelineStarted = true;
        void loadFrameSevenAuthSession(authContext.contextId, authFile).then(async () => {
          const secret = consumeFrameSevenAuthSecret(authContext.contextId);
          emit({ type: 'auth_ready', engine: 'frameseven', contextId: authContext.contextId, target: url });
          if (typeof beforeScan === 'function') await beforeScan(secret, { contextId: authContext.contextId });
          child.stdin?.write('\n');
        }).catch((error) => { child.kill?.('SIGTERM'); finish(reject, error); });
      }
    });
    child.stderr?.on('data', (chunk) => { const line = redactFrameSevenOutput(chunk); stderr = `${stderr}${line}`.slice(-32_000); emit({ type: 'engine_progress', engine: 'frameseven', stream: 'stderr', line: line.trimEnd() }); });
    if (authBrowser) {
      emit({ type: 'auth_required', engine: 'frameseven', target: url, message: 'Conclua o login na janela do navegador e confirme no GHOSTRECON.' });
      Promise.resolve(typeof waitForAuth === 'function' ? waitForAuth() : false).then((approved) => {
        if (!approved) {
          child.kill?.('SIGTERM');
          finish(reject, new Error('FrameSeven authentication refused by operator'));
          return;
        }
        try { child.stdin?.write('\n'); emit({ type: 'auth_confirmed', engine: 'frameseven', contextId: authContext?.contextId }); } catch { /* processo encerrou */ }
      }).catch(() => {});
    }
    const abort = () => { child.kill?.('SIGTERM'); finish(reject, signal?.reason || new Error('FrameSeven cancelado')); };
    signal?.addEventListener('abort', abort, { once: true });
    child.once('error', (error) => finish(reject, error));
    child.once('exit', (code, sig) => finish(code === 0 ? resolve : reject, code === 0 ? { engine: 'frameseven', code, signal: sig, outputDir: out, stdout, stderr } : new Error(`FrameSeven encerrou (${code ?? sig})`)));
  });
}
