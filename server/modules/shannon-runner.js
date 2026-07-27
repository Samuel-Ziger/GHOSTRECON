import fs from 'fs/promises';
import path from 'path';
import { resolveShannonHome } from './shannon-capabilities.js';
import { hostLiteralForUrl } from './recon-target.js';
import { getProcessExecutionContext } from '../lib/process-execution-context.mjs';
import { runProcess } from './module-runner.mjs';

/** Igual ao `apps/cli/src/commands/logs.ts` — fim do workflow no ficheiro append-only. */
const WORKFLOW_DONE_RE = /^Workflow (COMPLETED|FAILED)$/m;

function processAbortError(signal, label = 'Shannon') {
  const cause = signal?.reason instanceof Error ? signal.reason : null;
  const error = new Error(
    `${label} cancelado${cause?.message ? `: ${cause.message}` : ''}`,
    cause ? { cause } : undefined,
  );
  error.name = 'AbortError';
  error.code = 'PROCESS_ABORTED';
  return error;
}

function throwIfAborted(signal, label = 'Shannon') {
  if (signal?.aborted) throw processAbortError(signal, label);
}

function isProcessAbort(error) {
  return error?.name === 'AbortError' || error?.code === 'PROCESS_ABORTED';
}

function sleep(ms, signal = null) {
  throwIfAborted(signal);
  return new Promise((resolve, reject) => {
    let timer = null;
    const onAbort = () => {
      if (timer) clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
      reject(processAbortError(signal));
    };
    timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    timer.unref?.();
    signal?.addEventListener('abort', onAbort, { once: true });
    if (signal?.aborted) onAbort();
  });
}

export function shannonStartTimeoutMs() {
  const n = Number(process.env.GHOSTRECON_SHANNON_START_TIMEOUT_MS);
  return Number.isFinite(n) && n > 0 ? Math.min(n, 900000) : 240000;
}

export function shannonWorkflowWaitTimeoutMs() {
  const n = Number(process.env.GHOSTRECON_SHANNON_WORKFLOW_TIMEOUT_MS);
  if (Number.isFinite(n) && n > 0) return Math.min(n, 48 * 3600000);
  return 90 * 60 * 1000;
}

export function shannonMaxClonesPerRun() {
  const n = Number(process.env.GHOSTRECON_SHANNON_MAX_CLONES_PER_RUN);
  return Number.isFinite(n) && n > 0 ? Math.min(n, 5) : 1;
}

/** URL da Temporal Web UI que o CLI Shannon imprime após `start` (apps/cli/src/commands/start.ts). */
const TEMPORAL_UI_URL_RE = /https?:\/\/(?:localhost|127\.0\.0\.1):8233(?:\/[^\s]*)?/g;

function parseBoolEnv(v, defaultTrue = true) {
  const s = String(v ?? '').trim().toLowerCase();
  if (s === '') return defaultTrue;
  if (s === '1' || s === 'true' || s === 'yes' || s === 'on') return true;
  if (s === '0' || s === 'false' || s === 'no' || s === 'off') return false;
  return defaultTrue;
}

export function shannonEmitOpenTemporalUrl() {
  return parseBoolEnv(process.env.GHOSTRECON_SHANNON_OPEN_TEMPORAL_UI, true);
}

/** Espelha o output do CLI na stream NDJSON (log) da UI. `GHOSTRECON_SHANNON_MIRROR_CLI=0` desliga. */
export function shannonMirrorCliToGhostLog() {
  return parseBoolEnv(process.env.GHOSTRECON_SHANNON_MIRROR_CLI, true);
}

function stripAnsi(text) {
  return String(text).replace(/\u001b\[[\d;?]*[ -/]*[@-~]/g, '');
}

/**
 * Acumula chunks e emite linhas completas via `onLine` (NDJSON `log` no Ghost).
 * @param {(line: string) => void} onLine
 */
function createCliLineForwarder(onLine) {
  let buf = '';
  return {
    push(chunk) {
      buf += stripAnsi(String(chunk)).replace(/\r\n/g, '\n').replace(/\r/g, '\n');
      for (;;) {
        const i = buf.indexOf('\n');
        if (i < 0) break;
        const line = buf.slice(0, i);
        buf = buf.slice(i + 1);
        const out = line.length > 2400 ? `${line.slice(0, 2400)}…` : line;
        onLine(out.length ? out : ' ');
      }
    },
    flush() {
      const t = buf.trimEnd();
      buf = '';
      if (t) onLine(t.length > 2400 ? `${t.slice(0, 2400)}…` : t);
    },
  };
}

/**
 * Extrai a primeira URL Temporal do buffer; dedupe por `seen`.
 * @param {string} buffer
 * @param {Set<string>} seen
 * @returns {string | null}
 */
export function extractTemporalWebUiUrl(buffer, seen) {
  if (!buffer) return null;
  TEMPORAL_UI_URL_RE.lastIndex = 0;
  let m;
  while ((m = TEMPORAL_UI_URL_RE.exec(buffer)) !== null) {
    let url = m[0].replace(/[.,;)\]}>'"]+$/u, '');
    if (url.length < 12) continue;
    if (seen.has(url)) continue;
    seen.add(url);
    return url;
  }
  return null;
}

export function shannonReportMaxChars() {
  const n = Number(process.env.GHOSTRECON_SHANNON_REPORT_MAX_CHARS);
  return Number.isFinite(n) && n > 0 ? Math.min(n, 2_000_000) : 120_000;
}

/**
 * @param {string} shannonHome
 * @param {string} workspaceId
 */
export function workflowLogPath(shannonHome, workspaceId) {
  return path.join(shannonHome, 'workspaces', workspaceId, 'workflow.log');
}

/**
 * @param {string} clonePath
 */
export function shannonReportPath(clonePath) {
  return path.join(clonePath, '.shannon', 'deliverables', 'comprehensive_security_assessment_report.md');
}

/**
 * Espera até `workflow.log` conter COMPLETED ou FAILED, ou timeout.
 * @param {(msg: string, level?: string) => void} [onLog]
 */
export async function waitForShannonWorkflowEnd(
  shannonHome,
  workspaceId,
  onLog,
  {
    signal = null,
    pollIntervalMs = 2500,
    timeoutMs = shannonWorkflowWaitTimeoutMs(),
  } = {},
) {
  throwIfAborted(signal);
  const logFile = workflowLogPath(shannonHome, workspaceId);
  const deadline = Date.now() + Math.max(1, Number(timeoutMs) || shannonWorkflowWaitTimeoutMs());
  let lastSize = 0;
  let lastKeepalive = Date.now();

  while (Date.now() < deadline) {
    throwIfAborted(signal);
    try {
      const txt = await fs.readFile(logFile, 'utf8');
      if (WORKFLOW_DONE_RE.test(txt)) {
        const m = txt.match(WORKFLOW_DONE_RE);
        const outcome = m?.[1] === 'COMPLETED' ? 'completed' : 'failed';
        return { outcome, logPath: logFile, tail: txt.slice(-8000) };
      }
      if (txt.length > lastSize && onLog) {
        const delta = txt.slice(lastSize);
        lastSize = txt.length;
        const lines = delta.split('\n').filter((l) => l.trim());
        for (const line of lines.slice(-12)) {
          if (line.length > 400) onLog(`${line.slice(0, 400)}…`, 'info');
          else onLog(line, 'info');
        }
        lastKeepalive = Date.now();
      }
    } catch {
      /* ficheiro ainda não existe */
    }
    const pollDelay = Math.max(1, Number(pollIntervalMs) || 2500);
    await sleep(Math.min(pollDelay, Math.max(1, deadline - Date.now())), signal);
    if (onLog && Date.now() - lastKeepalive > 45000) {
      lastKeepalive = Date.now();
      onLog(
        'Shannon: a aguardar workflow.log (workflow ainda a correr — mantém esta página aberta; pode demorar vários minutos).',
        'info',
      );
    }
  }
  return { outcome: 'timeout', logPath: logFile, tail: '' };
}

/**
 * Lê o relatório consolidado gerado no repo clonado (overlay Shannon → `.shannon/deliverables/`).
 */
export async function readShannonComprehensiveReport(clonePath) {
  const p = shannonReportPath(clonePath);
  try {
    const raw = await fs.readFile(p, 'utf8');
    const max = shannonReportMaxChars();
    const truncated = raw.length > max ? `${raw.slice(0, max)}\n\n…[truncado a ${max} caracteres]` : raw;
    return { ok: true, path: p, content: truncated, bytes: Buffer.byteLength(raw, 'utf8') };
  } catch {
    return { ok: false, path: p };
  }
}

let shannonChain = Promise.resolve();

function enqueueShannonTask(task, signal) {
  throwIfAborted(signal);
  let started = false;
  let settled = false;
  let onQueuedAbort = null;

  const execution = shannonChain.then(async () => {
    started = true;
    if (onQueuedAbort) signal?.removeEventListener('abort', onQueuedAbort);
    throwIfAborted(signal);
    return task();
  });
  shannonChain = execution.catch(() => {});

  return new Promise((resolve, reject) => {
    const finish = (fn, value) => {
      if (settled) return;
      settled = true;
      if (onQueuedAbort) signal?.removeEventListener('abort', onQueuedAbort);
      fn(value);
    };
    onQueuedAbort = () => {
      if (started) return;
      finish(reject, processAbortError(signal));
    };
    signal?.addEventListener('abort', onQueuedAbort, { once: true });
    if (signal?.aborted) onQueuedAbort();
    execution.then(
      (value) => finish(resolve, value),
      (error) => finish(reject, error),
    );
  });
}

/**
 * Corre `./shannon start` (cwd = Shannon home), depois faz poll de `workflow.log`.
 * Serializado globalmente (um scan de cada vez) para não sobrecarregar Docker/Temporal.
 *
 * @param {{
 *   ghostRoot: string,
 *   domain: string,
 *   clonePath: string,
 *   repoFullName?: string,
 *   log?: (msg: string, level?: string) => void,
 *   emit?: (obj: Record<string, unknown>) => void,
 *   signal?: AbortSignal,
 *   processRunner?: typeof runProcess,
 *   waitForWorkflowImpl?: typeof waitForShannonWorkflowEnd,
 *   readReportImpl?: typeof readShannonComprehensiveReport,
 * }} opts
 */
export async function runShannonOnClone(opts) {
  const inheritedSignal = getProcessExecutionContext()?.signal ?? null;
  const signal = opts?.signal ?? inheritedSignal;
  const task = async () => {
    throwIfAborted(signal);
    const {
      ghostRoot,
      domain,
      clonePath,
      repoFullName = 'repo',
      log,
      emit,
      processRunner = runProcess,
      waitForWorkflowImpl = waitForShannonWorkflowEnd,
      readReportImpl = readShannonComprehensiveReport,
    } = opts;
    const shannonHome = resolveShannonHome(ghostRoot);
    const slug = String(repoFullName)
      .replace(/[/\\]/g, '__')
      .replace(/[^a-zA-Z0-9._-]+/g, '_')
      .slice(0, 72);
    const workspaceId = `ghostrecon-${String(domain)
      .replace(/[^a-zA-Z0-9.-]+/g, '-')
      .slice(0, 80)}-${Date.now()}-${slug}`;

    const apex = String(domain).trim();
    const targetUrl = `https://${hostLiteralForUrl(apex)}/`;
    const shannonScript = path.join(shannonHome, 'shannon');
    const args = ['start', '-u', targetUrl, '-r', path.resolve(clonePath), '-w', workspaceId];
    if (String(process.env.GHOSTRECON_SHANNON_PIPELINE_TESTING || '').trim() === '1') {
      args.push('--pipeline-testing');
    }

    log?.(`Shannon: start → workspace=${workspaceId}`, 'info');
    log?.(`Shannon: URL=${targetUrl} repo=${clonePath}`, 'info');

    const mirrorCli = shannonMirrorCliToGhostLog();
    const cliSink =
      mirrorCli && emit
        ? (line) => emit({ type: 'shannon_cli', line })
        : mirrorCli && typeof log === 'function'
          ? (line) => log(line, 'info')
          : null;
    const fwdOut = cliSink ? createCliLineForwarder(cliSink) : null;
    const fwdErr = cliSink ? createCliLineForwarder(cliSink) : null;

    if (mirrorCli && emit) {
      emit({ type: 'log', msg: '── Shannon CLI (espelho stdout/stderr) ──', level: 'section' });
    }

    let temporalBuffer = '';
    const temporalUrlsSeen = new Set();
    const tryEmitTemporalFromChildOutput = (chunk) => {
      if (!shannonEmitOpenTemporalUrl() || !emit) return;
      temporalBuffer = `${temporalBuffer}${String(chunk || '')}`.slice(-64 * 1024);
      const url = extractTemporalWebUiUrl(temporalBuffer, temporalUrlsSeen);
      if (!url) return;
      emit({
        type: 'open_url',
        url,
        label: 'Shannon — Temporal Web UI',
        source: 'shannon',
      });
      log?.(`Shannon: monitor Temporal (abre no browser) → ${url}`, 'success');
    };

    const onStdout = (d) => {
      const s = String(d);
      fwdOut?.push(s);
      tryEmitTemporalFromChildOutput(s);
    };
    const onStderr = (d) => {
      const s = String(d);
      fwdErr?.push(s);
      tryEmitTemporalFromChildOutput(s);
    };

    let startResult;
    try {
      startResult = await processRunner(process.execPath, [shannonScript, ...args], {
        cwd: shannonHome,
        timeoutMs: shannonStartTimeoutMs(),
        signal,
        spawnOpts: {
          cwd: shannonHome,
          env: { ...process.env, SHANNON_LOCAL: '1' },
          stdio: ['ignore', 'pipe', 'pipe'],
        },
        stdoutMaxBytes: 2 * 1024 * 1024,
        stderrMaxBytes: 2 * 1024 * 1024,
        onStdout,
        onStderr,
        label: 'Shannon start',
      });
    } catch (error) {
      fwdOut?.flush();
      fwdErr?.flush();
      if (isProcessAbort(error)) throw error;
      const timedOut = error?.code === 'PROCESS_TIMEOUT';
      const detail = `${error?.result?.stderr || ''}\n${error?.result?.stdout || ''}`
        .trim()
        .slice(-4000);
      return {
        ok: false,
        workspaceId,
        phase: 'start',
        exitCode: timedOut ? -2 : -1,
        detail: detail || error?.message || (timedOut ? 'timeout' : 'falha ao iniciar'),
      };
    }

    fwdOut?.flush();
    fwdErr?.flush();

    if (startResult.code !== 0) {
      const tail = `${startResult.stderr}\n${startResult.stdout}`.trim().slice(-4000);
      return {
        ok: false,
        workspaceId,
        phase: 'start',
        exitCode: startResult.code,
        detail: tail || `exit ${startResult.code}`,
      };
    }

    const wf = await waitForWorkflowImpl(shannonHome, workspaceId, log, { signal });
    if (wf.outcome === 'timeout') {
      log?.('Shannon: timeout a aguardar workflow.log (aumenta GHOSTRECON_SHANNON_WORKFLOW_TIMEOUT_MS)', 'warn');
      return { ok: false, workspaceId, phase: 'workflow', outcome: 'timeout', logPath: wf.logPath };
    }
    if (wf.outcome === 'failed') {
      log?.('Shannon: workflow FAILED — vê workflow.log no workspace', 'warn');
      return {
        ok: false,
        workspaceId,
        phase: 'workflow',
        outcome: 'failed',
        logTail: wf.tail,
        logPath: wf.logPath,
      };
    }

    let report = await readReportImpl(clonePath);
    for (let attempt = 0; !report.ok && attempt < 10; attempt++) {
      await sleep(2000, signal);
      report = await readReportImpl(clonePath);
    }
    if (!report.ok) {
      log?.(`Shannon: workflow COMPLETED mas relatório ainda não disponível em ${report.path}`, 'warn');
    } else {
      log?.(`Shannon: relatório ${report.path} (${report.bytes} bytes)`, 'success');
    }

    return {
      ok: true,
      workspaceId,
      outcome: 'completed',
      report,
      workflowLogPath: wf.logPath,
    };
  };

  return enqueueShannonTask(task, signal);
}
