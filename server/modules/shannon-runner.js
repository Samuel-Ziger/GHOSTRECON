import fs from 'fs/promises';
import { constants as fsConstants } from 'node:fs';
import path from 'path';
import { resolveShannonHome } from './shannon-capabilities.js';
import { hostLiteralForUrl } from './recon-target.js';
import { getProcessExecutionContext } from '../lib/process-execution-context.mjs';
import { runProcess } from './module-runner.mjs';
import { redactAutoText } from '../auto-agent/redaction.mjs';
import { redactLocalPathsForPublic } from './finding-redaction.mjs';

/** Igual ao `apps/cli/src/commands/logs.ts` — fim do workflow no ficheiro append-only. */
const WORKFLOW_DONE_RE = /^Workflow (COMPLETED|FAILED)$/m;
const WORKFLOW_LOG_READ_BYTES = 64 * 1024;

function safeShannonText(value) {
  const text = String(value ?? '').replace(
    /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?(?:-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|$)/g,
    '[REDACTED_PRIVATE_KEY]',
  );
  return redactLocalPathsForPublic(redactAutoText(text));
}

/** Lê apenas ficheiros regulares; a alocação nunca cresce com o tamanho do ficheiro. */
async function readBoundedShannonFile(filePath, maxBytes, { tail = false, signal = null } = {}) {
  throwIfAborted(signal);
  const handle = await fs.open(filePath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK);
  try {
    const stat = await handle.stat();
    if (!stat.isFile()) throw new Error('Shannon: artefato não é um ficheiro regular');
    const length = Math.min(stat.size, Math.max(1, Math.floor(maxBytes)));
    const start = tail ? Math.max(0, stat.size - length) : 0;
    const buffer = Buffer.alloc(length);
    let bytesRead = 0;
    while (bytesRead < length) {
      throwIfAborted(signal);
      const next = await handle.read(buffer, bytesRead, length - bytesRead, start + bytesRead);
      if (!next.bytesRead) break;
      bytesRead += next.bytesRead;
    }
    throwIfAborted(signal);
    let text = buffer.subarray(0, bytesRead).toString('utf8');
    // Nunca interpreta como linha completa um fragmento iniciado a meio do log.
    if (tail && start > 0) text = text.includes('\n') ? text.slice(text.indexOf('\n') + 1) : '';
    return { text, bytes: stat.size, truncated: stat.size > length };
  } finally {
    await handle.close();
  }
}

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

export function buildShannonChildEnv(source = process.env) {
  const exact = new Set([
    'PATH', 'HOME', 'USER', 'LOGNAME', 'SHELL', 'LANG', 'LANGUAGE',
    'TMPDIR', 'TEMP', 'TMP', 'XDG_RUNTIME_DIR',
    'DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_CONFIG',
    'ANTHROPIC_API_KEY', 'OPENAI_API_KEY',
  ]);
  const prefixes = ['LC_', 'COMPOSE_', 'SHANNON_', 'TEMPORAL_'];
  const out = {};
  for (const [key, value] of Object.entries(source || {})) {
    if (value == null) continue;
    if (!exact.has(key) && !prefixes.some((prefix) => key.startsWith(prefix))) continue;
    out[key] = String(value);
  }
  out.SHANNON_LOCAL = '1';
  return out;
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
  let discardLine = false;
  let privateKey = false;
  let forwardedChars = 0;
  const emitLine = (line) => {
    if (forwardedChars >= 64 * 1024) return;
    if (/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/.test(line)) privateKey = true;
    const safe = privateKey ? '[REDACTED_PRIVATE_KEY]' : safeShannonText(line);
    if (/-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/.test(line)) privateKey = false;
    const out = safe.length > 2400 ? `${safe.slice(0, 2400)}…` : safe;
    forwardedChars += out.length;
    onLine(out.length ? out : ' ');
    if (forwardedChars >= 64 * 1024) onLine('[Shannon: espelho do CLI truncado a 64 KiB]');
  };
  return {
    push(chunk) {
      if (forwardedChars >= 64 * 1024) return;
      const pieces = stripAnsi(String(chunk)).replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n');
      for (let index = 0; index < pieces.length; index += 1) {
        if (!discardLine) {
          if (buf.length + pieces[index].length > 8192) {
            // Não conserva nem publica prefixos de linhas arbitrariamente grandes.
            if (/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/.test(buf + pieces[index])) privateKey = true;
            buf = '';
            discardLine = true;
          } else {
            buf += pieces[index];
          }
        }
        if (index < pieces.length - 1) {
          emitLine(discardLine ? '[Shannon: linha extensa omitida]' : buf);
          buf = '';
          discardLine = false;
        }
        if (forwardedChars >= 64 * 1024) break;
      }
    },
    flush() {
      const t = buf.trimEnd();
      buf = '';
      if (discardLine) emitLine('[Shannon: linha extensa omitida]');
      else if (t) emitLine(t);
      discardLine = false;
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

export function extractTemporalWorkflowId(value) {
  const match = String(value || '').match(/\/workflows\/([^/?#\s]+)/i);
  if (!match?.[1]) return null;
  try { return decodeURIComponent(match[1]); } catch { return match[1]; }
}

export async function cancelShannonWorkflow({
  workflowId,
  processRunner = runProcess,
  reason = 'ghostrecon_cancelled',
} = {}) {
  const id = String(workflowId || '').trim();
  if (!id || id.length > 1024 || /[\r\n\0]/.test(id)) {
    return { attempted: false, requested: false, confirmed: false, reason: 'workflow_id_missing_or_invalid' };
  }
  try {
    const result = await processRunner('temporal', [
      'workflow', 'cancel', '--workflow-id', id, '--reason', String(reason).slice(0, 160),
    ], {
      timeoutMs: 30_000,
      signal: AbortSignal.timeout(30_000),
      rejectOnError: false,
      rejectOnTimeout: false,
      stdoutMaxBytes: 128 * 1024,
      stderrMaxBytes: 128 * 1024,
      spawnOpts: { env: buildShannonChildEnv(process.env) },
      label: 'Shannon Temporal cancel',
    });
    const requested = result?.code === 0 && !result?.timedOut && !result?.aborted && !result?.cancelled;
    return {
      attempted: true,
      requested,
      // O CLI confirma o pedido, não o término do workflow/atividades remotas.
      confirmed: false,
      reason: requested ? 'cancellation_requested_terminal_unobserved' : 'cancellation_request_failed',
      workflowId: id,
      exitCode: result?.code ?? null,
      error: requested ? null : safeShannonText(result?.stderr || result?.stdout || 'cancelamento não confirmado').slice(0, 500),
    };
  } catch (error) {
    if (error?.code === 'PROCESS_UNTERMINATED' || error?.fatal) throw error;
    return { attempted: true, requested: false, confirmed: false, workflowId: id, error: safeShannonText(error?.message || String(error)).slice(0, 500) };
  }
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
      const read = await readBoundedShannonFile(logFile, WORKFLOW_LOG_READ_BYTES, { tail: true, signal });
      const txt = read.text;
      if (WORKFLOW_DONE_RE.test(txt)) {
        const m = txt.match(WORKFLOW_DONE_RE);
        const outcome = m?.[1] === 'COMPLETED' ? 'completed' : 'failed';
        return { outcome, logPath: logFile, tail: `Workflow ${m[1]}`, logTruncated: read.truncated };
      }
      if (read.bytes !== lastSize && onLog) {
        lastSize = read.bytes;
        // O log pode cortar um segredo multiline no limite da janela de leitura.
        // Publica apenas progresso estrutural; o conteúdo bruto continua local.
        onLog(`Shannon: workflow.log atualizado (${read.bytes} bytes; término ainda não observado).`, 'info');
        lastKeepalive = Date.now();
      }
    } catch (error) {
      if (isProcessAbort(error) || signal?.aborted) throw processAbortError(signal);
      if (error?.code !== 'ENOENT') {
        return { outcome: 'unavailable', logPath: logFile, tail: '', reason: 'workflow_log_unreadable' };
      }
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
export async function readShannonComprehensiveReport(clonePath, { signal = null } = {}) {
  const p = shannonReportPath(clonePath);
  try {
    const max = shannonReportMaxChars();
    const read = await readBoundedShannonFile(p, max * 4 + 1, { signal });
    const sanitized = safeShannonText(read.text);
    const truncated = read.truncated || sanitized.length > max;
    const content = truncated ? `${sanitized.slice(0, max)}\n\n…[truncado a ${max} caracteres]` : sanitized;
    return { ok: true, path: p, content, bytes: read.bytes, truncated };
  } catch (error) {
    if (isProcessAbort(error) || signal?.aborted) throw processAbortError(signal);
    return { ok: false, path: p };
  }
}

function shannonSeverity(value) {
  const normalized = String(value || '').trim().toLowerCase();
  if (normalized === 'critical' || normalized === 'critico' || normalized === 'crítico') return ['critical', 92];
  if (normalized === 'high' || normalized === 'alto') return ['high', 82];
  if (normalized === 'medium' || normalized === 'med' || normalized === 'médio') return ['med', 58];
  if (normalized === 'low' || normalized === 'baixo') return ['low', 32];
  return ['info', 18];
}

export function extractShannonFindings(reportContent, {
  repoFullName = 'repo', workspaceId = '', reportPath = '',
} = {}) {
  const text = safeShannonText(String(reportContent || '').slice(0, shannonReportMaxChars()));
  const sections = text.split(/(?=^#{2,4}\s+)/m).slice(0, 160);
  const findings = [];
  const seen = new Set();
  for (const section of sections) {
    const heading = section.match(/^#{2,4}\s+(.{3,220})/m)?.[1]?.trim();
    if (!heading) continue;
    const severityRaw = heading.match(/\b(CRITICAL|HIGH|MEDIUM|MED|LOW|INFO)\b/i)?.[1]
      || section.match(/(?:severity|severidade)\s*[:|*-]+\s*\*{0,2}(critical|high|medium|med|low|info)/i)?.[1];
    if (!severityRaw) continue;
    const [prio, score] = shannonSeverity(severityRaw);
    const title = heading.replace(/[\[\]()_*`#]/g, ' ').replace(/\b(CRITICAL|HIGH|MEDIUM|MED|LOW|INFO)\b/ig, '').replace(/\s+/g, ' ').trim();
    if (!title || seen.has(title.toLowerCase())) continue;
    seen.add(title.toLowerCase());
    const file = section.match(/(?:file|path|arquivo)\s*[:|*-]+\s*`?([^\n`]{1,240})/i)?.[1]?.trim() || null;
    const evidence = section.replace(/^#{2,4}.*$/m, '').replace(/\s+/g, ' ').trim().slice(0, 600);
    findings.push({
      type: 'shannon_whitebox',
      prio,
      score,
      value: title.slice(0, 220),
      url: repoFullName ? `https://github.com/${repoFullName}` : null,
      meta: {
        source: 'shannon_whitebox',
        evidenceStatus: 'candidate_ai_report',
        workspaceId: workspaceId || null,
        reportPath: reportPath ? path.basename(reportPath) : null,
        file,
        evidence,
        note: 'Requer revisão humana; severidade veio do relatório white-box',
      },
    });
    if (findings.length >= 100) break;
  }
  return findings;
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
 *   cancelWorkflowImpl?: typeof cancelShannonWorkflow,
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
      log: rawLog,
      emit,
      processRunner = runProcess,
      waitForWorkflowImpl = waitForShannonWorkflowEnd,
      readReportImpl = readShannonComprehensiveReport,
      cancelWorkflowImpl = cancelShannonWorkflow,
    } = opts;
    const log = typeof rawLog === 'function'
      ? (message, level) => rawLog(safeShannonText(message), level)
      : null;
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
    let temporalUrl = null;
    const temporalUrlsSeen = new Set();
    const cancelTemporal = async (reason) => {
      const cleanup = await cancelWorkflowImpl({
        workflowId: extractTemporalWorkflowId(temporalUrl),
        workspaceId,
        processRunner,
        reason,
      });
      log?.(
        `Shannon: cancelamento Temporal ${cleanup.confirmed ? 'confirmado por término observado' : cleanup.requested ? 'solicitado; término não confirmado' : 'não solicitado/confirmado'}`,
        cleanup.confirmed ? 'info' : 'warn',
      );
      return cleanup;
    };
    const tryEmitTemporalFromChildOutput = (chunk, final = false) => {
      temporalBuffer = `${temporalBuffer}${stripAnsi(String(chunk || ''))}`.slice(-64 * 1024);
      // Não aceita um workflow ID parcial quando a URL cruza dois chunks.
      const completeOutput = final ? temporalBuffer : temporalBuffer.match(/[\s\S]*\s/)?.[0] || '';
      for (;;) {
        const rawUrl = extractTemporalWebUiUrl(completeOutput, temporalUrlsSeen);
        if (!rawUrl) break;
        const parsed = new URL(rawUrl);
        const url = `${parsed.origin}${parsed.pathname}`;
        if (extractTemporalWorkflowId(url)) temporalUrl = url;
        if (!shannonEmitOpenTemporalUrl() || !emit) continue;
        emit({
          type: 'open_url',
          url,
          label: 'Shannon — Temporal Web UI',
          source: 'shannon',
        });
        log?.(`Shannon: monitor Temporal (abre no browser) → ${url}`, 'success');
      }
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
          env: buildShannonChildEnv(process.env),
          stdio: ['ignore', 'pipe', 'pipe'],
        },
        stdoutMaxBytes: 2 * 1024 * 1024,
        stderrMaxBytes: 2 * 1024 * 1024,
        onStdout,
        onStderr,
        label: 'Shannon start',
      });
    } catch (error) {
      tryEmitTemporalFromChildOutput(`\n${error?.result?.stdout || ''}\n${error?.result?.stderr || ''}`, true);
      fwdOut?.flush();
      fwdErr?.flush();
      if (isProcessAbort(error)) {
        error.cleanup = await cancelTemporal('ghostrecon_operator_cancelled');
        throw error;
      }
      if (error?.code === 'PROCESS_UNTERMINATED' || error?.fatal) {
        error.cleanup = await cancelTemporal('ghostrecon_process_unterminated');
        throw error;
      }
      const timedOut = error?.code === 'PROCESS_TIMEOUT';
      const detail = safeShannonText(`${error?.result?.stderr || ''}\n${error?.result?.stdout || ''}`.trim()).slice(-4000);
      const cleanup = timedOut || temporalUrl
        ? await cancelTemporal(timedOut ? 'ghostrecon_start_timeout' : 'ghostrecon_start_failed')
        : null;
      return {
        ok: false,
        workspaceId,
        phase: 'start',
        exitCode: timedOut ? -2 : -1,
        detail: detail || safeShannonText(error?.message || (timedOut ? 'timeout' : 'falha ao iniciar')),
        cleanup,
      };
    }

    tryEmitTemporalFromChildOutput(`\n${startResult.stdout || ''}\n${startResult.stderr || ''}`, true);
    fwdOut?.flush();
    fwdErr?.flush();

    if (startResult.code !== 0) {
      const tail = safeShannonText(`${startResult.stderr || ''}\n${startResult.stdout || ''}`.trim()).slice(-4000);
      const cleanup = temporalUrl ? await cancelTemporal('ghostrecon_start_failed') : null;
      return {
        ok: false,
        workspaceId,
        phase: 'start',
        exitCode: startResult.code,
        detail: tail || `exit ${startResult.code}`,
        cleanup,
      };
    }

    let wf;
    try {
      wf = await waitForWorkflowImpl(shannonHome, workspaceId, log, { signal });
    } catch (error) {
      if (isProcessAbort(error)) {
        error.cleanup = await cancelTemporal('ghostrecon_operator_cancelled');
      }
      throw error;
    }
    if (wf.outcome === 'timeout') {
      log?.('Shannon: timeout a aguardar workflow.log (aumenta GHOSTRECON_SHANNON_WORKFLOW_TIMEOUT_MS)', 'warn');
      const cleanup = await cancelTemporal('ghostrecon_workflow_timeout');
      return {
        ok: false,
        workspaceId,
        phase: 'workflow',
        outcome: 'timeout',
        logPath: wf.logPath,
        cleanup,
      };
    }
    if (wf.outcome === 'failed') {
      log?.('Shannon: workflow FAILED — vê workflow.log no workspace', 'warn');
      return {
        ok: false,
        workspaceId,
        phase: 'workflow',
        outcome: 'failed',
        logTail: safeShannonText(wf.tail),
        logPath: wf.logPath,
      };
    }
    if (wf.outcome !== 'completed') {
      log?.('Shannon: estado do workflow indisponível; término não observado.', 'warn');
      const cleanup = await cancelTemporal('ghostrecon_workflow_state_unavailable');
      return { ok: false, workspaceId, phase: 'workflow', outcome: 'unavailable', reason: wf.reason || 'workflow_state_unknown', cleanup };
    }

    let report = await readReportImpl(clonePath, { signal });
    for (let attempt = 0; !report.ok && attempt < 10; attempt++) {
      await sleep(2000, signal);
      report = await readReportImpl(clonePath, { signal });
    }
    if (!report.ok) {
      log?.(`Shannon: workflow COMPLETED mas relatório ainda não disponível em ${report.path}`, 'warn');
    } else {
      report = { ...report, content: safeShannonText(String(report.content || '').slice(0, shannonReportMaxChars())) };
      log?.(`Shannon: relatório ${report.path} (${report.bytes} bytes)`, 'success');
    }

    return {
      ok: true,
      workspaceId,
      outcome: 'completed',
      report,
      findings: report.ok ? extractShannonFindings(report.content, {
        repoFullName,
        workspaceId,
        reportPath: report.path,
      }) : [],
      workflowLogPath: wf.logPath,
    };
  };

  return enqueueShannonTask(task, signal);
}
