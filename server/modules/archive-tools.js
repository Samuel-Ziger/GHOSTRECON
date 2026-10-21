import { runProcess } from './module-runner.mjs';

function abortError(signal, fallback = 'archive tools cancelado') {
  const reason = signal?.reason;
  if (reason?.name === 'AbortError' || reason?.code === 'PROCESS_ABORTED') return reason;
  const error = new Error(reason?.message || fallback, reason instanceof Error ? { cause: reason } : undefined);
  error.name = 'AbortError';
  error.code = 'PROCESS_ABORTED';
  return error;
}

function throwIfAborted(signal) {
  if (signal?.aborted) throw abortError(signal);
}

function isAbortError(error, signal) {
  return (
    signal?.aborted === true ||
    error?.name === 'AbortError' ||
    error?.code === 'PROCESS_ABORTED'
  );
}

function runProc(cmd, args, timeoutMs = 90000, { signal = null, runProcessImpl = runProcess } = {}) {
  return runProcessImpl(cmd, args, { timeoutMs, label: cmd, signal, stdoutMaxBytes: 4 * 1024 * 1024, stderrMaxBytes: 16 * 1024 });
}

async function commandExists(
  cmd,
  { signal = null, runProcessImpl = runProcess } = {},
) {
  throwIfAborted(signal);
  const finder = process.platform === 'win32' ? 'where' : 'which';
  try {
    const r = await runProc(finder, [cmd], 8000, { signal, runProcessImpl });
    return r.code === 0;
  } catch (error) {
    if (isAbortError(error, signal) || error?.fatal || error?.code === 'PROCESS_UNTERMINATED') throw error;
    return false;
  }
}

function normalizeUrls(lines, domain, urlAllowed) {
  const out = new Set();
  const d = String(domain || '').toLowerCase();
  for (const line of lines) {
    const u = String(line || '').trim();
    if (u.length > 8192 || !/^https?:\/\//i.test(u)) continue;
    try {
      const x = new URL(u);
      const h = x.hostname.toLowerCase();
      if (x.username || x.password) continue;
      if (typeof urlAllowed === 'function' ? urlAllowed(x.href) === true : h === d) {
        x.hash = '';
        out.add(x.href);
      }
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

function defaultArchiveToolExecutor(runProcessImpl = runProcess) {
  return {
    commandExists: (cmd, { signal } = {}) =>
      commandExists(cmd, { signal, runProcessImpl }),
    run: (cmd, args, { timeoutMs, signal } = {}) =>
      runProc(cmd, args, timeoutMs, { signal, runProcessImpl }),
  };
}

export async function fetchArchiveToolUrls(
  domain,
  log,
  {
    runGau = true,
    runWaybackurls = true,
    signal = null,
    executor = defaultArchiveToolExecutor(),
    urlAllowed = null,
    detailed = false,
    now = () => new Date(),
  } = {},
) {
  const urls = new Set();
  const outcomes = [];
  const evidence = new Map();

  throwIfAborted(signal);
  if (typeof domain !== 'string' || domain.length > 253 || !domain.split('.').every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label))) {
    throw new TypeError('archive tools: hostname inválido');
  }
  for (const [tool, selected] of [['gau', runGau], ['waybackurls', runWaybackurls]]) {
    if (!selected) continue;
    throwIfAborted(signal);
    const observedAt = new Date(now()).toISOString();
    const outcome = { tool, state: 'unavailable', count: 0, observedAt, version: null };
    try {
      if (!await executor.commandExists(tool, { signal })) {
        outcomes.push(outcome);
        log?.(`${tool}: ferramenta indisponível; coleta não executada`, 'warn');
        continue;
      }
      // Ferramentas sem interface de versão estável permanecem explicitamente
      // desconhecidas. Um adapter pode fornecer metadados sem executar rede.
      const r = await executor.run(tool, [domain], { timeoutMs: 120000, signal });
      throwIfAborted(signal);
      outcome.version = typeof r.version === 'string' ? r.version.slice(0, 120) : null;
      outcome.exitCode = r.code ?? null;
      if (r.timedOut || r.timeout) outcome.state = 'timeout';
      else if (r.code !== 0) outcome.state = 'failed';
      else if (r.stdoutStats?.truncated || r.stdoutTruncated || Buffer.byteLength(String(r.stdout || '')) > 4 * 1024 * 1024 || /\[ghostrecon: (?:output|stdout) truncated\]/.test(r.stdout || '')) outcome.state = 'partial';
      else outcome.state = 'done';
      if (outcome.state === 'done' || outcome.state === 'partial') {
        const output = Buffer.from(String(r.stdout || '')).subarray(0, 4 * 1024 * 1024).toString('utf8');
        // Não importar a última linha se a captura foi cortada no meio de uma URL.
        const lines = output.split('\n');
        if (outcome.state === 'partial' && !output.endsWith('\n')) lines.pop();
        const got = normalizeUrls(lines, domain, urlAllowed);
        outcome.count = got.length;
        for (const url of got) {
          urls.add(url);
          const entry = evidence.get(url) || { url, sources: [], classification: 'historical_url', liveStatus: 'unverified', retrievedAt: observedAt };
          entry.sources.push({ tool, version: outcome.version });
          evidence.set(url, entry);
        }
      }
      log?.(`${tool}: ${outcome.state}; ${outcome.count} URL(s) históricas, disponibilidade atual não verificada`, outcome.state === 'done' ? 'info' : 'warn');
    } catch (e) {
      if (isAbortError(e, signal) || e?.fatal || e?.code === 'PROCESS_UNTERMINATED') throw e;
      outcome.state = e?.code === 'PROCESS_TIMEOUT' || /timeout/i.test(e?.name || '') ? 'timeout' : 'failed';
      // Não persistir stdout, stderr ou URLs sensíveis de mensagens do processo.
      log?.(`${tool}: ${outcome.state}; coleta não concluída`, 'warn');
    }
    outcomes.push(outcome);
  }
  throwIfAborted(signal);
  return detailed ? { urls: [...urls], outcomes, evidence: [...evidence.values()] } : [...urls];
}
