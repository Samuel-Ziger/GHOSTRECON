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
  return runProcessImpl(cmd, args, { timeoutMs, label: cmd, signal });
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
    if (isAbortError(error, signal)) throw error;
    return false;
  }
}

function normalizeUrls(lines, domain) {
  const out = new Set();
  const d = String(domain || '').toLowerCase();
  for (const line of lines) {
    const u = String(line || '').trim();
    if (!/^https?:\/\//i.test(u)) continue;
    try {
      const x = new URL(u);
      const h = x.hostname.toLowerCase();
      if (h === d || h.endsWith(`.${d}`)) out.add(x.href);
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
  } = {},
) {
  const urls = new Set();

  throwIfAborted(signal);

  if (runGau && await executor.commandExists('gau', { signal })) {
    try {
      const r = await executor.run('gau', [domain], { timeoutMs: 120000, signal });
      const got = normalizeUrls(r.stdout.split('\n'), domain);
      for (const u of got) urls.add(u);
      if (typeof log === 'function') log(`gau: ${got.length} URL(s)`, 'info');
    } catch (e) {
      if (isAbortError(e, signal)) throw e;
      if (typeof log === 'function') log(`gau: ${e.message}`, 'warn');
    }
  }

  throwIfAborted(signal);

  if (runWaybackurls && await executor.commandExists('waybackurls', { signal })) {
    try {
      const r = await executor.run('waybackurls', [domain], { timeoutMs: 120000, signal });
      const got = normalizeUrls(r.stdout.split('\n'), domain);
      for (const u of got) urls.add(u);
      if (typeof log === 'function') log(`waybackurls: ${got.length} URL(s)`, 'info');
    } catch (e) {
      if (isAbortError(e, signal)) throw e;
      if (typeof log === 'function') log(`waybackurls: ${e.message}`, 'warn');
    }
  }

  throwIfAborted(signal);
  return [...urls];
}
