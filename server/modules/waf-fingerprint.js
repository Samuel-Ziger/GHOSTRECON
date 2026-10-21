import { runProcess } from './module-runner.mjs';

let cachedDefaultCapability = null;

export function parseWafw00fOutput(stdout = '', stderr = '') {
  const raw = [stdout, stderr].filter(Boolean).join('\n').replace(/\x1b\[[0-9;]*m/g, '');
  const lines = raw.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  const detected = [];
  for (const line of lines) {
    const match = line.match(/\bis behind\s+(.+?)(?:\.\s*$|$)/i)
      || line.match(/\bdetected(?:\s+waf)?(?:\s+is)?\s*[:=-]\s*(.+)$/i)
      || line.match(/^\[\+\]\s*(?:waf\s+)?(.+?)\s+detected\b/i);
    if (!match?.[1]) continue;
    const value = match[1].replace(/\s+/g, ' ').trim().slice(0, 180);
    if (value && !detected.includes(value)) detected.push(value);
  }
  return {
    waf: detected[0] || '',
    detected,
    state: detected.length ? 'detected'
      : /no waf detected|no waf was detected|does not seem to be behind a waf/i.test(raw)
        ? 'not_detected' : 'inconclusive',
  };
}

async function resolveCapability(executor, signal) {
  try {
    const result = await executor('wafw00f', ['--version'], {
      timeoutMs: 6_000,
      signal,
      label: 'wafw00f capability',
      stdoutMaxBytes: 32 * 1024,
      stderrMaxBytes: 32 * 1024,
    });
    return {
      available: result.code === 0,
      version: [result.stdout, result.stderr].join(' ').replace(/\s+/g, ' ').trim().slice(0, 120),
    };
  } catch (error) {
    if (signal?.aborted || error?.code === 'PROCESS_ABORTED') throw error;
    return { available: false, version: '', error: error?.message || String(error) };
  }
}

export function resetWafw00fCapabilityCacheForTests() {
  cachedDefaultCapability = null;
}

export async function wafw00fFingerprint(host, {
  executor = runProcess,
  signal = null,
  capability = null,
  timeoutMs = 28_000,
} = {}) {
  signal?.throwIfAborted?.();
  const target = String(host || '').trim();
  if (!target) return { tool: 'wafw00f', state: 'failed', waf: '', error: 'host vazio' };
  if (target.startsWith('-') || /[\s\0]/.test(target)) {
    return { tool: 'wafw00f', state: 'failed', waf: '', error: 'host inválido' };
  }
  let resolvedCapability = capability;
  if (!resolvedCapability) {
    if (executor === runProcess) {
      cachedDefaultCapability ||= resolveCapability(executor, signal);
      try {
        resolvedCapability = await cachedDefaultCapability;
      } catch (error) {
        cachedDefaultCapability = null;
        throw error;
      }
    } else {
      resolvedCapability = await resolveCapability(executor, signal);
    }
  }
  if (!resolvedCapability.available) {
    return {
      tool: 'wafw00f',
      state: 'unavailable',
      waf: '',
      version: resolvedCapability.version || '',
      error: resolvedCapability.error || 'wafw00f indisponível',
    };
  }
  try {
    const result = await executor('wafw00f', ['-a', target], {
      timeoutMs,
      signal,
      label: 'wafw00f fingerprint',
      stdoutMaxBytes: 512 * 1024,
      stderrMaxBytes: 256 * 1024,
    });
    const parsed = parseWafw00fOutput(result.stdout, result.stderr);
    signal?.throwIfAborted?.();
    if (result.timedOut) parsed.state = 'timeout';
    else if (result.code !== 0) parsed.state = 'failed';
    return {
      tool: 'wafw00f',
      ...parsed,
      version: resolvedCapability.version || '',
      exitCode: result.code,
    };
  } catch (error) {
    if (signal?.aborted || error?.code === 'PROCESS_ABORTED') throw error;
    return {
      tool: 'wafw00f',
      state: error?.code === 'PROCESS_TIMEOUT' ? 'timeout' : 'failed',
      waf: '',
      version: resolvedCapability.version || '',
      error: error?.message || String(error),
    };
  }
}
