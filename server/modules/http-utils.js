function abortReason(signal) {
  return signal?.reason || new DOMException('The operation was aborted', 'AbortError');
}

export function throwIfAborted(signal) {
  if (signal?.aborted) throw abortReason(signal);
}

export function isAbortError(error, signal = null) {
  return Boolean(
    signal?.aborted ||
      error?.name === 'AbortError' ||
      error?.name === 'TimeoutError' ||
      error?.code === 'ABORT_ERR',
  );
}

/**
 * Combina o cancelamento do pipeline com o deadline local da requisição.
 * O sinal pai nunca é substituído pelo timeout do módulo.
 */
export function combineAbortSignals(signal = null, timeoutMs = null) {
  const timeout = Number(timeoutMs);
  const timeoutSignal =
    Number.isFinite(timeout) && timeout > 0 ? AbortSignal.timeout(timeout) : null;
  if (signal && timeoutSignal) return AbortSignal.any([signal, timeoutSignal]);
  return signal || timeoutSignal || undefined;
}

export function abortableDelay(ms, signal = null) {
  throwIfAborted(signal);
  const delayMs = Math.max(0, Number(ms) || 0);
  if (delayMs === 0) return Promise.resolve();

  return new Promise((resolve, reject) => {
    let timer = null;
    const cleanup = () => {
      if (timer) clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
    };
    const onAbort = () => {
      cleanup();
      reject(abortReason(signal));
    };
    timer = setTimeout(() => {
      cleanup();
      resolve();
    }, delayMs);
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

export async function fetchWithBackoff(url, options = {}, cfg = {}) {
  const retries = Math.max(0, Number(cfg.retries ?? 2));
  const baseDelayMs = Math.max(100, Number(cfg.baseDelayMs ?? 450));
  const fetchImpl = cfg.fetchImpl || globalThis.fetch;
  if (typeof fetchImpl !== 'function') throw new TypeError('fetch implementation unavailable');
  const signal = options?.signal || null;
  let lastErr = null;
  for (let i = 0; i <= retries; i++) {
    throwIfAborted(signal);
    try {
      const res = await fetchImpl(url, options);
      const retryable = res.status === 429 || res.status >= 500;
      if (retryable && i < retries) {
        await abortableDelay(baseDelayMs * (i + 1), signal);
        continue;
      }
      return res;
    } catch (e) {
      if (isAbortError(e, signal)) throw e;
      lastErr = e;
      if (i < retries) {
        await abortableDelay(baseDelayMs * (i + 1), signal);
      }
    }
  }
  throw lastErr || new Error('fetchWithBackoff failed');
}
