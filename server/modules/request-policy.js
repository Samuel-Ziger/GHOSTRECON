import { UA, limits } from '../config.js';

const STABLE_UAS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
  'Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0',
];

/**
 * Stealth: módulo `stealth_requests` na UI ou GHOSTRECON_STEALTH=1
 */
export function stealthEnabled(modules) {
  if (Array.isArray(modules) && modules.includes('stealth_requests')) return true;
  const v = String(process.env.GHOSTRECON_STEALTH || '').trim().toLowerCase();
  return v === '1' || v === 'true' || v === 'yes';
}

export async function stealthPause(modules, signal = null) {
  if (!stealthEnabled(modules)) return;
  if (signal?.aborted) throw signal.reason || new DOMException('cancelado', 'AbortError');
  const lo = Math.max(20, Number(limits.stealthJitterMinMs ?? 60));
  const hi = Math.max(lo, Number(limits.stealthJitterMaxMs ?? 420));
  const ms = lo + Math.random() * (hi - lo);
  await new Promise((resolve, reject) => {
    let settled = false;
    let timer = null;
    const cleanup = () => {
      if (timer) clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
    };
    const settle = (callback, value) => {
      if (settled) return;
      settled = true;
      cleanup();
      callback(value);
    };
    const onAbort = () => {
      settle(reject, signal.reason || new DOMException('cancelado', 'AbortError'));
    };
    timer = setTimeout(() => settle(resolve), ms);
    signal?.addEventListener('abort', onAbort, { once: true });
    timer.unref?.();
    if (signal?.aborted) onAbort();
  });
}

export function pickStealthUserAgent(modules) {
  if (!stealthEnabled(modules)) return UA;
  const seed = (Array.isArray(modules) ? modules : [])
    .map((value) => String(value || '').trim().toLowerCase())
    .sort()
    .join('|') || 'stealth_requests';
  let hash = 2166136261;
  for (const char of seed) {
    hash ^= char.charCodeAt(0);
    hash = Math.imul(hash, 16777619) >>> 0;
  }
  return STABLE_UAS[hash % STABLE_UAS.length];
}

/**
 * Política estável por execução para consumidores novos. Ela não troca
 * identidade em 403/captcha e nunca repete uma requisição automaticamente.
 */
export function createStableRequestPolicy({
  modules = [],
  signal = null,
  fetchImpl = globalThis.fetch,
  sleepImpl = null,
} = {}) {
  const enabled = stealthEnabled(modules);
  const userAgent = pickStealthUserAgent(modules);
  let requests = 0;
  const beforeRequest = async (requestSignal = null) => {
    if (!enabled) return;
    if (sleepImpl) {
      const lo = Math.max(20, Number(limits.stealthJitterMinMs ?? 60));
      await sleepImpl(lo, requestSignal || signal);
      return;
    }
    await stealthPause(modules, requestSignal || signal);
  };
  return Object.freeze({
    enabled,
    userAgent,
    beforeRequest,
    async fetch(url, init = {}) {
      const requestSignal = init.signal || signal || null;
      await beforeRequest(requestSignal);
      requests += 1;
      const headers = new Headers(init.headers || {});
      if (!headers.has('user-agent')) headers.set('user-agent', userAgent);
      return fetchImpl(url, { ...init, headers, signal: requestSignal || undefined });
    },
    stats() {
      return { enabled, userAgent, requests, retries: 0, identityRotations: 0 };
    },
  });
}
