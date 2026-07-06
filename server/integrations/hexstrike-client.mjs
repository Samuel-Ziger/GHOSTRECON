const DEFAULT_BASE_URL = 'http://127.0.0.1:8888';

export const HEXSTRIKE_SAFE_POST_PREFIXES = Object.freeze([
  '/api/intelligence/',
  '/api/bugbounty/',
  '/api/visual/',
  '/api/tools/',
  '/api/processes/list',
  '/api/processes/dashboard',
  '/api/telemetry',
  '/api/cache/stats',
  '/api/cache/clear',
  '/api/payloads/',
]);

export function resolveHexstrikeBaseUrl() {
  return String(process.env.GHOST_HEXSTRIKE_URL || process.env.GHOSTRECON_HEXSTRIKE_URL || DEFAULT_BASE_URL)
    .trim()
    .replace(/\/+$/, '');
}

export function normalizeHexstrikePath(path) {
  if (!path || typeof path !== 'string') return null;
  const p = path.trim().split('?')[0];
  if (!p.startsWith('/') || p.includes('..')) return null;
  return p;
}

export function isAllowedHexstrikePostPath(path) {
  const p = normalizeHexstrikePath(path);
  if (!p) return false;
  return HEXSTRIKE_SAFE_POST_PREFIXES.some((pref) => p === pref.replace(/\/$/, '') || p.startsWith(pref));
}

function timeoutSignal(timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  return { signal: controller.signal, cancel: () => clearTimeout(timer) };
}

async function readJsonOrText(response, maxText = 50_000) {
  const ct = String(response.headers?.get?.('content-type') || '').toLowerCase();
  if (ct.includes('json')) {
    try {
      return await response.json();
    } catch {
      return { text: String(await response.text()).slice(0, maxText) };
    }
  }
  return { text: String(await response.text()).slice(0, maxText), content_type: response.headers?.get?.('content-type') || '' };
}

export class HexstrikeClient {
  constructor(opts = {}) {
    this.baseUrl = String(opts.baseUrl || resolveHexstrikeBaseUrl()).replace(/\/+$/, '');
    this.fetchImpl = opts.fetchImpl || globalThis.fetch;
    this.timeoutMs = Number(opts.timeoutMs || process.env.GHOSTRECON_HEXSTRIKE_TIMEOUT_MS || 5000);
    if (typeof this.fetchImpl !== 'function') {
      throw new Error('fetch indisponivel para HexStrike client');
    }
  }

  async get(path, opts = {}) {
    const p = normalizeHexstrikePath(path);
    if (!p) return { ok: false, status: 400, data: { error: 'caminho HexStrike invalido', path } };
    const timeoutMs = Number(opts.timeoutMs || this.timeoutMs);
    const t = timeoutSignal(timeoutMs);
    try {
      const response = await this.fetchImpl(`${this.baseUrl}${p}`, {
        method: 'GET',
        signal: t.signal,
        headers: { accept: 'application/json' },
      });
      const data = await readJsonOrText(response, opts.maxText);
      return { ok: response.ok, status: response.status, data };
    } catch (e) {
      return { ok: false, status: 0, data: { error: e?.name === 'AbortError' ? 'timeout' : e?.message || String(e) } };
    } finally {
      t.cancel();
    }
  }

  async post(path, payload = {}, opts = {}) {
    if (!isAllowedHexstrikePostPath(path)) {
      return {
        ok: false,
        status: 400,
        data: {
          error: 'caminho HexStrike nao permitido',
          path,
          allowedPrefixes: HEXSTRIKE_SAFE_POST_PREFIXES,
        },
      };
    }
    const p = normalizeHexstrikePath(path);
    const timeoutMs = Number(opts.timeoutMs || this.timeoutMs);
    const t = timeoutSignal(timeoutMs);
    try {
      const response = await this.fetchImpl(`${this.baseUrl}${p}`, {
        method: 'POST',
        signal: t.signal,
        headers: { accept: 'application/json', 'content-type': 'application/json' },
        body: JSON.stringify(payload || {}),
      });
      const data = await readJsonOrText(response, opts.maxText);
      return { ok: response.ok, status: response.status, data };
    } catch (e) {
      return { ok: false, status: 0, data: { error: e?.name === 'AbortError' ? 'timeout' : e?.message || String(e) } };
    } finally {
      t.cancel();
    }
  }

  telemetry(opts = {}) {
    return this.get('/api/telemetry', opts);
  }

  health(opts = {}) {
    return this.get('/health', { timeoutMs: Number(opts.timeoutMs || 45_000), ...opts });
  }
}

