/**
 * Rotação de identidade com decisões por comportamento (403 / 429 / captcha).
 *
 * - Sem proxies: roda UA + Accept-Language + sec-ch-ua coerentes por "sessão" e retries em 403.
 * - Com proxies (URLs http/https): usa undici.ProxyAgent quando disponível.
 *
 * Opt-in: identity.enabled no POST /api/recon/stream ou módulo `identity_rotation` na UI.
 */

import { stealthPause, pickStealthUserAgent } from './request-policy.js';

const ACCEPT_LANGS = [
  'pt-PT,pt;q=0.9,en-US;q=0.8,en;q=0.7',
  'en-US,en;q=0.9',
  'en-GB,en;q=0.9,pt;q=0.8',
  'de-DE,de;q=0.9,en;q=0.8',
];

const CAPTCHA_HINTS =
  /recaptcha|hcaptcha|g-recaptcha|h-captcha|cf-browser-verification|challenge-platform|__cf_chl_js|turnstile|please complete the security check|attention required.*cloudflare/i;

let _undici = null;
async function loadUndici() {
  if (_undici !== null) return _undici;
  try {
    _undici = await import('undici');
  } catch {
    _undici = false;
  }
  return _undici;
}

function normalizeProxyEntry(raw) {
  const s = String(raw || '').trim();
  if (!s) return null;
  // Already URL form: http(s)://user:pass@host:port
  if (/^https?:\/\//i.test(s)) {
    try {
      return new URL(s).href;
    } catch {
      return null;
    }
  }
  // user:pass@host:port
  const upHost = s.match(/^([^:\s]+):([^@\s]+)@([^:\s]+):(\d{2,5})$/);
  if (upHost) {
    const [, user, pass, host, port] = upHost;
    try {
      return new URL(`http://${encodeURIComponent(user)}:${encodeURIComponent(pass)}@${host}:${port}`).href;
    } catch {
      return null;
    }
  }
  // host:port:user:pass (formato comum de listas comerciais)
  const hpup = s.match(/^([^:\s]+):(\d{2,5}):([^:\s]+):(.+)$/);
  if (hpup) {
    const [, host, port, user, pass] = hpup;
    try {
      return new URL(`http://${encodeURIComponent(user)}:${encodeURIComponent(pass)}@${host}:${port}`).href;
    } catch {
      return null;
    }
  }
  // host:port (sem auth)
  const hp = s.match(/^([^:\s]+):(\d{2,5})$/);
  if (hp) {
    const [, host, port] = hp;
    try {
      return new URL(`http://${host}:${port}`).href;
    } catch {
      return null;
    }
  }
  return null;
}

function parseProxyList(list) {
  if (!Array.isArray(list)) return [];
  const out = [];
  for (const item of list) {
    const n = normalizeProxyEntry(item);
    if (!n) continue;
    if (!out.includes(n)) out.push(n);
    if (out.length >= 32) break;
  }
  return out;
}

function proxiesFromEnv() {
  const raw = String(process.env.GHOSTRECON_PROXY_POOL || '').trim();
  if (!raw) return [];
  return raw.split(/[,;\n]/).map((s) => s.trim()).filter(Boolean).slice(0, 32);
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

/** @param {Headers|Record<string,string>|undefined|null} h */
function headersToObject(h) {
  if (!h) return {};
  if (typeof Headers !== 'undefined' && h instanceof Headers) return Object.fromEntries([...h.entries()]);
  if (typeof h === 'object') return { ...h };
  return {};
}

export function mergeIdentityBodyFromEnv(body = {}) {
  const src = body && typeof body === 'object' ? body : {};
  const out = { ...src };
  if (!out.proxyPool?.length && proxiesFromEnv().length) {
    out.proxyPool = proxiesFromEnv();
  }
  return out;
}

/**
 * @param {{ enabled?: boolean, behavior?: boolean, proxyPool?: string[], modules?: string[] }} opts
 */
export function createIdentityController(opts = {}) {
  const enabled = Boolean(opts.enabled);
  const behavior = opts.behavior !== false;
  const modules = Array.isArray(opts.modules) ? opts.modules : [];
  const proxies = parseProxyList(
    opts.proxyPool?.length ? opts.proxyPool : proxiesFromEnv(),
  );
  const rotationStrategyRaw = String(
    opts.rotation || process.env.GHOSTRECON_PROXY_ROTATION || 'round_robin',
  )
    .trim()
    .toLowerCase();
  const rotationStrategy = ['round_robin', 'random', 'fixed'].includes(rotationStrategyRaw)
    ? rotationStrategyRaw
    : 'round_robin';
  let proxyIdx = 0;
  /** @type {Map<string, { score: number, burnedUntil: number }>} */
  const health = new Map();
  let backoffMul = 1;
  let uaSlot = Math.floor(Math.random() * 512);

  function proxyKey() {
    if (!proxies.length) return '_direct';
    return proxies[proxyIdx % proxies.length] || '_direct';
  }

  function bumpHealth(url, delta) {
    const k = url || '_direct';
    const cur = health.get(k) || { score: 0, burnedUntil: 0 };
    cur.score += delta;
    health.set(k, cur);
  }

  function markBurned(url) {
    const k = url || '_direct';
    const cur = health.get(k) || { score: 0, burnedUntil: 0 };
    cur.score += 80;
    cur.burnedUntil = Date.now() + 30 * 60_000;
    health.set(k, cur);
  }

  function rotateIdentity() {
    uaSlot += 1;
    if (proxies.length) {
      if (rotationStrategy === 'fixed') {
        // Mantém o mesmo proxy durante todo o run.
      } else if (rotationStrategy === 'random' && proxies.length > 1) {
        let next = proxyIdx;
        for (let i = 0; i < 4; i++) {
          const cand = Math.floor(Math.random() * proxies.length);
          if (cand !== proxyIdx) {
            next = cand;
            break;
          }
        }
        proxyIdx = next;
      } else {
        proxyIdx += 1;
      }
      let tries = 0;
      while (tries < proxies.length) {
        const p = proxies[proxyIdx % proxies.length];
        const h = health.get(p) || { score: 0, burnedUntil: 0 };
        if (h.burnedUntil > Date.now() || h.score > 100) {
          proxyIdx++;
          tries++;
          continue;
        }
        break;
      }
    }
  }

  function pickAcceptLanguage() {
    return ACCEPT_LANGS[Math.abs(uaSlot) % ACCEPT_LANGS.length];
  }

  function buildChromeLikeHeaders(base = {}) {
    const ua = pickStealthUserAgent(modules);
    const out = {
      ...base,
      'User-Agent': base['User-Agent'] || ua,
      'Accept-Language': base['Accept-Language'] || pickAcceptLanguage(),
      Accept: base.Accept || 'text/html,application/xhtml+xml,application/json,*/*;q=0.8',
    };
    if (/Chrome\//.test(out['User-Agent']) && !out['sec-ch-ua']) {
      out['sec-ch-ua'] = '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"';
      out['sec-ch-ua-mobile'] = '?0';
      out['sec-ch-ua-platform'] = '"Windows"';
    }
    return out;
  }

  async function currentDispatcher() {
    if (!proxies.length) return undefined;
    let href;
    try {
      href = new URL(proxies[proxyIdx % proxies.length]).href;
    } catch {
      return undefined;
    }
    const undici = await loadUndici();
    if (!undici || !undici.ProxyAgent) return undefined;
    try {
      return new undici.ProxyAgent(href);
    } catch {
      return undefined;
    }
  }

  async function beforeRequest() {
    const extra = Math.max(0, backoffMul - 1) * 400;
    if (extra) await sleep(extra);
    await stealthPause(modules);
  }

  function evaluateResponse(status, retryAfterHeader, textPrefix) {
    const text = String(textPrefix || '');
    const captcha = CAPTCHA_HINTS.test(text);
    const rotate403 = status === 403;
    const rate429 = status === 429;
    return { captcha, rotate403, rate429, retryAfterHeader };
  }

  async function wait429(headers) {
    const ra = headers?.get?.('retry-after');
    if (ra) {
      const n = Number(ra);
      if (Number.isFinite(n) && n > 0) {
        await sleep(Math.min(120_000, n * 1000));
        return;
      }
    }
    backoffMul = Math.min(8, backoffMul + 1);
    await sleep(Math.min(30_000, 800 * backoffMul));
  }

  function afterSuccess() {
    backoffMul = Math.max(1, backoffMul - 0.25);
  }

  /**
   * GET/POST genérico com política de identidade.
   * @returns {Promise<Response>}
   */
  async function fetchWithPolicy(url, init, { maxAttempts = 3 } = {}) {
    if (!enabled) {
      return fetch(url, init);
    }
    const attempts = behavior ? maxAttempts : 1;
    let lastRes = null;
    const baseHdr = headersToObject(init.headers);
    for (let a = 0; a < attempts; a++) {
      await beforeRequest();
      const dispatcher = await currentDispatcher();
      let headers;
      if (a === 0) {
        headers = buildChromeLikeHeaders(baseHdr);
      } else {
        headers = {
          ...baseHdr,
          'User-Agent': pickStealthUserAgent(modules),
          'Accept-Language': pickAcceptLanguage(),
          Accept:
            baseHdr.Accept ||
            'text/html,application/xhtml+xml,application/json,*/*;q=0.8',
        };
        if (/Chrome\//.test(headers['User-Agent']) && !headers['sec-ch-ua']) {
          headers['sec-ch-ua'] = '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"';
          headers['sec-ch-ua-mobile'] = '?0';
          headers['sec-ch-ua-platform'] = '"Windows"';
        }
      }
      const nextInit = { ...init, headers };
      if (dispatcher) nextInit.dispatcher = dispatcher;
      else delete nextInit.dispatcher;
      const res = await fetch(url, nextInit);
      lastRes = res;
      const peekBuf = await res.clone().arrayBuffer();
      const peek = new TextDecoder('utf-8', { fatal: false }).decode(
        peekBuf.byteLength > 24_000 ? peekBuf.slice(0, 24_000) : peekBuf,
      );
      const ev = evaluateResponse(res.status, res.headers, peek);
      if (ev.captcha) {
        markBurned(proxyKey());
        rotateIdentity();
        if (a < attempts - 1) continue;
      }
      if (ev.rate429) {
        bumpHealth(proxyKey(), 5);
        await wait429(res.headers);
        if (a < attempts - 1) continue;
      }
      if (ev.rotate403) {
        bumpHealth(proxyKey(), 10);
        rotateIdentity();
        if (a < attempts - 1) continue;
      }
      if (res.ok || (res.status >= 400 && res.status < 500 && res.status !== 403 && res.status !== 429)) {
        afterSuccess();
      }
      return res;
    }
    return lastRes;
  }

  return {
    enabled,
    behavior,
    getStats: () => ({
      backoffMul,
      proxyIdx,
      rotationStrategy,
      uaSlot,
      proxies: proxies.length,
      health: Object.fromEntries([...health.entries()].slice(0, 16)),
    }),
    getCurrentProxy: () => {
      if (!proxies.length) return null;
      return proxies[proxyIdx % proxies.length] || null;
    },
    getProxyPool: () => [...proxies],
    /** Para probeHttp (redirect follow). */
    async fetchHtmlProbe(url, init) {
      if (!enabled) return fetch(url, init);
      return fetchWithPolicy(url, init, { maxAttempts: behavior ? 3 : 1 });
    },
    /** Para verify (redirect manual, GET). */
    async fetchVerifyGet(url, init) {
      if (!enabled) return fetch(url, init);
      return fetchWithPolicy(url, init, { maxAttempts: behavior ? 2 : 1 });
    },
    /** POST verify. */
    async fetchVerifyPost(url, init) {
      if (!enabled) return fetch(url, init);
      return fetchWithPolicy(url, init, { maxAttempts: behavior ? 2 : 1 });
    },
  };
}

export function shouldEnableIdentity({ modules = [], identityBody = null } = {}) {
  if (identityBody && typeof identityBody === 'object' && identityBody.enabled) return true;
  if (
    identityBody &&
    typeof identityBody === 'object' &&
    Array.isArray(identityBody.proxyPool) &&
    identityBody.proxyPool.length
  )
    return true;
  if (Array.isArray(modules) && modules.includes('identity_rotation')) return true;
  const v = String(process.env.GHOSTRECON_IDENTITY_ROTATION || '').trim().toLowerCase();
  return v === '1' || v === 'true' || v === 'yes';
}

export function normalizeIdentityOptions(modules, identityBody) {
  const raw = identityBody && typeof identityBody === 'object' ? identityBody : {};
  const body = mergeIdentityBodyFromEnv(raw);
  const enabled = shouldEnableIdentity({ modules, identityBody: body });
  return {
    enabled,
    behavior: body.behavior !== false,
    proxyPool: parseProxyList(body.proxyPool || []),
    rotation: String(body.rotation || '').trim().toLowerCase() || undefined,
  };
}
