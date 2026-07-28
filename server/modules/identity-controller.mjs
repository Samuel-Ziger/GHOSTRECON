/**
 * Rotação de identidade com decisões por comportamento (403 / 429 / captcha).
 *
 * - Sem proxies: roda UA + Accept-Language + sec-ch-ua coerentes por "sessão" e retries em 403.
 * - Com proxies (URLs http/https): usa undici.ProxyAgent quando disponível.
 *
 * Opt-in: identity.enabled no POST /api/recon/stream ou módulo `identity_rotation` na UI.
 */

import { stealthPause, pickStealthUserAgent } from './request-policy.js';
import {
  isSocksUrl,
  createSocksDispatcher,
  isolatedSocksUser,
  injectIsolationCredentials,
} from './socks5-dispatcher.js';
import { isStrict, sanitizeOutboundHeaders, telemetryFor } from './tor-strict.js';
import { readResponseSnippet } from './module-runner.mjs';

const ACCEPT_LANGS = [
  'pt-PT,pt;q=0.9,en-US;q=0.8,en;q=0.7',
  'en-US,en;q=0.9',
  'en-GB,en;q=0.9,pt;q=0.8',
  'de-DE,de;q=0.9,en;q=0.8',
];

const CAPTCHA_HINTS =
  /recaptcha|hcaptcha|g-recaptcha|h-captcha|cf-browser-verification|challenge-platform|__cf_chl_js|turnstile|please complete the security check|attention required.*cloudflare/i;

const IDENTITY_ROTATIONS = new Set(['round_robin', 'random', 'fixed']);

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
  // SOCKS — preservado exactamente, parseSocksUrl lida com auth/host:port
  if (/^socks(5h?|4a?):\/\//i.test(s)) {
    try {
      return new URL(s).href;
    } catch {
      return null;
    }
  }
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

function hasOwn(value, key) {
  return Boolean(
    value
    && typeof value === 'object'
    && Object.prototype.hasOwnProperty.call(value, key),
  );
}

function envFlag(env, key) {
  const value = String(env?.[key] || '').trim().toLowerCase();
  return value === '1' || value === 'true' || value === 'yes' || value === 'on';
}

function normalizeRotation(value, fallback = 'round_robin') {
  const normalized = String(value || '').trim().toLowerCase();
  return IDENTITY_ROTATIONS.has(normalized) ? normalized : fallback;
}

function proxiesFromEnv(env = process.env) {
  const raw = String(env?.GHOSTRECON_PROXY_POOL || '').trim();
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

export function mergeIdentityBodyFromEnv(body = {}, env = process.env) {
  const src = body && typeof body === 'object' ? body : {};
  const out = { ...src };
  if (!hasOwn(src, 'proxyPool')) {
    const envProxies = proxiesFromEnv(env);
    if (envProxies.length) out.proxyPool = envProxies;
  }
  return out;
}

/**
 * Resolve a configuração de identidade uma única vez antes dos gates.
 *
 * A precedência é campo a campo: request explícito, seleção do módulo (para
 * habilitação), ambiente injetado e, por fim, defaults conservadores. O
 * snapshot retornado é profundamente congelado para poder ser vinculado ao
 * plano aprovado sem sofrer mutações ou uma segunda leitura de `process.env`.
 *
 * @param {{
 *   modules?: string[],
 *   identityBody?: Record<string, unknown>|null,
 *   env?: Record<string, unknown>,
 * }} input
 */
export function resolveEffectiveIdentityConfig({
  modules = [],
  identityBody = null,
  env = process.env,
} = {}) {
  const request = identityBody && typeof identityBody === 'object'
    ? identityBody
    : {};
  const normalizedModules = Object.freeze(
    [...new Set(
      (Array.isArray(modules) ? modules : [])
        .map((moduleId) => String(moduleId || '').trim())
        .filter(Boolean),
    )],
  );
  const requestHasProxyPool = hasOwn(request, 'proxyPool');
  const requestedProxies = requestHasProxyPool && Array.isArray(request.proxyPool)
    ? request.proxyPool
    : [];
  const envProxies = requestHasProxyPool ? [] : proxiesFromEnv(env);
  const proxyPool = Object.freeze(parseProxyList(
    requestHasProxyPool ? requestedProxies : envProxies,
  ));

  let enabled;
  if (hasOwn(request, 'enabled')) {
    enabled = request.enabled === true;
  } else if (requestHasProxyPool && proxyPool.length > 0) {
    enabled = true;
  } else if (normalizedModules.includes('identity_rotation')) {
    enabled = true;
  } else {
    enabled = envFlag(env, 'GHOSTRECON_IDENTITY_ROTATION') || proxyPool.length > 0;
  }

  const requestHasRotation = hasOwn(request, 'rotation');
  const rotation = requestHasRotation
    ? normalizeRotation(request.rotation)
    : normalizeRotation(env?.GHOSTRECON_PROXY_ROTATION);
  const isolate = hasOwn(request, 'isolate')
    ? request.isolate === true
    : envFlag(env, 'GHOSTRECON_TOR_ISOLATE');

  return Object.freeze({
    resolved: true,
    enabled,
    behavior: hasOwn(request, 'behavior') ? request.behavior !== false : true,
    proxyPool,
    rotation,
    isolate,
    isolationKey: typeof request.isolationKey === 'string' ? request.isolationKey : null,
    runId: typeof request.runId === 'string' || typeof request.runId === 'number'
      ? String(request.runId)
      : null,
    target: typeof request.target === 'string' ? request.target : null,
    modules: normalizedModules,
  });
}

/**
 * @param {{
 *   resolved?: boolean,
 *   enabled?: boolean,
 *   behavior?: boolean,
 *   proxyPool?: string[],
 *   modules?: string[],
 *   env?: Record<string, unknown>,
 * }} opts
 */
export function createIdentityController(opts = {}) {
  const resolved = opts.resolved === true;
  const env = resolved
    ? null
    : (opts.env && typeof opts.env === 'object' ? opts.env : process.env);
  const enabled = Boolean(opts.enabled);
  const behavior = opts.behavior !== false;
  const modules = Array.isArray(opts.modules) ? opts.modules : [];
  const proxyInput = resolved
    ? (Array.isArray(opts.proxyPool) ? opts.proxyPool : [])
    : (opts.proxyPool?.length ? opts.proxyPool : proxiesFromEnv(env));
  const proxies = parseProxyList(proxyInput);
  const rotationStrategy = normalizeRotation(
    resolved ? opts.rotation : (opts.rotation || env?.GHOSTRECON_PROXY_ROTATION),
  );
  const isolate = opts.isolate === true
    || (!resolved && envFlag(env, 'GHOSTRECON_TOR_ISOLATE'));
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

  // Cache de dispatchers SOCKS5 — criar Agent por proxy é caro e o keep-alive
  // serve para não rotear cada request por circuit novo (a não ser que o caller
  // queira isolation explícita).
  /** @type {Map<string, import('undici').Dispatcher>} */
  const socksDispatchers = new Map();
  function rememberSocksDispatcher(key, dispatcher) {
    if (socksDispatchers.size >= 16) {
      const oldest = socksDispatchers.keys().next().value;
      if (oldest) socksDispatchers.delete(oldest);
    }
    socksDispatchers.set(key, dispatcher);
  }

  async function currentDispatcher() {
    if (!proxies.length) return undefined;
    let href;
    try {
      href = new URL(proxies[proxyIdx % proxies.length]).href;
    } catch {
      return undefined;
    }
    if (isSocksUrl(href)) {
      // Stream isolation por target/run quando GHOSTRECON_TOR_ISOLATE=1 ou opts.isolate=true.
      const isolationKey = opts.isolationKey || opts.runId || opts.target || '';
      let useHref = href;
      if (isolate) {
        const u = new URL(href);
        if (!u.username) {
          const user = isolatedSocksUser('gr', isolationKey || 'auto');
          useHref = injectIsolationCredentials(href, user, isolationKey || 'x');
        }
      }
      const cacheKey = useHref;
      let dispatcher = socksDispatchers.get(cacheKey);
      if (!dispatcher) {
        try {
          dispatcher = await createSocksDispatcher(useHref);
          rememberSocksDispatcher(cacheKey, dispatcher);
        } catch (e) {
          // Não fazer fallback silencioso para directo — devolver undefined sinaliza erro upstream.
          console.error('[identity] SOCKS dispatcher falhou:', e?.message || e);
          return undefined;
        }
      }
      return dispatcher;
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
    if (!enabled && !isStrict()) {
      return fetch(url, init);
    }
    const attempts = behavior ? maxAttempts : 1;
    let lastRes = null;
    const baseHdr = headersToObject(init.headers);
    // Em strict, queremos hostname para o sanitizer aplicar regras de cookie scope.
    let targetHost = '';
    try { targetHost = new URL(url).hostname; } catch { /* ignore */ }
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
      // Em strict, sobrepomos com headers Tor Browser-like e fazemos strip.
      if (isStrict()) {
        headers = sanitizeOutboundHeaders(headers, { targetHost });
      }
      const nextInit = { ...init, headers };
      if (dispatcher) nextInit.dispatcher = dispatcher;
      else delete nextInit.dispatcher;
      // STRICT: bloqueia se não conseguimos um dispatcher SOCKS (não cair em directo).
      if (isStrict() && !dispatcher) {
        throw new Error('tor-strict: dispatcher SOCKS não disponível — fetch directo bloqueado');
      }
      // Telemetria
      if (opts.runId) {
        const t = telemetryFor(String(opts.runId));
        t.requests += 1;
        const kind = (() => {
          if (!proxies.length) return 'direct';
          const cur = proxies[proxyIdx % proxies.length] || '';
          if (/^socks/i.test(cur)) return 'socks';
          if (/^https?:/i.test(cur)) return 'http';
          return 'direct';
        })();
        t.proxyKindCounts[kind] = (t.proxyKindCounts[kind] || 0) + 1;
        if (kind === 'socks') t.requestsViaTor += 1;
      }
      const res = await fetch(url, nextInit);
      lastRes = res;
      const peek = await readResponseSnippet(res.clone(), 24_000);
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
      resolved,
      isolate,
      uaSlot,
      proxies: proxies.length,
      health: Object.fromEntries([...health.entries()].slice(0, 16)),
    }),
    getCurrentProxy: () => {
      if (!proxies.length) return null;
      return proxies[proxyIdx % proxies.length] || null;
    },
    getCurrentProxyKind: () => {
      const cur = proxies[proxyIdx % proxies.length] || '';
      if (!cur) return 'direct';
      if (/^socks(5h?|4a?):/i.test(cur)) return 'socks';
      if (/^https?:/i.test(cur)) return 'http';
      return 'unknown';
    },
    isCurrentProxyTor: () => {
      const cur = proxies[proxyIdx % proxies.length] || '';
      if (!cur) return false;
      try {
        const u = new URL(cur);
        return /^socks(5h?|4a?):/i.test(cur) && (u.hostname === '127.0.0.1' || u.hostname === '::1' || u.port === '9050');
      } catch { return false; }
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

export function shouldEnableIdentity({
  modules = [],
  identityBody = null,
  env = process.env,
} = {}) {
  return resolveEffectiveIdentityConfig({ modules, identityBody, env }).enabled;
}

export function normalizeIdentityOptions(modules, identityBody, { env = process.env } = {}) {
  const snapshot = resolveEffectiveIdentityConfig({ modules, identityBody, env });
  // Compatibilidade: callers históricos acrescentam runId/target depois desta
  // chamada. Mantemos o wrapper mutável, mas `resolved:true` garante que o
  // controller não volte a consultar o ambiente.
  return {
    ...snapshot,
    proxyPool: [...snapshot.proxyPool],
    modules: [...snapshot.modules],
  };
}
