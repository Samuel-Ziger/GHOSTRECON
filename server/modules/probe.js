import { limits } from '../config.js';
import { detectTech } from './tech.js';
import { extractHtmlSurface } from './html-surface.js';
import { stealthPause, pickStealthUserAgent } from './request-policy.js';
import { flattenResponseHeaderPairs } from './header-intel.js';
import { mapPool as runMapPool, readResponseSnippet } from './module-runner.mjs';

function extractTitle(html) {
  const m = html.match(/<title[^>]*>([^<]{0,300})/i);
  return m ? m[1].trim().replace(/\s+/g, ' ') : '';
}

/** Cabeçalhos relevantes para análise de superfície (sem armazenar corpo). */
export function snapshotSecurityHeaders(headers) {
  const get = (n) => headers.get(n) || '';
  const snap = {
    strictTransportSecurity: get('strict-transport-security'),
    contentSecurityPolicy: get('content-security-policy'),
    xFrameOptions: get('x-frame-options'),
    xContentTypeOptions: get('x-content-type-options'),
    permissionsPolicy: get('permissions-policy'),
    referrerPolicy: get('referrer-policy'),
    crossOriginOpenerPolicy: get('cross-origin-opener-policy'),
    crossOriginEmbedderPolicy: get('cross-origin-embedder-policy'),
    server: get('server'),
    altSvc: get('alt-svc'),
    setCookieSample: [],
  };
  if (typeof headers.getSetCookie === 'function') {
    snap.setCookieSample = headers.getSetCookie().slice(0, 6);
  } else {
    const sc = get('set-cookie');
    if (sc) snap.setCookieSample = [sc];
  }
  return snap;
}

function buildRequestHeaders(auth, modules = []) {
  const h = {
    'User-Agent': pickStealthUserAgent(modules),
    Accept: 'text/html,application/xhtml+xml,*/*;q=0.8',
  };
  if (auth?.headers && typeof auth.headers === 'object') {
    for (const [k, v] of Object.entries(auth.headers)) {
      if (!k || v == null) continue;
      h[String(k)] = String(v);
    }
  }
  if (auth?.cookie) h.Cookie = String(auth.cookie);
  return h;
}

function detectWaf(headers, bodySnippet = '') {
  const blob = [
    headers.get('server') || '',
    headers.get('x-sucuri-id') || '',
    headers.get('cf-ray') || '',
    headers.get('x-akamai-request-id') || '',
    headers.get('x-cdn') || '',
    bodySnippet.slice(0, 1200),
  ]
    .join(' ')
    .toLowerCase();
  if (/cloudflare|cf-ray/.test(blob)) return 'cloudflare';
  if (/akamai/.test(blob)) return 'akamai';
  if (/sucuri/.test(blob)) return 'sucuri';
  if (/imperva|incapsula/.test(blob)) return 'imperva';
  if (/aws\s*waf|awselb/.test(blob)) return 'aws-waf';
  return '';
}

export async function probeHttp(url, opts = {}) {
  const {
    auth,
    modules = [],
    identityCtrl = null,
    signal = null,
    fetchImpl = globalThis.fetch,
    urlAllowed = () => true,
  } = opts;
  if (signal?.aborted) throw signal.reason || new DOMException('cancelado', 'AbortError');
  if (!urlAllowed(url)) {
    return { ok: false, url, error: 'fora do escopo autorizado' };
  }
  if (!identityCtrl?.enabled) await stealthPause(modules, signal);
  const controller = new AbortController();
  let timedOut = false;
  const forwardAbort = () => {
    if (!controller.signal.aborted) {
      controller.abort(signal?.reason || new DOMException('cancelado', 'AbortError'));
    }
  };
  signal?.addEventListener('abort', forwardAbort, { once: true });
  if (signal?.aborted) forwardAbort();
  const t = setTimeout(() => {
    timedOut = true;
    controller.abort(new DOMException('timeout', 'TimeoutError'));
  }, limits.probeTimeoutMs);
  try {
    if (controller.signal.aborted) {
      throw signal?.reason || controller.signal.reason || new DOMException('cancelado', 'AbortError');
    }
    const fetchInit = {
      method: 'GET',
      // Redirect automático poderia enviar credenciais/probe para outra
      // origem antes de a política de escopo validar o Location.
      redirect: 'manual',
      signal: controller.signal,
      headers: buildRequestHeaders(auth, modules),
    };
    const res = identityCtrl?.enabled
      ? await identityCtrl.fetchHtmlProbe(url, fetchInit)
      : await fetchImpl(url, fetchInit);
    if (!urlAllowed(res.url || url)) {
      return { ok: false, url, error: 'redirect fora do escopo autorizado' };
    }
    const text = await readResponseSnippet(res, limits.maxBodySnippet);
    const title = extractTitle(text);
    const tech = detectTech(res.headers, text);
    const securityHeaders = snapshotSecurityHeaders(res.headers);
    const waf = detectWaf(res.headers, text);
    const ct = res.headers.get('content-type') || '';
    let surface = null;
    if (/text\/html|application\/xhtml/i.test(ct)) {
      try {
        surface = extractHtmlSurface(text, res.url);
      } catch {
        surface = null;
      }
    }
    const out = {
      ok: true,
      url: res.url,
      status: res.status,
      title,
      tech,
      waf,
      securityHeaders,
      surface,
      /** Primeiros bytes HTML (só text/html) — comentários / heurísticas sem novo fetch. */
      htmlSample: /text\/html|application\/xhtml/i.test(ct) ? text : '',
    };
    if (modules.includes('header_intel')) {
      out.responseHeadersFlat = flattenResponseHeaderPairs(res.headers);
    }
    return out;
  } catch (e) {
    if (signal?.aborted) throw signal.reason || e;
    return {
      ok: false,
      url,
      error: timedOut || e.name === 'TimeoutError' ? 'timeout' : String(e.message || e),
    };
  } finally {
    clearTimeout(t);
    signal?.removeEventListener('abort', forwardAbort);
  }
}

export async function mapPool(items, concurrency, fn, opts = {}) {
  return runMapPool(items, concurrency, fn, opts);
}
