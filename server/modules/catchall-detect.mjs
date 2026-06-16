/**
 * catchall-detect.mjs
 *
 * Detector de catch-all / soft-404. SPAs (Vue/React/Angular) e alguns CDNs
 * (Cloudflare Pages, Netlify, etc.) respondem HTTP 200 + index.html para
 * QUALQUER caminho — inclusive paths inexistentes. Isso gera falsos positivos
 * em qualquer probe que confie apenas no status 200 (source maps, dotfiles,
 * endpoints "sem auth", dirsearch, etc.).
 *
 * Uso:
 *   const sig = await detectCatchAll(targetUrl, fetchImpl);
 *   if (matchesCatchAll(sig, { status, contentType, body })) // ignorar achado
 */

import { createHash } from 'crypto';

function hashBody(body) {
  return createHash('sha256').update(String(body || '').slice(0, 20_000), 'utf8').digest('hex');
}

function randomPath(ext = '') {
  const rand = Math.random().toString(36).slice(2, 12);
  const stamp = Date.now().toString(36);
  return `/ghostrecon-noexist-${rand}-${stamp}${ext}`;
}

async function fetchSample(url, fetchImpl, timeoutMs = 10_000) {
  const f = fetchImpl || globalThis.fetch;
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), timeoutMs);
  try {
    const res = await f(url, {
      headers: { Accept: '*/*' },
      redirect: 'manual',
      signal: ac.signal,
    });
    const body = await res.text();
    return {
      status: res.status,
      contentType: (res.headers?.get?.('content-type') || '').toLowerCase(),
      len: body.length,
      hash: hashBody(body),
    };
  } finally {
    clearTimeout(t);
  }
}

/**
 * Sonda 2 caminhos garantidamente inexistentes e decide se o alvo tem catch-all.
 * @returns {{catchAll:boolean,status:number|null,contentType:string|null,bodyLen:number|null,hashes:string[],samples:object[]}}
 */
export async function detectCatchAll(targetUrl, fetchImpl, { samples = 2, timeoutMs = 10_000 } = {}) {
  const sig = { catchAll: false, status: null, contentType: null, bodyLen: null, hashes: [], samples: [] };
  const f = fetchImpl || globalThis.fetch;
  if (!f || !targetUrl) return sig;

  const results = [];
  for (let i = 0; i < Math.max(2, samples); i += 1) {
    try {
      const url = new URL(randomPath(i % 2 ? '.php' : ''), targetUrl).href;
      results.push(await fetchSample(url, f, timeoutMs));
    } catch {
      // ignore (timeout/abort/parse)
    }
  }
  sig.samples = results;

  if (results.length >= 2) {
    const [a, b] = results;
    const both2xx = a.status >= 200 && a.status < 300 && b.status >= 200 && b.status < 300;
    const similar = a.hash === b.hash || Math.abs(a.len - b.len) <= Math.max(24, a.len * 0.03);
    if (both2xx && similar) {
      sig.catchAll = true;
      sig.status = a.status;
      sig.contentType = a.contentType;
      sig.bodyLen = a.len;
      sig.hashes = [...new Set([a.hash, b.hash])];
    }
  }
  return sig;
}

/**
 * Decide se uma resposta é, na verdade, a página catch-all do alvo.
 * @param {object|null} sig — saída de detectCatchAll
 * @param {{status?:number,contentType?:string,body?:string}} resp
 */
export function matchesCatchAll(sig, { status = null, contentType = null, body = null } = {}) {
  if (!sig || !sig.catchAll) return false;

  if (body != null) {
    const hash = hashBody(body);
    if (sig.hashes.includes(hash)) return true;
    if (sig.bodyLen != null) {
      const closeLen = Math.abs(String(body).length - sig.bodyLen) <= Math.max(24, sig.bodyLen * 0.05);
      const ct = String(contentType || '').split(';')[0].trim();
      const sigCt = String(sig.contentType || '').split(';')[0].trim();
      const sameCt = !ct || !sigCt || ct === sigCt;
      if (closeLen && sameCt) return true;
    }
  }

  // Sem corpo para comparar: se o status bate com o do catch-all e o content-type
  // é HTML (típico de fallback de SPA), trata como provável catch-all.
  if (body == null && status != null && status === sig.status) {
    const ct = String(contentType || '').split(';')[0].trim();
    if (ct && /html/.test(ct) && /html/.test(String(sig.contentType || ''))) return true;
  }

  return false;
}
