import { readResponseSnippet } from './module-runner.mjs';

/**
 * Adapta o fetch central do pipeline ao contrato simples dos auditores legados.
 * Mantém proxy/identidade, AbortSignal, redirect manual, escopo e limite de corpo.
 */
export function createFetchRequestAdapter({
  fetchImpl = globalThis.fetch,
  urlAllowed = null,
  maxBytes = 64 * 1024,
} = {}) {
  return async function fetchRequestAdapter(url, options = {}) {
    if (typeof fetchImpl !== 'function') {
      return { status: null, headers: {}, body: '', error: 'fetch_unavailable' };
    }
    if (urlAllowed && !urlAllowed(url)) {
      return { status: null, headers: {}, body: '', error: 'out_of_scope' };
    }
    try {
      const res = await fetchImpl(url, {
        method: options.method || 'GET',
        headers: options.headers || {},
        body: options.body ?? undefined,
        signal: options.signal || null,
        redirect: 'manual',
      });
      const finalUrl = res.url || url;
      if (urlAllowed && !urlAllowed(finalUrl)) {
        return { status: null, headers: {}, body: '', error: 'out_of_scope_redirect' };
      }
      const headers = {};
      for (const [name, value] of res.headers?.entries?.() || []) headers[name.toLowerCase()] = value;
      const contentLength = Number(res.headers?.get?.('content-length') || 0);
      const body = contentLength > maxBytes ? '' : await readResponseSnippet(res, maxBytes);
      return { status: res.status, headers, body, error: null, url: finalUrl };
    } catch (error) {
      if (options.signal?.aborted) throw options.signal.reason || error;
      return { status: null, headers: {}, body: '', error: error?.message || String(error) };
    }
  };
}
