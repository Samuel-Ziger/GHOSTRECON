import { reconHttpContext } from './http-history.mjs';

export function installOutboundFetch({
  history,
  torIsStrict,
  createSocksDispatcher,
  firstProxyPoolEntry = defaultFirstProxyPoolEntry,
} = {}) {
  if (!history) throw new Error('installOutboundFetch: history store required');
  const originalFetch = globalThis.fetch ? globalThis.fetch.bind(globalThis) : null;
  if (!originalFetch || globalThis.__ghostreconFetchHistoryWrapped) {
    return { installed: false, originalFetch };
  }

  const strictFetchDispatchers = new Map();
  const {
    normalizeHeadersForHistory,
    bodyPreviewForHistory,
    redactBodyTextForHistory,
    recordReconHttpHistory,
    responsePreviewMax,
  } = history;

  function isLoopbackFetchTarget(input) {
    try {
      const raw = typeof input === 'string' ? input : String(input?.url || input || '');
      const u = new URL(raw);
      return u.hostname === '127.0.0.1' || u.hostname === 'localhost' || u.hostname === '::1';
    } catch {
      return false;
    }
  }

  async function strictFetchInit(input, init = {}) {
    if (!torIsStrict?.() || init?.dispatcher || isLoopbackFetchTarget(input)) return init || {};
    const proxyHref = firstProxyPoolEntry();
    if (!/^socks(5h?|4a?):\/\//i.test(proxyHref)) {
      throw new Error('tor-strict: GHOSTRECON_PROXY_POOL sem SOCKS — fetch direto bloqueado');
    }
    let dispatcher = strictFetchDispatchers.get(proxyHref);
    if (!dispatcher) {
      dispatcher = await createSocksDispatcher(proxyHref);
      strictFetchDispatchers.set(proxyHref, dispatcher);
    }
    return { ...(init || {}), dispatcher };
  }

  globalThis.__ghostreconFetchHistoryWrapped = true;
  globalThis.fetch = async (input, init = {}) => {
    const ctx = reconHttpContext.getStore();
    if (!ctx) return originalFetch(input, await strictFetchInit(input, init));

    const started = Date.now();
    let method = String(init?.method || '').toUpperCase();
    let url = '';
    let reqHeaders = {};
    let reqBody = bodyPreviewForHistory(init?.body);
    try {
      if (typeof Request !== 'undefined' && input instanceof Request) {
        url = input.url;
        method = method || String(input.method || 'GET').toUpperCase();
        reqHeaders = normalizeHeadersForHistory(input.headers);
        if (!reqBody && method !== 'GET' && method !== 'HEAD') {
          try {
            reqBody = await input.clone().text();
            reqBody = reqBody.slice(0, 8000);
          } catch {
            reqBody = '';
          }
        }
      } else {
        url = typeof input === 'string' ? input : String(input?.url || input || '');
        method = method || 'GET';
      }
      reqHeaders = { ...reqHeaders, ...normalizeHeadersForHistory(init?.headers) };
    } catch {
      url = String(input || '');
      method = method || 'GET';
    }

    try {
      const effectiveInit = await strictFetchInit(input, init);
      const response = await originalFetch(input, effectiveInit);
      const respHeaders = normalizeHeadersForHistory(response.headers);
      const mimeType = (response.headers.get('content-type') || '').split(';')[0].trim();
      const contentLengthHdr = response.headers.get('content-length');
      const row = recordReconHttpHistory({
        ...ctx,
        source: 'fetch',
        method,
        url,
        requestHeaders: reqHeaders,
        requestBody: reqBody,
        status: response.status,
        statusText: response.statusText,
        ok: response.ok,
        durationMs: Date.now() - started,
        responseHeaders: respHeaders,
        mimeType,
        responseSize: contentLengthHdr ? Number(contentLengthHdr) : null,
      });
      response
        .clone()
        .text()
        .then((body) => {
          row.responseBody = redactBodyTextForHistory(body).slice(0, responsePreviewMax);
          if (row.responseSize == null) row.responseSize = body.length;
        })
        .catch(() => {});
      return response;
    } catch (e) {
      recordReconHttpHistory({
        ...ctx,
        source: 'fetch',
        method,
        url,
        requestHeaders: reqHeaders,
        requestBody: reqBody,
        durationMs: Date.now() - started,
        error: e?.message || String(e),
      });
      throw e;
    }
  };

  return { installed: true, originalFetch };
}

function defaultFirstProxyPoolEntry() {
  return (
    String(process.env.GHOSTRECON_PROXY_POOL || '')
      .split(/[,;\n]/)
      .map((s) => s.trim())
      .filter(Boolean)[0] || 'socks5h://127.0.0.1:9050'
  );
}
