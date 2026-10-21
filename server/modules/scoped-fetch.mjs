/**
 * Fetch com redirect manual + validação de escopo antes de seguir Location.
 * Evita enviar a segunda request para origem fora da allowlist.
 */

function sameOrigin(a, b) {
  try {
    const left = new URL(a);
    const right = new URL(b);
    return left.origin === right.origin;
  } catch {
    return false;
  }
}

function defaultUrlAllowed(requestUrl) {
  return (candidate) => sameOrigin(requestUrl, candidate);
}

function resolveUrlAllowed(requestUrl, urlAllowed) {
  if (typeof urlAllowed === 'function') return urlAllowed;
  return defaultUrlAllowed(requestUrl);
}

function closeRedirectBody(response) {
  try {
    if (typeof response?.body?.cancel === 'function') {
      Promise.resolve(response.body.cancel()).catch(() => {});
    }
  } catch {
    // O redirect continua bloqueado/limitado mesmo se o transporte nao atestar cancelamento.
  }
}

async function fetchWithSignal(fetchImpl, url, init) {
  const signal = init?.signal || null;
  if (signal?.aborted) throw signal.reason || new DOMException('cancelado', 'AbortError');
  const pending = Promise.resolve().then(() => fetchImpl(url, init));
  if (!signal) return pending;
  return new Promise((resolve, reject) => {
    let settled = false;
    const cleanup = () => signal.removeEventListener('abort', onAbort);
    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      cleanup();
      callback(value);
    };
    const onAbort = () => finish(
      reject,
      signal.reason || new DOMException('cancelado', 'AbortError'),
    );
    signal.addEventListener('abort', onAbort, { once: true });
    pending.then((response) => {
      if (signal.aborted) {
        closeRedirectBody(response);
        finish(reject, signal.reason || new DOMException('cancelado', 'AbortError'));
        return;
      }
      finish(resolve, response);
    }, (error) => finish(reject, error));
    if (signal.aborted) onAbort();
  });
}

/**
 * @param {string} url
 * @param {RequestInit & { fetchImpl?: typeof fetch, urlAllowed?: (u: string) => boolean, maxRedirects?: number, returnMeta?: boolean }} opts
 */
export async function fetchScoped(url, opts = {}) {
  const {
    fetchImpl = globalThis.fetch,
    urlAllowed = null,
    maxRedirects = 5,
    returnMeta = false,
    ...init
  } = opts;
  if (typeof fetchImpl !== 'function') {
    throw new Error('fetch indisponível');
  }

  let current = String(url || '');
  if (!current) throw new Error('url vazia');

  for (let hop = 0; hop <= Math.max(0, maxRedirects); hop += 1) {
    if (init.signal?.aborted) {
      throw init.signal.reason || new DOMException('cancelado', 'AbortError');
    }
    const allowed = resolveUrlAllowed(current, urlAllowed);
    if (allowed(current) !== true) {
      const error = new Error(`redirect/url fora do escopo autorizado: ${current}`);
      error.code = 'OUT_OF_SCOPE';
      throw error;
    }

    const res = await fetchWithSignal(fetchImpl, current, {
      ...init,
      redirect: 'manual',
    });
    if (init.signal?.aborted) {
      closeRedirectBody(res);
      throw init.signal.reason || new DOMException('cancelado', 'AbortError');
    }

    const finalUrl = res.url || current;
    if (allowed(finalUrl) !== true) {
      closeRedirectBody(res);
      const error = new Error(`resposta fora do escopo autorizado: ${finalUrl}`);
      error.code = 'OUT_OF_SCOPE';
      throw error;
    }

    if (res.status >= 300 && res.status < 400) {
      const location = res.headers?.get?.('location') || res.headers?.get?.('Location');
      if (!location) {
        return returnMeta ? { response: res, url: finalUrl, redirects: hop } : res;
      }
      let next;
      try {
        next = new URL(location, finalUrl).href;
      } catch {
        closeRedirectBody(res);
        const error = new Error(`Location inválido: ${location}`);
        error.code = 'OUT_OF_SCOPE';
        throw error;
      }
      if (allowed(next) !== true) {
        closeRedirectBody(res);
        const error = new Error(`redirect fora do escopo autorizado: ${next}`);
        error.code = 'OUT_OF_SCOPE';
        throw error;
      }
      closeRedirectBody(res);
      current = next;
      continue;
    }

    return returnMeta ? { response: res, url: finalUrl, redirects: hop } : res;
  }

  const error = new Error(`excesso de redirects (${maxRedirects})`);
  error.code = 'TOO_MANY_REDIRECTS';
  throw error;
}

export function urlAllowedOrSameOrigin(baseUrl, urlAllowed) {
  if (typeof urlAllowed === 'function') return urlAllowed;
  return defaultUrlAllowed(baseUrl);
}
