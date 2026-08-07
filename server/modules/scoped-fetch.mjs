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

/**
 * @param {string} url
 * @param {RequestInit & { fetchImpl?: typeof fetch, urlAllowed?: (u: string) => boolean, maxRedirects?: number }} opts
 */
export async function fetchScoped(url, opts = {}) {
  const {
    fetchImpl = globalThis.fetch,
    urlAllowed = null,
    maxRedirects = 5,
    ...init
  } = opts;
  if (typeof fetchImpl !== 'function') {
    throw new Error('fetch indisponível');
  }

  let current = String(url || '');
  if (!current) throw new Error('url vazia');

  for (let hop = 0; hop <= Math.max(0, maxRedirects); hop += 1) {
    const allowed = resolveUrlAllowed(current, urlAllowed);
    if (allowed(current) !== true) {
      const error = new Error(`redirect/url fora do escopo autorizado: ${current}`);
      error.code = 'OUT_OF_SCOPE';
      throw error;
    }

    const res = await fetchImpl(current, {
      ...init,
      redirect: 'manual',
    });

    const finalUrl = res.url || current;
    if (allowed(finalUrl) !== true) {
      const error = new Error(`resposta fora do escopo autorizado: ${finalUrl}`);
      error.code = 'OUT_OF_SCOPE';
      throw error;
    }

    if (res.status >= 300 && res.status < 400) {
      const location = res.headers?.get?.('location') || res.headers?.get?.('Location');
      if (!location) return res;
      let next;
      try {
        next = new URL(location, finalUrl).href;
      } catch {
        const error = new Error(`Location inválido: ${location}`);
        error.code = 'OUT_OF_SCOPE';
        throw error;
      }
      if (allowed(next) !== true) {
        const error = new Error(`redirect fora do escopo autorizado: ${next}`);
        error.code = 'OUT_OF_SCOPE';
        throw error;
      }
      current = next;
      continue;
    }

    return res;
  }

  const error = new Error(`excesso de redirects (${maxRedirects})`);
  error.code = 'TOO_MANY_REDIRECTS';
  throw error;
}

export function urlAllowedOrSameOrigin(baseUrl, urlAllowed) {
  if (typeof urlAllowed === 'function') return urlAllowed;
  return defaultUrlAllowed(baseUrl);
}
