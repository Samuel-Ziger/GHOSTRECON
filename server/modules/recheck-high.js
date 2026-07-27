import { pickStealthUserAgent } from './request-policy.js';
import { combineAbortSignals, throwIfAborted } from './http-utils.js';

function buildHeaders(auth = {}, modules = []) {
  const h = {
    'User-Agent': pickStealthUserAgent(modules),
    Accept: 'text/html,application/xhtml+xml,application/json,*/*;q=0.8',
  };
  const extra = auth?.headers && typeof auth.headers === 'object' ? auth.headers : {};
  for (const [k, v] of Object.entries(extra)) {
    if (!k || v == null) continue;
    h[String(k)] = String(v);
  }
  if (auth?.cookie) h.Cookie = String(auth.cookie);
  return h;
}

function resolveUrl(f) {
  if (f?.url && /^https?:\/\//i.test(String(f.url))) return String(f.url);
  const v = f?.value;
  if (typeof v === 'string' && /^https?:\/\//i.test(v)) return v;
  return null;
}

/**
 * URLs de buscadores (Google/Bing/DDG/GitHub search) — um 200 aqui só significa
 * que o buscador respondeu, NÃO que o dork encontrou algo. Recheck inútil/enganoso.
 */
function isSearchEngineUrl(url) {
  try {
    const h = new URL(url).hostname.toLowerCase();
    if (/(?:^|\.)google\.[a-z.]+$/.test(h) && /\/search/.test(new URL(url).pathname)) return true;
    if (/(?:^|\.)(bing|duckduckgo|yandex|baidu)\./.test(h)) return true;
    if (h === 'github.com' && /\/search/.test(new URL(url).pathname)) return true;
    if (h === 'www.google.com' || h === 'google.com') return true;
    return false;
  } catch {
    return false;
  }
}

/**
 * Pedido HTTP leve em achados HIGH / HIGH_PROBABILITY com URL, para refrescar meta (status).
 */
export async function runHighPrioHttpRecheck({
  findings,
  auth,
  modules,
  log,
  limit = 20,
  signal = null,
  fetchImpl = globalThis.fetch,
}) {
  throwIfAborted(signal);
  if (typeof fetchImpl !== 'function') throw new TypeError('fetch implementation unavailable');
  const cap = Math.max(1, Number(process.env.GHOSTRECON_HIGH_RECHECK_MAX || limit));
  const picked = [];
  for (const f of findings || []) {
    if (picked.length >= cap) break;
    if (f?.prio !== 'high' && f?.attackTier !== 'HIGH_PROBABILITY') continue;
    // Dorks/sugestões não são verificáveis por GET — pular.
    if (f?.type === 'dork' || f?.confidence === 'suggestion') continue;
    const url = resolveUrl(f);
    if (!url) continue;
    // Recheck em página de buscador não verifica nada — só polui o meta.
    if (isSearchEngineUrl(url)) continue;
    picked.push({ f, url });
  }
  if (!picked.length) return { checked: 0 };
  if (typeof log === 'function') log(`Recheck HIGH: ${picked.length} URL(s) com GET rápido`, 'info');

  for (const { f, url } of picked) {
    throwIfAborted(signal);
    try {
      const res = await fetchImpl(url, {
        method: 'GET',
        redirect: 'manual',
        signal: combineAbortSignals(signal, 12_000),
        headers: buildHeaders(auth, modules),
      });
      const tag = `recheck_http=${res.status}@${new Date().toISOString()}`;
      f.meta = [f.meta, tag].filter(Boolean).join(' • ');
    } catch (e) {
      if (signal?.aborted) throw signal.reason || e;
      const tag = `recheck_http=err:${String(e?.message || e).slice(0, 80)}@${new Date().toISOString()}`;
      f.meta = [f.meta, tag].filter(Boolean).join(' • ');
    }
  }
  return { checked: picked.length };
}
