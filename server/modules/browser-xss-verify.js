/**
 * Verificação opcional em browser (Playwright) para XSS refletido simples.
 * Ative com GHOSTRECON_PLAYWRIGHT_XSS=1 e `npm install playwright` (+ browsers).
 */
import { throwIfAborted } from './http-utils.js';

function abortReason(signal) {
  return signal?.reason || new DOMException('The operation was aborted', 'AbortError');
}

async function raceWithAbort(operation, signal, onAbort = null) {
  if (!signal) return operation;
  throwIfAborted(signal);

  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (fn, value) => {
      if (settled) return;
      settled = true;
      signal.removeEventListener('abort', handleAbort);
      fn(value);
    };
    const handleAbort = () => {
      try {
        Promise.resolve(onAbort?.()).catch(() => {});
      } catch {
        // best-effort: o erro de cancelamento original continua sendo o resultado.
      }
      finish(reject, abortReason(signal));
    };
    signal.addEventListener('abort', handleAbort, { once: true });
    Promise.resolve(operation).then(
      (value) => finish(resolve, value),
      (error) => finish(reject, error),
    );
  });
}

function markerFor(f, i) {
  return `gr_xss_${Date.now().toString(36)}_${i}_${Math.random().toString(36).slice(2, 6)}`;
}

function pickCandidateUrls(findings, limit) {
  const out = [];
  const seen = new Set();
  for (const f of findings || []) {
    if (out.length >= limit) break;
    if (f?.type !== 'xss' && f?.type !== 'param' && f?.type !== 'endpoint') continue;
    const u = f.url || (typeof f.value === 'string' && /^https?:\/\//i.test(f.value) ? f.value : null);
    if (!u || !/\?./.test(u) || seen.has(u)) continue;
    seen.add(u);
    out.push({ f, url: u });
  }
  return out;
}

/**
 * @returns {Promise<object[]>} novos findings (tipo intel) com nota de DOM
 */
export async function runOptionalPlaywrightXssProbe({
  findings,
  log,
  limit = 4,
  signal = null,
  chromiumImpl = null,
}) {
  const enabled = String(process.env.GHOSTRECON_PLAYWRIGHT_XSS || '').trim() === '1';
  if (!enabled) return [];
  throwIfAborted(signal);

  let chromium = chromiumImpl;
  if (!chromium) {
    try {
      const pw = await import('playwright');
      chromium = pw.chromium;
    } catch (e) {
      if (signal?.aborted) throw signal.reason || e;
      if (typeof log === 'function') log(`Playwright: módulo não disponível (${e?.message || e})`, 'warn');
      return [];
    }
  }

  const candidates = pickCandidateUrls(findings, Math.max(1, Number(process.env.GHOSTRECON_PLAYWRIGHT_XSS_MAX || limit)));
  if (!candidates.length) return [];

  if (typeof log === 'function') log(`Playwright XSS: ${candidates.length} URL(s) com query`, 'info');

  const launchPromise = Promise.resolve().then(() => chromium.launch({ headless: true }));
  if (signal) {
    launchPromise
      .then((lateBrowser) => {
        if (signal.aborted) return Promise.resolve(lateBrowser?.close?.()).catch(() => {});
        return null;
      })
      .catch(() => {});
  }
  let browser;
  try {
    browser = await raceWithAbort(launchPromise, signal);
  } catch (e) {
    if (signal?.aborted) throw signal.reason || e;
    if (typeof log === 'function') log(`Playwright: falha ao iniciar browser (${e?.message || e})`, 'warn');
    return [];
  }
  if (!browser) return [];
  const out = [];
  try {
    const page = await raceWithAbort(
      browser.newPage({ javaScriptEnabled: true }),
      signal,
      () => browser.close(),
    );
    let i = 0;
    for (const { url } of candidates) {
      throwIfAborted(signal);
      i += 1;
      const m = markerFor(null, i);
      let testUrl;
      try {
        const u = new URL(url);
        const keys = [...u.searchParams.keys()];
        const pk = keys[0];
        if (!pk) continue;
        u.searchParams.set(pk, `${m}`);
        testUrl = u.href;
      } catch {
        continue;
      }
      try {
        await raceWithAbort(
          page.goto(testUrl, { waitUntil: 'domcontentloaded', timeout: 18_000 }),
          signal,
          () => page.close(),
        );
        const html = await raceWithAbort(page.content(), signal, () => page.close());
        const inDom = html.includes(m);
        out.push({
          type: 'intel',
          prio: inDom ? 'high' : 'low',
          score: inDom ? 78 : 28,
          value: `Playwright DOM probe (${inDom ? 'marker presente' : 'marker ausente'})`,
          meta: `tool=playwright_xss • url=${testUrl.slice(0, 220)} • marker=${m}`,
          url: testUrl,
        });
      } catch (e) {
        if (signal?.aborted) throw signal.reason || e;
        out.push({
          type: 'intel',
          prio: 'low',
          score: 22,
          value: 'Playwright XSS: navegação falhou',
          meta: `tool=playwright_xss • err=${String(e?.message || e).slice(0, 160)}`,
          url: testUrl,
        });
      }
    }
  } finally {
    await Promise.resolve(browser.close()).catch(() => {});
  }
  return out;
}
