import { limits } from '../config.js';
import { pickStealthUserAgent, stealthPause } from './request-policy.js';
import { readResponseSnippet } from './module-runner.mjs';

export const moduleManifest = {
  id: 'service_worker_audit',
  name: 'Service Worker Audit',
  category: 'surface',
  intrusive: false,
  requiresAuth: false,
  requiresKali: false,
  timeoutMs: 20_000,
  concurrency: 2,
  outputs: ['finding'],
};

const COMMON_SW_PATHS = [
  '/service-worker.js',
  '/sw.js',
  '/worker.js',
  '/ngsw-worker.js',
  '/firebase-messaging-sw.js',
];

function prioFor(score) {
  if (score >= 72) return 'high';
  if (score >= 50) return 'med';
  if (score >= 30) return 'low';
  return 'info';
}

function metaText(meta) {
  return Object.entries(meta || {})
    .filter(([, v]) => v != null && v !== '')
    .map(([k, v]) => `${k}=${Array.isArray(v) ? v.join(',') : String(v)}`)
    .join(' - ');
}

function makeFinding({ issue, score, url, meta = {} }) {
  return {
    type: 'service_worker',
    prio: prioFor(score),
    score,
    value: issue,
    meta: metaText({ source: 'service_worker_audit', ...meta }),
    url,
    owasp: 'A08:2021',
  };
}

function resolveUrl(raw, baseUrl) {
  try { return new URL(raw || '', baseUrl).href; } catch { return ''; }
}

export function findServiceWorkerRegistrations(text, { baseUrl = '' } = {}) {
  const s = String(text || '').slice(0, 800_000);
  const out = [];
  const re = /(?:navigator\.)?serviceWorker\s*\.\s*register\s*\(\s*["'`]([^"'`]+)["'`](?:\s*,\s*({[\s\S]{0,300}?}))?/gi;
  let m;
  while ((m = re.exec(s)) !== null && out.length < 30) {
    const scriptUrl = resolveUrl(m[1], baseUrl);
    const opts = m[2] || '';
    const scopeMatch = opts.match(/scope\s*:\s*["'`]([^"'`]+)["'`]/i);
    out.push({
      scriptUrl,
      scope: scopeMatch ? resolveUrl(scopeMatch[1], baseUrl) : '',
      raw: m[0].replace(/\s+/g, ' ').slice(0, 220),
    });
  }
  return out.filter((x) => x.scriptUrl);
}

export function auditServiceWorkerScript(text, { url = '', headers = null, registration = null } = {}) {
  const s = String(text || '').slice(0, 1_000_000);
  const findings = [];
  const headerAllowed = headers?.get?.('service-worker-allowed') || headers?.['service-worker-allowed'] || '';
  const push = (issue, score, meta = {}) => findings.push(makeFinding({ issue, score, url, meta }));

  if (!s) return findings;
  if (/importScripts\s*\(\s*["'`]http:\/\//i.test(s)) {
    push('Service Worker importa script via HTTP', 82, { reason: 'importScripts_http' });
  }
  if (/importScripts\s*\([^)]*(?:cdn|unpkg|jsdelivr|cloudfront|third-party|analytics)/i.test(s)) {
    push('Service Worker importa script externo/terceiro', 58, { reason: 'importScripts_external' });
  }
  if (/self\.skipWaiting\s*\(/i.test(s) && /clients\.claim\s*\(/i.test(s)) {
    push('Service Worker assume controle imediatamente (skipWaiting + clients.claim)', 44, { reason: 'immediate_takeover' });
  }
  if (/addEventListener\s*\(\s*["'`]fetch["'`]/i.test(s) && /caches?\.(?:match|open|put|add|addAll)/i.test(s)) {
    const sensitiveCache = /(?:\/api\/|graphql|token|auth|session|account|profile|me\b|user\b|admin)/i.test(s);
    if (sensitiveCache) {
      push('Service Worker pode cachear respostas sensiveis', 64, { reason: 'sensitive_cache_pattern' });
    } else {
      push('Service Worker intercepta fetch e usa Cache API', 34, { reason: 'fetch_cache_review' });
    }
  }
  if (/cache(?:Name)?\s*[:=]\s*["'`][^"'`]*(?:v1|dev|test|debug)/i.test(s)) {
    push('Service Worker usa nome de cache com indicio dev/test', 36, { reason: 'cache_name_dev_hint' });
  }
  if (headerAllowed && String(headerAllowed).trim() === '/') {
    push('Service-Worker-Allowed permite escopo raiz', 48, { reason: 'root_scope_header' });
  }
  if (registration?.scope) {
    try {
      const scopePath = new URL(registration.scope).pathname;
      if (scopePath === '/') push('Service Worker registrado com scope raiz', 44, { reason: 'root_scope_registration' });
    } catch { /* ignore */ }
  }
  return findings;
}

async function fetchWorker(url, { fetchImpl = fetch, timeoutMs = 8_000, headers = {} } = {}) {
  const res = await fetchImpl(url, {
    method: 'GET',
    redirect: 'follow',
    signal: AbortSignal.timeout(timeoutMs),
    headers: {
      Accept: 'application/javascript,text/javascript,*/*;q=0.8',
      ...headers,
    },
  });
  if (!res.ok) return null;
  const ct = String(res.headers?.get?.('content-type') || '').toLowerCase();
  if (ct && !/javascript|ecmascript|text\/plain|application\/octet-stream/.test(ct)) return null;
  const text = await readResponseSnippet(res, 1_000_000);
  if (!/serviceworker|addEventListener\s*\(\s*["'`](?:install|activate|fetch)|importScripts|workbox|caches\./i.test(text)) {
    return null;
  }
  return { text, headers: res.headers, url: res.url || url };
}

export async function runServiceWorkerAudit({
  probeResults = [],
  origins = [],
  modules = [],
  fetchImpl = fetch,
  log = () => {},
} = {}) {
  const ua = pickStealthUserAgent(modules);
  const timeoutMs = Math.min(12_000, limits.probeTimeoutMs || 10_000);
  const candidates = [];
  const seen = new Set();

  for (const row of probeResults || []) {
    const r = row?.r || row;
    if (!r?.ok || !r.htmlSample) continue;
    for (const reg of findServiceWorkerRegistrations(r.htmlSample, { baseUrl: r.url })) {
      candidates.push(reg);
    }
  }
  for (const origin of origins || []) {
    for (const p of COMMON_SW_PATHS) {
      try { candidates.push({ scriptUrl: new URL(p, origin).href, scope: '' }); } catch { /* skip */ }
    }
  }

  const findings = [];
  for (const c of candidates) {
    if (!c?.scriptUrl || seen.has(c.scriptUrl)) continue;
    seen.add(c.scriptUrl);
    await stealthPause(modules);
    const worker = await fetchWorker(c.scriptUrl, {
      fetchImpl,
      timeoutMs,
      headers: { 'User-Agent': ua },
    }).catch(() => null);
    if (!worker) continue;
    const rows = auditServiceWorkerScript(worker.text, {
      url: worker.url,
      headers: worker.headers,
      registration: c,
    });
    findings.push(...rows);
    if (rows.length) log(`Service Worker audit: ${rows.length} achado(s) em ${worker.url}`, 'warn');
    else log(`Service Worker audit: ${worker.url} sem alerta`, 'info');
  }

  return findings;
}
