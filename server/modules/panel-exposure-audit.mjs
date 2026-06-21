import { limits } from '../config.js';
import { mapPool, readResponseSnippet } from './module-runner.mjs';
import { pickStealthUserAgent, stealthPause } from './request-policy.js';

export const moduleManifest = {
  id: 'panel_exposure_audit',
  name: 'Panel Exposure Audit',
  category: 'surface',
  intrusive: false,
  requiresAuth: false,
  requiresKali: false,
  timeoutMs: 25_000,
  concurrency: 3,
  outputs: ['finding'],
};

const PANEL_PATHS = [
  '/admin',
  '/administrator',
  '/login',
  '/dashboard',
  '/console',
  '/grafana',
  '/kibana',
  '/jenkins',
  '/actuator',
  '/actuator/health',
  '/prometheus',
  '/metrics',
  '/phpmyadmin',
  '/wp-admin/',
  '/server-status',
  '/debug',
];

const TITLE_RE = /<title[^>]*>([^<]{0,180})<\/title>/i;

function metaText(meta) {
  return Object.entries(meta || {})
    .filter(([, v]) => v != null && v !== '')
    .map(([k, v]) => `${k}=${Array.isArray(v) ? v.join(',') : String(v)}`)
    .join(' - ');
}

function classifyPanel(url, status, body, headers) {
  const text = String(body || '').slice(0, 120_000);
  const lower = text.toLowerCase();
  const ct = String(headers?.get?.('content-type') || '').toLowerCase();
  const title = (text.match(TITLE_RE)?.[1] || '').trim().replace(/\s+/g, ' ');
  const path = (() => { try { return new URL(url).pathname.toLowerCase(); } catch { return ''; } })();
  const markers = [];

  if (/grafana/i.test(`${title} ${text.slice(0, 3000)}`) || path.includes('grafana')) markers.push('grafana');
  if (/kibana|elastic/i.test(`${title} ${text.slice(0, 3000)}`) || path.includes('kibana')) markers.push('kibana');
  if (/jenkins/i.test(`${title} ${text.slice(0, 3000)}`) || path.includes('jenkins')) markers.push('jenkins');
  if (/phpmyadmin/i.test(`${title} ${text.slice(0, 3000)}`) || path.includes('phpmyadmin')) markers.push('phpmyadmin');
  if (/wordpress/i.test(`${title} ${text.slice(0, 3000)}`) || path.includes('wp-admin')) markers.push('wordpress_admin');
  if (/prometheus/i.test(`${title} ${text.slice(0, 3000)}`) || path.includes('prometheus')) markers.push('prometheus');
  if (/spring boot|actuator|{"status":"up"/i.test(`${title} ${text.slice(0, 3000)}`) || path.includes('actuator')) markers.push('spring_actuator');
  if (/server status|apache status/i.test(`${title} ${text.slice(0, 3000)}`) || path.includes('server-status')) markers.push('server_status');
  if (/\b(admin|dashboard|console|sign in|login)\b/i.test(`${title} ${text.slice(0, 2000)}`)) markers.push('login_panel');
  if (ct.includes('json') && /"(?:status|version|build|health)"/i.test(text)) markers.push('json_status');

  if (!markers.length) return null;
  const sensitive = markers.some((m) => /actuator|prometheus|server_status|json_status|jenkins|kibana|grafana/.test(m));
  return {
    title,
    markers: [...new Set(markers)],
    prio: sensitive && status < 400 ? 'med' : 'low',
    score: sensitive && status < 400 ? 58 : 36,
  };
}

async function probePath(url, { modules = [], fetchImpl = fetch } = {}) {
  await stealthPause(modules);
  const res = await fetchImpl(url, {
    method: 'GET',
    redirect: 'follow',
    signal: AbortSignal.timeout(Math.min(9000, limits.probeTimeoutMs || 9000)),
    headers: {
      Accept: 'text/html,application/json,text/plain,*/*;q=0.8',
      'User-Agent': pickStealthUserAgent(modules),
    },
  });
  if (![200, 401, 403].includes(res.status)) return null;
  const body = await readResponseSnippet(res, 180_000);
  const hit = classifyPanel(res.url || url, res.status, body, res.headers);
  if (!hit) return null;
  return {
    type: 'panel',
    prio: hit.prio,
    score: hit.score,
    value: `Painel/superficie administrativa detectada: ${res.url || url}`,
    meta: metaText({
      source: 'panel_exposure_audit',
      status: res.status,
      markers: hit.markers,
      title: hit.title,
      safe_check: 'single_get_common_path',
      note: 'Nao foi feito brute force nem tentativa de login',
    }),
    url: res.url || url,
    owasp: 'A05:2021',
    mitre: 'T1592',
  };
}

export async function runPanelExposureAudit({
  origins = [],
  modules = [],
  fetchImpl = fetch,
  log = () => {},
} = {}) {
  const maxOrigins = Math.max(1, Math.min(20, Number(process.env.GHOSTRECON_PANEL_MAX_ORIGINS || 8)));
  const maxPaths = Math.max(1, Math.min(PANEL_PATHS.length, Number(process.env.GHOSTRECON_PANEL_MAX_PATHS || 12)));
  const bases = [...new Set((origins || []).map((o) => String(o || '').replace(/\/$/, '')))].slice(0, maxOrigins);
  const jobs = [];
  for (const base of bases) {
    for (const path of PANEL_PATHS.slice(0, maxPaths)) {
      try { jobs.push(new URL(path, `${base}/`).href); } catch { /* skip */ }
    }
  }

  const findings = [];
  const seen = new Set();
  await mapPool(jobs, 3, async (url) => {
    try {
      const f = await probePath(url, { modules, fetchImpl });
      if (!f) return;
      const key = String(f.url || f.value).toLowerCase();
      if (seen.has(key)) return;
      seen.add(key);
      findings.push(f);
    } catch {
      /* common paths often 404/403/timeout; silence keeps log useful */
    }
  }, { timeoutMs: 12_000, label: 'panel exposure path' });

  if (findings.length) log(`Panel exposure: ${findings.length} painel/is ou endpoint(s) administrativo(s)`, 'warn');
  return findings;
}
