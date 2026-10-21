import { limits } from '../config.js';
import { mapPool, readResponseSnippet } from './module-runner.mjs';
import { pickStealthUserAgent, stealthPause } from './request-policy.js';
import { fetchScoped, urlAllowedOrSameOrigin } from './scoped-fetch.mjs';
import { combineAbortSignals, isAbortError, throwIfAborted } from './http-utils.js';

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
  const ct = String(headers?.get?.('content-type') || '').toLowerCase();
  const title = (text.match(TITLE_RE)?.[1] || '').trim().replace(/\s+/g, ' ');
  const markers = [];

  if (/\bgrafana\b|grafana-app/i.test(`${title} ${text.slice(0, 5000)}`)) markers.push('grafana');
  if (/\bkibana\b|elastic[ -]stack/i.test(`${title} ${text.slice(0, 5000)}`)) markers.push('kibana');
  if (/\bjenkins\b|jenkins-agent-protocols/i.test(`${title} ${text.slice(0, 5000)}`)) markers.push('jenkins');
  if (/\bphpmyadmin\b|pmahomme/i.test(`${title} ${text.slice(0, 5000)}`)) markers.push('phpmyadmin');
  if (/wp-login\.php|wordpress/i.test(`${title} ${text.slice(0, 5000)}`)) markers.push('wordpress_admin');
  if (/\bprometheus\b|prometheus_http_requests_total/i.test(`${title} ${text.slice(0, 5000)}`)) markers.push('prometheus');
  if (/spring boot|\bactuator\b|{"status"\s*:\s*"up"/i.test(`${title} ${text.slice(0, 5000)}`)) markers.push('spring_actuator');
  if (/server status for|apache server status/i.test(`${title} ${text.slice(0, 5000)}`)) markers.push('server_status');
  if (/\b(admin|dashboard|console|sign in|login)\b/i.test(`${title} ${text.slice(0, 2000)}`)) markers.push('login_panel');
  if (ct.includes('json') && /"(?:status|version|build|health)"/i.test(text)) markers.push('json_status');

  if (!markers.length) return null;
  return {
    title,
    markers: [...new Set(markers)],
    prio: 'info',
    score: 25,
  };
}

function normalizedBodySample(body) {
  return String(body || '')
    .slice(0, 32_000)
    .replace(/\b[0-9a-f]{16,}\b/gi, '<token>')
    .replace(/\b\d{6,}\b/g, '<number>')
    .replace(/\/ghostrecon-panel-baseline-[^\s"'<>]*/gi, '<baseline>')
    .replace(/\s+/g, ' ')
    .trim();
}

export function looksLikePanelSoft404(candidate, baseline) {
  if (!candidate || !baseline) return false;
  if (Number(candidate.status) !== Number(baseline.status)) return false;
  const left = normalizedBodySample(candidate.body);
  const right = normalizedBodySample(baseline.body);
  if (!left || !right) return false;
  if (left === right) return true;
  const lengthDelta = Math.abs(left.length - right.length) / Math.max(left.length, right.length, 1);
  const sameTitle = String(candidate.title || '').toLowerCase() === String(baseline.title || '').toLowerCase();
  const prefix = Math.min(1200, left.length, right.length);
  return sameTitle && lengthDelta <= 0.03 && prefix >= 80 && left.slice(0, prefix) === right.slice(0, prefix);
}

async function fetchPanelObservation(url, {
  modules = [], fetchImpl = fetch, urlAllowed = null, signal = null,
} = {}) {
  throwIfAborted(signal);
  await stealthPause(modules);
  const res = await fetchScoped(url, {
    fetchImpl,
    method: 'GET',
    urlAllowed: urlAllowedOrSameOrigin(url, urlAllowed),
    signal: combineAbortSignals(signal, Math.min(9000, limits.probeTimeoutMs || 9000)),
    headers: {
      Accept: 'text/html,application/json,text/plain,*/*;q=0.8',
      'User-Agent': pickStealthUserAgent(modules),
    },
  });
  const body = await readResponseSnippet(res, 180_000);
  const title = (body.match(TITLE_RE)?.[1] || '').trim().replace(/\s+/g, ' ');
  return { res, body, title, status: res.status, url: res.url || url };
}

async function probePath(url, {
  modules = [], fetchImpl = fetch, urlAllowed = null, signal = null, baseline = null,
} = {}) {
  const observation = await fetchPanelObservation(url, { modules, fetchImpl, urlAllowed, signal });
  const { res, body } = observation;
  if (![200, 401, 403].includes(res.status)) return null;
  if (looksLikePanelSoft404(observation, baseline)) return null;
  const hit = classifyPanel(res.url || url, res.status, body, res.headers);
  if (!hit) return null;
  return {
    type: 'panel',
    prio: hit.prio,
    score: hit.score,
    value: `Painel/superficie administrativa detectada: ${res.url || url}`,
    meta: metaText({
      source: 'panel_exposure_audit',
      evidence_status: 'inventory',
      authorization_tested: false,
      status: res.status,
      markers: hit.markers,
      title: hit.title,
      safe_check: 'single_get_common_path',
      note: 'Presença de painel não prova acesso indevido; nenhum login ou bypass foi testado',
    }),
    url: res.url || url,
    mitre: 'T1592',
  };
}

export async function runPanelExposureAudit({
  origins = [],
  modules = [],
  fetchImpl = fetch,
  urlAllowed = null,
  signal = null,
  baselinePathFactory = () => `/ghostrecon-panel-baseline-${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}-not-found`,
  log = () => {},
} = {}) {
  throwIfAborted(signal);
  const maxOrigins = Math.max(1, Math.min(20, Number(process.env.GHOSTRECON_PANEL_MAX_ORIGINS || 8)));
  const maxPaths = Math.max(1, Math.min(PANEL_PATHS.length, Number(process.env.GHOSTRECON_PANEL_MAX_PATHS || 12)));
  const bases = [...new Set((origins || []).map((o) => String(o || '').replace(/\/$/, '')))].slice(0, maxOrigins);
  const baselines = new Map();
  await mapPool(bases, 3, async (base) => {
    try {
      const baselineUrl = new URL(baselinePathFactory(base), `${base}/`).href;
      const observation = await fetchPanelObservation(baselineUrl, {
        modules, fetchImpl, urlAllowed, signal,
      });
      baselines.set(base, observation);
    } catch (error) {
      if (isAbortError(error, signal)) throw error;
    }
  }, { timeoutMs: 12_000, label: 'panel exposure baseline' });

  const jobs = [];
  for (const base of bases) {
    if (!baselines.has(base)) {
      log(`Panel exposure: baseline indisponível para ${base}; origem ignorada para evitar falso positivo`, 'info');
      continue;
    }
    for (const path of PANEL_PATHS.slice(0, maxPaths)) {
      try { jobs.push({ base, url: new URL(path, `${base}/`).href }); } catch { /* skip */ }
    }
  }

  const findings = [];
  const seen = new Set();
  await mapPool(jobs, 3, async ({ base, url }) => {
    try {
      const f = await probePath(url, {
        modules, fetchImpl, urlAllowed, signal, baseline: baselines.get(base) || null,
      });
      if (!f) return;
      const key = String(f.url || f.value).toLowerCase();
      if (seen.has(key)) return;
      seen.add(key);
      findings.push(f);
    } catch (error) {
      if (isAbortError(error, signal)) throw error;
      /* common paths often 404/403/timeout; silence keeps log useful */
    }
  }, { timeoutMs: 12_000, label: 'panel exposure path' });

  if (findings.length) log(`Panel exposure: ${findings.length} painel/is ou endpoint(s) administrativo(s)`, 'warn');
  return findings;
}
