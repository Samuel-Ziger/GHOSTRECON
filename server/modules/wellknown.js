import { limits, UA } from '../config.js';
import { fetchScoped, urlAllowedOrSameOrigin } from './scoped-fetch.mjs';

function parseSecurityTxt(text) {
  const out = {};
  const lines = String(text || '').split(/\r?\n/);
  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const idx = line.indexOf(':');
    if (idx <= 0) continue;
    const key = line.slice(0, idx).trim().toLowerCase();
    const value = line.slice(idx + 1).trim();
    if (!key || !value) continue;
    if (!out[key]) out[key] = [];
    out[key].push(value);
  }
  return out;
}

function normalizeEndpointUrl(endpointValue, baseOrigin) {
  const v = String(endpointValue || '').trim();
  if (!v) return null;
  if (/^https?:\/\//i.test(v)) return v;
  try {
    // endpointValue pode ser path relativo.
    return new URL(v.startsWith('/') ? v : `/${v}`, baseOrigin).href;
  } catch {
    return null;
  }
}

async function fetchText(url, timeoutMs, urlAllowed = null) {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), Math.max(1, timeoutMs || 8000));
  try {
    const res = await fetchScoped(url, {
      method: 'GET',
      signal: controller.signal,
      headers: { 'User-Agent': UA, Accept: 'text/plain,*/*;q=0.8' },
      urlAllowed: urlAllowedOrSameOrigin(url, urlAllowed),
    });
    if (!res.ok) return null;
    return await res.text();
  } catch (error) {
    if (error?.code === 'OUT_OF_SCOPE' || error?.code === 'TOO_MANY_REDIRECTS') return null;
    throw error;
  } finally {
    clearTimeout(t);
  }
}

async function fetchJson(url, timeoutMs, urlAllowed = null) {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), Math.max(1, timeoutMs || 8000));
  try {
    const res = await fetchScoped(url, {
      method: 'GET',
      signal: controller.signal,
      headers: { 'User-Agent': UA, Accept: 'application/json,*/*;q=0.8' },
      urlAllowed: urlAllowedOrSameOrigin(url, urlAllowed),
    });
    if (!res.ok) return null;
    const txt = await res.text();
    try {
      return JSON.parse(txt);
    } catch {
      return null;
    }
  } catch (error) {
    if (error?.code === 'OUT_OF_SCOPE' || error?.code === 'TOO_MANY_REDIRECTS') return null;
    throw error;
  } finally {
    clearTimeout(t);
  }
}

/**
 * security.txt via /.well-known (origem já inclui http/https e trailing "/")
 * @returns {Promise<{findings:Array<object>, raw?:string}>}
 */
export async function fetchWellKnownSecurityTxt(baseOrigin, { urlAllowed = null } = {}) {
  const url = new URL('/.well-known/security.txt', baseOrigin).href;
  const text = await fetchText(url, limits.wellKnownSecurityTxtTimeoutMs, urlAllowed);
  if (!text) return { ok: false, findings: [] };

  const parsed = parseSecurityTxt(text);

  const findings = [];
  if (parsed.contact?.length) {
    findings.push({
      type: 'intel',
      prio: 'low',
      score: 22,
      value: `security.txt contact: ${parsed.contact[0].slice(0, 120)}`,
      meta: url,
      url,
    });
  }
  if (parsed.encryption?.length) {
    findings.push({
      type: 'intel',
      prio: 'low',
      score: 26,
      value: `security.txt encryption: ${parsed.encryption[0].slice(0, 160)}`,
      meta: url,
      url,
    });
  }
  if (parsed.policy?.length) {
    findings.push({
      type: 'intel',
      prio: 'low',
      score: 24,
      value: `security.txt policy: ${parsed.policy[0].slice(0, 160)}`,
      meta: url,
      url,
    });
  }

  return { ok: true, findings };
}

/**
 * Descoberta OIDC (open id-configuration) via /.well-known
 * @returns {Promise<{ok:boolean, endpoints:Array<{url:string, label:string}>}>}
 */
export async function fetchWellKnownOpenIdConfiguration(baseOrigin, { urlAllowed = null } = {}) {
  const url = new URL('/.well-known/openid-configuration', baseOrigin).href;
  const allowed = urlAllowedOrSameOrigin(url, urlAllowed);
  const data = await fetchJson(url, limits.wellKnownOpenIdTimeoutMs, allowed);
  if (!data) return { ok: false, endpoints: [] };

  const fields = [
    'authorization_endpoint',
    'token_endpoint',
    'userinfo_endpoint',
    'jwks_uri',
    'end_session_endpoint',
    'introspection_endpoint',
    'revocation_endpoint',
    'device_authorization_endpoint',
  ];

  const endpoints = [];
  for (const f of fields) {
    if (data[f]) {
      const u = normalizeEndpointUrl(data[f], baseOrigin);
      if (u && allowed(u) === true) endpoints.push({ url: u, label: f });
    }
  }

  // Dedup por URL
  const seen = new Set();
  const dedup = [];
  for (const e of endpoints) {
    if (seen.has(e.url)) continue;
    seen.add(e.url);
    dedup.push(e);
  }

  return { ok: true, endpoints: dedup.slice(0, limits.wellKnownOpenIdMaxEndpoints), metadata: data };
}
