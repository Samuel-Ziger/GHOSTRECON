import { createHash } from 'node:crypto';
import { limits } from '../config.js';
import { pickStealthUserAgent, stealthPause } from './request-policy.js';
import { readResponseSnippet } from './module-runner.mjs';

export const moduleManifest = {
  id: 'jwt_jwks_audit',
  name: 'JWT / JWKS Audit',
  category: 'surface',
  intrusive: false,
  requiresAuth: false,
  requiresKali: false,
  timeoutMs: 20_000,
  concurrency: 2,
  outputs: ['finding'],
};

const COMMON_JWKS_PATHS = [
  '/.well-known/jwks.json',
  '/jwks.json',
  '/oauth2/jwks',
  '/oauth/jwks',
];

function b64urlBytes(s) {
  let raw = String(s || '').replace(/-/g, '+').replace(/_/g, '/');
  while (raw.length % 4) raw += '=';
  try { return Buffer.from(raw, 'base64'); } catch { return Buffer.alloc(0); }
}

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
    type: 'jwt_jwks',
    prio: prioFor(score),
    score,
    value: issue,
    meta: metaText({ source: 'jwt_jwks_audit', ...meta }),
    url,
    owasp: 'A02:2021',
    mitre: 'T1606',
  };
}

export function jwksFingerprint(jwks) {
  const keys = Array.isArray(jwks?.keys) ? jwks.keys : [];
  const slim = keys.map((k) => ({
    kty: k.kty || '',
    kid: k.kid || '',
    alg: k.alg || '',
    use: k.use || '',
    crv: k.crv || '',
    n: k.n ? createHash('sha256').update(String(k.n)).digest('hex').slice(0, 16) : '',
    x: k.x ? createHash('sha256').update(String(k.x)).digest('hex').slice(0, 16) : '',
  })).sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
  return createHash('sha256').update(JSON.stringify(slim)).digest('hex');
}

export function auditJwks(jwks, { url = '', issuer = '' } = {}) {
  const findings = [];
  const keys = Array.isArray(jwks?.keys) ? jwks.keys : [];
  if (!keys.length) {
    return [makeFinding({
      issue: 'JWKS publico sem chaves validas',
      score: 38,
      url,
      meta: { issuer, reason: 'keys_empty' },
    })];
  }

  const kidCount = new Map();
  for (const key of keys) {
    const kid = String(key?.kid || '').trim();
    if (kid) kidCount.set(kid, (kidCount.get(kid) || 0) + 1);
  }
  for (const [kid, count] of kidCount.entries()) {
    if (count > 1) {
      findings.push(makeFinding({
        issue: `JWKS com kid duplicado: ${kid}`,
        score: 78,
        url,
        meta: { issuer, kid, count },
      }));
    }
  }

  keys.slice(0, 40).forEach((key, idx) => {
    const kid = String(key?.kid || '').trim();
    const kty = String(key?.kty || '').toUpperCase();
    const alg = String(key?.alg || '').toUpperCase();
    const use = String(key?.use || '').toLowerCase();
    const keyMeta = { issuer, kid: kid || `index:${idx}`, kty, alg: alg || null, use: use || null };

    if (!kid) {
      findings.push(makeFinding({
        issue: 'JWKS key sem kid',
        score: keys.length > 1 ? 62 : 42,
        url,
        meta: { ...keyMeta, reason: 'missing_kid' },
      }));
    }
    if (kty === 'OCT') {
      findings.push(makeFinding({
        issue: 'JWKS expoe chave simetrica (kty=oct)',
        score: 92,
        url,
        meta: { ...keyMeta, reason: 'public_symmetric_key' },
      }));
    }
    if (/^HS\d+$/i.test(alg) || alg === 'NONE') {
      findings.push(makeFinding({
        issue: `JWKS declara algoritmo fraco/inadequado: ${alg}`,
        score: alg === 'NONE' ? 88 : 76,
        url,
        meta: { ...keyMeta, reason: 'weak_alg' },
      }));
    }
    if (kty === 'RSA' && key?.n) {
      const bits = b64urlBytes(key.n).length * 8;
      if (bits > 0 && bits < 2048) {
        findings.push(makeFinding({
          issue: `RSA fraco no JWKS (${bits} bits)`,
          score: 68,
          url,
          meta: { ...keyMeta, bits },
        }));
      }
    }
    if (kty === 'EC' && key?.crv && !/^(P-256|P-384|P-521|ED25519)$/i.test(String(key.crv))) {
      findings.push(makeFinding({
        issue: `Curva EC incomum no JWKS: ${key.crv}`,
        score: 42,
        url,
        meta: { ...keyMeta, crv: key.crv },
      }));
    }
    if (use && !['sig', 'enc'].includes(use)) {
      findings.push(makeFinding({
        issue: `JWKS key use incomum: ${use}`,
        score: 34,
        url,
        meta: keyMeta,
      }));
    }
  });

  if (keys.length > 20) {
    findings.push(makeFinding({
      issue: `JWKS com muitas chaves publicas (${keys.length})`,
      score: 32,
      url,
      meta: { issuer, count: keys.length, reason: 'rotation_hygiene_review' },
    }));
  }
  return findings;
}

async function fetchJsonWithHeaders(url, { fetchImpl = fetch, timeoutMs = 8_000, headers = {} } = {}) {
  const res = await fetchImpl(url, {
    method: 'GET',
    redirect: 'follow',
    signal: AbortSignal.timeout(timeoutMs),
    headers: {
      Accept: 'application/json,*/*;q=0.8',
      ...headers,
    },
  });
  if (!res.ok) return null;
  const text = await readResponseSnippet(res, 1_200_000);
  try {
    return { json: JSON.parse(text), headers: res.headers, url: res.url || url };
  } catch {
    return null;
  }
}

async function discoverJwksFromOidc(origin, opts) {
  const url = new URL('/.well-known/openid-configuration', origin).href;
  const doc = await fetchJsonWithHeaders(url, opts).catch(() => null);
  const jwksUri = doc?.json?.jwks_uri;
  if (!jwksUri) return [];
  try {
    return [{ url: new URL(jwksUri, origin).href, issuer: doc.json.issuer || '' }];
  } catch {
    return [];
  }
}

export async function runJwtJwksAudit({
  origins = [],
  modules = [],
  log = () => {},
  fetchImpl = fetch,
} = {}) {
  const findings = [];
  const seenUrls = new Set();
  const ua = pickStealthUserAgent(modules);
  const timeoutMs = Math.min(12_000, limits.wellKnownOpenIdTimeoutMs || 8_000);
  const candidates = [];

  for (const origin of origins.slice(0, Math.max(1, limits.wellKnownMaxHosts || 8))) {
    for (const c of await discoverJwksFromOidc(origin, { fetchImpl, timeoutMs, headers: { 'User-Agent': ua } })) {
      candidates.push(c);
    }
    for (const p of COMMON_JWKS_PATHS) {
      try { candidates.push({ url: new URL(p, origin).href, issuer: '' }); } catch { /* skip */ }
    }
  }

  for (const candidate of candidates) {
    if (!candidate?.url || seenUrls.has(candidate.url)) continue;
    seenUrls.add(candidate.url);
    await stealthPause(modules);
    const fetched = await fetchJsonWithHeaders(candidate.url, {
      fetchImpl,
      timeoutMs,
      headers: { 'User-Agent': ua },
    }).catch(() => null);
    if (!fetched?.json?.keys) continue;
    const rows = auditJwks(fetched.json, { url: fetched.url, issuer: candidate.issuer });
    findings.push(...rows);
    if (rows.length) log(`JWKS audit: ${rows.length} achado(s) em ${fetched.url}`, 'warn');
    else log(`JWKS audit: ${fetched.url} sem alerta`, 'info');
  }

  return findings;
}
