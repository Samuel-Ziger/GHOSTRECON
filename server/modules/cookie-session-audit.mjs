export const moduleManifest = {
  id: 'cookie_session_audit',
  name: 'Cookie / Session Audit',
  category: 'surface',
  intrusive: false,
  requiresAuth: false,
  requiresKali: false,
  timeoutMs: 15_000,
  concurrency: 1,
  outputs: ['finding'],
};

const SESSION_COOKIE_RE = /(?:session|sess|sid|auth|jwt|token|id_token|access|refresh|remember|login)/i;
const CSRF_COOKIE_RE = /(?:csrf|xsrf|anti[-_]?forgery|requestverificationtoken)/i;
const ANALYTICS_COOKIE_RE = /^(?:_ga|_gid|_gat|_fbp|_gcl_|ajs_|amplitude_|mp_|optimizely|clarity|_cl)/i;

export function splitSetCookieHeader(value) {
  const s = String(value || '');
  if (!s) return [];
  const out = [];
  let start = 0;
  let inExpires = false;

  for (let i = 0; i < s.length; i++) {
    if (s.slice(i, i + 8).toLowerCase() === 'expires=') {
      inExpires = true;
      i += 7;
      continue;
    }
    if (inExpires && s[i] === ';') {
      inExpires = false;
      continue;
    }
    if (s[i] !== ',' || inExpires) continue;
    if (!/^\s*[!#$%&'*+\-.^_`|~0-9A-Za-z]+=/.test(s.slice(i + 1))) continue;
    const part = s.slice(start, i).trim();
    if (part) out.push(part);
    start = i + 1;
  }

  const tail = s.slice(start).trim();
  if (tail) out.push(tail);
  return out;
}

export function parseSetCookie(raw) {
  const parts = String(raw || '').split(';').map((p) => p.trim()).filter(Boolean);
  if (!parts.length || !parts[0].includes('=')) return null;
  const idx = parts[0].indexOf('=');
  const name = parts[0].slice(0, idx).trim();
  if (!name) return null;
  const attrs = {};
  for (const attr of parts.slice(1)) {
    const eq = attr.indexOf('=');
    const key = (eq >= 0 ? attr.slice(0, eq) : attr).trim().toLowerCase();
    const val = eq >= 0 ? attr.slice(eq + 1).trim() : true;
    if (key) attrs[key] = val;
  }
  return {
    name,
    attrs,
    httpOnly: Object.prototype.hasOwnProperty.call(attrs, 'httponly'),
    secure: Object.prototype.hasOwnProperty.call(attrs, 'secure'),
    sameSite: typeof attrs.samesite === 'string' ? attrs.samesite.toLowerCase() : '',
    domain: typeof attrs.domain === 'string' ? attrs.domain.toLowerCase() : '',
    path: typeof attrs.path === 'string' ? attrs.path : '',
    maxAgeSec: attrs['max-age'] != null && attrs['max-age'] !== true ? Number(attrs['max-age']) : null,
    expiresAt: typeof attrs.expires === 'string' ? Date.parse(attrs.expires) : null,
  };
}

function prioFor(score) {
  if (score >= 75) return 'high';
  if (score >= 55) return 'med';
  if (score >= 35) return 'low';
  return 'info';
}

function cookieLifetimeDays(cookie) {
  if (Number.isFinite(cookie.maxAgeSec)) return cookie.maxAgeSec / 86400;
  if (Number.isFinite(cookie.expiresAt)) {
    const diff = cookie.expiresAt - Date.now();
    if (diff > 0) return diff / 86400000;
  }
  return null;
}

function cookieContext(name) {
  const sessionLike = SESSION_COOKIE_RE.test(name);
  const csrfLike = CSRF_COOKIE_RE.test(name);
  const analyticsLike = ANALYTICS_COOKIE_RE.test(name);
  return { sessionLike, csrfLike, analyticsLike, sensitive: sessionLike && !analyticsLike };
}

function buildFinding({ issue, score, cookie, url, detail }) {
  const host = (() => {
    try { return new URL(url).hostname; } catch { return 'unknown'; }
  })();
  return {
    type: 'cookie_session',
    prio: prioFor(score),
    score,
    value: `${issue}: ${cookie.name} @ ${host}`,
    meta: [
      `cookie=${cookie.name}`,
      cookie.sameSite ? `samesite=${cookie.sameSite}` : 'samesite=missing',
      cookie.domain ? `domain=${cookie.domain}` : '',
      cookie.path ? `path=${cookie.path}` : '',
      detail || '',
    ].filter(Boolean).join(' - '),
    url,
    owasp: 'A05:2021',
  };
}

export function auditCookieHeaders(headers, { url = '', target = null } = {}) {
  const findings = [];
  const seen = new Set();
  const rawHeaders = [];
  for (const h of headers || []) rawHeaders.push(...splitSetCookieHeader(h));

  for (const raw of rawHeaders) {
    const cookie = parseSetCookie(raw);
    if (!cookie) continue;
    const ctx = cookieContext(cookie.name);
    if (ctx.analyticsLike) continue;

    const push = (issue, score, detail = '') => {
      const key = `${issue}:${cookie.name}:${url}`;
      if (seen.has(key)) return;
      seen.add(key);
      findings.push(buildFinding({ issue, score, cookie, url, target, detail }));
    };

    const isHttps = /^https:/i.test(url);
    if (isHttps && !cookie.secure) {
      push(
        ctx.sensitive ? 'Cookie sensivel sem Secure' : 'Cookie sem Secure em HTTPS',
        ctx.sensitive ? 78 : 42,
      );
    }
    if (ctx.sensitive && !ctx.csrfLike && !cookie.httpOnly) {
      push('Cookie de sessao/token sem HttpOnly', 82);
    }
    if (ctx.sensitive && !cookie.sameSite) {
      push('Cookie de sessao/token sem SameSite', 64);
    }
    if (cookie.sameSite === 'none' && !cookie.secure) {
      push('Cookie SameSite=None sem Secure', 76);
    }
    if (cookie.domain) {
      const labels = cookie.domain.replace(/^\./, '').split('.').filter(Boolean);
      if (labels.length <= 1) push('Cookie com Domain excessivamente amplo', 72, 'public_suffix_like=yes');
      else if (cookie.domain.startsWith('.') && ctx.sensitive) push('Cookie sensivel compartilhado entre subdominios', 48);
    }
    const days = cookieLifetimeDays(cookie);
    if (ctx.sensitive && days != null && days > 30) {
      push('Cookie sensivel com expiracao longa', days > 365 ? 68 : 56, `lifetime_days=${Math.round(days)}`);
    }
  }

  return findings;
}

export function auditCookieSession(probeResults, { target = null } = {}) {
  const out = [];
  const seen = new Set();
  for (const row of probeResults || []) {
    const r = row?.r || row;
    if (!r?.ok || !r.securityHeaders?.setCookieSample?.length) continue;
    for (const f of auditCookieHeaders(r.securityHeaders.setCookieSample, { url: r.url, target })) {
      const key = `${f.type}:${f.value}:${f.meta}:${f.url}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(f);
    }
  }
  return out;
}
