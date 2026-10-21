import { readFileSync, statSync } from 'node:fs';
import { isIP } from 'node:net';
import { createHash } from 'node:crypto';
import { domainToASCII } from 'node:url';

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

const ANALYTICS_COOKIE_RE = /^(?:_ga|_gid|_gat|_fbp|_gcl_|ajs_|amplitude_|mp_|optimizely|clarity|_cl)/i;
const MAX_SET_COOKIE_HEADER_CHARS = 65_536;
const MAX_COOKIE_HEADER_ROWS = 64;
const MAX_COOKIES_AUDITED = 128;
const MAX_PUBLIC_SUFFIX_LIST_CHARS = 2_000_000;
const MAX_PUBLIC_SUFFIX_RULES = 100_000;
const SYSTEM_PUBLIC_SUFFIX_LIST_PATHS = Object.freeze([
  '/usr/share/publicsuffix/public_suffix_list.dat',
  '/usr/share/publicsuffix/effective_tld_names.dat',
  '/usr/share/libpsl/public_suffix_list.dat',
  '/usr/share/libpsl/effective_tld_names.dat',
]);
const SESSION_COOKIE_TOKENS = new Set([
  'session', 'sess', 'sid', 'auth', 'jwt', 'token', 'access', 'refresh', 'remember', 'login',
]);
const CSRF_COOKIE_TOKENS = new Set(['csrf', 'xsrf']);

let cachedPublicSuffixList;

function emptyPublicSuffixList(reason = 'unavailable') {
  return Object.freeze({
    available: false,
    source: 'none',
    reason,
    ruleCount: 0,
    versionHash: '',
    exact: new Set(),
    wildcard: new Set(),
    exception: new Set(),
  });
}

function canonicalDomain(value, { allowLeadingDot = false } = {}) {
  let candidate = String(value || '').trim().toLowerCase();
  if (allowLeadingDot) candidate = candidate.replace(/^\./, '');
  if (!candidate || candidate.endsWith('.') || candidate.startsWith('.')) return '';
  if (candidate.startsWith('[') && candidate.endsWith(']')) candidate = candidate.slice(1, -1);
  if (isIP(candidate)) return candidate;
  const ascii = domainToASCII(candidate).toLowerCase();
  if (!ascii || ascii.length > 253 || !/^[a-z0-9.-]+$/.test(ascii)) return '';
  const labels = ascii.split('.');
  if (labels.some((label) => !label || label.length > 63
    || label.startsWith('-') || label.endsWith('-'))) return '';
  return ascii;
}

/**
 * Compila o formato oficial public_suffix_list.dat. Regras invalidas sao
 * ignoradas; limites impedem que uma fonte local corrompida esgote memoria.
 */
export function parsePublicSuffixList(text, { source = 'injected' } = {}) {
  const input = String(text || '');
  if (!input || input.length > MAX_PUBLIC_SUFFIX_LIST_CHARS) {
    throw new RangeError('public_suffix_list_invalid_or_too_large');
  }
  const exact = new Set();
  const wildcard = new Set();
  const exception = new Set();

  for (const rawLine of input.split(/\r?\n/u)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('//')) continue;
    const isException = line.startsWith('!');
    const isWildcard = line.startsWith('*.');
    const rawRule = line.slice(isException ? 1 : isWildcard ? 2 : 0);
    const rule = canonicalDomain(rawRule);
    if (!rule) continue;
    const bucket = isException ? exception : isWildcard ? wildcard : exact;
    bucket.add(rule);
    if (exact.size + wildcard.size + exception.size > MAX_PUBLIC_SUFFIX_RULES) {
      throw new RangeError('public_suffix_list_has_too_many_rules');
    }
  }

  const ruleCount = exact.size + wildcard.size + exception.size;
  if (!ruleCount) throw new TypeError('public_suffix_list_has_no_valid_rules');
  return Object.freeze({
    available: true,
    source: String(source || 'injected').slice(0, 160),
    reason: '',
    ruleCount,
    versionHash: createHash('sha256').update(input).digest('hex'),
    exact,
    wildcard,
    exception,
  });
}

/** Carrega uma PSL publica apenas de caminhos de sistema fixos e limitados. */
export function loadSystemPublicSuffixList({
  paths = SYSTEM_PUBLIC_SUFFIX_LIST_PATHS,
  statImpl = statSync,
  readFileImpl = readFileSync,
} = {}) {
  for (const candidate of Array.isArray(paths) ? paths.slice(0, 8) : []) {
    try {
      const stats = statImpl(candidate);
      if (!stats?.isFile?.() || stats.size <= 0 || stats.size > MAX_PUBLIC_SUFFIX_LIST_CHARS) continue;
      return parsePublicSuffixList(readFileImpl(candidate, 'utf8'), {
        source: `system_psl:${String(candidate).split('/').pop() || 'public_suffix_list.dat'}`,
      });
    } catch {
      // A ausencia de uma das localizacoes padrao nao autoriza ler outro path.
    }
  }
  return emptyPublicSuffixList('system_public_suffix_list_not_found');
}

export function defaultPublicSuffixList() {
  if (!cachedPublicSuffixList) cachedPublicSuffixList = loadSystemPublicSuffixList();
  return cachedPublicSuffixList;
}

/** Aplica a regra prevalente da PSL, incluindo wildcard e exception. */
export function publicSuffixInfo(value, { publicSuffixList = defaultPublicSuffixList() } = {}) {
  const domain = canonicalDomain(value, { allowLeadingDot: true });
  const psl = publicSuffixList;
  if (!domain || isIP(domain) || !psl?.available) {
    return {
      available: Boolean(psl?.available),
      domain,
      publicSuffix: '',
      registrableDomain: '',
      isPublicSuffix: false,
      rule: '',
      source: psl?.source || 'none',
      versionHash: psl?.versionHash || '',
    };
  }

  const labels = domain.split('.');
  let match = { kind: 'default', labelCount: 1, rule: '*' };
  for (let i = 0; i < labels.length; i++) {
    const suffix = labels.slice(i).join('.');
    if (psl.exception.has(suffix)) {
      const publicSuffix = labels.slice(i + 1).join('.');
      const suffixLabels = publicSuffix ? publicSuffix.split('.').length : 0;
      return {
        available: true,
        domain,
        publicSuffix,
        registrableDomain: labels.length > suffixLabels
          ? labels.slice(-(suffixLabels + 1)).join('.')
          : '',
        isPublicSuffix: domain === publicSuffix,
        rule: `!${suffix}`,
        source: psl.source,
        versionHash: psl.versionHash || '',
      };
    }
    const exactLabelCount = labels.length - i;
    if (psl.exact.has(suffix) && exactLabelCount > match.labelCount) {
      match = { kind: 'exact', labelCount: exactLabelCount, rule: suffix };
    }
    if (i > 0 && psl.wildcard.has(suffix)) {
      const wildcardLabelCount = exactLabelCount + 1;
      if (wildcardLabelCount > match.labelCount) {
        match = { kind: 'wildcard', labelCount: wildcardLabelCount, rule: `*.${suffix}` };
      }
    }
  }

  const publicSuffix = labels.slice(-match.labelCount).join('.');
  return {
    available: true,
    domain,
    publicSuffix,
    registrableDomain: labels.length > match.labelCount
      ? labels.slice(-(match.labelCount + 1)).join('.')
      : '',
    isPublicSuffix: domain === publicSuffix,
    rule: match.rule,
    source: psl.source,
    versionHash: psl.versionHash || '',
  };
}

function normalizedCookieName(name) {
  return String(name || '')
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .toLowerCase();
}

function nameHasToken(name, tokens) {
  const normalized = normalizedCookieName(name);
  const parts = normalized.split(/[^a-z0-9]+/).filter(Boolean);
  return parts.some((part) => tokens.has(part));
}

export function splitSetCookieHeader(value) {
  const s = String(value || '');
  if (!s || s.length > MAX_SET_COOKIE_HEADER_CHARS) return [];
  const out = [];
  let start = 0;
  let quoted = false;

  for (let i = 0; i < s.length; i++) {
    if (s[i] === '"' && s[i - 1] !== '\\') quoted = !quoted;
    if (s[i] !== ',' || quoted) continue;
    // A vírgula da data é seguida por um dia, não por cookie-name=.
    // Expires pode ser o último atributo antes do próximo Set-Cookie.
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
  if (!/^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(name)) return null;
  const attrs = Object.create(null);
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
    partitioned: Object.prototype.hasOwnProperty.call(attrs, 'partitioned'),
    sameSite: typeof attrs.samesite === 'string' ? attrs.samesite.toLowerCase() : '',
    domain: typeof attrs.domain === 'string' ? attrs.domain.toLowerCase() : '',
    path: typeof attrs.path === 'string' ? attrs.path : '',
    maxAgeSec: /^-?\d+$/.test(String(attrs['max-age'] ?? '')) ? Number(attrs['max-age']) : null,
    expiresAt: typeof attrs.expires === 'string' ? Date.parse(attrs.expires) : null,
  };
}

function prioFor(score) {
  if (score >= 75) return 'high';
  if (score >= 55) return 'med';
  if (score >= 35) return 'low';
  return 'info';
}

function cookieLifetimeDays(cookie, nowMs) {
  if (Number.isFinite(cookie.maxAgeSec)) return cookie.maxAgeSec / 86400;
  if (Number.isFinite(cookie.expiresAt)) {
    const diff = cookie.expiresAt - nowMs;
    if (diff > 0) return diff / 86400000;
  }
  return null;
}

function cookieContext(name) {
  const normalized = normalizedCookieName(name);
  const compact = normalized.replace(/[^a-z0-9]/g, '');
  const sessionLike = nameHasToken(name, SESSION_COOKIE_TOKENS)
    || /^(?:phpsessid|jsessionid|sessionid|sessid|aspsessionid[a-z0-9]{0,16})$/.test(compact)
    || compact === 'connectsid';
  const csrfLike = nameHasToken(name, CSRF_COOKIE_TOKENS)
    || compact === 'antiforgery'
    || compact === 'requestverificationtoken';
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
      'source=cookie_session_audit',
      'evidence_status=configuration_observation',
      'session_role=heuristic',
      'impact_tested=false',
      cookie.sameSite ? `samesite=${cookie.sameSite}` : 'samesite=missing',
      cookie.domain ? `domain=${cookie.domain}` : '',
      cookie.path ? `path=${cookie.path}` : '',
      detail || '',
    ].filter(Boolean).join(' - '),
    url,
    owasp: 'A05:2021',
  };
}

export function auditCookieHeaders(headers, {
  url = '',
  target = null,
  now = Date.now,
  publicSuffixList = defaultPublicSuffixList(),
} = {}) {
  const findings = [];
  const seen = new Set();
  const rawHeaders = [];
  const headerRows = (Array.isArray(headers) ? headers : [headers]).slice(0, MAX_COOKIE_HEADER_ROWS);
  for (const h of headerRows) {
    for (const raw of splitSetCookieHeader(h)) {
      if (rawHeaders.length >= MAX_COOKIES_AUDITED) break;
      rawHeaders.push(raw);
    }
    if (rawHeaders.length >= MAX_COOKIES_AUDITED) break;
  }
  const nowMs = typeof now === 'function' ? Number(now()) : Number(now);
  let requestUrl;
  try { requestUrl = new URL(url); } catch { requestUrl = null; }

  for (const raw of rawHeaders) {
    const cookie = parseSetCookie(raw);
    if (!cookie) continue;
    // Max-Age tem precedência sobre Expires. Remoção não cria sessão exposta.
    if (Number.isFinite(cookie.maxAgeSec) ? cookie.maxAgeSec <= 0
      : Number.isFinite(cookie.expiresAt) && cookie.expiresAt <= nowMs) continue;
    const ctx = cookieContext(cookie.name);
    if (ctx.analyticsLike) continue;

    const push = (issue, score, detail = '') => {
      const key = `${issue}:${cookie.name}:${cookie.domain}:${cookie.path}:${url}`;
      if (seen.has(key)) return;
      seen.add(key);
      findings.push(buildFinding({ issue, score, cookie, url, target, detail }));
    };

    const isHttps = requestUrl?.protocol === 'https:';
    const domain = cookie.domain
      ? canonicalDomain(cookie.domain, { allowLeadingDot: true })
      : '';
    const host = canonicalDomain(requestUrl?.hostname || '');
    const domainMatchesHost = domain && host
      && (host === domain || (!isIP(host) && host.endsWith(`.${domain}`)));
    if (cookie.domain && (!domain || (host && !domainMatchesHost))) {
      push('Cookie com Domain incompatível com a origem', 22,
        'browser_acceptance=expected_rejection; domain_match=false; impact_tested=false');
      continue;
    }
    const suffix = domain ? publicSuffixInfo(domain, { publicSuffixList }) : null;
    if (suffix?.available && suffix.isPublicSuffix && host && host !== domain) {
      push('Cookie Domain aponta para sufixo público', 22, [
        'browser_acceptance=expected_rejection',
        `public_suffix_rule=${suffix.rule}`,
        `public_suffix_source=${suffix.source}`,
        suffix.versionHash ? `public_suffix_snapshot=${suffix.versionHash}` : '',
        'impact_tested=false',
      ].join('; '));
      continue;
    }
    if (suffix?.available && suffix.isPublicSuffix && !host) {
      push('Cookie Domain é sufixo público; aceitação não verificada', 18, [
        'browser_acceptance=unknown_without_request_host',
        `public_suffix_rule=${suffix.rule}`,
        `public_suffix_source=${suffix.source}`,
        suffix.versionHash ? `public_suffix_snapshot=${suffix.versionHash}` : '',
        'impact_tested=false',
      ].filter(Boolean).join('; '));
      continue;
    }
    const invalidHostPrefix = cookie.name.startsWith('__Host-')
      && (!isHttps || !cookie.secure || cookie.domain || cookie.path !== '/');
    const invalidSecurePrefix = cookie.name.startsWith('__Secure-') && (!isHttps || !cookie.secure);
    if (requestUrl && (invalidHostPrefix || invalidSecurePrefix)) {
      push('Cookie com requisitos do prefixo não atendidos', 22,
        'browser_acceptance=expected_rejection; prefix_check=secure_origin_secure_flag_host_path');
      continue;
    }
    if (cookie.partitioned && !cookie.secure) {
      push('Cookie Partitioned sem Secure', 24,
        'browser_acceptance=expected_rejection_in_supporting_browsers; impact_tested=false');
      continue;
    }
    if (cookie.sameSite === 'none' && !cookie.secure) {
      push('Cookie SameSite=None sem Secure', 24, 'browser_acceptance=expected_rejection_in_modern_browsers');
      continue;
    }
    if (isHttps && !cookie.secure) {
      push(
        ctx.sensitive ? 'Cookie sensivel sem Secure' : 'Cookie sem Secure em HTTPS',
        ctx.sensitive ? 48 : 30,
      );
    }
    if (ctx.sensitive && !ctx.csrfLike && !cookie.httpOnly) {
      push('Cookie de sessao/token sem HttpOnly', 48, 'sensitivity_inferred_from_name=true');
    }
    if (ctx.sensitive && !cookie.sameSite) {
      push('Cookie de sessao/token sem SameSite explícito', 30, 'browser_default_lax_may_apply=true');
    }
    if (cookie.sameSite && !['lax', 'strict', 'none'].includes(cookie.sameSite)) {
      push('Cookie com SameSite não reconhecido', 24, 'browser_default_may_apply=true');
    }
    if (cookie.domain) {
      const labels = domain.split('.').filter(Boolean);
      if (!suffix?.available && labels.length <= 1) {
        push('Cookie com Domain de rótulo único; aceitação não verificada', 22,
          'public_suffix_check=unavailable; impact_tested=false');
      } else if (ctx.sensitive && !(suffix?.isPublicSuffix && host === domain)) {
        push('Cookie sensivel com escopo de domínio e subdomínios', 30, [
          `public_suffix_check=${suffix?.available ? 'performed' : 'unavailable'}`,
          suffix?.rule ? `public_suffix_rule=${suffix.rule}` : '',
          suffix?.versionHash ? `public_suffix_snapshot=${suffix.versionHash}` : '',
          suffix?.registrableDomain ? `registrable_domain=${suffix.registrableDomain}` : '',
          'leading_dot_does_not_change_scope=true',
          'impact_tested=false',
        ].filter(Boolean).join('; '));
      }
    }
    const days = cookieLifetimeDays(cookie, nowMs);
    if (ctx.sensitive && days != null && days > 30) {
      push('Cookie sensivel solicita expiracao longa', 32,
        `requested_lifetime_days=${Math.round(days)}; browser_lifetime_cap_not_evaluated=true`);
    }
  }

  return findings;
}

export function auditCookieSession(probeResults, {
  target = null,
  now = Date.now,
  publicSuffixList = defaultPublicSuffixList(),
} = {}) {
  const out = [];
  const seen = new Set();
  for (const row of probeResults || []) {
    const r = row?.r || row;
    if (!r?.ok || !r.securityHeaders?.setCookieSample?.length) continue;
    for (const f of auditCookieHeaders(r.securityHeaders.setCookieSample, {
      url: r.url,
      target,
      now,
      publicSuffixList,
    })) {
      const key = `${f.type}:${f.value}:${f.meta}:${f.url}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(f);
    }
  }
  return out;
}
