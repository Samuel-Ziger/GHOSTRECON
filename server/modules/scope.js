/**
 * Escopo do engagement: domínio raiz + subdomínios, com exclusões opcionais (fora de escopo).
 */

import net from 'node:net';

/** Limite de entradas vindas da UI / API (por pedido). */
export const OUT_OF_SCOPE_CLIENT_MAX = 120;

function normalizeHostname(value) {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/^\[|\]$/g, '')
    .replace(/\.$/, '');
}

export function hostnameInScope(hostname, rootDomain) {
  const h = normalizeHostname(hostname);
  const r = normalizeHostname(rootDomain);
  if (!h || !r) return false;
  if (net.isIP(h) || net.isIP(r)) return h === r;
  return h === r || h.endsWith(`.${r}`);
}

/**
 * @param {string} raw ex. env GHOSTRECON_OUT_OF_SCOPE
 * @returns {string[]} hostnames normalizados (únimos)
 */
export function parseOutOfScopeEnv(raw) {
  if (raw == null || typeof raw !== 'string') return [];
  return [
    ...new Set(
      raw
        .split(/[\s,]+/)
        .map((s) => s.trim().toLowerCase())
        .filter((s) => s.length > 0 && !s.startsWith('#')),
    ),
  ];
}

/**
 * Uma linha da lista (hostname, URL ou *.wildcard.host).
 */
export function normalizeOutOfScopeToken(token) {
  const raw = String(token || '').trim();
  if (!raw || raw.startsWith('#')) return '';
  const ipRule = normalizeIpScopeRule(raw);
  if (ipRule) return ipRule;
  if (raw.toLowerCase().startsWith('*.')) return raw.toLowerCase();
  try {
    if (/^https?:\/\//i.test(raw)) {
      return new URL(raw).hostname.toLowerCase();
    }
  } catch {
    return '';
  }
  const first = raw.split(/[/?#]/)[0].replace(/:\d+$/, '').trim();
  if (!first) return '';
  return first.toLowerCase();
}

/**
 * Textarea / JSON: linhas e vírgulas; aceita URLs completas.
 * @param {string|string[]|null|undefined} value
 */
export function parseOutOfScopeClientInput(value, maxEntries = OUT_OF_SCOPE_CLIENT_MAX) {
  if (value == null) return [];
  const chunks = Array.isArray(value) ? value : [value];
  const tokens = [];
  for (const chunk of chunks) {
    for (const line of String(chunk).split(/\r?\n/)) {
      for (const part of line.split(',')) {
        const t = part.trim();
        if (t) tokens.push(t);
      }
    }
  }
  const out = [];
  const seen = new Set();
  for (const tok of tokens) {
    const n = normalizeOutOfScopeToken(tok);
    if (!n || seen.has(n)) continue;
    seen.add(n);
    out.push(n);
    if (out.length >= maxEntries) break;
  }
  return out;
}

export function mergeOutOfScopeLists(envList, clientList) {
  return [...new Set([...(envList || []), ...(clientList || [])])];
}

/**
 * Regra opcional com wildcard: "*.cdn.example.com" ou "*cdn.example.com" → sufixo DNS.
 */
export function hostnameMatchesOutOfScope(hostname, rules) {
  const h = normalizeHostname(hostname);
  if (!h || !Array.isArray(rules) || !rules.length) return false;
  for (let r of rules) {
    r = normalizeOutOfScopeToken(r);
    if (!r) continue;
    if (net.isIP(h) && ipMatchesScopeRule(h, r)) return true;
    if (r.startsWith('*.')) {
      r = r.slice(2);
      if (!r) continue;
      if (h === r || h.endsWith(`.${r}`)) return true;
      continue;
    }
    if (h === r || h.endsWith(`.${r}`)) return true;
  }
  return false;
}

function normalizeDomainScopeRule(value) {
  const raw = String(value || '').trim().toLowerCase();
  if (!raw) return '';
  const wildcard = raw.startsWith('*.');
  const candidate = wildcard ? raw.slice(2) : raw;
  let hostname = candidate;
  try {
    if (/^https?:\/\//i.test(candidate)) hostname = new URL(candidate).hostname;
  } catch {
    return '';
  }
  hostname = normalizeHostname(hostname.split(/[/?#]/)[0].replace(/:\d+$/, ''));
  if (!hostname || net.isIP(hostname)) return '';
  return wildcard ? `*.${hostname}` : hostname;
}

function normalizeIpScopeRule(value) {
  const raw = String(value || '').trim().toLowerCase();
  if (!raw) return '';
  const [address, prefixRaw] = raw.split('/');
  const normalizedAddress = normalizeHostname(address);
  const family = net.isIP(normalizedAddress);
  if (!family) return '';
  if (prefixRaw == null) return normalizedAddress;
  if (!/^\d+$/.test(prefixRaw)) return '';
  const prefix = Number(prefixRaw);
  const max = family === 4 ? 32 : 128;
  if (prefix < 0 || prefix > max) return '';
  return `${normalizedAddress}/${prefix}`;
}

function normalizeEngagementExclusionRule(value) {
  const ipRule = normalizeIpScopeRule(value);
  if (ipRule) return ipRule;
  return normalizeOutOfScopeToken(value);
}

function ipv4ToInt(address) {
  const parts = String(address).split('.').map(Number);
  if (
    parts.length !== 4
    || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)
  ) return null;
  return (
    ((parts[0] << 24) >>> 0)
    + ((parts[1] << 16) >>> 0)
    + ((parts[2] << 8) >>> 0)
    + parts[3]
  ) >>> 0;
}

export function ipMatchesScopeRule(address, rule) {
  const host = normalizeHostname(address);
  const normalizedRule = normalizeIpScopeRule(rule);
  if (!host || !normalizedRule) return false;
  if (!normalizedRule.includes('/')) return host === normalizedRule;
  const [base, prefixRaw] = normalizedRule.split('/');
  const prefix = Number(prefixRaw);
  const family = net.isIP(host);
  if (!family || family !== net.isIP(base)) return false;
  if (family === 4) {
    const hostInt = ipv4ToInt(host);
    const baseInt = ipv4ToInt(base);
    if (hostInt == null || baseInt == null) return false;
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    return (hostInt & mask) === (baseInt & mask);
  }
  // IPv6 exato continua suportado; CIDR IPv6 falha fechado até existir um
  // parser binário dedicado e testado.
  return prefix === 128 && host === base;
}

export function hostnameMatchesDomainScopeRule(hostname, rule) {
  const host = normalizeHostname(hostname);
  const normalizedRule = normalizeDomainScopeRule(rule);
  if (!host || !normalizedRule || net.isIP(host)) return false;
  if (normalizedRule.startsWith('*.')) {
    const suffix = normalizedRule.slice(2);
    return host !== suffix && host.endsWith(`.${suffix}`);
  }
  return host === normalizedRule;
}

function normalizePolicyList(values, normalize) {
  return Object.freeze([
    ...new Set((Array.isArray(values) ? values : []).map(normalize).filter(Boolean)),
  ].sort());
}

/**
 * Política imutável derivada de um engagement já vinculado e revalidado.
 * A presença da política torna scopeDomains/scopeIps uma allowlist fechada:
 * entrada exata não autoriza subdomínios; `*.example.test` autoriza apenas
 * descendentes.
 */
export function createEngagementScopePolicy({
  rootDomain,
  engagement,
  engagementId = null,
  authorizationBinding,
} = {}) {
  if (!engagement) return null;
  const normalizedRoot = normalizeHostname(rootDomain);
  const binding = String(authorizationBinding || '').trim();
  if (!normalizedRoot) throw new Error('scope policy requer rootDomain');
  if (!binding) throw new Error('scope policy requer authorizationBinding revalidado');
  const selectedEngagementId = String(engagementId || engagement.id || '').trim();
  if (!selectedEngagementId) throw new Error('scope policy requer engagementId');
  if (engagement.id && String(engagement.id).trim() !== selectedEngagementId) {
    throw new Error('scope policy engagementId diverge do engagement revalidado');
  }
  return Object.freeze({
    schemaVersion: 1,
    rootDomain: normalizedRoot,
    engagementId: selectedEngagementId,
    authorizationBinding: binding,
    scopeDomains: normalizePolicyList(engagement.scopeDomains, normalizeDomainScopeRule),
    scopeIps: normalizePolicyList(engagement.scopeIps, normalizeIpScopeRule),
    exclusions: normalizePolicyList(
      engagement.exclusions,
      normalizeEngagementExclusionRule,
    ),
  });
}

export function validateEngagementScopePolicy(policy, {
  rootDomain,
  engagementId = null,
  authorizationBinding = null,
} = {}) {
  if (policy == null) return null;
  if (!policy || typeof policy !== 'object' || policy.schemaVersion !== 1) {
    throw new Error('scope policy inválida');
  }
  const expectedRoot = normalizeHostname(rootDomain);
  if (!expectedRoot || normalizeHostname(policy.rootDomain) !== expectedRoot) {
    throw new Error('scope policy não pertence ao alvo do pipeline');
  }
  const expectedEngagementId = String(engagementId || '').trim();
  if (expectedEngagementId && String(policy.engagementId || '').trim() !== expectedEngagementId) {
    throw new Error('scope policy não pertence ao engagement do pipeline');
  }
  const expectedBinding = String(authorizationBinding || '').trim();
  if (
    expectedBinding
    && String(policy.authorizationBinding || '').trim() !== expectedBinding
  ) {
    throw new Error('scope policy não corresponde à autorização revalidada');
  }
  return Object.freeze({
    schemaVersion: 1,
    rootDomain: expectedRoot,
    engagementId: String(policy.engagementId || '').trim(),
    authorizationBinding: String(policy.authorizationBinding || '').trim(),
    scopeDomains: normalizePolicyList(policy.scopeDomains, normalizeDomainScopeRule),
    scopeIps: normalizePolicyList(policy.scopeIps, normalizeIpScopeRule),
    exclusions: normalizePolicyList(
      policy.exclusions,
      normalizeEngagementExclusionRule,
    ),
  });
}

function hostMatchesEngagementPolicy(hostname, policy) {
  if (!policy) return true;
  const host = normalizeHostname(hostname);
  if (!host) return false;
  if (net.isIP(host)) {
    if (policy.exclusions.some((rule) => ipMatchesScopeRule(host, rule))) return false;
    return policy.scopeIps.some((rule) => ipMatchesScopeRule(host, rule));
  }
  if (hostnameMatchesOutOfScope(host, policy.exclusions)) return false;
  return policy.scopeDomains.some((rule) => hostnameMatchesDomainScopeRule(host, rule));
}

export function hostInReconScope(
  hostname,
  rootDomain,
  outOfScopeRules = [],
  engagementScopePolicy = null,
) {
  const normalizedHost = normalizeHostname(hostname);
  // Um engagement pode autorizar explicitamente IPs/CIDRs relacionados a um
  // alvo por domínio. Nesse caso a allowlist formal, e não a relação DNS
  // implícita, é a única autoridade para qualquer operação no IP descoberto.
  if (engagementScopePolicy && net.isIP(normalizedHost)) {
    if (hostnameMatchesOutOfScope(normalizedHost, outOfScopeRules)) return false;
    return hostMatchesEngagementPolicy(normalizedHost, engagementScopePolicy);
  }
  if (!hostnameInScope(hostname, rootDomain)) return false;
  if (hostnameMatchesOutOfScope(hostname, outOfScopeRules)) return false;
  return hostMatchesEngagementPolicy(hostname, engagementScopePolicy);
}

export function urlInReconScope(
  urlStr,
  rootDomain,
  outOfScopeRules = [],
  engagementScopePolicy = null,
) {
  try {
    const h = new URL(urlStr).hostname;
    return hostInReconScope(h, rootDomain, outOfScopeRules, engagementScopePolicy);
  } catch {
    return false;
  }
}
