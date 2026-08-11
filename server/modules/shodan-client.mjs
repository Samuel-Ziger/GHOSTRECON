import { UA, limits as defaultLimits } from '../config.js';

const SHODAN_BASE = 'https://api.shodan.io';
const DEFAULT_TIMEOUT_MS = 20000;

function envFlagOn(env, name, defaultOn = true) {
  const raw = env?.[name];
  if (raw == null || String(raw).trim() === '') return defaultOn;
  const v = String(raw).trim().toLowerCase();
  if (['0', 'false', 'off', 'no'].includes(v)) return false;
  if (['1', 'true', 'on', 'yes'].includes(v)) return true;
  return defaultOn;
}

export function shodanFeatureFlags(env = process.env) {
  const n = Number(env.GHOSTRECON_SHODAN_MAX_QUERY_CREDITS ?? 4);
  return {
    enableDnsDomain: envFlagOn(env, 'GHOSTRECON_SHODAN_DNS_DOMAIN', true),
    enableSearch: envFlagOn(env, 'GHOSTRECON_SHODAN_SEARCH', true),
    maxQueryCredits: Number.isFinite(n) && n >= 0 ? Math.floor(n) : 4,
  };
}

function redactSecrets(text, apiKey) {
  let out = String(text || '');
  const key = String(apiKey || '').trim();
  if (key) out = out.split(key).join('[REDACTED]');
  out = out.replace(/([?&]key=)[^&\s"']+/gi, '$1[REDACTED]');
  return out;
}

function buildUrl(pathname, apiKey, params = {}) {
  const u = new URL(pathname.startsWith('http') ? pathname : `${SHODAN_BASE}${pathname}`);
  u.searchParams.set('key', apiKey);
  for (const [k, v] of Object.entries(params)) {
    if (v == null || v === '') continue;
    u.searchParams.set(k, String(v));
  }
  return u.toString();
}

async function shodanFetch(pathname, apiKey, {
  params = {},
  fetchImpl = globalThis.fetch,
  signal,
  timeoutMs = DEFAULT_TIMEOUT_MS,
} = {}) {
  const url = buildUrl(pathname, apiKey, params);
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  const onAbort = () => ctrl.abort();
  if (signal) {
    if (signal.aborted) ctrl.abort();
    else signal.addEventListener('abort', onAbort, { once: true });
  }
  try {
    const res = await fetchImpl(url, {
      headers: { Accept: 'application/json', 'User-Agent': UA },
      signal: ctrl.signal,
    });
    const text = await res.text();
    let json = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      json = null;
    }
    return { ok: res.ok, status: res.status, json, text };
  } finally {
    clearTimeout(timer);
    if (signal) signal.removeEventListener('abort', onAbort);
  }
}

export async function fetchShodanApiInfo(apiKey, opts = {}) {
  const key = String(apiKey || '').trim();
  if (!key) return { ok: false, note: 'SHODAN_API_KEY em falta' };
  try {
    const res = await shodanFetch('/api-info', key, opts);
    if (!res.ok) {
      return { ok: false, note: redactSecrets(`Shodan api-info HTTP ${res.status}`, key) };
    }
    const j = res.json || {};
    return {
      ok: true,
      plan: j.plan || '',
      queryCredits: j.query_credits ?? j.credits?.query ?? null,
      scanCredits: j.scan_credits ?? j.credits?.scan ?? null,
      unlocked: Boolean(j.unlocked || j.unlocked_left != null),
    };
  } catch (e) {
    return { ok: false, note: redactSecrets(e?.message || String(e), key) };
  }
}

export async function fetchShodanDomainDns(domain, apiKey, opts = {}) {
  const key = String(apiKey || '').trim();
  if (!key) return { ok: false, note: 'SHODAN_API_KEY em falta', subdomains: [], ips: [], creditsUsed: 0 };
  const d = String(domain || '').trim().toLowerCase();
  if (!d) return { ok: false, note: 'domínio em falta', subdomains: [], ips: [], creditsUsed: 0 };
  const maxSubs = opts.maxSubdomains ?? defaultLimits.shodanDomainMaxSubdomains ?? 200;
  try {
    const res = await shodanFetch(`/dns/domain/${encodeURIComponent(d)}`, key, {
      ...opts,
      params: { page: 1, ...(opts.params || {}) },
    });
    if (!res.ok) {
      return {
        ok: false,
        note: redactSecrets(`Shodan dns/domain HTTP ${res.status}`, key),
        subdomains: [],
        ips: [],
        creditsUsed: 0,
      };
    }
    const j = res.json || {};
    const subs = new Set();
    const ips = new Set();
    for (const raw of j.subdomains || []) {
      const label = String(raw || '').trim().toLowerCase();
      if (!label) continue;
      const fqdn = label.includes(d) ? label : `${label}.${d}`;
      subs.add(fqdn);
      if (subs.size >= maxSubs) break;
    }
    for (const row of j.data || []) {
      const sub = String(row?.subdomain || '').trim().toLowerCase();
      const type = String(row?.type || '').toUpperCase();
      const value = String(row?.value || '').trim();
      if (sub) {
        const fqdn = sub.includes(d) ? sub : `${sub}.${d}`;
        if (subs.size < maxSubs) subs.add(fqdn);
      }
      if (type === 'A' && /^\d{1,3}(\.\d{1,3}){3}$/.test(value)) ips.add(value);
    }
    return {
      ok: true,
      subdomains: [...subs].slice(0, maxSubs),
      ips: [...ips],
      creditsUsed: 1,
    };
  } catch (e) {
    return {
      ok: false,
      note: redactSecrets(e?.message || String(e), key),
      subdomains: [],
      ips: [],
      creditsUsed: 0,
    };
  }
}

export async function fetchShodanHostCount(query, apiKey, opts = {}) {
  const key = String(apiKey || '').trim();
  if (!key) return { ok: false, note: 'SHODAN_API_KEY em falta', total: 0, facets: {} };
  try {
    const facets = opts.facets || 'port,product,vuln,org';
    const res = await shodanFetch('/shodan/host/count', key, {
      ...opts,
      params: { query, facets },
    });
    if (!res.ok) {
      return {
        ok: false,
        note: redactSecrets(`Shodan host/count HTTP ${res.status}`, key),
        total: 0,
        facets: {},
      };
    }
    const j = res.json || {};
    return { ok: true, total: Number(j.total) || 0, facets: j.facets || {} };
  } catch (e) {
    return { ok: false, note: redactSecrets(e?.message || String(e), key), total: 0, facets: {} };
  }
}

export async function fetchShodanHostSearch(query, apiKey, opts = {}) {
  const key = String(apiKey || '').trim();
  if (!key) return { ok: false, note: 'SHODAN_API_KEY em falta', matches: [], creditsUsed: 0 };
  const maxMatches = opts.maxMatches ?? defaultLimits.shodanSearchMaxMatches ?? 40;
  try {
    const res = await shodanFetch('/shodan/host/search', key, {
      ...opts,
      params: {
        query,
        page: 1,
        minify: opts.minify === false ? 'false' : 'true',
      },
    });
    if (!res.ok) {
      return {
        ok: false,
        note: redactSecrets(`Shodan host/search HTTP ${res.status}`, key),
        matches: [],
        creditsUsed: 0,
      };
    }
    const j = res.json || {};
    const matches = (Array.isArray(j.matches) ? j.matches : []).slice(0, maxMatches).map((m) => ({
      ip: m.ip_str || m.ip || null,
      port: m.port ?? null,
      product: m.product || m?.http?.component || '',
      hostnames: Array.isArray(m.hostnames) ? m.hostnames.slice(0, 8) : [],
      org: m.org || m.isp || '',
      vulns: Array.isArray(m.vulns) ? m.vulns.slice(0, 5) : Object.keys(m.vulns || {}).slice(0, 5),
      title: m?.http?.title || '',
    }));
    return { ok: true, matches, total: Number(j.total) || matches.length, creditsUsed: 1 };
  } catch (e) {
    return {
      ok: false,
      note: redactSecrets(e?.message || String(e), key),
      matches: [],
      creditsUsed: 0,
    };
  }
}

/**
 * Lookup passivo Shodan (GET /shodan/host/{ip}) — requer SHODAN_API_KEY.
 * Enriquecido: ASN, país, tags, produtos dos banners.
 */
export async function shodanHostSummary(ip, apiKey, opts = {}) {
  const key = String(apiKey || '').trim();
  if (!key) return { ok: false, note: 'SHODAN_API_KEY em falta' };
  const targetIp = String(ip || '').trim();
  if (!targetIp) return { ok: false, note: 'IP em falta' };

  try {
    const res = await shodanFetch(`/shodan/host/${encodeURIComponent(targetIp)}`, key, {
      ...opts,
      params: {
        history: 'false',
        minify: opts.minify === true ? 'true' : 'false',
      },
    });
    if (!res.ok) {
      return { ok: false, note: redactSecrets(`Shodan HTTP ${res.status}`, key) };
    }
    const j = res.json || {};
    const hostnames = Array.isArray(j.hostnames) ? j.hostnames.slice(0, 8) : [];
    const ports = Array.isArray(j.ports) ? j.ports.slice(0, 20) : [];
    const org = j.org || j.isp || '';
    const vulner = Array.isArray(j.vulns)
      ? j.vulns.slice(0, 8)
      : Object.keys(j.vulns || {}).slice(0, 8);
    const products = [];
    const titles = [];
    for (const banner of Array.isArray(j.data) ? j.data.slice(0, 30) : []) {
      if (banner?.product) products.push(String(banner.product));
      const title = banner?.http?.title;
      if (title) titles.push(String(title).slice(0, 80));
    }

    return {
      ok: true,
      ip: targetIp,
      org,
      asn: j.asn || '',
      country: j.country_name || j.country_code || '',
      tags: Array.isArray(j.tags) ? j.tags.slice(0, 10) : [],
      hostnames,
      ports,
      vulns: vulner,
      products: [...new Set(products)].slice(0, 12),
      titles: [...new Set(titles)].slice(0, 5),
      rawCount: Array.isArray(j.data) ? j.data.length : ports.length,
    };
  } catch (e) {
    return { ok: false, note: redactSecrets(e?.message || String(e), key) };
  }
}

function summarizeFacets(facets, maxPer = 5) {
  const parts = [];
  for (const [name, rows] of Object.entries(facets || {})) {
    if (!Array.isArray(rows) || !rows.length) continue;
    const top = rows
      .slice(0, maxPer)
      .map((r) => `${r.value ?? r[0]}(${r.count ?? r[1]})`)
      .join(', ');
    if (top) parts.push(`${name}: ${top}`);
  }
  return parts.join(' · ');
}

function findingDraft(partial) {
  return {
    type: partial.type || 'intel',
    prio: partial.prio || 'med',
    score: partial.score ?? 50,
    value: partial.value,
    meta: partial.meta || '',
    url: partial.url || '',
    how: partial.how || '',
    relation: partial.relation || '',
  };
}

/**
 * Orquestra membership passivo: api-info, dns/domain, count, search, host lookups.
 */
export async function runShodanMembershipRecon({
  domain,
  hosts = [],
  apiKey,
  hostInScope = () => false,
  limits: lim = defaultLimits,
  fetchImpl = globalThis.fetch,
  signal,
  collectIpv4Impl,
  enableDnsDomain,
  enableSearch,
  maxQueryCredits,
} = {}) {
  const key = String(apiKey || '').trim();
  const flags = shodanFeatureFlags();
  const dnsOn = enableDnsDomain ?? flags.enableDnsDomain;
  const searchOn = enableSearch ?? flags.enableSearch;
  const creditBudget = maxQueryCredits ?? flags.maxQueryCredits;
  const logs = [];
  const findings = [];
  const subdomains = [];
  const outOfScopeIps = [];
  let creditsUsed = 0;

  if (!key) {
    return {
      ok: false,
      note: 'SHODAN_API_KEY em falta',
      creditsUsed: 0,
      subdomains: [],
      outOfScopeIps: [],
      findings: [],
      logs: [{ level: 'warn', message: 'Shodan: define SHODAN_API_KEY para lookup passivo (api.shodan.io)' }],
    };
  }

  const opts = { fetchImpl, signal };
  const d = String(domain || '').trim().toLowerCase();

  const info = await fetchShodanApiInfo(key, opts);
  if (info.ok) {
    logs.push({
      level: 'info',
      message: `Shodan api-info: plan=${info.plan || 'n/a'} query_credits=${info.queryCredits ?? 'n/a'}`,
    });
  } else if (info.note) {
    logs.push({ level: 'warn', message: `Shodan api-info: ${info.note}` });
  }

  const ipSet = new Set();
  const resolveHosts = [d, ...hosts].filter(Boolean);

  if (dnsOn && creditsUsed < creditBudget && d) {
    const dns = await fetchShodanDomainDns(d, key, {
      ...opts,
      maxSubdomains: lim.shodanDomainMaxSubdomains,
    });
    if (dns.ok) {
      creditsUsed += dns.creditsUsed;
      for (const h of dns.subdomains) {
        if (hostInScope(h)) subdomains.push(h);
      }
      for (const ip of dns.ips) {
        if (hostInScope(ip)) ipSet.add(ip);
        else outOfScopeIps.push(ip);
      }
      logs.push({
        level: 'success',
        message: `Shodan DNS domain: ${dns.subdomains.length} sub(s), ${dns.ips.length} A — créditos ${creditsUsed}/${creditBudget}`,
      });
      if (subdomains.length) {
        findings.push(
          findingDraft({
            type: 'asset',
            prio: 'med',
            score: 55,
            value: `Shodan DNS: ${subdomains.length} hostname(s) para ${d}`,
            meta: subdomains.slice(0, 20).join(', ') + (subdomains.length > 20 ? '…' : ''),
            url: `https://www.shodan.io/search?query=hostname%3A${encodeURIComponent(d)}`,
            how: `API Shodan GET /dns/domain/${d} (1 query credit).`,
            relation: 'Subdomínios e registos DNS indexados pelo Shodan para o domínio do programa.',
          }),
        );
      }
    } else {
      logs.push({ level: 'warn', message: `Shodan DNS domain: ${dns.note}` });
    }
  } else if (!dnsOn) {
    logs.push({ level: 'info', message: 'Shodan DNS domain desativado (GHOSTRECON_SHODAN_DNS_DOMAIN=0)' });
  }

  if (d) {
    const countQ = `hostname:${d}`;
    const count = await fetchShodanHostCount(countQ, key, opts);
    if (count.ok) {
      const facetStr = summarizeFacets(count.facets);
      findings.push(
        findingDraft({
          type: 'intel',
          prio: count.total > 0 ? 'med' : 'low',
          score: count.total > 0 ? 52 : 30,
          value: `Shodan count hostname:${d} → ${count.total}`,
          meta: facetStr || 'sem facets',
          url: `https://www.shodan.io/search?query=${encodeURIComponent(countQ)}`,
          how: 'API Shodan GET /shodan/host/count com facets (não consome query credits).',
          relation: 'Resumo da superfície indexada (portas/produtos/vulns/org) sem gastar créditos de search.',
        }),
      );
      logs.push({ level: 'info', message: `Shodan count: ${count.total} resultado(s) para hostname:${d}` });
    } else {
      logs.push({ level: 'warn', message: `Shodan count: ${count.note}` });
    }
  }

  const searchQueries = [];
  if (searchOn && d) {
    searchQueries.push({ label: 'hostname', query: `hostname:${d}` });
    searchQueries.push({ label: 'ssl', query: `ssl.cert.subject.cn:"${d}"` });
  } else if (!searchOn) {
    logs.push({ level: 'info', message: 'Shodan search desativado (GHOSTRECON_SHODAN_SEARCH=0)' });
  }

  for (const sq of searchQueries) {
    if (creditsUsed >= creditBudget) {
      logs.push({
        level: 'info',
        message: `Shodan search ${sq.label} omitido: orçamento de créditos esgotado (${creditsUsed}/${creditBudget})`,
      });
      continue;
    }
    const search = await fetchShodanHostSearch(sq.query, key, {
      ...opts,
      maxMatches: lim.shodanSearchMaxMatches,
    });
    if (!search.ok) {
      logs.push({ level: 'warn', message: `Shodan search ${sq.label}: ${search.note}` });
      continue;
    }
    creditsUsed += search.creditsUsed;
    let inScopeMatches = 0;
    for (const m of search.matches) {
      const ip = m.ip ? String(m.ip) : '';
      if (!ip) continue;
      if (!hostInScope(ip)) {
        outOfScopeIps.push(ip);
        continue;
      }
      ipSet.add(ip);
      inScopeMatches += 1;
      for (const hn of m.hostnames || []) {
        if (hostInScope(hn)) subdomains.push(String(hn).toLowerCase());
      }
      const scopedHostnames = (m.hostnames || []).filter((hn) => hostInScope(hn));
      findings.push(
        findingDraft({
          type: 'intel',
          prio: m.vulns?.length ? 'high' : 'med',
          score: m.vulns?.length ? 72 : 48,
          value: `Shodan search ${sq.label}: ${ip}${m.port != null ? `:${m.port}` : ''}`,
          meta: [
            m.product && `product: ${m.product}`,
            m.org && `org: ${m.org}`,
            m.title && `title: ${m.title}`,
            scopedHostnames.length && `hostnames: ${scopedHostnames.join(', ')}`,
            m.vulns?.length && `vulns: ${m.vulns.join(', ')}`,
          ]
            .filter(Boolean)
            .join(' · '),
          url: `https://www.shodan.io/host/${ip}`,
          how: `API Shodan GET /shodan/host/search?query=${sq.query} (1 query credit/página).`,
          relation: 'Banner/serviço indexado associado ao domínio via filtro hostname ou certificado SSL.',
        }),
      );
    }
    logs.push({
      level: 'success',
      message: `Shodan search ${sq.label}: ${inScopeMatches}/${search.matches.length} match(es) in-scope — créditos ${creditsUsed}/${creditBudget}`,
    });
  }

  let resolved = [];
  if (typeof collectIpv4Impl === 'function') {
    resolved = await collectIpv4Impl(
      resolveHosts,
      lim.shodanResolveMaxHosts ?? 14,
      lim.shodanMaxIps ?? 12,
      { signal },
    );
  }
  for (const ip of resolved) {
    if (hostInScope(ip)) ipSet.add(ip);
    else outOfScopeIps.push(ip);
  }

  const ips = [...ipSet].slice(0, lim.shodanMaxIps ?? 12);
  if (outOfScopeIps.length) {
    logs.push({
      level: 'info',
      message: `Shodan: ${new Set(outOfScopeIps).size} IP(s) fora da allowlist formal ignorado(s)`,
    });
  }

  for (const ip of ips) {
    const host = await shodanHostSummary(ip, key, opts);
    if (!host.ok) {
      logs.push({ level: 'warn', message: `Shodan ${ip}: ${host.note}` });
      continue;
    }
    const portStr = host.ports?.length ? host.ports.join(', ') : '—';
    const hn = host.hostnames?.length ? host.hostnames.join(', ') : '—';
    const vn = host.vulns?.length ? host.vulns.join(', ') : '';
    findings.push(
      findingDraft({
        type: 'intel',
        prio: host.vulns?.length ? 'high' : 'med',
        score: host.vulns?.length ? 74 : 50,
        value: `Shodan host ${ip}`,
        meta: [
          host.org && `org: ${host.org}`,
          host.asn && `asn: ${host.asn}`,
          host.country && `country: ${host.country}`,
          host.tags?.length && `tags: ${host.tags.join(', ')}`,
          `ports: ${portStr}`,
          `hostnames: ${hn}`,
          host.products?.length && `products: ${host.products.join(', ')}`,
          host.titles?.length && `titles: ${host.titles.join(' | ')}`,
          vn && `cve/tags: ${vn}`,
        ]
          .filter(Boolean)
          .join(' · '),
        url: `https://www.shodan.io/host/${ip}`,
        how: `API Shodan GET /shodan/host/{ip} (sem query credit). IP ${ip} após DNS/search do alvo ${d}.`,
        relation:
          'O IP aparece porque hostnames do recon ou resultados Shodan o associam ao domínio. Portas/serviços/vulns são inventário passivo da superfície internet.',
      }),
    );
  }

  return {
    ok: true,
    creditsUsed,
    creditBudget,
    apiInfo: info.ok ? info : null,
    subdomains: [...new Set(subdomains.map((h) => String(h).toLowerCase()))],
    outOfScopeIps: [...new Set(outOfScopeIps)],
    ips,
    findings,
    logs,
  };
}
