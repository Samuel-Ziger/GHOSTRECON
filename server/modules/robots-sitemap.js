import { UA, limits } from '../config.js';
import { hostInReconScope, urlInReconScope } from './scope.js';
import { fetchScoped } from './scoped-fetch.mjs';

export { hostnameInScope } from './scope.js';

function extractSitemapLines(robotsText) {
  const out = [];
  if (!robotsText) return out;
  for (const line of robotsText.split(/\r?\n/)) {
    const m = line.match(/^\s*Sitemap:\s*(\S+)/i);
    if (m) out.push(m[1].trim());
  }
  return out;
}

function extractDisallowInteresting(robotsText, rootDomain) {
  const paths = [];
  if (!robotsText) return paths;
  for (const line of robotsText.split(/\r?\n/)) {
    const m = line.match(/^\s*Disallow:\s*(\S+)/i);
    if (!m) continue;
    const p = m[1].trim();
    if (!p || p === '/') continue;
    if (/\/(admin|api|internal|debug|backup|\.git|config|test|dev|staging)/i.test(p)) paths.push(p);
  }
  return [...new Set(paths)].slice(0, 30);
}

async function fetchText(url, timeoutMs, {
  rootDomain = '',
  outOfScopeRules = [],
  scopePolicy = null,
} = {}) {
  try {
    const res = await fetchScoped(url, {
      headers: { 'User-Agent': UA, Accept: 'text/plain,text/html,application/xml,*/*' },
      signal: AbortSignal.timeout(timeoutMs),
      urlAllowed: (candidate) => urlInReconScope(
        candidate,
        rootDomain,
        outOfScopeRules,
        scopePolicy,
      ),
    });
    if (!res.ok) return null;
    const t = await res.text();
    return t.length > 2_000_000 ? t.slice(0, 2_000_000) : t;
  } catch (error) {
    if (error?.code === 'OUT_OF_SCOPE' || error?.code === 'TOO_MANY_REDIRECTS') return null;
    throw error;
  }
}

function parseSitemapLocs(
  xml,
  rootDomain,
  limit,
  outOfScopeRules = [],
  scopePolicy = null,
) {
  const urls = [];
  const re = /<loc>\s*([^<]+)\s*<\/loc>/gi;
  let m;
  while ((m = re.exec(xml)) !== null) {
    const u = m[1].trim();
    try {
      const parsed = new URL(u);
      if (hostInReconScope(parsed.hostname, rootDomain, outOfScopeRules, scopePolicy)) urls.push(u);
    } catch {
      continue;
    }
    if (urls.length >= limit) break;
  }
  return urls;
}

/**
 * @param {string} baseOrigin ex. https://www.example.com/
 * @param {string} rootDomain ex. example.com
 * @param {string[]} [outOfScopeRules] hosts fora de escopo (env GHOSTRECON_OUT_OF_SCOPE)
 */
export async function crawlRobotsAndSitemapsForOrigin(
  baseOrigin,
  rootDomain,
  outOfScopeRules = [],
  scopePolicy = null,
) {
  const result = {
    robotsUrl: null,
    robotsOk: false,
    sitemapUrls: [],
    disallowHints: [],
    pageUrls: [],
    error: null,
  };

  let origin;
  try {
    origin = new URL(baseOrigin);
  } catch (e) {
    result.error = e?.message || String(e);
    return result;
  }
  if (!urlInReconScope(origin.href, rootDomain, outOfScopeRules, scopePolicy)) {
    result.error = 'origem fora do escopo autorizado';
    return result;
  }

  const robotsUrl = new URL('/robots.txt', origin).href;
  result.robotsUrl = robotsUrl;
  const to = limits.robotsFetchTimeoutMs;
  const scopeOpts = { rootDomain, outOfScopeRules, scopePolicy };

  try {
    const robots = await fetchText(robotsUrl, to, scopeOpts);
    if (robots) {
      result.robotsOk = true;
      result.sitemapUrls = extractSitemapLines(robots)
        .filter((sm) => urlInReconScope(sm, rootDomain, outOfScopeRules, scopePolicy));
      result.disallowHints = extractDisallowInteresting(robots, rootDomain);
    }
  } catch (e) {
    result.error = e?.message || String(e);
  }

  const defaultSitemap = new URL('/sitemap.xml', origin).href;
  if (
    urlInReconScope(defaultSitemap, rootDomain, outOfScopeRules, scopePolicy)
    && !result.sitemapUrls.includes(defaultSitemap)
  ) {
    result.sitemapUrls.unshift(defaultSitemap);
  }

  const seenSitemaps = new Set();
  const pageUrls = new Set();
  let sitemapCount = 0;
  const maxPages = limits.maxSitemapUrlsPerHost;
  const maxFiles = limits.maxSitemapFilesTotal;

  for (const sm of result.sitemapUrls) {
    if (sitemapCount >= maxFiles) break;
    if (seenSitemaps.has(sm)) continue;
    if (!urlInReconScope(sm, rootDomain, outOfScopeRules, scopePolicy)) continue;
    seenSitemaps.add(sm);
    sitemapCount++;

    let xml;
    try {
      xml = await fetchText(sm, to, scopeOpts);
    } catch {
      continue;
    }
    if (!xml) continue;

    if (/<sitemapindex/i.test(xml)) {
      const nested = [];
      const re = /<loc>\s*([^<]+)\s*<\/loc>/gi;
      let m;
      while ((m = re.exec(xml)) !== null) nested.push(m[1].trim());
      for (const inner of nested.slice(0, 8)) {
        if (sitemapCount >= maxFiles) break;
        if (seenSitemaps.has(inner)) continue;
        if (!urlInReconScope(inner, rootDomain, outOfScopeRules, scopePolicy)) continue;
        seenSitemaps.add(inner);
        sitemapCount++;
        try {
          const innerXml = await fetchText(inner, to, scopeOpts);
          if (innerXml) {
            for (const u of parseSitemapLocs(
              innerXml,
              rootDomain,
              maxPages - pageUrls.size,
              outOfScopeRules,
              scopePolicy,
            ))
              pageUrls.add(u);
          }
        } catch {
          /* skip */
        }
      }
    } else {
      for (const u of parseSitemapLocs(
        xml,
        rootDomain,
        maxPages - pageUrls.size,
        outOfScopeRules,
        scopePolicy,
      )) pageUrls.add(u);
    }
    if (pageUrls.size >= maxPages) break;
  }

  result.pageUrls = [...pageUrls];
  return result;
}
