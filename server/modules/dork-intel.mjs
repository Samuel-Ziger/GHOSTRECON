import { googleCseSearch } from './google-cse.js';
import { readResponseSnippet } from './module-runner.mjs';

const MAX_BODY_BYTES = 128 * 1024;
const DEFAULT_MAX_QUERIES = 8;

const ERROR_PATTERNS = {
  directory: /<title>\s*index of|parent directory|directory listing for/i,
  sqlerrors: /sql syntax.*(?:mysql|mariadb)|ora-\d{4,}|oledb provider|postgresql.*error|sqlite.*exception/i,
  phperrors: /(?:fatal error|warning):[^<\n]{0,120}(?:php|include|require)|stack trace:[\s\S]{0,200}\.php/i,
  phpinfo: /<title>phpinfo\(\)|php version|php credits|php variable/i,
  login: /<form[\s\S]{0,1200}(?:type=["']password["']|name=["'](?:password|passwd|senha)["'])/i,
  config: /(?:^|\n)\s*(?:database_url|db_(?:host|name|user)|api[_-]?url|\[[a-z0-9_.-]+\])\s*[:=]/i,
  database: /(?:create\s+table|insert\s+into|sqlite format 3|postgresql database dump)/i,
  logs: /(?:^|\n)(?:\d{4}-\d{2}-\d{2}[t\s]|\[[^\]]{3,30}\])[^\n]{0,160}(?:error|warn|request|exception)/i,
  passwords: /(?:password|passwd|pwd)\s*[:=]\s*["'][^"'\r\n]{8,}["']/i,
  sensitive: /(?:\[core\][\s\S]{0,300}repositoryformatversion|-----begin [a-z ]+private key-----|(?:api[_-]?key|client_secret|access_token)\s*[:=])/i,
};

const DOCUMENT_EXT_RE = /\.(?:pdf|docx?|odt|xlsx?|ods|csv|pptx?|odp)(?:$|[?#])/i;
const ARCHIVE_EXT_RE = /\.(?:bak|old|backup|orig|zip|tar|tgz|gz|7z|rar)(?:$|[?#])/i;
const DB_EXT_RE = /\.(?:sql|db|sqlite|sqlite3|mdb)(?:$|[?#])/i;
const LOG_EXT_RE = /\.(?:log|out|trace)(?:$|[?#])/i;
const CONFIG_EXT_RE = /(?:^|\/)\.(?:env|git\/config)|\.(?:ini|conf|cnf|config|ya?ml|toml)(?:$|[?#])/i;

function abortError(signal) {
  return signal?.reason || new DOMException('The operation was aborted', 'AbortError');
}

function combinedSignal(parent, timeoutMs) {
  const timeout = AbortSignal.timeout(Math.max(1_000, Number(timeoutMs) || 12_000));
  return parent ? AbortSignal.any([parent, timeout]) : timeout;
}

function headerValue(headers, name) {
  if (!headers) return '';
  if (typeof headers.get === 'function') return String(headers.get(name) || '');
  return String(headers[String(name).toLowerCase()] || headers[name] || '');
}

function looksLikeSoft404(status, contentType, body) {
  if (Number(status) !== 200 || !/html/i.test(contentType)) return false;
  return /<title>[^<]*(?:404|not found|não encontrad|página inexistente)|\b(?:page|resource) not found\b/i.test(body);
}

function evidenceFor(category, url, contentType, body) {
  const text = String(body || '').slice(0, MAX_BODY_BYTES);
  if (category === 'documents') {
    return DOCUMENT_EXT_RE.test(url) || /application\/(?:pdf|msword|vnd\.|octet-stream)|text\/csv/i.test(contentType)
      ? 'document_type_or_extension'
      : null;
  }
  if (category === 'backup') {
    return ARCHIVE_EXT_RE.test(url) && !/text\/html/i.test(contentType) ? 'archive_extension_and_non_html' : null;
  }
  if (category === 'database' && DB_EXT_RE.test(url) && !/text\/html/i.test(contentType)) {
    return 'database_extension_and_non_html';
  }
  if (category === 'logs' && LOG_EXT_RE.test(url) && !/text\/html/i.test(contentType)) {
    return 'log_extension_and_non_html';
  }
  if (category === 'config' && CONFIG_EXT_RE.test(url) && !/text\/html/i.test(contentType)) {
    return 'config_extension_and_non_html';
  }
  const pattern = ERROR_PATTERNS[category];
  return pattern?.test(text) ? `content_signature:${category}` : null;
}

function scoreFor(category, evidence) {
  if (category === 'login' || category === 'documents') return { score: 42, prio: 'low', type: 'osint_inventory' };
  if (['directory', 'sqlerrors', 'phperrors', 'phpinfo'].includes(category)) {
    return { score: 66, prio: 'med', type: 'osint_candidate' };
  }
  return { score: evidence?.startsWith('content_signature') ? 68 : 58, prio: 'med', type: 'osint_candidate' };
}

export async function validateDorkResult(url, category, {
  fetchImpl = globalThis.fetch,
  signal = null,
  urlAllowed = null,
  timeoutMs = 12_000,
} = {}) {
  if (signal?.aborted) throw abortError(signal);
  if (typeof urlAllowed === 'function' && urlAllowed(url) !== true) {
    return { ok: false, reason: 'out_of_scope' };
  }
  const parsed = new URL(url);
  if (!['http:', 'https:'].includes(parsed.protocol)) return { ok: false, reason: 'unsupported_protocol' };
  const res = await fetchImpl(parsed.href, {
    method: 'GET',
    redirect: 'manual',
    signal: combinedSignal(signal, timeoutMs),
    headers: {
      Accept: '*/*',
      Range: `bytes=0-${MAX_BODY_BYTES - 1}`,
      'User-Agent': 'GHOSTRECON/1.0 authorized-recon',
    },
  });
  const location = headerValue(res.headers, 'location');
  if (res.status >= 300 && res.status < 400) {
    let redirectUrl = '';
    try { redirectUrl = new URL(location, parsed).href; } catch { /* invalid redirect */ }
    if (!redirectUrl || (typeof urlAllowed === 'function' && urlAllowed(redirectUrl) !== true)) {
      return { ok: false, reason: 'redirect_out_of_scope', status: res.status };
    }
    return { ok: false, reason: 'redirect_not_followed', status: res.status, redirectUrl };
  }
  if (res.status < 200 || res.status >= 300) return { ok: false, reason: `http_${res.status}`, status: res.status };
  const contentType = headerValue(res.headers, 'content-type').slice(0, 160);
  const body = await readResponseSnippet(res, MAX_BODY_BYTES);
  if (looksLikeSoft404(res.status, contentType, body)) return { ok: false, reason: 'soft_404', status: res.status };
  const evidence = evidenceFor(category, parsed.href, contentType, body);
  if (!evidence) return { ok: false, reason: 'category_not_confirmed', status: res.status };
  return { ok: true, status: res.status, contentType, evidence };
}

export async function runDorkIntel({
  target,
  dorks = [],
  apiKey = process.env.GOOGLE_CSE_KEY,
  cx = process.env.GOOGLE_CSE_CX,
  fetchImpl = globalThis.fetch,
  searchImpl = googleCseSearch,
  signal = null,
  urlAllowed = null,
  maxQueries = DEFAULT_MAX_QUERIES,
  maxFindings = 20,
  log = null,
} = {}) {
  if (!apiKey || !cx) {
    return { findings: [], metrics: { status: 'provider_not_configured', queries: 0, validated: 0 } };
  }
  const byCategory = new Map();
  for (const dork of dorks || []) {
    const category = String(dork?.mod || '').trim();
    if (!category || byCategory.has(category) || !dork?.query) continue;
    byCategory.set(category, dork);
  }
  const selected = [...byCategory.values()].slice(0, Math.max(1, Number(maxQueries) || DEFAULT_MAX_QUERIES));
  const findings = [];
  const seen = new Set();
  let candidates = 0;
  let validationErrors = 0;
  for (const dork of selected) {
    if (signal?.aborted) throw abortError(signal);
    let items = [];
    try {
      items = await searchImpl(dork.query, apiKey, cx, { fetchImpl, signal });
    } catch (error) {
      if (signal?.aborted || error?.name === 'AbortError') throw error;
      validationErrors += 1;
      log?.(`Dork intel [${dork.mod}]: ${error.message}`, 'warn');
      continue;
    }
    for (const item of items.slice(0, 10)) {
      if (findings.length >= maxFindings) break;
      const link = String(item?.link || '');
      if (!link || seen.has(link)) continue;
      if (typeof urlAllowed === 'function' && urlAllowed(link) !== true) continue;
      seen.add(link);
      candidates += 1;
      try {
        const validation = await validateDorkResult(link, dork.mod, { fetchImpl, signal, urlAllowed });
        if (!validation.ok) continue;
        const classification = scoreFor(dork.mod, validation.evidence);
        findings.push({
          type: classification.type,
          prio: classification.prio,
          score: classification.score,
          value: `${dork.mod}: resultado público validado`,
          url: link,
          meta: {
            source: 'google_cse',
            category: dork.mod,
            status: validation.status,
            contentType: validation.contentType,
            evidence: validation.evidence,
            target,
            confidence: dork.mod === 'login' || dork.mod === 'documents' ? 'inventory' : 'candidate',
          },
        });
      } catch (error) {
        if (signal?.aborted || error?.name === 'AbortError') throw error;
        validationErrors += 1;
      }
    }
  }
  return {
    findings,
    metrics: {
      status: 'done',
      queries: selected.length,
      candidates,
      validated: findings.length,
      validationErrors,
    },
  };
}

