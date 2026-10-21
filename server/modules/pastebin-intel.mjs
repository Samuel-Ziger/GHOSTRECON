import { googleCseSearch } from './google-cse.js';

export const moduleManifest = Object.freeze({
  id: 'pastebin',
  name: 'Public Paste References',
  category: 'discovery',
  intrusive: false,
  requiresAuth: false,
  requiresKali: false,
  timeoutMs: 60_000,
  concurrency: 1,
  outputs: ['finding', 'intel'],
});

const PUBLIC_PASTE_HOSTS = Object.freeze(new Set([
  'pastebin.com',
  'paste.ee',
  'controlc.com',
  'rentry.co',
  'hastebin.com',
]));

const SENSITIVE_ASSIGNMENT_RE = /\b(password|passwd|pwd|api[_-]?key|secret|token|authorization)\s*[:=]\s*([^\s,;]{4,})/gi;
const BEARER_RE = /\bBearer\s+[A-Za-z0-9._~+\/-]{12,}/gi;

function normalizeTarget(target) {
  const raw = String(target || '').trim().toLowerCase();
  if (!raw) return '';
  try {
    return new URL(/^https?:\/\//i.test(raw) ? raw : `https://${raw}`).hostname
      .toLowerCase();
  } catch {
    return '';
  }
}

export function isPublicPasteUrl(value) {
  try {
    const url = new URL(String(value || ''));
    const host = url.hostname.toLowerCase().replace(/^www\./, '');
    return /^https?:$/.test(url.protocol) && !url.username && !url.password && !url.port && PUBLIC_PASTE_HOSTS.has(host);
  } catch {
    return false;
  }
}

function safePublicPasteUrl(value) {
  const parsed = new URL(String(value || ''));
  parsed.username = '';
  parsed.password = '';
  parsed.hash = '';
  for (const key of parsed.searchParams.keys()) parsed.searchParams.set(key, '<redacted>');
  return parsed.toString();
}

export function redactPasteSearchText(value) {
  return String(value || '')
    .replace(SENSITIVE_ASSIGNMENT_RE, (_all, key) => `${key}=<redacted>`)
    .replace(BEARER_RE, 'Bearer <redacted>')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 240);
}

export function pasteResultReferencesTarget(item, target) {
  const domain = normalizeTarget(target);
  if (!domain || !isPublicPasteUrl(item?.link)) return false;
  const haystack = [item?.title, item?.snippet, item?.link]
    .map((part) => String(part || '').toLowerCase())
    .join(' ');
  const escaped = domain.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`(^|[^a-z0-9.-])${escaped}([^a-z0-9.-]|$)`, 'i').test(haystack);
}

function pasteQueries(domain) {
  const sites = [...PUBLIC_PASTE_HOSTS].map((host) => `site:${host}`).join(' OR ');
  return [
    `"${domain}" (${sites})`,
    `"@${domain}" (${sites})`,
  ];
}

export async function runPastebinIntel({
  target,
  apiKey = process.env.GOOGLE_CSE_KEY,
  cx = process.env.GOOGLE_CSE_CX,
  searchImpl = googleCseSearch,
  signal = null,
  log = null,
  maxResults = 20,
  now = () => new Date(),
  timeoutMs = moduleManifest.timeoutMs,
} = {}) {
  const domain = normalizeTarget(target);
  if (!domain) return { findings: [], metrics: { status: 'invalid_target', queries: 0, results: 0 } };
  if (!apiKey || !cx) {
    log?.('Paste intelligence indisponível: configure GOOGLE_CSE_KEY e GOOGLE_CSE_CX.', 'info');
    return { findings: [], metrics: { status: 'provider_not_configured', queries: 0, results: 0 } };
  }

  const findings = [];
  const seen = new Set();
  const outcomes = [];
  const resultLimit = Math.max(1, Math.min(20, Number(maxResults) || 20));
  const deadline = AbortSignal.timeout(Math.max(1, Math.min(moduleManifest.timeoutMs, Number(timeoutMs) || moduleManifest.timeoutMs)));
  const requestSignal = signal ? AbortSignal.any([signal, deadline]) : deadline;
  let queriesRun = 0;
  for (const query of pasteQueries(domain)) {
    if (signal?.aborted) throw signal.reason || new DOMException('Aborted', 'AbortError');
    if (deadline.aborted) { outcomes.push({ query: queriesRun + 1, state: 'timeout' }); break; }
    queriesRun += 1;
    let rows;
    try {
      rows = await searchImpl(query, apiKey, cx, { signal: requestSignal, timeoutMs: moduleManifest.timeoutMs });
      signal?.throwIfAborted();
      requestSignal.throwIfAborted();
      if (!Array.isArray(rows)) throw new TypeError('provider_schema');
      outcomes.push({ query: queriesRun, state: 'done', returned: rows.length });
    } catch (error) {
      signal?.throwIfAborted();
      // Texto de erro do provedor pode conter a chave ou o snippet privado.
      const state = requestSignal.aborted || error?.name === 'TimeoutError' ? 'timeout' : [403, 429].includes(error?.status) ? 'quota_or_denied' : 'provider_failed';
      outcomes.push({ query: queriesRun, state });
      log?.(`Paste intelligence: ${state}; consulta incompleta.`, 'warn');
      break;
    }
    for (const item of rows.slice(0, 10)) {
      if (findings.length >= resultLimit) break;
      const link = String(item?.link || '').trim();
      if (!pasteResultReferencesTarget(item, domain)) continue;
      const evidenceLink = safePublicPasteUrl(link);
      if (seen.has(evidenceLink)) continue;
      seen.add(evidenceLink);
      const context = redactPasteSearchText(`${item?.title || ''} ${item?.snippet || ''}`);
      const sensitiveHint = /\b(password|passwd|api[_-]?key|secret|token|credential|leak|dump)\b/i.test(context);
      findings.push({
        type: 'public_paste_reference',
        prio: 'info',
        score: sensitiveHint ? 28 : 22,
        value: `Referência pública ao alvo encontrada em ${new URL(link).hostname}`,
        // O snippet do provedor pode conter um segredo real. Ele serve apenas
        // para triagem local e nunca é persistido no finding/NDJSON.
        meta: `source=google_cse • classification=candidate • target=${domain} • snippet_persisted=no`,
        url: evidenceLink,
        verification: {
          classification: 'candidate',
          evidence: {
            source: 'google_cse_public_paste',
            providerHost: new URL(link).hostname,
            target: domain,
            searchResultMatched: true,
          },
          verified: false,
          retrievedAt: new Date(now()).toISOString(),
          observedAt: null,
        },
      });
    }
    if (findings.length >= resultLimit) break;
  }

  log?.(`Paste intelligence: ${findings.length} referência(s) pública(s) candidata(s).`, findings.length ? 'find' : 'info');
  return {
    findings,
    metrics: {
      status: outcomes.every((o) => o.state === 'done') ? 'ok' : outcomes.some((o) => o.state === 'done') ? 'partial' : outcomes.at(-1)?.state || 'provider_failed',
      queries: queriesRun,
      results: findings.length,
      coverage: 'first_page_per_query; not_exhaustive',
      outcomes,
    },
  };
}
