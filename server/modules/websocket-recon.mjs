export const moduleManifest = {
  id: 'websocket_recon',
  name: 'WebSocket Recon',
  category: 'surface',
  intrusive: false,
  requiresAuth: false,
  requiresKali: false,
  timeoutMs: 8_000,
  concurrency: 1,
  outputs: ['finding'],
};

const WS_URL_RE = /\bwss?:\/\/[^\s"'`<>)\\]+/gi;
const WS_CTOR_LITERAL_RE = /new\s+WebSocket\s*\(\s*([`'"])([^`'"]{1,500})\1/gi;
const WS_CTOR_TEMPLATE_RE = /new\s+WebSocket\s*\(\s*`([^`]{1,500})`/gi;
const TOKEN_PARAM_RE = /(?:^|[?&])(?:access_?token|auth|jwt|token|id_?token|api_?key|key|signature|sig)=/i;
const SENSITIVE_PATH_RE = /\/(?:admin|internal|private|graphql|socket|ws|realtime|events|stream|notify|chat|trading|payments?)(?:\/|$)/i;

function cleanWsCandidate(raw) {
  return String(raw || '')
    .trim()
    .replace(/[),.;\]}]+$/g, '')
    .replace(/&quot;/g, '"')
    .slice(0, 700);
}

function normalizeWsUrl(raw, baseUrl = '') {
  const candidate = cleanWsCandidate(raw);
  if (!candidate) return null;

  if (/^wss?:\/\//i.test(candidate)) return candidate;
  if (!baseUrl || !candidate.startsWith('/')) return null;

  try {
    const base = new URL(baseUrl);
    base.protocol = base.protocol === 'https:' ? 'wss:' : 'ws:';
    return new URL(candidate, base.href).href;
  } catch {
    return null;
  }
}

export function extractWebSocketUrlsFromText(text, { baseUrl = '' } = {}) {
  const body = String(text || '').slice(0, 700_000);
  const out = new Set();

  for (const re of [WS_URL_RE, WS_CTOR_LITERAL_RE, WS_CTOR_TEMPLATE_RE]) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(body)) !== null) {
      const raw = m[2] || m[1] || m[0];
      const normalized = normalizeWsUrl(raw, baseUrl);
      if (normalized) out.add(normalized);
      if (out.size >= 80) break;
    }
  }

  return [...out];
}

function hostOf(url) {
  try { return new URL(url).hostname; } catch { return 'unknown'; }
}

function prioFor(score) {
  if (score >= 75) return 'high';
  if (score >= 55) return 'med';
  if (score >= 35) return 'low';
  return 'info';
}

function finding({ score, issue, url, meta = [], owasp = 'A02:2021' }) {
  return {
    type: 'websocket_recon',
    prio: prioFor(score),
    score,
    value: `${issue}: ${hostOf(url)}`,
    meta: ['source=websocket_recon', ...meta].filter(Boolean).join(' - '),
    url,
    owasp,
  };
}

export function auditWebSocketUrls(urls, { target = '' } = {}) {
  const findings = [];
  const seen = new Set();

  for (const rawUrl of urls || []) {
    let url;
    try { url = new URL(rawUrl); } catch { continue; }
    const href = url.href;
    const keyBase = `${url.protocol}//${url.host}${url.pathname}`;

    const push = (key, row) => {
      const dedupeKey = `${key}:${keyBase}`;
      if (seen.has(dedupeKey)) return;
      seen.add(dedupeKey);
      findings.push(row);
    };

    const sameTarget =
      target && (url.hostname === target || url.hostname.endsWith(`.${target}`));

    push('inventory', finding({
      score: SENSITIVE_PATH_RE.test(url.pathname) ? 42 : 24,
      issue: 'WebSocket endpoint exposto no client',
      url: href,
      meta: [
        `scheme=${url.protocol.replace(':', '')}`,
        `path=${url.pathname || '/'}`,
        sameTarget ? 'scope=same_target' : 'scope=external_or_unknown',
      ],
    }));

    if (url.protocol === 'ws:') {
      push('cleartext', finding({
        score: 78,
        issue: 'WebSocket sem TLS (ws://)',
        url: href,
        meta: ['risk=cleartext_session_or_token_exposure'],
        owasp: 'A02:2021',
      }));
    }

    if (TOKEN_PARAM_RE.test(url.search)) {
      push('query-token', finding({
        score: 84,
        issue: 'Token em query string de WebSocket',
        url: href,
        meta: ['risk=token_in_logs_referrers_or_history', `query=${url.search.slice(0, 140)}`],
        owasp: 'A07:2021',
      }));
    }

    if (SENSITIVE_PATH_RE.test(url.pathname) && !TOKEN_PARAM_RE.test(url.search)) {
      push('sensitive-path', finding({
        score: 58,
        issue: 'WebSocket sensivel sem auth visivel na URL',
        url: href,
        meta: ['heuristic=check_origin_and_authz_on_upgrade'],
        owasp: 'A01:2021',
      }));
    }
  }

  return findings.sort((a, b) => b.score - a.score);
}

export function runWebSocketRecon({
  urlCorpus = [],
  jsBodies = [],
  htmlBodies = [],
  target = '',
} = {}) {
  const urls = new Set();
  for (const u of urlCorpus || []) {
    const normalized = normalizeWsUrl(u);
    if (normalized) urls.add(normalized);
  }
  for (const row of jsBodies || []) {
    for (const u of extractWebSocketUrlsFromText(row?.body || '', { baseUrl: row?.url || '' })) urls.add(u);
  }
  for (const row of htmlBodies || []) {
    for (const u of extractWebSocketUrlsFromText(row?.body || row?.html || '', { baseUrl: row?.url || '' })) urls.add(u);
  }
  return { findings: auditWebSocketUrls([...urls], { target }), urls: [...urls] };
}
