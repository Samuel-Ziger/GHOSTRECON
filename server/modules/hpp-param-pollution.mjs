export const moduleManifest = {
  id: 'hpp_param_pollution',
  name: 'HTTP Parameter Pollution Audit',
  category: 'surface',
  intrusive: false,
  requiresAuth: false,
  requiresKali: false,
  timeoutMs: 5_000,
  concurrency: 1,
  outputs: ['finding'],
};

const RISKY_PARAM_RE = /^(?:next|return|returnurl|return_url|redirect|redirect_uri|url|uri|continue|callback|cb|jsonp|dest|destination|target|file|path|template|role|admin|is_admin|debug|id|uid|user|account)$/i;

function prioFor(score) {
  if (score >= 75) return 'high';
  if (score >= 55) return 'med';
  if (score >= 35) return 'low';
  return 'info';
}

function safeUrl(raw) {
  try { return new URL(String(raw)); } catch { return null; }
}

function normalizeParam(name) {
  return String(name || '').trim().toLowerCase();
}

export function duplicateQueryParams(rawUrl) {
  const u = safeUrl(rawUrl);
  if (!u) return [];
  const counts = new Map();
  for (const [name, value] of u.searchParams.entries()) {
    const key = normalizeParam(name);
    if (!key) continue;
    const row = counts.get(key) || { name: key, values: [], count: 0 };
    row.count += 1;
    if (value && row.values.length < 5) row.values.push(value.slice(0, 80));
    counts.set(key, row);
  }
  return [...counts.values()].filter((x) => x.count > 1);
}

function finding({ issue, score, param, url, meta = [] }) {
  return {
    type: 'hpp_param_pollution',
    prio: prioFor(score),
    score,
    value: `${issue}: ?${param}=`,
    meta: ['source=hpp_param_pollution', ...meta].filter(Boolean).join(' - '),
    url,
    owasp: 'A04:2021',
  };
}

export function auditHppParamPollution(urls, { paramRows = [] } = {}) {
  const findings = [];
  const seen = new Set();
  const paramStats = new Map();

  const push = (key, row) => {
    if (seen.has(key)) return;
    seen.add(key);
    findings.push(row);
  };

  for (const rawUrl of urls || []) {
    const u = safeUrl(rawUrl);
    if (!u || !u.search) continue;
    const observedInUrl = new Map();

    for (const [name, value] of u.searchParams.entries()) {
      const key = normalizeParam(name);
      if (!key) continue;
      const stat = paramStats.get(key) || { count: 0, urls: new Set(), values: new Set(), sampleUrl: rawUrl };
      stat.count += 1;
      stat.urls.add(`${u.origin}${u.pathname}`);
      if (value) stat.values.add(String(value).slice(0, 80));
      paramStats.set(key, stat);
      observedInUrl.set(key, (observedInUrl.get(key) || 0) + 1);
    }

    for (const dup of duplicateQueryParams(rawUrl)) {
      const score = RISKY_PARAM_RE.test(dup.name) ? 72 : 54;
      push(`dup:${dup.name}:${u.origin}${u.pathname}`, finding({
        issue: 'Parametro repetido na mesma URL',
        score,
        param: dup.name,
        url: rawUrl,
        meta: [
          `occurrences=${dup.count}`,
          dup.values.length ? `sample_values=${dup.values.join(',').slice(0, 120)}` : '',
          RISKY_PARAM_RE.test(dup.name) ? 'risk=parser_disagreement_on_sensitive_param' : 'risk=parser_disagreement',
        ],
      }));
    }
  }

  for (const row of paramRows || []) {
    const name = normalizeParam(row?.name);
    if (!name || paramStats.has(name)) continue;
    paramStats.set(name, {
      count: Number(row.count || 1),
      urls: new Set(),
      values: new Set(),
      sampleUrl: row.sampleUrl,
    });
  }

  for (const [name, stat] of paramStats.entries()) {
    if (!RISKY_PARAM_RE.test(name)) continue;
    const uniqueUrls = stat.urls.size;
    const uniqueValues = stat.values.size;
    const count = Number(stat.count || 0);
    if (count < 3 && uniqueUrls < 2 && uniqueValues < 2) continue;
    push(`shape:${name}`, finding({
      issue: 'Parametro sensivel observado em multiplos contextos',
      score: /^(?:redirect|redirect_uri|returnurl|return_url|next|url|callback|jsonp)$/i.test(name) ? 58 : 44,
      param: name,
      url: stat.sampleUrl,
      meta: [
        `observations=${count}`,
        uniqueUrls ? `unique_paths=${uniqueUrls}` : '',
        uniqueValues ? `unique_values=${uniqueValues}` : '',
        'heuristic=prioritize_hpp_and_parser_order_tests',
      ],
    }));
  }

  return findings.sort((a, b) => b.score - a.score);
}
