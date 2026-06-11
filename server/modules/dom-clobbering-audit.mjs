export const moduleManifest = {
  id: 'dom_clobbering_audit',
  name: 'DOM Clobbering Audit',
  category: 'surface',
  intrusive: false,
  requiresAuth: false,
  requiresKali: false,
  timeoutMs: 5_000,
  concurrency: 1,
  outputs: ['finding'],
};

const ATTR_RE = /\b(?:id|name)\s*=\s*(["'])([^"']{1,120})\1/gi;
const RESERVED_NAMES = new Set([
  '__proto__',
  'constructor',
  'prototype',
  'location',
  'document',
  'window',
  'forms',
  'attributes',
  'children',
  'submit',
  'action',
  'method',
  'target',
  'srcdoc',
  'innerhtml',
  'outerhtml',
  'contentwindow',
  'opener',
]);

const JS_PATTERNS = [
  {
    key: 'document-dynamic-prop',
    re: /document\s*\[\s*(?:location|window|[a-zA-Z_$][\w$]*)/gi,
    score: 58,
    issue: 'Acesso dinamico a propriedade de document',
  },
  {
    key: 'forms-name-access',
    re: /document\.forms\s*\[\s*[^'"\]]/gi,
    score: 54,
    issue: 'Acesso a form por nome dinamico',
  },
  {
    key: 'window-named-prop',
    re: /window\s*\[\s*(?:location|document|[a-zA-Z_$][\w$]*)/gi,
    score: 50,
    issue: 'Acesso dinamico a propriedade de window',
  },
  {
    key: 'hash-to-dom',
    re: /getElementById\s*\(\s*(?:location\.(?:hash|search)|window\.location)/gi,
    score: 64,
    issue: 'Lookup DOM controlado por location',
  },
];

function prioFor(score) {
  if (score >= 75) return 'high';
  if (score >= 55) return 'med';
  if (score >= 35) return 'low';
  return 'info';
}

function cleanName(value) {
  return String(value || '').trim().toLowerCase();
}

function makeFinding({ issue, score, url, name = '', meta = [] }) {
  return {
    type: 'dom_clobbering',
    prio: prioFor(score),
    score,
    value: name ? `${issue}: ${name}` : issue,
    meta: ['source=dom_clobbering_audit', ...meta].filter(Boolean).join(' - '),
    url,
    owasp: 'A03:2021',
  };
}

export function extractDomNamedProperties(html) {
  const src = String(html || '').slice(0, 500_000);
  const out = [];
  ATTR_RE.lastIndex = 0;
  let m;
  while ((m = ATTR_RE.exec(src)) !== null) {
    const raw = m[2];
    const name = cleanName(raw);
    if (!name) continue;
    out.push({ name, raw, index: m.index });
    if (out.length >= 400) break;
  }
  return out;
}

export function auditDomClobberingHtml(html, { url = '' } = {}) {
  const findings = [];
  const seen = new Set();
  const names = extractDomNamedProperties(html);
  const counts = new Map();

  const push = (key, row) => {
    if (seen.has(key)) return;
    seen.add(key);
    findings.push(row);
  };

  for (const item of names) {
    counts.set(item.name, (counts.get(item.name) || 0) + 1);
    if (RESERVED_NAMES.has(item.name)) {
      push(`reserved:${item.name}`, makeFinding({
        issue: 'id/name colide com propriedade global sensivel',
        score: /^(?:__proto__|constructor|prototype|location|document|window)$/.test(item.name) ? 68 : 52,
        name: item.raw,
        url,
        meta: ['surface=html_named_property'],
      }));
    }
  }

  for (const [name, count] of counts.entries()) {
    if (count < 2) continue;
    if (!RESERVED_NAMES.has(name) && count < 3) continue;
    push(`duplicate:${name}`, makeFinding({
      issue: 'id/name duplicado pode alterar resolucao DOM',
      score: RESERVED_NAMES.has(name) ? 60 : 42,
      name,
      url,
      meta: [`duplicates=${count}`, 'surface=html_named_property'],
    }));
  }

  return findings;
}

export function auditDomClobberingJs(js, { url = '' } = {}) {
  const src = String(js || '').slice(0, 700_000);
  const findings = [];
  const seen = new Set();

  for (const p of JS_PATTERNS) {
    p.re.lastIndex = 0;
    let m;
    let count = 0;
    while ((m = p.re.exec(src)) !== null && count < 2) {
      const snippet = src.slice(Math.max(0, m.index - 45), Math.min(src.length, m.index + 115)).replace(/\s+/g, ' ').trim();
      const key = `${p.key}:${snippet}`;
      if (!seen.has(key)) {
        seen.add(key);
        findings.push(makeFinding({
          issue: p.issue,
          score: p.score,
          url,
          meta: [`pattern=${p.key}`, `snippet=${snippet.slice(0, 180)}`],
        }));
      }
      count += 1;
    }
  }

  return findings;
}

export function runDomClobberingAudit({ htmlBodies = [], jsBodies = [] } = {}) {
  const findings = [];
  const seen = new Set();
  const pushAll = (rows) => {
    for (const f of rows || []) {
      const key = `${f.type}:${f.value}:${f.url}:${f.meta}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push(f);
    }
  };

  for (const row of htmlBodies || []) {
    pushAll(auditDomClobberingHtml(row?.body || row?.html || '', { url: row?.url || '' }));
  }
  for (const row of jsBodies || []) {
    pushAll(auditDomClobberingJs(row?.body || '', { url: row?.url || '' }));
  }

  return { findings: findings.sort((a, b) => b.score - a.score) };
}
