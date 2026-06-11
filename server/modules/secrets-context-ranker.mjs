export const moduleManifest = {
  id: 'secrets_context_ranker',
  name: 'Secrets Context Ranker',
  category: 'prioritization',
  intrusive: false,
  requiresAuth: false,
  requiresKali: false,
  timeoutMs: 3_000,
  concurrency: 1,
  outputs: ['finding'],
};

const HIGH_VALUE_KIND_RE = /aws|github|gitlab|slack|stripe|private|rsa|ssh|jwt|supabase|firebase|google|sendgrid|twilio|openai|api[_ -]?key|token/i;
const PROD_CONTEXT_RE = /(?:^|[/.?_-])(?:prod|production|live|main|release|app|api|admin|dashboard|billing|payment|config|env)(?:[/.?_-]|$)/i;
const TEST_CONTEXT_RE = /(?:^|[/.?_-])(?:test|tests|spec|fixture|mock|sample|example|demo|dev|local|staging)(?:[/.?_-]|$)/i;
const LOW_VALUE_KIND_RE = /google[_ -]?analytics|sentry[_ -]?dsn|mapbox|public|publishable|captcha|recaptcha/i;

function prioFor(score) {
  if (score >= 75) return 'high';
  if (score >= 55) return 'med';
  if (score >= 35) return 'low';
  return 'info';
}

function kindFromValue(value) {
  const m = String(value || '').match(/^\[([^\]]+)\]/);
  return m ? m[1] : 'secret';
}

function pathFromUrl(rawUrl) {
  try {
    const u = new URL(rawUrl);
    return `${u.hostname}${u.pathname}`;
  } catch {
    return String(rawUrl || '').slice(0, 140);
  }
}

export function scoreSecretContext(finding) {
  const value = String(finding?.value || '');
  const meta = typeof finding?.meta === 'string' ? finding.meta : JSON.stringify(finding?.meta || {});
  const url = String(finding?.url || '');
  const haystack = `${value} ${meta} ${url}`;
  const kind = kindFromValue(value);
  let score = 50;
  const reasons = [];

  if (HIGH_VALUE_KIND_RE.test(kind) || HIGH_VALUE_KIND_RE.test(value)) {
    score += 22;
    reasons.push('high_value_kind');
  }
  if (/value_fp=/.test(meta)) {
    score += 8;
    reasons.push('stable_fingerprint');
  }
  if (PROD_CONTEXT_RE.test(haystack)) {
    score += 10;
    reasons.push('prod_or_sensitive_path');
  }
  if (/\.map(?:\?|$)|sourceMappingURL/i.test(haystack)) {
    score += 8;
    reasons.push('source_map_context');
  }
  if (/github\.com|GitHub Code Search/i.test(haystack)) {
    score += 6;
    reasons.push('public_code_index');
  }
  if (TEST_CONTEXT_RE.test(haystack)) {
    score -= 18;
    reasons.push('test_or_demo_context');
  }
  if (LOW_VALUE_KIND_RE.test(haystack)) {
    score -= 12;
    reasons.push('often_public_or_low_impact');
  }

  score = Math.max(20, Math.min(95, score));
  return { score, prio: prioFor(score), kind, reasons };
}

export function rankSecretFindings(findings, { limit = 20 } = {}) {
  const rows = [];
  const seen = new Set();

  for (const f of findings || []) {
    if (f?.type !== 'secret') continue;
    const { score, prio, kind, reasons } = scoreSecretContext(f);
    if (score < 55 && !reasons.includes('test_or_demo_context')) continue;
    const ref = pathFromUrl(f.url || '');
    const key = `${kind}:${ref}:${f.value}`;
    if (seen.has(key)) continue;
    seen.add(key);
    rows.push({
      type: 'secret_context',
      prio,
      score,
      value: `Secret context rank: ${kind} @ ${ref || 'unknown'}`,
      meta: [
        'source=secrets_context_ranker',
        `original_prio=${f.prio || 'unknown'}`,
        reasons.length ? `reasons=${reasons.join(',')}` : 'reasons=generic_secret',
      ].join(' - '),
      url: f.url,
      owasp: 'A07:2021',
    });
  }

  return rows.sort((a, b) => b.score - a.score).slice(0, Math.max(1, limit));
}
