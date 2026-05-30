/**
 * Achados de configuração de cabeçalhos (orientação a hardening / superfície).
 * Não substitui auditoria manual.
 */

function cookieFlagsIssues(lines) {
  const issues = [];
  for (const line of lines || []) {
    const l = String(line).toLowerCase();
    if (!l.trim()) continue;
    if (!l.includes('httponly')) issues.push('Set-Cookie sem HttpOnly (amostra)');
    if (!l.includes('secure') && !l.includes('__host-') && !l.includes('__secure-'))
      issues.push('Set-Cookie sem Secure em contexto HTTPS (amostra)');
    break;
  }
  return issues;
}

/**
 * @param {string} pageUrl URL final após redirects
 * @param {object} snap resultado de snapshotSecurityHeaders()
 * @returns {{ text: string, prio: string, score: number }[]}
 */
export function analyzeSecurityHeaders(pageUrl, snap) {
  if (!snap) return [];
  const out = [];
  const isHttps = String(pageUrl).toLowerCase().startsWith('https:');

  if (isHttps && !snap.strictTransportSecurity) {
    out.push({
      text: 'Sem Strict-Transport-Security (HSTS)',
      prio: 'med',
      score: 48,
    });
  }
  if (!snap.contentSecurityPolicy) {
    out.push({
      text: 'Sem Content-Security-Policy',
      prio: 'low',
      score: 32,
    });
  }
  if (!snap.xFrameOptions && !/frame-ancestors/i.test(snap.contentSecurityPolicy || '')) {
    out.push({
      text: 'Sem X-Frame-Options / frame-ancestors em CSP (clickjacking)',
      prio: 'low',
      score: 35,
    });
  }
  if (!snap.xContentTypeOptions) {
    out.push({
      text: 'Sem X-Content-Type-Options: nosniff',
      prio: 'low',
      score: 30,
    });
  }
  if (!snap.referrerPolicy) {
    out.push({
      text: 'Sem Referrer-Policy explícita',
      prio: 'low',
      score: 26,
    });
  }

  for (const msg of cookieFlagsIssues(snap.setCookieSample)) {
    out.push({ text: msg, prio: 'med', score: 44 });
  }

  return out;
}

/**
 * Analisa fraquezas em CSP presente (não só ausência).
 * @returns {{ text: string, score: number, issue: string }[]}
 */
export function analyzeCspWeaknesses(cspRaw) {
  const csp = String(cspRaw || '').trim();
  if (!csp) return [];
  const out = [];
  const lower = csp.toLowerCase();

  if (/\bunsafe-inline\b/.test(lower)) {
    out.push({ text: 'CSP permite unsafe-inline — DOM/reflected XSS difícil de conter', score: 62, issue: 'unsafe-inline' });
  }
  if (/\bunsafe-eval\b/.test(lower)) {
    out.push({ text: 'CSP permite unsafe-eval — vetor de injeção JS', score: 65, issue: 'unsafe-eval' });
  }
  if (/(?:^|[;\s])default-src\s+\*/.test(lower) || /(?:^|[;\s])script-src[^;]*\*[^;]*$/.test(lower)) {
    out.push({ text: 'CSP usa wildcard (*) em script-src/default-src', score: 68, issue: 'wildcard-src' });
  }
  if (/data:\s*[^;]*script|script-src[^;]*data:/i.test(lower)) {
    out.push({ text: 'CSP permite data: em script-src — bypass comum', score: 60, issue: 'data-script' });
  }
  if (!/frame-ancestors/i.test(lower) && !/none/i.test(lower)) {
    out.push({ text: 'CSP sem frame-ancestors — clickjacking depende só de X-Frame-Options', score: 48, issue: 'no-frame-ancestors' });
  }
  if (/upgrade-insecure-requests/i.test(lower) === false && /http:/i.test(csp)) {
    out.push({ text: 'CSP referencia http: sem upgrade-insecure-requests', score: 45, issue: 'mixed-in-csp' });
  }
  return out;
}

const PERMISSIONS_POLICY_SENSITIVE = [
  'camera', 'microphone', 'geolocation', 'payment', 'usb', 'interest-cohort',
];

/**
 * @returns {{ text: string, score: number, missing: string[] }[]}
 */
export function analyzePermissionsPolicyGaps(snap) {
  const pp = String(snap?.permissionsPolicy || snap?.['permissions-policy'] || '').trim();
  if (pp) return [];
  return [{
    text: 'Permissions-Policy ausente — APIs sensíveis do browser sem restrição declarada',
    score: 38,
    missing: PERMISSIONS_POLICY_SENSITIVE,
  }];
}

const CLICKJACKING_HEADERS = [
  { key: 'contentSecurityPolicy', label: 'Content-Security-Policy', check: (s) => Boolean(s.contentSecurityPolicy) },
  {
    key: 'xFrameOptions',
    label: 'X-Frame-Options / frame-ancestors',
    check: (s) => Boolean(s.xFrameOptions) || /frame-ancestors/i.test(s.contentSecurityPolicy || ''),
  },
  { key: 'xContentTypeOptions', label: 'X-Content-Type-Options', check: (s) => Boolean(s.xContentTypeOptions) },
  { key: 'referrerPolicy', label: 'Referrer-Policy', check: (s) => Boolean(s.referrerPolicy) },
];

/**
 * Agrega gaps críticos de hardening (CSP + anti-clickjacking + nosniff + referrer).
 * Emite um achado composto quando 3+ controles estão ausentes.
 *
 * @returns {{ text: string, prio: string, score: number, missing: string[] } | null}
 */
export function summarizeSecurityHeaderGaps(pageUrl, snap) {
  if (!snap) return null;
  const missing = CLICKJACKING_HEADERS.filter((h) => !h.check(snap)).map((h) => h.label);
  if (missing.length < 3) return null;

  const clickjackingExposed = !CLICKJACKING_HEADERS[0].check(snap)
    && !CLICKJACKING_HEADERS[1].check(snap);

  return {
    text: `${missing.length} headers de segurança ausentes (${missing.join(', ')})`,
    prio: clickjackingExposed ? 'high' : 'med',
    score: clickjackingExposed ? 72 : 58,
    missing,
    clickjackingRisk: clickjackingExposed,
    host: (() => {
      try { return new URL(pageUrl).hostname; } catch { return pageUrl; }
    })(),
  };
}
