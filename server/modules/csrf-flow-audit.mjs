export const moduleManifest = {
  id: 'csrf_flow_audit',
  name: 'CSRF Flow Audit',
  category: 'surface',
  intrusive: false,
  requiresAuth: false,
  requiresKali: false,
  timeoutMs: 15_000,
  concurrency: 1,
  outputs: ['finding'],
};

const TOKEN_NAME_RE = /(?:csrf|xsrf|anti[-_]?forgery|authenticity|requestverificationtoken|nonce)/i;
const MUTATING_PATH_RE = /(?:delete|remove|logout|update|save|create|checkout|pay|transfer|password|email|profile|admin)/i;

function attrMap(tag) {
  const attrs = {};
  const re = /([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*(?:=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>`]+)))?/g;
  let m;
  while ((m = re.exec(String(tag || ''))) !== null) {
    const key = m[1].toLowerCase();
    if (key === 'form' || key === 'input') continue;
    attrs[key] = m[2] ?? m[3] ?? m[4] ?? true;
  }
  return attrs;
}

function resolveAction(action, baseUrl) {
  try {
    return new URL(action || baseUrl || '/', baseUrl || 'http://example.invalid/').href;
  } catch {
    return String(action || baseUrl || '');
  }
}

function inputNames(html) {
  const out = [];
  const re = /<input\b[^>]*\bname\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s"'>`]+))[^>]*>/gi;
  let m;
  while ((m = re.exec(String(html || ''))) !== null && out.length < 80) {
    out.push(String(m[1] || m[2] || m[3] || '').trim());
  }
  return out.filter(Boolean);
}

function hiddenMethod(body) {
  const re = /<input\b[^>]*\bname\s*=\s*(?:"_method"|'_method'|_method)[^>]*\bvalue\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s"'>`]+))[^>]*>/i;
  const m = String(body || '').match(re);
  return m ? String(m[1] || m[2] || m[3] || '').toUpperCase() : '';
}

export function extractForms(html, { url = '' } = {}) {
  const s = String(html || '').slice(0, 700_000);
  const out = [];
  const re = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
  let m;
  while ((m = re.exec(s)) !== null && out.length < 80) {
    const attrs = attrMap(m[1] || '');
    const body = m[2] || '';
    const names = inputNames(body);
    const method = String(attrs.method || 'get').toUpperCase();
    const override = hiddenMethod(body);
    const effectiveMethod = override || method;
    const action = resolveAction(attrs.action || url, url);
    out.push({
      method,
      effectiveMethod,
      action,
      inputNames: names,
      hasToken: names.some((n) => TOKEN_NAME_RE.test(n)),
      snippet: m[0].replace(/\s+/g, ' ').slice(0, 220),
    });
  }
  return out;
}

function prioFor(score) {
  if (score >= 75) return 'high';
  if (score >= 55) return 'med';
  if (score >= 35) return 'low';
  return 'info';
}

function sameOrigin(a, b) {
  try { return new URL(a).origin === new URL(b).origin; } catch { return false; }
}

function finding({ form, url, issue, score, detail = '' }) {
  let path = form.action || url;
  try { path = new URL(path).pathname || '/'; } catch { /* keep raw */ }
  return {
    type: 'csrf_flow',
    prio: prioFor(score),
    score,
    value: `${issue} @ ${path}`,
    meta: [
      `method=${form.effectiveMethod}`,
      `inputs=${form.inputNames.slice(0, 8).join(',') || '-'}`,
      detail,
    ].filter(Boolean).join(' - '),
    url: form.action || url,
    owasp: 'A01:2021',
  };
}

export function auditCsrfHtml(html, { url = '', hasSessionCookie = false } = {}) {
  const findings = [];
  const seen = new Set();
  for (const form of extractForms(html, { url })) {
    const mutating = /^(POST|PUT|PATCH|DELETE)$/i.test(form.effectiveMethod);
    const actionLooksMutating = MUTATING_PATH_RE.test(form.action || '');
    const push = (f) => {
      const key = `${f.value}:${f.meta}:${f.url}`;
      if (seen.has(key)) return;
      seen.add(key);
      findings.push(f);
    };

    if (mutating && !form.hasToken) {
      push(finding({
        form,
        url,
        issue: 'Formulario mutavel sem token CSRF visivel',
        score: hasSessionCookie ? 68 : 58,
        detail: `session_cookie=${hasSessionCookie ? 'yes' : 'unknown'}`,
      }));
    }
    if (!mutating && actionLooksMutating && !form.hasToken) {
      push(finding({
        form,
        url,
        issue: 'Formulario GET aponta para acao sensivel sem token',
        score: 46,
      }));
    }
    if (mutating && form.action && url && !sameOrigin(form.action, url)) {
      push(finding({
        form,
        url,
        issue: 'Formulario mutavel envia dados para outra origem',
        score: 52,
        detail: 'cross_origin=yes',
      }));
    }
  }
  return findings;
}

export function auditCsrfFlows(probeResults, { target = null } = {}) {
  const out = [];
  const seen = new Set();
  for (const row of probeResults || []) {
    const r = row?.r || row;
    if (!r?.ok || !r.htmlSample) continue;
    const cookies = r.securityHeaders?.setCookieSample || [];
    const hasSessionCookie = cookies.some((c) => /session|sess|sid|auth|token|jwt/i.test(String(c)));
    for (const f of auditCsrfHtml(r.htmlSample, { url: r.url, target, hasSessionCookie })) {
      const key = `${f.type}:${f.value}:${f.url}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(f);
    }
  }
  return out;
}
