/**
 * client-auth-audit.mjs
 *
 * Detecção generalista de falhas de autenticação/autorização no frontend.
 * Cobre padrões observados em pentests reais (SPA admin embutido, credenciais
 * hardcoded, bypass via sessionStorage/localStorage, painéis ocultos no bundle).
 *
 * Análise estática sobre bundles JS — sem rede.
 */

const ADMIN_ROUTE_RE = /["'`](\/(?:admin|painel|dashboard|backoffice|manage|console|campanhas|panel)[a-zA-Z0-9_\-./]*)["'`]/gi;

const HARDCODED_CRED_RE = [
  {
    id: 'password_literal_compare',
    re: /(?:password|senha|passwd|pass)\s*(?:===|==|!==|!=)\s*["']([^"']{4,120})["']/gi,
    score: 95,
  },
  {
    id: 'password_var_compare',
    re: /(?:if\s*\(\s*(?:input|value|pwd|pass)\s*(?:===|==)\s*(?:password|senha|ADMIN_PASS|adminPass|SECRET))/gi,
    score: 88,
  },
  {
    id: 'admin_credential_const',
    re: /(?:ADMIN_(?:PASS|PASSWORD|KEY|SENHA)|adminPassword|defaultPassword)\s*[:=]\s*["']([^"']{4,80})["']/gi,
    score: 94,
  },
];

const STORAGE_AUTH_GATE_RE = /(?:sessionStorage|localStorage)\.getItem\s*\(\s*["']([^"']+)["']\s*\)\s*(?:===|==)\s*["']([^"']+)["']/gi;

const SENSITIVE_STORAGE_KEY_RE = /(?:sessionStorage|localStorage)\.(?:getItem|setItem)\s*\(\s*["']([^"']*(?:contato|contact|campanha|campaign|template|admin|token|secret|user|cred|password|senha)[^"']*)["']/gi;

const ADMIN_PANEL_IN_BUNDLE_RE = /(?:painel|admin-panel|AdminPanel|AdminDashboard|router\.(?:push|replace)\s*\(\s*["']\/(?:admin|painel))/gi;

function makeFinding({ type, value, score, url, meta, owasp, mitre, cvss }) {
  const prio = score >= 85 ? 'critical' : score >= 70 ? 'high' : score >= 50 ? 'medium' : score >= 30 ? 'low' : 'info';
  return { type, value, score, prio, url, meta: meta || {}, owasp, mitre, cvss: cvss || null, source: 'client_auth_audit' };
}

function snippet(text, idx, span = 50) {
  const start = Math.max(0, idx - span);
  const end = Math.min(text.length, idx + span);
  return text.slice(start, end).replace(/\s+/g, ' ').trim().slice(0, 160);
}

function isLikelyFalsePositivePassword(val) {
  const v = String(val || '').toLowerCase();
  if (v.length < 4) return true;
  if (/^(true|false|null|undefined|password|senha|admin|test|1234|0000)$/i.test(v)) return true;
  if (/^\$\{/.test(v)) return true;
  return false;
}

/**
 * Audita texto JS/HTML em busca de falhas client-side de auth.
 * @param {string} text
 * @param {{ url?: string, target?: string }} opts
 */
export function auditClientSideAuth(text, { url = null, target = null } = {}) {
  if (!text || typeof text !== 'string') return { findings: [], summary: {} };

  const cap = text.slice(0, 600_000);
  const findings = [];
  const summary = {
    hardcodedCreds: 0,
    storageBypass: 0,
    adminRoutes: 0,
    sensitiveStorage: 0,
  };

  for (const { id, re, score } of HARDCODED_CRED_RE) {
    re.lastIndex = 0;
    let m;
    let n = 0;
    while ((m = re.exec(cap)) !== null && n < 3) {
      const captured = m[1];
      if (captured && isLikelyFalsePositivePassword(captured)) continue;
      summary.hardcodedCreds++;
      findings.push(makeFinding({
        type: 'client_hardcoded_credential',
        value: 'Credencial ou senha de admin aparentemente hardcoded no JavaScript público',
        score,
        url,
        meta: {
          pattern: id,
          snippet: snippet(cap, m.index),
          redacted: captured ? `${String(captured).slice(0, 2)}…${String(captured).slice(-2)}` : null,
          target,
        },
        owasp: 'A07:2021',
        mitre: 'T1552',
        cvss: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
      }));
      n++;
    }
  }

  const storageGates = [];
  STORAGE_AUTH_GATE_RE.lastIndex = 0;
  let sg;
  while ((sg = STORAGE_AUTH_GATE_RE.exec(cap)) !== null && storageGates.length < 5) {
    storageGates.push({ key: sg[1], expected: sg[2], snippet: snippet(cap, sg.index) });
  }
  if (storageGates.length) {
    summary.storageBypass = storageGates.length;
    findings.push(makeFinding({
      type: 'client_storage_auth_bypass',
      value: `Autenticação baseada em ${storageGates[0].key.includes('local') ? 'localStorage' : 'sessionStorage'} — bypassável via DevTools`,
      score: 94,
      url,
      meta: {
        gates: storageGates.map((g) => ({ key: g.key, expected: g.expected })),
        snippet: storageGates[0].snippet,
        target,
        bypass: `sessionStorage.setItem("${storageGates[0].key}", "${storageGates[0].expected}")`,
      },
      owasp: 'A07:2021',
      mitre: 'T1552',
      cvss: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
    }));
  }

  const adminRoutes = new Set();
  ADMIN_ROUTE_RE.lastIndex = 0;
  let ar;
  while ((ar = ADMIN_ROUTE_RE.exec(cap)) !== null && adminRoutes.size < 20) {
    adminRoutes.add(ar[1].split('?')[0]);
  }
  if (adminRoutes.size) summary.adminRoutes = adminRoutes.size;

  const sensitiveKeys = new Set();
  SENSITIVE_STORAGE_KEY_RE.lastIndex = 0;
  let sk;
  while ((sk = SENSITIVE_STORAGE_KEY_RE.exec(cap)) !== null && sensitiveKeys.size < 10) {
    sensitiveKeys.add(sk[1]);
  }
  if (sensitiveKeys.size) {
    summary.sensitiveStorage = sensitiveKeys.size;
    findings.push(makeFinding({
      type: 'client_sensitive_browser_storage',
      value: 'Dados sensíveis persistidos em sessionStorage/localStorage no navegador',
      score: 62,
      url,
      meta: { keys: [...sensitiveKeys].slice(0, 10), target },
      owasp: 'A02:2021',
      mitre: 'T1530',
    }));
  }

  if (ADMIN_PANEL_IN_BUNDLE_RE.test(cap) && adminRoutes.size >= 1) {
    findings.push(makeFinding({
      type: 'client_admin_panel_in_public_bundle',
      value: 'Painel administrativo embutido no bundle JavaScript público da landing',
      score: 55,
      url,
      meta: {
        routes: [...adminRoutes].slice(0, 15),
        target,
        note: 'Facilita descoberta de rotas e lógica de auth para atacantes',
      },
      owasp: 'A02:2021',
      mitre: 'T1592',
    }));
  } else if (adminRoutes.size >= 2) {
    findings.push(makeFinding({
      type: 'client_admin_routes_exposed',
      value: `${adminRoutes.size} rota(s) administrativa(s) exposta(s) no bundle JS`,
      score: 48,
      url,
      meta: { routes: [...adminRoutes].slice(0, 15), target },
      owasp: 'A02:2021',
    }));
  }

  return { findings, summary };
}

/**
 * Deduplica findings de múltiplos bundles.
 */
export function mergeClientAuthFindings(results) {
  const findings = [];
  const seen = new Set();
  for (const r of results || []) {
    for (const f of r.findings || []) {
      const key = `${f.type}::${f.value}::${JSON.stringify(f.meta?.gates || f.meta?.routes || '')}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push(f);
    }
  }
  return findings;
}
