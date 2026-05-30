/**
 * client-surface-audit.mjs
 *
 * Auditoria generalista de superfície client-side (SPA, PWA, APIs consumidas no browser).
 * Análise estática de JS/HTML/headers + probe opcional de source maps.
 *
 * Cobre (heurístico, generalista):
 *   XSS sinks (DOM/reflected/mutation hints), open redirect, postMessage, prototype pollution,
 *   JSONP, WebSocket, Service Worker, browser storage, JWT in storage, CSRF forms, SRI,
 *   CSP fraca, mixed content, tabnabbing, debug/verbose errors, framework exposure, etc.
 *
 * Complementa (não substitui): cors_audit, firebase_audit, client_auth_audit, verify.js,
 * dom_xss_verify, graphql_recon, jwt_lab, security_headers.
 */

import { auditClientSideAuth } from './client-auth-audit.mjs';
import { analyzeCspWeaknesses, analyzePermissionsPolicyGaps } from './security-headers.js';
import { parseSourceMap } from './js-intel.mjs';

const UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36';

/** Mapeamento finding.type → categorias OWASP/client-side (documentação / export). */
export const VULN_TAXONOMY = {
  client_dom_xss_sink: ['DOM XSS', 'Reflected XSS', 'Mutation XSS', 'JavaScript Injection', 'HTML Injection'],
  client_csti: ['Client-Side Template Injection', 'HTML Injection'],
  client_dom_clobbering: ['DOM Clobbering'],
  client_open_redirect_sink: ['Open Redirect', 'DOM Open Redirect', 'URL Parameter Injection'],
  client_postmessage_no_origin: ['PostMessage Origin Validation Failure', 'Client-Side Authorization Bypass'],
  client_postmessage_handler: ['PostMessage Data Validation Failure'],
  client_prototype_pollution: ['Prototype Pollution', 'Client-Side Prototype Pollution'],
  client_jsonp_exposed: ['JSONP Abuse'],
  client_websocket_in_bundle: ['Cross-Site WebSocket Hijacking', 'WebSocket Authentication Bypass'],
  client_service_worker: ['Service Worker Abuse', 'Service Worker Takeover', 'PWA Cache Manipulation'],
  client_jwt_in_storage: ['JWT Storage in LocalStorage', 'LocalStorage Sensitive Data Exposure'],
  client_indexeddb_sensitive: ['IndexedDB Sensitive Data Exposure'],
  client_csrf_form_no_token: ['CSRF Through Frontend Logic', 'Client-Side Request Forgery (CSRF-like Client-Side Attack)'],
  client_sri_missing: ['Missing Subresource Integrity', 'Third-Party Script Injection', 'Supply Chain Attack'],
  client_mixed_content: ['Mixed Content', 'HTTP Resource Inclusion', 'Insecure Resource Loading'],
  client_tabnabbing: ['Tabnabbing', 'Reverse Tabnabbing', 'UI Redressing'],
  client_debug_enabled: ['Debug Mode Enabled', 'Verbose Client Errors'],
  client_env_exposed: ['Exposed Environment Variables'],
  client_internal_endpoint: ['Exposed Internal Endpoints', 'Hidden Functionality Disclosure', 'API Endpoint Enumeration'],
  client_insecure_api_consumption: ['Insecure Direct API Consumption'],
  client_validation_bypass_hint: ['Client-Side Validation Bypass', 'Business Logic Manipulation', 'Parameter Tampering'],
  client_fragment_abuse: ['Fragment Identifier Abuse'],
  client_cache_sensitive: ['Browser Cache Leakage', 'Sensitive Data in Browser Cache'],
  client_csp_weak: ['Weak Content Security Policy', 'CSP Bypass'],
  client_permissions_policy_missing: ['Missing Permissions Policy'],
  client_trusted_types_missing: ['Missing Trusted Types'],
  client_source_map_disclosure: ['Source Map Disclosure', 'Stack Trace Disclosure'],
  client_framework_exposed: ['Outdated JavaScript Libraries', 'Vulnerable React Components', 'Vulnerable Vue Components'],
  client_oauth_token_storage: ['OAuth Token Exposure'],
  client_hardcoded_credential: ['Hardcoded Secrets', 'Client-Side Access Control Bypass'],
  client_storage_auth_bypass: ['Client-Side Authorization Bypass', 'SessionStorage Sensitive Data Exposure'],
};

function makeFinding({ type, value, score, url, meta, owasp, mitre, categories }) {
  const prio = score >= 85 ? 'critical' : score >= 70 ? 'high' : score >= 50 ? 'medium' : score >= 30 ? 'low' : 'info';
  return {
    type,
    value,
    score,
    prio,
    url,
    meta: { ...(meta || {}), categories: categories || VULN_TAXONOMY[type] || [] },
    owasp: owasp || 'A03:2021',
    mitre: mitre || 'T1189',
    source: 'client_surface_audit',
  };
}

function snippet(text, idx, span = 55) {
  const start = Math.max(0, idx - span);
  return String(text).slice(start, Math.min(text.length, idx + span)).replace(/\s+/g, ' ').trim().slice(0, 180);
}

function scanPatterns(text, patterns, cap = 600_000) {
  const s = String(text || '').slice(0, cap);
  const hits = [];
  for (const p of patterns) {
    p.re.lastIndex = 0;
    let m;
    let n = 0;
    while ((m = p.re.exec(s)) !== null && n < (p.max || 2)) {
      hits.push({ ...p, match: m[0], index: m.index, groups: m.slice(1) });
      n++;
    }
  }
  return hits;
}

const JS_PATTERNS = [
  {
    type: 'client_dom_xss_sink',
    re: /\.(?:innerHTML|outerHTML)\s*=|document\.(?:write|writeln)\s*\(|(?:eval|Function)\s*\(|dangerouslySetInnerHTML|v-html\s*=|insertAdjacentHTML\s*\(|ng-bind-html|\$sce\.trustAsHtml/gi,
    score: 68,
    value: 'Sink DOM XSS detectado no JavaScript (innerHTML/eval/document.write/v-html)',
    owasp: 'A03:2021',
  },
  {
    type: 'client_csti',
    re: /\{\{\s*[^}]+\s*\}\}|\$\{\s*[^}]+\s*\}|Handlebars\.compile|\.render\s*\(\s*[^,]+,\s*\{/gi,
    score: 66,
    value: 'Client-Side Template Injection (CSTI) — interpolação de template com input',
    owasp: 'A03:2021',
    categories: ['Client-Side Template Injection', 'HTML Injection'],
  },
  {
    type: 'client_dom_clobbering',
    re: /(?:getElementById|getElementsByName|document\.(\w+))\s*[\[.]/gi,
    score: 48,
    value: 'Acesso DOM por id/name — revisar DOM clobbering em HTML dinâmico',
    owasp: 'A03:2021',
    categories: ['DOM Clobbering'],
  },
  {
    type: 'client_open_redirect_sink',
    re: /(?:location\.(?:href|replace|assign)|window\.open|router\.(?:push|replace))\s*\(\s*(?:[^'"]+\+|(?:location\.|window\.|document\.|params\.|query\.|route\.))/gi,
    score: 62,
    value: 'Possível open redirect client-side (location/router com input dinâmico)',
    owasp: 'A01:2021',
  },
  {
    type: 'client_open_redirect_sink',
    re: /(?:redirect|returnUrl|return_to|next|url|goto)\s*[:=]\s*(?:params|query|searchParams|location\.search)/gi,
    score: 58,
    value: 'Parâmetro de redirect ligado a input do cliente sem validação aparente',
    owasp: 'A01:2021',
  },
  {
    type: 'client_postmessage_handler',
    re: /addEventListener\s*\(\s*['"]message['"]/gi,
    score: 45,
    value: 'Handler postMessage registrado — validar origin e schema dos dados',
    owasp: 'A01:2021',
  },
  {
    type: 'client_postmessage_no_origin',
    re: /addEventListener\s*\(\s*['"]message['"][^)]*\)\s*\{[^}]{0,400}(?!origin)/gi,
    score: 72,
    value: 'Handler postMessage sem verificação evidente de event.origin',
    owasp: 'A01:2021',
    max: 1,
  },
  {
    type: 'client_prototype_pollution',
    re: /__proto__|constructor\s*\.\s*prototype|Object\.assign\s*\(\s*\{\}|\.merge\s*\(|deepMerge\s*\(|lodash\.merge/gi,
    score: 65,
    value: 'Padrão de prototype pollution / merge inseguro de objetos',
    owasp: 'A03:2021',
  },
  {
    type: 'client_jsonp_exposed',
    re: /[?&](?:callback|jsonp|cb)=|[`'"]\/jsonp\/|jsonp:\s*true/gi,
    score: 60,
    value: 'Uso ou endpoint JSONP detectado — risco de exfiltração cross-origin',
    owasp: 'A02:2021',
  },
  {
    type: 'client_websocket_in_bundle',
    re: /new\s+WebSocket\s*\(|wss?:\/\/[a-zA-Z0-9._-]+/gi,
    score: 48,
    value: 'WebSocket client-side — validar Origin, auth e mensagens',
    owasp: 'A02:2021',
  },
  {
    type: 'client_service_worker',
    re: /navigator\.serviceWorker\.(?:register|getRegistration)|workbox\.|self\.skipWaiting\s*\(/gi,
    score: 55,
    value: 'Service Worker registrado no cliente — revisar scope e cache',
    owasp: 'A02:2021',
  },
  {
    type: 'client_jwt_in_storage',
    re: /(?:localStorage|sessionStorage)\.(?:setItem|getItem)\s*\(\s*['"][^'"]*(?:jwt|id_token|access_token|refresh_token|auth_token)[^'"]*['"]/gi,
    score: 70,
    value: 'JWT/token OAuth persistido em localStorage/sessionStorage',
    owasp: 'A07:2021',
  },
  {
    type: 'client_indexeddb_sensitive',
    re: /indexedDB\.open\s*\(\s*['"][^'"]+['"]|idb\.(?:get|put)\s*\(/gi,
    score: 52,
    value: 'IndexedDB usado no cliente — validar dados sensíveis e criptografia',
    owasp: 'A02:2021',
  },
  {
    type: 'client_debug_enabled',
    re: /NODE_ENV\s*[=:]\s*['"]development['"]|__DEV__\s*[:=]\s*true|debug\s*[:=]\s*true|enableVerboseLogging|showStackTrace/gi,
    score: 58,
    value: 'Modo debug/verbose aparente no bundle de produção',
    owasp: 'A02:2021',
  },
  {
    type: 'client_env_exposed',
    re: /process\.env\.(?:SECRET|API_KEY|PASSWORD|PRIVATE|TOKEN)|import\.meta\.env\.(?:VITE_|NEXT_PUBLIC_)[A-Z_]+/gi,
    score: 75,
    value: 'Variável de ambiente/secreto referenciada no bundle client-side',
    owasp: 'A02:2021',
  },
  {
    type: 'client_internal_endpoint',
    re: /['"`](?:\/(?:internal|private|admin|debug|staging|dev|localhost|127\.0\.0\.1)[^'"`]{0,120})['"`]/gi,
    score: 54,
    value: 'Endpoint interno/debug exposto no JavaScript público',
    owasp: 'A02:2021',
  },
  {
    type: 'client_insecure_api_consumption',
    re: /fetch\s*\(\s*[`'"]https?:\/\/(?:api\.|backend\.|internal\.)/gi,
    score: 50,
    value: 'Consumo direto de API no browser — validar auth e CORS',
    owasp: 'A01:2021',
  },
  {
    type: 'client_validation_bypass_hint',
    re: /(?:required|minLength|pattern)\s*[:=][^;]{0,80};\s*(?:fetch|axios|submit)|validate\s*\([^)]*\)\s*\{\s*return\s*true/gi,
    score: 56,
    value: 'Validação aparentemente só no cliente antes de request',
    owasp: 'A04:2021',
  },
  {
    type: 'client_fragment_abuse',
    re: /location\.hash|window\.location\.hash|#\$\{|decodeURIComponent\s*\(\s*location\.hash/gi,
    score: 50,
    value: 'Lógica dependente de fragment (#) — vetor DOM XSS / open redirect',
    owasp: 'A03:2021',
  },
  {
    type: 'client_cache_sensitive',
    re: /Cache-Control\s*[:=]\s*['"]?(?:public|max-age=\d{5,})/gi,
    score: 42,
    value: 'Cache longo configurado no cliente — risco de vazamento em disco',
    owasp: 'A02:2021',
  },
  {
    type: 'client_oauth_token_storage',
    re: /(?:access_token|id_token|refresh_token)\s*[:=]\s*(?:localStorage|sessionStorage)/gi,
    score: 78,
    value: 'Token OAuth armazenado no browser storage',
    owasp: 'A07:2021',
  },
  {
    type: 'client_framework_exposed',
    re: /react(?:-dom)?\/(?:16\.|17\.|0\.|15\.)|@angular\/core\/(?:[0-9]\.|1[0-4]\.)|vue(?:@|\/)(?:2\.0|2\.1|2\.2|2\.3|2\.4|2\.5)/gi,
    score: 55,
    value: 'Versão antiga de framework JS detectada no bundle',
    owasp: 'A06:2021',
  },
];

/**
 * Analisa bundle JavaScript.
 */
export function auditJsSurface(text, { url = null, target = null, includeAuth = true } = {}) {
  if (!text || typeof text !== 'string') return { findings: [], summary: {} };
  const findings = [];
  const seenTypes = new Set();

  for (const hit of scanPatterns(text, JS_PATTERNS)) {
    if (hit.type === 'client_postmessage_no_origin') {
      const block = text.slice(hit.index, hit.index + 500);
      if (/event\.origin|e\.origin|msg\.origin|origin\s*===|origin\s*!==/.test(block)) continue;
    }
    const key = `${hit.type}::${hit.value}`;
    if (seenTypes.has(key)) continue;
    seenTypes.add(key);
    findings.push(makeFinding({
      type: hit.type,
      value: hit.value,
      score: hit.score,
      url,
      meta: { snippet: snippet(text, hit.index), target, pattern: hit.match?.slice(0, 80) },
      owasp: hit.owasp,
    }));
  }

  const auth = includeAuth ? auditClientSideAuth(text, { url, target }) : { findings: [], summary: {} };
  for (const f of auth.findings || []) {
    findings.push({ ...f, source: 'client_surface_audit', meta: { ...f.meta, via: 'client_auth_audit' } });
  }

  return { findings, summary: { jsPatterns: findings.length, ...auth.summary } };
}

/**
 * Analisa HTML (página inicial / amostra).
 */
export function auditHtmlSurface(html, { url = null, target = null, isHttps = true } = {}) {
  if (!html || typeof html !== 'string') return { findings: [], summary: {} };
  const cap = html.slice(0, 400_000);
  const findings = [];

  const scriptRe = /<script\b[^>]*\ssrc\s*=\s*["']([^"']+)["'][^>]*>/gi;
  let sm;
  let externalScripts = 0;
  let missingSri = 0;
  while ((sm = scriptRe.exec(cap)) !== null) {
    const tag = sm[0];
    const src = sm[1];
    if (/^https?:\/\//i.test(src) || src.startsWith('//')) {
      externalScripts++;
      if (!/\bintegrity\s*=/.test(tag)) missingSri++;
    }
    if (isHttps && /^http:\/\//i.test(src)) {
      findings.push(makeFinding({
        type: 'client_mixed_content',
        value: 'Script HTTP carregado em página HTTPS (mixed content)',
        score: 64,
        url,
        meta: { src: src.slice(0, 120), target },
        owasp: 'A02:2021',
      }));
    }
  }
  if (missingSri >= 1 && externalScripts >= 1) {
    findings.push(makeFinding({
      type: 'client_sri_missing',
      value: `${missingSri} script(s) externo(s) sem atributo integrity (SRI)`,
      score: missingSri >= 2 ? 68 : 58,
      url,
      meta: { externalScripts, missingSri, target },
      owasp: 'A08:2021',
    }));
  }

  const linkRe = /<link\b[^>]*\ssrc\s*=\s*["']([^"']+)["'][^>]*>/gi;
  let lm;
  while ((lm = linkRe.exec(cap)) !== null) {
    if (isHttps && /^http:\/\//i.test(lm[1])) {
      findings.push(makeFinding({
        type: 'client_mixed_content',
        value: 'Recurso HTTP em link/stylesheet em página HTTPS',
        score: 58,
        url,
        meta: { href: lm[1].slice(0, 100) },
      }));
    }
  }

  const formRe = /<form\b[^>]*>/gi;
  let fm;
  while ((fm = formRe.exec(cap)) !== null) {
    const tag = fm[0];
    const method = (/method\s*=\s*["']?(post|put|patch|delete)/i.test(tag) ? 'mutating' : 'get');
    if (method === 'mutating' && !/(?:csrf|xsrf|_token|authenticity)/i.test(cap.slice(fm.index, fm.index + 800))) {
      findings.push(makeFinding({
        type: 'client_csrf_form_no_token',
        value: 'Form HTML mutável sem token CSRF visível',
        score: 62,
        url,
        meta: { snippet: tag.slice(0, 120), target },
        owasp: 'A01:2021',
      }));
      break;
    }
  }

  const tabRe = /<a\b[^>]*target\s*=\s*["']?_blank["']?[^>]*>/gi;
  let tm;
  while ((tm = tabRe.exec(cap)) !== null) {
    if (!/\brel\s*=\s*["'][^"']*noopener/i.test(tm[0])) {
      findings.push(makeFinding({
        type: 'client_tabnabbing',
        value: 'Link target=_blank sem rel=noopener (tabnabbing / reverse tabnabbing)',
        score: 52,
        url,
        meta: { snippet: tm[0].slice(0, 100), target },
        owasp: 'A02:2021',
      }));
      break;
    }
  }

  if (/<iframe\b/i.test(cap) && !/sandbox\s*=/.test(cap.slice(0, 5000))) {
    findings.push(makeFinding({
      type: 'client_tabnabbing',
      value: 'iframe sem sandbox — risco de UI redressing / clickjacking auxiliar',
      score: 48,
      url,
      meta: { note: 'Combinar com ausência de X-Frame-Options/CSP frame-ancestors', target },
      categories: ['Clickjacking', 'UI Redressing'],
    }));
  }

  return { findings, summary: { externalScripts, missingSri } };
}

/**
 * Analisa snapshot de headers (objeto de probe.js).
 */
export function auditHeaderSurface(snap, { url = null } = {}) {
  const findings = [];
  if (!snap) return { findings, summary: {} };

  for (const w of analyzeCspWeaknesses(snap.contentSecurityPolicy)) {
    findings.push(makeFinding({
      type: 'client_csp_weak',
      value: w.text,
      score: w.score,
      url,
      meta: { csp: String(snap.contentSecurityPolicy || '').slice(0, 200), issue: w.issue },
      owasp: 'A02:2021',
    }));
  }

  for (const g of analyzePermissionsPolicyGaps(snap)) {
    findings.push(makeFinding({
      type: 'client_permissions_policy_missing',
      value: g.text,
      score: g.score,
      url,
      meta: { missing: g.missing },
      owasp: 'A02:2021',
    }));
  }

  if (snap.contentSecurityPolicy && !/trusted-types/i.test(snap.contentSecurityPolicy)) {
    if (/unsafe-inline|unsafe-eval/i.test(snap.contentSecurityPolicy)) {
      findings.push(makeFinding({
        type: 'client_trusted_types_missing',
        value: 'CSP permite inline/eval mas não declara trusted-types',
        score: 44,
        url,
        meta: { note: 'Considerar Trusted Types para mitigar DOM XSS' },
        owasp: 'A03:2021',
      }));
    }
  }

  if (!snap.xContentTypeOptions && !snap.contentSecurityPolicy) {
    findings.push(makeFinding({
      type: 'client_mime_sniffing',
      value: 'Sem X-Content-Type-Options: nosniff — risco de MIME sniffing',
      score: 46,
      url,
      meta: { note: 'Complementar com Content-Type correto nos recursos' },
      owasp: 'A02:2021',
      categories: ['MIME Sniffing Issues'],
    }));
  }

  return { findings, summary: {} };
}

export function extractSourceMapUrl(jsText, jsUrl) {
  if (!jsText || !jsUrl) return null;
  const m = String(jsText).match(/\/\/[#@]\s*sourceMappingURL=([^\s'"]+)/);
  if (!m) return null;
  let mapPath = m[1].trim();
  if (mapPath.startsWith('data:')) return null;
  try {
    return new URL(mapPath, jsUrl).href;
  } catch {
    return null;
  }
}

export async function probeSourceMapDisclosure(mapUrl, { fetchImpl = null } = {}) {
  const fetchFn = fetchImpl || globalThis.fetch;
  if (!fetchFn || !mapUrl) return null;
  try {
    const res = await fetchFn(mapUrl, {
      headers: { 'User-Agent': UA, Accept: 'application/json,*/*' },
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) return null;
    const text = await res.text();
    const parsed = parseSourceMap(text);
    if (!parsed.sources?.length) return null;
    return makeFinding({
      type: 'client_source_map_disclosure',
      value: `Source map público expõe ${parsed.sources.length} ficheiro(s) fonte`,
      score: parsed.internal?.length ? 62 : 52,
      url: mapUrl,
      meta: {
        sourcesSample: parsed.sources.slice(0, 8),
        internalSample: parsed.internal.slice(0, 5),
      },
      owasp: 'A02:2021',
      categories: ['Source Map Disclosure', 'Stack Trace Disclosure', 'Hidden Functionality Disclosure'],
    });
  } catch {
    return null;
  }
}

/**
 * Agrega JS + HTML + headers numa auditoria.
 */
export function auditClientSurface({ jsText = '', htmlText = '', headers = null, url = null, target = null, isHttps = true }) {
  const js = auditJsSurface(jsText, { url, target });
  const html = auditHtmlSurface(htmlText, { url, target, isHttps });
  const hdr = auditHeaderSurface(headers, { url });
  const findings = [...js.findings, ...html.findings, ...hdr.findings];
  return {
    findings,
    summary: {
      total: findings.length,
      js: js.findings.length,
      html: html.findings.length,
      headers: hdr.findings.length,
    },
  };
}

export function mergeClientSurfaceFindings(results) {
  const findings = [];
  const seen = new Set();
  for (const r of results || []) {
    for (const f of r.findings || []) {
      const key = `${f.type}::${f.value}::${f.url || ''}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push(f);
    }
  }
  findings.sort((a, b) => (b.score || 0) - (a.score || 0));
  return findings;
}
