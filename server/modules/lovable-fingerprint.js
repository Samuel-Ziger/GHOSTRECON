import fs from 'fs/promises';
import path from 'path';
import { createHash } from 'crypto';

/**
 * lovable-fingerprint.js
 *
 * Detecta sinais de app Lovable, coleta indicadores de exposição em cliente e
 * executa probes leves de configuração insegura.
 */

const COMMON_TABLES = [
  'users', 'profiles', 'orders', 'payments', 'tickets', 'messages', 'posts',
  'comments', 'subscriptions', 'api_keys', 'tokens', 'sessions', 'invoices', 'leads',
  // tabelas de alto impacto identificadas em campo (foconopapiro / Lovable apps)
  'user_plans', 'study_records', 'user_roles', 'admin_users', 'roles',
];

const COMMON_DOTFILES = [
  { path: '/.env', severity: 'critical', label: 'dotenv' },
  { path: '/.env.production', severity: 'critical', label: 'dotenv-prod' },
  { path: '/.env.local', severity: 'critical', label: 'dotenv-local' },
  { path: '/.git/config', severity: 'high', label: 'git-config' },
  { path: '/.git/HEAD', severity: 'high', label: 'git-head' },
  { path: '/package.json', severity: 'medium', label: 'package-json' },
  { path: '/package-lock.json', severity: 'low', label: 'package-lock' },
];

const COMMON_AUTHLESS_ENDPOINTS = [
  '/api/admin', '/api/admin/users', '/api/users', '/api/private', '/api/internal',
  '/api/debug', '/api/stats', '/api/export', '/api/account', '/api/config',
];

const REQUIRED_SECURITY_HEADERS = [
  { name: 'content-security-policy', severity: 'medium', owasp: 'A05:2021' },
  { name: 'strict-transport-security', severity: 'medium', owasp: 'A02:2021' },
  { name: 'x-frame-options', severity: 'low', owasp: 'A05:2021' },
  { name: 'x-content-type-options', severity: 'low', owasp: 'A05:2021' },
  { name: 'referrer-policy', severity: 'info', owasp: 'A05:2021' },
];

const SECRET_PATTERNS = [
  { name: 'stripe_secret', re: /\bsk_(?:live|test)_[A-Za-z0-9]{20,}\b/g, severity: 'critical' },
  { name: 'supabase_jwt', re: /\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b/g, severity: 'high' },
  { name: 'resend_key', re: /\bre_[A-Za-z0-9]{20,}\b/g, severity: 'high' },
  { name: 'openai_key', re: /\bsk-[A-Za-z0-9_-]{32,}\b/g, severity: 'high' },
];

const SUPABASE_URL_RE = /https?:\/\/(?:[a-z0-9]{8,30})\.supabase\.co/gi;
const SUPABASE_JWT_RE = /\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b/g;
const JS_BUNDLE_RE = /(?:src|href)\s*=\s*["']([^"']+\.(?:js|mjs))(?:\?[^"']*)?["']/gi;
const LOVABLE_HINTS = [
  /<meta\s+name=["']lovable["']/i,
  /lovable\.(app|dev|tagger|cdn)/i,
  /__LOVABLE__/i,
  /data-lovable[-=]/i,
];

function decodeJwtPayload(jwt) {
  try {
    const parts = jwt.split('.');
    if (parts.length !== 3) return null;
    const pad = '='.repeat((4 - (parts[1].length % 4)) % 4);
    const b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/') + pad;
    const json = Buffer.from(b64, 'base64').toString('utf8');
    return JSON.parse(json);
  } catch {
    return null;
  }
}

function sha256Hex(value) {
  return createHash('sha256').update(String(value || ''), 'utf8').digest('hex');
}

function maskSecret(value) {
  const s = String(value || '');
  if (s.length <= 24) return s ? `${s.slice(0, 4)}...` : '';
  return `${s.slice(0, 12)}...${s.slice(-10)}`;
}

function htmlEscape(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function safeSegment(value, fallback = 'target') {
  const s = String(value || '')
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/[^a-z0-9._-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 80);
  return s || fallback;
}

function snippetAround(text, index, secret, span = 340) {
  const body = String(text || '');
  const start = Math.max(0, index - span);
  const end = Math.min(body.length, index + String(secret || '').length + span);
  return body.slice(start, end).replaceAll(String(secret || ''), maskSecret(secret));
}

function collectSupabaseJwtEvidence({ targetUrl, rootText, bundles, storeRawSecrets = false }) {
  const sources = [
    { label: 'HTML inicial', url: targetUrl, text: rootText || '' },
    ...(bundles || []).map((b) => ({ label: 'JS bundle', url: b.url || b.path || targetUrl, text: b.text || '' })),
  ];
  const seen = new Set();
  const out = [];
  for (const source of sources) {
    SUPABASE_JWT_RE.lastIndex = 0;
    let m;
    while ((m = SUPABASE_JWT_RE.exec(source.text)) !== null) {
      const token = m[0];
      const hash = sha256Hex(token);
      if (seen.has(hash)) continue;
      seen.add(hash);
      const claims = decodeJwtPayload(token);
      out.push({
        source: source.label,
        sourceUrl: source.url,
        masked: maskSecret(token),
        hash,
        claims,
        snippet: snippetAround(source.text, m.index, token),
        raw: storeRawSecrets ? token : undefined,
      });
    }
  }
  return out;
}

async function writeSupabasePocPage({
  outputDir,
  targetUrl,
  supabaseUrl,
  context,
  evidence,
  storeRawSecrets = false,
}) {
  if (!outputDir) return null;
  await fs.mkdir(outputDir, { recursive: true });
  let host = 'target';
  try {
    host = new URL(targetUrl).hostname;
  } catch {
    host = targetUrl;
  }
  let supabaseRef = context?.anonKeyClaims?.ref || '';
  if (!supabaseRef && supabaseUrl) {
    try {
      supabaseRef = new URL(supabaseUrl).hostname.split('.')[0] || '';
    } catch {
      supabaseRef = '';
    }
  }
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const file = `supabase-poc_${safeSegment(host)}_${safeSegment(supabaseRef, 'sb')}_${stamp}.html`;
  const fullPath = path.join(outputDir, file);
  const rlsRows = Array.isArray(context?.rlsBrokenDetails)
    ? context.rlsBrokenDetails
    : (context?.rlsBrokenTables || []).map((table) => ({ table, status: 200 }));
  const payload = {
    generatedAt: new Date().toISOString(),
    targetUrl,
    supabaseUrl,
    anonKeyClaims: context?.anonKeyClaims || null,
    bundlesScanned: context?.bundlesScanned || 0,
    secretsFound: context?.secretsFound || [],
    rlsBrokenTables: rlsRows,
    evidence,
    storesRawSecrets: Boolean(storeRawSecrets),
  };
  const json = JSON.stringify(payload, null, 2);
  const evidenceBlocks = evidence.map((ev) => `
    <section class="card">
      <div class="kv"><strong>Origem</strong><span>${htmlEscape(ev.source)} · <a href="${htmlEscape(ev.sourceUrl)}">${htmlEscape(ev.sourceUrl)}</a></span></div>
      <div class="kv"><strong>JWT</strong><code>${htmlEscape(ev.masked)}</code></div>
      <div class="kv"><strong>SHA-256</strong><code>${htmlEscape(ev.hash)}</code></div>
      <div class="kv"><strong>Claims</strong><pre>${htmlEscape(JSON.stringify(ev.claims || {}, null, 2))}</pre></div>
      <div class="kv block"><strong>Trecho preservado</strong><pre>${htmlEscape(ev.snippet)}</pre></div>
    </section>`).join('\n');
  const rlsBlocks = rlsRows.length
    ? rlsRows.map((r) => `
      <tr>
        <td>${htmlEscape(r.table)}</td>
        <td>${htmlEscape(r.status)}</td>
        <td>${htmlEscape(r.rowCount ?? '-')}</td>
        <td><code>${htmlEscape((r.columns || []).join(', ') || '-')}</code></td>
        <td><a href="${htmlEscape(r.url || '')}">${htmlEscape(r.url || '-')}</a></td>
      </tr>`).join('\n')
    : '<tr><td colspan="5">Nenhuma tabela comum respondeu 200 no probe somente leitura, ou o probe nao correu.</td></tr>';
  const html = `<!doctype html>
<html lang="pt">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>GHOSTRECON Supabase PoC</title>
  <style>
    :root{color-scheme:dark;--bg:#05080b;--panel:#0d141b;--line:#24424d;--text:#d9eef4;--muted:#89a5ad;--cyan:#00d4ff;--amber:#ffc46b;--red:#ff5577;--green:#00ff88}
    body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
    header{padding:22px 26px;border-bottom:1px solid var(--line);background:#091017}
    h1{margin:0 0 8px;font-size:21px;letter-spacing:.04em;text-transform:uppercase}
    main{padding:20px 26px;max-width:1180px}
    a{color:var(--cyan);word-break:break-all}
    code,pre{font-family:"SFMono-Regular",Consolas,monospace}
    pre{white-space:pre-wrap;word-break:break-word;margin:8px 0 0;padding:12px;background:#050a0f;border:1px solid rgba(137,165,173,.22);overflow:auto}
    .muted{color:var(--muted)}
    .card{background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:14px;margin:14px 0}
    .kv{display:grid;grid-template-columns:140px 1fr;gap:12px;margin:8px 0;align-items:start}
    .kv.block{display:block}
    .pill{display:inline-block;border:1px solid var(--line);padding:3px 8px;border-radius:999px;color:var(--amber);font-family:monospace;font-size:12px}
    table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);margin-top:10px}
    th,td{padding:9px 10px;border-bottom:1px solid rgba(137,165,173,.18);text-align:left;vertical-align:top}
    th{color:var(--amber);font-size:12px;text-transform:uppercase}
    .warn{border-color:rgba(255,196,107,.38);color:var(--amber)}
  </style>
</head>
<body>
  <header>
    <h1>GHOSTRECON Supabase PoC</h1>
    <div class="muted">Gerado em ${htmlEscape(payload.generatedAt)} · evidência local do bundle cliente</div>
  </header>
  <main>
    <section class="card warn">
      <div class="kv"><strong>Alvo</strong><a href="${htmlEscape(targetUrl)}">${htmlEscape(targetUrl)}</a></div>
      <div class="kv"><strong>Supabase</strong><a href="${htmlEscape(supabaseUrl || '')}">${htmlEscape(supabaseUrl || 'nao identificado')}</a></div>
      <div class="kv"><strong>Bundles lidos</strong><span>${htmlEscape(context?.bundlesScanned || 0)}</span></div>
      <div class="kv"><strong>Segredos crus</strong><span class="pill">${storeRawSecrets ? 'armazenados por env' : 'nao armazenados'}</span></div>
    </section>

    <h2>JWT encontrado</h2>
    ${evidenceBlocks || '<p class="muted">Nenhum JWT preservado na evidência.</p>'}

    <h2>Probe RLS somente leitura</h2>
    <table>
      <thead><tr><th>Tabela</th><th>Status</th><th>Rows</th><th>Colunas vistas</th><th>URL</th></tr></thead>
      <tbody>${rlsBlocks}</tbody>
    </table>

    <h2>JSON da PoC</h2>
    <pre>${htmlEscape(json)}</pre>
    <script type="application/json" id="ghostrecon-poc-data">${htmlEscape(json)}</script>
  </main>
</body>
</html>
`;
  await fs.writeFile(fullPath, html, 'utf8');
  return { path: fullPath, file };
}

async function safeFetch(url, opts, fetchImpl) {
  const f = fetchImpl || globalThis.fetch;
  if (!f) throw new Error('fetch indisponivel - passe opts.fetch');
  const ac = new AbortController();
  const timeout = setTimeout(() => ac.abort(), opts?.timeout ?? 12000);
  try {
    return await f(url, { ...(opts || {}), signal: ac.signal });
  } finally {
    clearTimeout(timeout);
  }
}

async function fetchText(url, fetchImpl, headers) {
  try {
    const res = await safeFetch(url, { headers: headers || {} }, fetchImpl);
    if (!res.ok) return { status: res.status, text: '' };
    return { status: res.status, text: await res.text() };
  } catch {
    return { status: 0, text: '' };
  }
}

async function fetchWithHeaders(url, fetchImpl, headers) {
  try {
    const res = await safeFetch(url, { headers: headers || {} }, fetchImpl);
    return { status: res.status, headers: res.headers, text: await res.text() };
  } catch {
    return { status: 0, headers: null, text: '' };
  }
}

function extractMatches(text, regex) {
  const out = new Set();
  regex.lastIndex = 0;
  let m;
  while ((m = regex.exec(text)) !== null) {
    out.add(m[1] || m[0]);
    if (regex.lastIndex === m.index) regex.lastIndex += 1;
  }
  return [...out];
}

function isLovableMarkup(html) {
  return LOVABLE_HINTS.some((re) => re.test(html || ''));
}

function isLovableHost(targetUrl) {
  try {
    return /\.lovable\.(app|dev)$/i.test(new URL(targetUrl).hostname);
  } catch {
    return false;
  }
}

function makeFinding({ type, value, score = 50, url, meta, owasp, mitre }) {
  const prio = score >= 85 ? 'critical' : score >= 70 ? 'high' : score >= 50 ? 'medium' : score >= 30 ? 'low' : 'info';
  return { type, value, score, prio, url, meta, owasp, mitre, source: 'lovable-fingerprint' };
}

async function fetchBundlesFromHtml(targetUrl, html, fetchImpl, maxBundles = 8) {
  const bundlePaths = extractMatches(html || '', JS_BUNDLE_RE).slice(0, Math.max(1, maxBundles));
  const out = [];
  for (const path of bundlePaths) {
    try {
      const url = new URL(path, targetUrl).href;
      const { status, text } = await fetchText(url, fetchImpl);
      if (status === 200 && text) out.push({ path, url, text });
    } catch {
      // ignore URL parse/fetch failures
    }
  }
  return out;
}

function scanForSecrets(content, targetUrl) {
  const findings = [];
  for (const pattern of SECRET_PATTERNS) {
    const matches = extractMatches(content, pattern.re);
    if (!matches.length) continue;
    findings.push(makeFinding({
      type: 'secret_exposed',
      value: `${pattern.name} encontrado no bundle cliente`,
      score: pattern.severity === 'critical' ? 90 : 75,
      url: targetUrl,
      meta: { secretType: pattern.name, count: matches.length },
      owasp: 'A05:2021',
      mitre: 'T1552',
    }));
  }
  return findings;
}

async function probeSupabaseTables({ supabaseUrl, anonKey, fetchImpl, tables }) {
  const out = [];
  for (const table of (tables || COMMON_TABLES)) {
    const url = `${supabaseUrl}/rest/v1/${encodeURIComponent(table)}?select=*&limit=1`;
    try {
      const res = await safeFetch(url, {
        headers: { apikey: anonKey, Authorization: `Bearer ${anonKey}`, 'Accept-Profile': 'public' },
      }, fetchImpl);
      if (res.status === 200) {
        const text = await res.text();
        let rows = [];
        try {
          const parsed = JSON.parse(text);
          rows = Array.isArray(parsed) ? parsed : [];
        } catch {
          rows = [];
        }
        const columns = rows[0] && typeof rows[0] === 'object' ? Object.keys(rows[0]).slice(0, 24) : [];
        out.push({ table, status: 200, url, rowCount: rows.length, columns });
      }
    } catch {
      // ignore request failures
    }
  }
  return out;
}

async function probeDotfiles({ targetUrl, fetchImpl }) {
  const out = [];
  for (const entry of COMMON_DOTFILES) {
    try {
      const url = new URL(entry.path, targetUrl).href;
      const res = await safeFetch(url, { headers: { Accept: '*/*' } }, fetchImpl);
      if (res.status !== 200) continue;
      const body = await res.text();
      if (/<html[\s>]/i.test(body)) continue;
      out.push({ ...entry, url, bodySize: body.length, contentType: (res.headers?.get?.('content-type') || '').toLowerCase() });
    } catch {
      // ignore
    }
  }
  return out;
}

async function probeSourceMaps({ targetUrl, fetchImpl, bundles }) {
  const out = [];
  for (const b of bundles || []) {
    try {
      const mapPath = `${b.path}.map`;
      const mapUrl = new URL(mapPath, targetUrl).href;
      const res = await safeFetch(mapUrl, { headers: { Accept: 'application/json,*/*' } }, fetchImpl);
      if (res.status === 200) out.push({ jsPath: b.path, mapPath, mapUrl });
    } catch {
      // ignore
    }
  }
  return out;
}

async function probeCorsPermissive({ targetUrl, fetchImpl }) {
  try {
    const origin = 'https://evil.example';
    const res = await safeFetch(targetUrl, { headers: { Origin: origin } }, fetchImpl);
    const acao = res.headers?.get?.('access-control-allow-origin') || '';
    const acc = (res.headers?.get?.('access-control-allow-credentials') || '').toLowerCase() === 'true';
    return {
      wildcard: acao === '*',
      reflected: acao === origin,
      originReflected: acao === origin ? origin : null,
      allowCredentials: acc,
    };
  } catch {
    return { wildcard: false, reflected: false, originReflected: null, allowCredentials: false };
  }
}

async function probeAuthlessEndpoints({ targetUrl, fetchImpl }) {
  const out = [];
  for (const path of COMMON_AUTHLESS_ENDPOINTS) {
    try {
      const url = new URL(path, targetUrl).href;
      const res = await safeFetch(url, { headers: { Accept: 'application/json,*/*' } }, fetchImpl);
      if (res.status >= 200 && res.status < 300) {
        const body = await res.text();
        out.push({ path, url, status: res.status, bodySize: body.length, contentType: res.headers?.get?.('content-type') || '' });
      }
    } catch {
      // ignore
    }
  }
  return out;
}

function analyzeSecurityHeadersFromResponse(rootHeaders) {
  const missing = [];
  if (!rootHeaders) return missing;
  const lower = new Map();
  if (typeof rootHeaders.entries === 'function') {
    for (const [k, v] of rootHeaders.entries()) lower.set(k.toLowerCase(), v);
  }
  for (const h of REQUIRED_SECURITY_HEADERS) {
    if (!lower.has(h.name)) missing.push(h);
  }
  return missing;
}

export async function fingerprintLovable(targetUrl, opts = {}) {
  const fetchImpl = opts.fetch || globalThis.fetch;
  const probeRls = opts.probeRls !== false;
  const probeMisconfig = opts.probeMisconfig !== false;
  const maxBundles = Math.max(1, Math.min(20, opts.maxJsBundles ?? 8));

  const findings = [];
  const context = {
    targetUrl,
    isLovable: false,
    supabaseUrl: null,
    anonKey: null,
    anonKeyClaims: null,
    bundlesScanned: 0,
    secretsFound: [],
    rlsBrokenTables: [],
    rlsBrokenDetails: [],
    dotfilesExposed: [],
    sourceMapsExposed: [],
    corsPermissive: null,
    authlessEndpoints: [],
    missingSecurityHeaders: [],
    pocPath: null,
    pocFile: null,
  };

  const rootFull = await fetchWithHeaders(targetUrl, fetchImpl);
  if (!rootFull.text && !isLovableHost(targetUrl)) return { isLovable: false, findings, context };

  context.isLovable = isLovableMarkup(rootFull.text) || isLovableHost(targetUrl);
  if (context.isLovable) {
    findings.push(makeFinding({
      type: 'lovable_detected',
      value: 'Aplicacao com sinais de origem Lovable (markup/host)',
      score: 35,
      url: targetUrl,
      meta: { fromMarkup: isLovableMarkup(rootFull.text), fromHost: isLovableHost(targetUrl) },
      owasp: 'A05:2021',
      mitre: 'T1595',
    }));
  }

  const bundles = await fetchBundlesFromHtml(targetUrl, rootFull.text, fetchImpl, maxBundles);
  context.bundlesScanned = bundles.length;
  const joined = `${rootFull.text}\n${bundles.map((b) => b.text).join('\n')}`;

  const secretFindings = scanForSecrets(joined, targetUrl);
  if (secretFindings.length) {
    findings.push(...secretFindings);
    context.secretsFound = secretFindings.map((s) => s.meta?.secretType);
  }

  const supabaseUrl = extractMatches(joined, SUPABASE_URL_RE)[0] || null;
  const jwtCandidates = extractMatches(joined, SUPABASE_JWT_RE);
  let anonKey = null;
  let anonClaims = null;
  for (const jwt of jwtCandidates) {
    const claims = decodeJwtPayload(jwt);
    if (claims?.role === 'anon' || claims?.iss?.includes('supabase')) {
      anonKey = jwt;
      anonClaims = claims;
      break;
    }
  }
  context.supabaseUrl = supabaseUrl;
  context.anonKey = anonKey;
  context.anonKeyClaims = anonClaims;

  if (supabaseUrl) {
    findings.push(makeFinding({
      type: 'supabase_url_exposed',
      value: `Endpoint Supabase no cliente: ${supabaseUrl}`,
      score: 30,
      url: supabaseUrl,
      meta: { source: 'bundle/html' },
      owasp: 'A05:2021',
      mitre: 'T1592',
    }));
  }

  if (anonKey) {
    findings.push(makeFinding({
      type: 'supabase_anon_key_exposed',
      value: 'Anon key JWT encontrada no bundle cliente',
      score: 45,
      url: targetUrl,
      meta: { role: anonClaims?.role, ref: anonClaims?.ref, iat: anonClaims?.iat },
      owasp: 'A05:2021',
      mitre: 'T1552',
    }));
  }

  if (probeRls && supabaseUrl && anonKey) {
    const broken = await probeSupabaseTables({ supabaseUrl, anonKey, fetchImpl, tables: opts.tables || COMMON_TABLES });
    context.rlsBrokenTables = broken.map((b) => b.table);
    context.rlsBrokenDetails = broken;
    if (broken.length) {
      findings.push(makeFinding({
        type: 'supabase_rls_bypass_suspected',
        value: `Tabelas acessiveis com anon key sem autenticacao: ${broken.map((b) => b.table).join(', ')}`,
        score: broken.length >= 2 ? 92 : 82,
        url: `${supabaseUrl}/rest/v1/`,
        meta: { tables: broken, cve: 'CVE-2025-48757' },
        owasp: 'A01:2021',
        mitre: 'T1190',
      }));
    }
  }

  if (probeMisconfig) {
    const dotfiles = await probeDotfiles({ targetUrl, fetchImpl });
    context.dotfilesExposed = dotfiles.map((d) => d.path);
    findings.push(...dotfiles.map((d) => makeFinding({
      type: 'dotfile_exposed',
      value: `Arquivo potencialmente sensivel exposto: ${d.path}`,
      score: d.severity === 'critical' ? 88 : d.severity === 'high' ? 78 : 60,
      url: d.url,
      meta: { label: d.label, bodySize: d.bodySize, contentType: d.contentType },
      owasp: 'A05:2021',
      mitre: 'T1083',
    })));

    const maps = await probeSourceMaps({ targetUrl, fetchImpl, bundles });
    context.sourceMapsExposed = maps.map((m) => m.mapPath);
    findings.push(...maps.map((m) => makeFinding({
      type: 'source_map_exposed',
      value: `Source map publico: ${m.mapPath}`,
      score: 58,
      url: m.mapUrl,
      meta: { jsPath: m.jsPath },
      owasp: 'A05:2021',
      mitre: 'T1592',
    })));

    const cors = await probeCorsPermissive({ targetUrl, fetchImpl });
    context.corsPermissive = cors;
    if (cors.wildcard || cors.reflected) {
      findings.push(makeFinding({
        type: 'cors_misconfiguration',
        value: cors.wildcard ? 'CORS permissivo: Access-Control-Allow-Origin=*' : `CORS refletindo Origin arbitraria (${cors.originReflected})`,
        score: cors.allowCredentials ? 78 : 62,
        url: targetUrl,
        meta: cors,
        owasp: 'A05:2021',
        mitre: 'T1190',
      }));
    }

    const authless = await probeAuthlessEndpoints({ targetUrl, fetchImpl });
    context.authlessEndpoints = authless.map((a) => a.path);
    findings.push(...authless.map((a) => makeFinding({
      type: 'auth_missing_endpoint',
      value: `Endpoint potencialmente sensivel sem auth: ${a.path} (HTTP ${a.status})`,
      score: 80,
      url: a.url,
      meta: { path: a.path, contentType: a.contentType, bodySize: a.bodySize },
      owasp: 'A07:2021',
      mitre: 'T1078',
    })));

    const missing = analyzeSecurityHeadersFromResponse(rootFull.headers);
    context.missingSecurityHeaders = missing.map((h) => h.name);
    if (missing.length >= 3) {
      findings.push(makeFinding({
        type: 'security_headers_missing',
        value: `${missing.length} headers de seguranca ausentes (${missing.map((h) => h.name).join(', ')})`,
        score: missing.some((h) => h.name === 'content-security-policy' || h.name === 'strict-transport-security') ? 40 : 25,
        url: targetUrl,
        meta: { missing: missing.map((h) => h.name) },
        owasp: 'A05:2021',
        mitre: 'T1056',
      }));
    }
  }

  if (opts.pocDir && (supabaseUrl || anonKey || context.secretsFound.includes('supabase_jwt'))) {
    try {
      const evidence = collectSupabaseJwtEvidence({
        targetUrl,
        rootText: rootFull.text,
        bundles,
        storeRawSecrets: opts.storeRawSecrets === true,
      });
      if (evidence.length || supabaseUrl) {
        const poc = await writeSupabasePocPage({
          outputDir: opts.pocDir,
          targetUrl,
          supabaseUrl,
          context,
          evidence,
          storeRawSecrets: opts.storeRawSecrets === true,
        });
        if (poc?.path) {
          context.pocPath = poc.path;
          context.pocFile = poc.file;
          for (const f of findings) {
            const isSupabaseFinding =
              String(f.type || '').includes('supabase') ||
              String(f.value || '').toLowerCase().includes('supabase') ||
              String(f.meta?.secretType || '').includes('supabase');
            if (!isSupabaseFinding) continue;
            const meta = f.meta && typeof f.meta === 'object' && !Array.isArray(f.meta) ? f.meta : {};
            f.meta = { ...meta, pocPath: poc.path, pocFile: poc.file };
          }
        }
      }
    } catch (e) {
      context.pocError = e?.message || String(e);
    }
  }

  return { isLovable: context.isLovable, findings, context };
}

export const _internals = {
  COMMON_TABLES,
  COMMON_DOTFILES,
  COMMON_AUTHLESS_ENDPOINTS,
  REQUIRED_SECURITY_HEADERS,
  SECRET_PATTERNS,
  decodeJwtPayload,
  isLovableHost,
  isLovableMarkup,
  probeDotfiles,
  probeSourceMaps,
  probeCorsPermissive,
  probeAuthlessEndpoints,
  analyzeSecurityHeadersFromResponse,
};

export default fingerprintLovable;
