/**
 * supabase-rls-audit.mjs
 *
 * Probes generalistas Supabase além dos achados específicos de campo:
 * RLS desabilitado/permissivo, Storage público, Auth misconfig, GraphQL,
 * RPC, Edge Functions, Service Role no cliente, Realtime hints.
 */

import https from 'node:https';
import http from 'node:http';

const TIMEOUT_MS = 12_000;
const UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36';
export const AUDIT_MARKER = 'ghostrecon_audit_poc';

export const SUPABASE_SENSITIVE_TABLES = [
  'users', 'profiles', 'user', 'accounts', 'account', 'admin', 'admin_users', 'roles', 'user_roles',
  'orders', 'payments', 'invoices', 'subscriptions', 'user_plans', 'plans', 'products', 'prices',
  'messages', 'notifications', 'tickets', 'posts', 'comments', 'leads', 'customers', 'clients',
  'study_records', 'sessions', 'tokens', 'api_keys', 'secrets', 'credentials', 'audit_logs', 'logs',
  'files', 'documents', 'uploads', 'media', 'avatars', 'settings', 'config', 'configuration',
  'coupons', 'discounts', 'carts', 'wishlists', 'addresses', 'payment_methods', 'transactions',
  'organizations', 'teams', 'members', 'invites', 'permissions', 'privileges',
];

export const SUPABASE_STORAGE_BUCKETS = [
  'public', 'avatars', 'uploads', 'files', 'media', 'images', 'documents', 'assets', 'private', 'backups',
];

export const SUPABASE_RPC_NAMES = [
  'get_user', 'get_users', 'admin_stats', 'search_users', 'execute_sql', 'run_query', 'delete_user',
  'update_role', 'grant_admin', 'list_all', 'export_data', 'get_secrets',
];

export const SUPABASE_EDGE_FUNCTIONS = [
  'hello', 'webhook', 'stripe-webhook', 'admin', 'export', 'send-email', 'process-payment',
];

export const SUPABASE_VULN_TAXONOMY = {
  supabase_rls_disabled_read: ['RLS Desabilitado', 'Tabelas públicas sem necessidade', 'Excessive Data Exposure', 'BOLA'],
  supabase_rls_write_anon: ['RLS Desabilitado', 'Política RLS com true', 'Bypass de RLS por lógica falha', 'Mass Assignment'],
  supabase_rls_update_anon: ['Política RLS Excessivamente Permissiva', 'IDOR em tabelas Supabase', 'Horizontal Privilege Escalation'],
  supabase_service_role_exposed: ['Exposição da chave Service Role', 'Service Role em aplicações cliente', 'Vazamento de JWT'],
  supabase_storage_public_list: ['Storage Bucket Público', 'Bucket Enumeration', 'Exposição de Arquivos Privados'],
  supabase_storage_upload_anon: ['Upload Arbitrário de Arquivos', 'Storage Bucket Excessivamente Permissivo'],
  supabase_open_signup: ['Signup Aberto Indevidamente', 'Anonymous Authentication Abuse'],
  supabase_user_enumeration: ['Enumeração de Usuários', 'Reset de Senha Enumerável'],
  supabase_graphql_introspection: ['GraphQL Introspection Exposta', 'GraphQL sem Controle de Acesso'],
  supabase_rpc_exposed: ['RPC sem Controle de Acesso', 'Exposição de Funções Sensíveis', 'Escalada de Privilégio via RPC'],
  supabase_edge_function_public: ['Edge Function sem autenticação', 'Exposição de Funções Sensíveis'],
  supabase_realtime_hint: ['Realtime Channel Exposure', 'Canal Realtime sem autenticação'],
  supabase_jwt_long_lived: ['Excessive Session Lifetime', 'JWT reutilizável'],
};

function makeFinding({ type, value, score, url, meta, owasp, mitre, cvss }) {
  const prio = score >= 85 ? 'critical' : score >= 70 ? 'high' : score >= 50 ? 'medium' : score >= 30 ? 'low' : 'info';
  return {
    type,
    value,
    score,
    prio,
    url,
    meta: { ...(meta || {}), categories: SUPABASE_VULN_TAXONOMY[type] || [] },
    owasp: owasp || 'A01:2021',
    mitre: mitre || 'T1190',
    cvss: cvss || null,
    source: 'supabase_audit',
  };
}

async function rawRequest(url, { method = 'GET', headers = {}, body = null } = {}) {
  return new Promise((resolve) => {
    let parsed;
    try { parsed = new URL(url); } catch { return resolve({ status: null, headers: {}, body: '', error: 'invalid_url' }); }
    const mod = parsed.protocol === 'https:' ? https : http;
    const req = mod.request({
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method,
      timeout: TIMEOUT_MS,
      headers: { 'User-Agent': UA, Accept: 'application/json, */*', ...headers, ...(body ? { 'Content-Length': Buffer.byteLength(body) } : {}) },
    }, (res) => {
      const resHeaders = {};
      for (const [k, v] of Object.entries(res.headers || {})) resHeaders[k.toLowerCase()] = v;
      let buf = '';
      res.setEncoding('utf8');
      res.on('data', (c) => { buf += c; if (buf.length > 65536) req.destroy(); });
      res.on('end', () => resolve({ status: res.statusCode, headers: resHeaders, body: buf, error: null }));
    });
    req.on('error', (e) => resolve({ status: null, headers: {}, body: '', error: e.message }));
    req.on('timeout', () => { req.destroy(); resolve({ status: null, headers: {}, body: '', error: 'timeout' }); });
    if (body) req.write(body);
    req.end();
  });
}

function sbHeaders(key, token = null) {
  return {
    apikey: key,
    Authorization: `Bearer ${token || key}`,
    'Content-Type': 'application/json',
    Prefer: 'return=representation',
  };
}

function decodeJwtPayload(token) {
  try {
    const parts = String(token || '').split('.');
    if (parts.length < 2) return null;
    const pad = '='.repeat((4 - (parts[1].length % 4)) % 4);
    return JSON.parse(Buffer.from(parts[1].replace(/-/g, '+').replace(/_/g, '/') + pad, 'base64').toString('utf8'));
  } catch { return null; }
}

function parseJsonArray(body) {
  try {
    const j = JSON.parse(body || '[]');
    return Array.isArray(j) ? j : [];
  } catch { return []; }
}

function parseJsonObject(body) {
  try { return JSON.parse(body || '{}'); } catch { return null; }
}

const SUPABASE_URL_RE = /https?:\/\/[a-z0-9]{8,30}\.supabase\.co/gi;
const SUPABASE_URL_ENV_RE = /(?:NEXT_PUBLIC_|VITE_|PUBLIC_|REACT_APP_)?SUPABASE_URL\s*[:=]\s*['"](https?:\/\/[^'"]+\.supabase\.co)['"]/gi;
const SUPABASE_JWT_RE = /\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{3,})\b/g;

/**
 * Extrai URL, anon key, tokens de usuário e service_role do HTML/JS do alvo.
 */
export function extractSupabaseCredentials(text) {
  const empty = { supabaseUrl: null, anonKey: null, authTokens: [], serviceRoleKey: null };
  if (!text || typeof text !== 'string') return empty;

  const cap = text.slice(0, 800_000);
  let supabaseUrl = null;

  SUPABASE_URL_RE.lastIndex = 0;
  let m = SUPABASE_URL_RE.exec(cap);
  if (m) supabaseUrl = m[0].replace(/\/+$/, '');

  if (!supabaseUrl) {
    SUPABASE_URL_ENV_RE.lastIndex = 0;
    m = SUPABASE_URL_ENV_RE.exec(cap);
    if (m) supabaseUrl = m[1].replace(/\/+$/, '');
  }

  let anonKey = null;
  let serviceRoleKey = null;
  const authTokens = [];
  const seen = new Set();

  SUPABASE_JWT_RE.lastIndex = 0;
  while ((m = SUPABASE_JWT_RE.exec(cap)) !== null) {
    const jwt = m[1];
    if (seen.has(jwt)) continue;
    seen.add(jwt);
    const claims = decodeJwtPayload(jwt);
    if (!claims) continue;

    const role = claims.role;
    const iss = String(claims.iss || '');

    if (role === 'service_role') {
      serviceRoleKey = jwt;
    } else if (role === 'anon') {
      anonKey = anonKey || jwt;
      if (!supabaseUrl && claims.ref) {
        supabaseUrl = `https://${claims.ref}.supabase.co`;
      }
    } else if (role === 'authenticated' && claims.sub) {
      authTokens.push({ jwt, sub: claims.sub, exp: claims.exp || null });
    } else if (/supabase/i.test(iss) && role !== 'service_role' && !anonKey) {
      anonKey = jwt;
      if (!supabaseUrl && claims.ref) supabaseUrl = `https://${claims.ref}.supabase.co`;
    }
  }

  return { supabaseUrl, anonKey, authTokens, serviceRoleKey };
}

async function validateAuthToken(supabaseUrl, anonKey, token) {
  const res = await rawRequest(`${supabaseUrl}/auth/v1/user`, { headers: sbHeaders(anonKey, token) });
  return res.status === 200;
}

function parseAccessToken(body) {
  const j = parseJsonObject(body);
  return j?.access_token || j?.session?.access_token || null;
}

/**
 * Obtém JWT autenticado automaticamente: env → bundle → signup anônimo → signup aberto → service_role.
 */
export async function resolveSupabaseAuthToken(supabaseUrl, anonKey, { bundleText = '', log = null, envToken = null } = {}) {
  if (envToken) {
    return { authToken: envToken, apiKey: anonKey, source: 'env' };
  }

  const extracted = extractSupabaseCredentials(bundleText);
  const now = Math.floor(Date.now() / 1000);

  for (const t of extracted.authTokens) {
    if (t.exp && t.exp < now) continue;
    try {
      if (await validateAuthToken(supabaseUrl, anonKey, t.jwt)) {
        log?.(`[supabase-audit] Token autenticado encontrado no bundle (user_id=${t.sub})`, 'info');
        return { authToken: t.jwt, apiKey: anonKey, source: 'bundle_authenticated' };
      }
    } catch { /* skip */ }
  }

  try {
    const anonRes = await rawRequest(`${supabaseUrl}/auth/v1/signup`, {
      method: 'POST',
      headers: { ...sbHeaders(anonKey), 'X-Supabase-Api-Version': '2024-01-01' },
      body: JSON.stringify({ data: {}, gotrue_meta_security: {} }),
    });
    const anonToken = parseAccessToken(anonRes.body);
    if (anonRes.status === 200 && anonToken) {
      log?.('[supabase-audit] Sessão anônima criada — token obtido automaticamente', 'info');
      return { authToken: anonToken, apiKey: anonKey, source: 'anonymous_signin' };
    }
  } catch { /* skip */ }

  try {
    const email = `ghostrecon.audit.${Date.now()}@ghostrecon.invalid`;
    const signupRes = await rawRequest(`${supabaseUrl}/auth/v1/signup`, {
      method: 'POST',
      headers: { ...sbHeaders(anonKey), 'X-Supabase-Api-Version': '2024-01-01' },
      body: JSON.stringify({ email, password: 'GhostReconAudit!2026Aa' }),
    });
    const signupToken = parseAccessToken(signupRes.body);
    if (signupRes.status === 200 && signupToken) {
      log?.('[supabase-audit] Conta de teste criada — access_token obtido automaticamente', 'info');
      return { authToken: signupToken, apiKey: anonKey, source: 'open_signup' };
    }
  } catch { /* skip */ }

  if (extracted.serviceRoleKey) {
    log?.('[supabase-audit] service_role no bundle — usando para probes autenticados', 'warn');
    return { authToken: extracted.serviceRoleKey, apiKey: extracted.serviceRoleKey, source: 'bundle_service_role' };
  }

  return { authToken: null, apiKey: anonKey, source: null };
}

/**
 * Descobre credenciais Supabase no alvo (HTML + bundles JS).
 */
export async function discoverSupabaseFromTarget(targetUrl, { fetchImpl = null, log = null, maxFiles = 8 } = {}) {
  log?.('[supabase-audit] Extraindo URL/key dos bundles do alvo', 'info');
  const bundleText = await fetchClientBundleText(targetUrl, { fetchImpl, maxFiles });
  const creds = extractSupabaseCredentials(bundleText);
  return {
    ...creds,
    bundleText,
    context: {
      supabaseUrl: creds.supabaseUrl,
      anonKey: creds.anonKey,
      bundleText,
      serviceRoleKey: creds.serviceRoleKey || null,
    },
  };
}

/**
 * Detecta service_role JWT ou strings no bundle cliente.
 */
export function detectServiceRoleExposure(text, { anonKey = null } = {}) {
  const findings = [];
  if (!text || typeof text !== 'string') return findings;
  const cap = text.slice(0, 800_000);

  const jwtRe = /\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{3,})\b/g;
  let m;
  while ((m = jwtRe.exec(cap)) !== null) {
    const jwt = m[1];
    if (anonKey && jwt === anonKey) continue;
    const claims = decodeJwtPayload(jwt);
    if (claims?.role === 'service_role') {
      findings.push(makeFinding({
        type: 'supabase_service_role_exposed',
        value: 'CRÍTICO: JWT service_role exposta no código cliente — bypass total de RLS',
        score: 98,
        url: null,
        meta: {
          role: 'service_role',
          iss: claims.iss || null,
          recommendation: 'Rotacionar service_role imediatamente; usar apenas anon/publishable no frontend',
        },
        owasp: 'A07:2021',
        mitre: 'T1552',
        cvss: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
      }));
      break;
    }
  }

  if (/service[_-]?role|SUPABASE_SERVICE_ROLE|sb_secret_[a-z0-9_]+/i.test(cap)) {
    const hasLiteral = /(?:service[_-]?role|SUPABASE_SERVICE_ROLE\w*)\s*[:=]\s*['"][^'"]{8,}/i.test(cap)
      || /\bsb_secret_[a-z0-9_]{6,}\b/i.test(cap);
    if (hasLiteral) {
      findings.push(makeFinding({
        type: 'supabase_service_role_exposed',
        value: 'Referência literal a service_role / SUPABASE_SERVICE_ROLE no bundle cliente',
        score: 95,
        url: null,
        meta: { pattern: 'service_role_literal' },
        owasp: 'A07:2021',
        mitre: 'T1552',
      }));
    }
  }

  return findings;
}

/**
 * Probe RLS: leitura anônima em tabelas sensíveis.
 */
export async function probeRlsReadTables(supabaseUrl, anonKey, log, tables = SUPABASE_SENSITIVE_TABLES) {
  const findings = [];
  const exposed = [];

  for (const table of tables) {
    const url = `${supabaseUrl}/rest/v1/${encodeURIComponent(table)}?select=*&limit=3`;
    const res = await rawRequest(url, { headers: sbHeaders(anonKey) });
    if (res.status !== 200) continue;

    const rows = parseJsonArray(res.body);
    exposed.push({ table, rowCount: rows.length, columns: rows[0] ? Object.keys(rows[0]).slice(0, 20) : [] });
    log?.(`[supabase-audit] RLS read: ${table} acessível (${rows.length} row(s))`, 'warn');

    const sensitiveCols = (rows[0] ? Object.keys(rows[0]) : []).filter((c) =>
      /email|password|token|secret|stripe|credit|ssn|cpf|phone|role|admin|privilege/i.test(c),
    );

    findings.push(makeFinding({
      type: 'supabase_rls_disabled_read',
      value: `RLS ausente/permissivo: tabela "${table}" legível com anon key (${rows.length} row(s))`,
      score: sensitiveCols.length ? 92 : rows.length ? 85 : 72,
      url,
      meta: {
        table,
        rowCount: rows.length,
        columns: rows[0] ? Object.keys(rows[0]).slice(0, 15) : [],
        sensitiveColumns: sensitiveCols,
        fix: `ALTER TABLE ${table} ENABLE ROW LEVEL SECURITY; CREATE POLICY ... USING (auth.uid() = user_id);`,
      },
      owasp: 'A01:2021',
      mitre: 'T1213',
    }));
  }

  if (exposed.length >= 3) {
    findings.push(makeFinding({
      type: 'supabase_rls_disabled_read',
      value: `${exposed.length} tabelas sensíveis legíveis sem autenticação — RLS provavelmente desabilitado ou USING (true)`,
      score: 94,
      url: `${supabaseUrl}/rest/v1/`,
      meta: { tables: exposed.map((e) => e.table), pattern: 'mass_exposure' },
      owasp: 'A01:2021',
    }));
  }

  return { findings, exposed };
}

/**
 * Probe RLS write: INSERT/PATCH anônimo com cleanup.
 */
export async function probeRlsWriteTables(supabaseUrl, anonKey, log, exposedTables = []) {
  const findings = [];
  const targets = exposedTables.length
    ? exposedTables.slice(0, 3).map((e) => e.table)
    : ['profiles', 'users'];

  for (const table of targets) {
    const postUrl = `${supabaseUrl}/rest/v1/${encodeURIComponent(table)}`;
    const payload = { audit_marker: AUDIT_MARKER, created_at: new Date().toISOString() };
    const res = await rawRequest(postUrl, {
      method: 'POST',
      headers: sbHeaders(anonKey),
      body: JSON.stringify(payload),
    });

    if (res.status === 201 || res.status === 200) {
      log?.(`[supabase-audit] RLS write: INSERT anônimo em ${table}`, 'warn');
      let insertedId = null;
      try { insertedId = JSON.parse(res.body)?.[0]?.id || JSON.parse(res.body)?.id; } catch { /* skip */ }

      if (insertedId) {
        await rawRequest(`${postUrl}?id=eq.${insertedId}`, { method: 'DELETE', headers: sbHeaders(anonKey) });
      } else {
        await rawRequest(`${postUrl}?audit_marker=eq.${AUDIT_MARKER}`, { method: 'DELETE', headers: sbHeaders(anonKey) });
      }

      findings.push(makeFinding({
        type: 'supabase_rls_write_anon',
        value: `RLS write bypass: INSERT anônimo aceito em "${table}"`,
        score: 93,
        url: postUrl,
        meta: { table, httpStatus: res.status, cleanup: true },
        owasp: 'A01:2021',
        mitre: 'T1565',
      }));
    }

    const patchUrl = `${postUrl}?audit_marker=eq.${AUDIT_MARKER}`;
    const patch = await rawRequest(patchUrl, {
      method: 'PATCH',
      headers: sbHeaders(anonKey),
      body: JSON.stringify({ patched: true }),
    });
    if (patch.status >= 200 && patch.status < 300) {
      findings.push(makeFinding({
        type: 'supabase_rls_update_anon',
        value: `RLS UPDATE anônimo possível em "${table}"`,
        score: 88,
        url: patchUrl,
        meta: { table },
        owasp: 'A01:2021',
      }));
    }
  }

  return findings;
}

/**
 * Storage: listagem de buckets e objetos com anon key.
 */
export async function probeStorageExposure(supabaseUrl, anonKey, log) {
  const findings = [];

  const bucketsUrl = `${supabaseUrl}/storage/v1/bucket`;
  const bucketsRes = await rawRequest(bucketsUrl, { headers: sbHeaders(anonKey) });
  if (bucketsRes.status === 200) {
    let buckets = [];
    try { buckets = JSON.parse(bucketsRes.body); } catch { buckets = []; }
    if (Array.isArray(buckets) && buckets.length) {
      log?.(`[supabase-audit] Storage: ${buckets.length} bucket(s) listável(is)`, 'warn');
      findings.push(makeFinding({
        type: 'supabase_storage_public_list',
        value: `Storage: ${buckets.length} bucket(s) enumerável(is) com anon key`,
        score: 80,
        url: bucketsUrl,
        meta: { buckets: buckets.map((b) => b.name || b.id).slice(0, 10), publicBuckets: buckets.filter((b) => b.public).map((b) => b.name) },
        owasp: 'A01:2021',
        mitre: 'T1530',
      }));
    }
  }

  for (const bucket of SUPABASE_STORAGE_BUCKETS) {
    const listUrl = `${supabaseUrl}/storage/v1/object/list/${encodeURIComponent(bucket)}`;
    const listRes = await rawRequest(listUrl, {
      method: 'POST',
      headers: sbHeaders(anonKey),
      body: JSON.stringify({ prefix: '', limit: 3, offset: 0 }),
    });
    if (listRes.status === 200) {
      let items = [];
      try { items = JSON.parse(listRes.body); } catch { items = []; }
      if (Array.isArray(items) && items.length) {
        findings.push(makeFinding({
          type: 'supabase_storage_public_list',
          value: `Storage bucket "${bucket}": listagem pública (${items.length}+ objeto(s))`,
          score: 78,
          url: listUrl,
          meta: { bucket, sample: items.slice(0, 3).map((i) => i.name) },
          owasp: 'A01:2021',
        }));
      }
    }

    const pubUrl = `${supabaseUrl}/storage/v1/object/public/${encodeURIComponent(bucket)}`;
    const pubRes = await rawRequest(pubUrl, { headers: sbHeaders(anonKey) });
    if (pubRes.status === 200 && pubRes.body && pubRes.body.length > 50) {
      findings.push(makeFinding({
        type: 'supabase_storage_public_list',
        value: `Storage bucket "${bucket}" aparenta ser público (GET /object/public)`,
        score: 70,
        url: pubUrl,
        meta: { bucket },
      }));
    }
  }

  return findings;
}

/**
 * Auth: signup aberto, enumeração, JWT lifetime.
 */
export async function probeAuthMisconfig(supabaseUrl, anonKey, log) {
  const findings = [];
  const settingsUrl = `${supabaseUrl}/auth/v1/settings`;
  const settingsRes = await rawRequest(settingsUrl, { headers: sbHeaders(anonKey) });

  if (settingsRes.status === 200) {
    let settings = null;
    try { settings = JSON.parse(settingsRes.body); } catch { /* skip */ }

    const signupDisabled = settings?.disable_signup === true || settings?.SITE_URL === undefined && settings?.external?.email === false;
    if (settings && !signupDisabled && settings?.external?.email !== false) {
      const signupUrl = `${supabaseUrl}/auth/v1/signup`;
      const email = `ghostrecon.audit.${Date.now()}@ghostrecon.invalid`;
      const signupRes = await rawRequest(signupUrl, {
        method: 'POST',
        headers: { ...sbHeaders(anonKey), 'X-Supabase-Api-Version': '2024-01-01' },
        body: JSON.stringify({ email, password: 'GhostReconAudit!2026Aa' }),
      });
      if (signupRes.status === 200) {
        log?.('[supabase-audit] Auth: cadastro público habilitado', 'warn');
        findings.push(makeFinding({
          type: 'supabase_open_signup',
          value: 'Cadastro público Supabase Auth habilitado (signup via API)',
          score: 68,
          url: signupUrl,
          meta: { note: 'Conta de teste criada — remover manualmente se necessário' },
          owasp: 'A07:2021',
        }));
      }
    }

    if (settings?.external?.anonymous === true || settings?.external?.anonymous_users === true) {
      findings.push(makeFinding({
        type: 'supabase_open_signup',
        value: 'Autenticação anônima habilitada no projeto Supabase',
        score: 72,
        url: settingsUrl,
        meta: { anonymous: true },
        owasp: 'A07:2021',
      }));
    }
  }

  const recoverUrl = `${supabaseUrl}/auth/v1/recover`;
  const fake1 = await rawRequest(recoverUrl, {
    method: 'POST',
    headers: sbHeaders(anonKey),
    body: JSON.stringify({ email: 'definitely-not-exists-ghostrecon@ghostrecon.invalid' }),
  });
  const fake2 = await rawRequest(recoverUrl, {
    method: 'POST',
    headers: sbHeaders(anonKey),
    body: JSON.stringify({ email: 'admin@example.com' }),
  });

  if (fake1.status && fake2.status && fake1.status !== fake2.status) {
    findings.push(makeFinding({
      type: 'supabase_user_enumeration',
      value: 'Reset de senha retorna respostas distintas — possível enumeração de usuários',
      score: 62,
      url: recoverUrl,
      meta: { statusUnknown: fake1.status, statusMaybeExists: fake2.status },
      owasp: 'A07:2021',
    }));
  } else if (fake1.body !== fake2.body && Math.abs((fake1.body || '').length - (fake2.body || '').length) > 20) {
    findings.push(makeFinding({
      type: 'supabase_user_enumeration',
      value: 'Reset de senha: corpo de resposta difere entre e-mails — enumeração possível',
      score: 58,
      url: recoverUrl,
      meta: { bodyLenDiff: Math.abs((fake1.body || '').length - (fake2.body || '').length) },
      owasp: 'A07:2021',
    }));
  }

  return findings;
}

/**
 * GraphQL introspection via Supabase pg_graphql.
 */
export async function probeSupabaseGraphql(supabaseUrl, anonKey, log) {
  const url = `${supabaseUrl}/graphql/v1`;
  const query = JSON.stringify({
    query: 'query IntrospectionProbe { __schema { queryType { name } types { name kind } } }',
  });
  const res = await rawRequest(url, {
    method: 'POST',
    headers: sbHeaders(anonKey),
    body: query,
  });

  if (res.status === 200 && /__schema|"Query"|"Mutation"/i.test(res.body)) {
    log?.('[supabase-audit] GraphQL introspection ativo', 'warn');
    return makeFinding({
      type: 'supabase_graphql_introspection',
      value: 'GraphQL introspection exposto via Supabase (/graphql/v1)',
      score: 74,
      url,
      meta: { snippet: res.body.slice(0, 200) },
      owasp: 'A01:2021',
      mitre: 'T1190',
    });
  }
  return null;
}

/**
 * RPC exposure — POST em funções comuns.
 */
export async function probeRpcExposure(supabaseUrl, anonKey, log) {
  const findings = [];
  for (const fn of SUPABASE_RPC_NAMES) {
    const url = `${supabaseUrl}/rest/v1/rpc/${encodeURIComponent(fn)}`;
    const res = await rawRequest(url, {
      method: 'POST',
      headers: sbHeaders(anonKey),
      body: '{}',
    });
    if (res.status === 200 && !/function.*does not exist|PGRST202/i.test(res.body)) {
      log?.(`[supabase-audit] RPC: ${fn} respondeu HTTP 200`, 'warn');
      findings.push(makeFinding({
        type: 'supabase_rpc_exposed',
        value: `RPC "${fn}" invocável com anon key (HTTP 200)`,
        score: 76,
        url,
        meta: { function: fn, bodySnippet: res.body.slice(0, 120) },
        owasp: 'A01:2021',
        mitre: 'T1068',
      }));
    }
  }
  return findings;
}

/**
 * Edge Functions — probe paths comuns (sem auth).
 */
export async function probeEdgeFunctions(supabaseUrl, anonKey, log) {
  const findings = [];
  for (const fn of SUPABASE_EDGE_FUNCTIONS) {
    const url = `${supabaseUrl}/functions/v1/${fn}`;
    const res = await rawRequest(url, { headers: sbHeaders(anonKey) });
    if (res.status === 200 || res.status === 405) {
      findings.push(makeFinding({
        type: 'supabase_edge_function_public',
        value: `Edge Function "${fn}" acessível sem autenticação aparente (HTTP ${res.status})`,
        score: res.status === 200 ? 70 : 55,
        url,
        meta: { function: fn, status: res.status },
        owasp: 'A01:2021',
      }));
    }
  }
  return findings;
}

/**
 * Realtime hints no bundle + canal REST metadata.
 */
export function probeRealtimeHints(bundleText, { supabaseUrl = null } = {}) {
  const findings = [];
  if (!bundleText) return findings;
  const cap = String(bundleText).slice(0, 600_000);

  if (/\.channel\s*\(|supabase\.channel|realtime\.subscribe|postgres_changes/i.test(cap)) {
    const publicChannel = /channel\s*\(\s*['"](?:public|broadcast|room|global)['"]/i.test(cap);
    findings.push(makeFinding({
      type: 'supabase_realtime_hint',
      value: 'Realtime Supabase usado no cliente — validar RLS nos canais postgres_changes',
      score: publicChannel ? 65 : 48,
      url: supabaseUrl,
      meta: { publicChannelHint: publicChannel },
      owasp: 'A01:2021',
    }));
  }
  return findings;
}

/**
 * Analisa anon key JWT para lifetime excessivo.
 */
export function analyzeAnonKeyLifetime(anonKey) {
  const claims = decodeJwtPayload(anonKey);
  if (!claims?.exp) return null;
  const now = Math.floor(Date.now() / 1000);
  const ttlDays = (claims.exp - now) / 86400;
  if (ttlDays > 365 * 5) {
    return makeFinding({
      type: 'supabase_jwt_long_lived',
      value: `JWT anon key com expiração muito longa (~${Math.round(ttlDays)} dias)`,
      score: 42,
      url: null,
      meta: { exp: claims.exp, ttlDays: Math.round(ttlDays) },
      owasp: 'A07:2021',
    });
  }
  return null;
}

/**
 * Busca bundles JS do alvo para detectar service_role no cliente.
 */
export async function fetchClientBundleText(targetUrl, { fetchImpl = null, maxFiles = 6 } = {}) {
  const fetchFn = fetchImpl || globalThis.fetch;
  if (!fetchFn || !targetUrl) return '';
  try {
    const res = await fetchFn(targetUrl, { headers: { 'User-Agent': UA, Accept: 'text/html,*/*' }, signal: AbortSignal.timeout(TIMEOUT_MS) });
    const html = await res.text();
    const origin = new URL(targetUrl).origin;
    const jsUrls = [];
    const re = /(?:src|href)\s*=\s*["']([^"']+\.(?:js|mjs))(?:\?[^"']*)?["']/gi;
    let m;
    while ((m = re.exec(html)) !== null && jsUrls.length < maxFiles) {
      let u = m[1];
      if (u.startsWith('/')) u = `${origin}${u}`;
      else if (!/^https?:\/\//i.test(u)) u = `${origin}/${u}`;
      jsUrls.push(u);
    }
    let text = html;
    for (const u of jsUrls) {
      try {
        const r = await fetchFn(u, { headers: { 'User-Agent': UA }, signal: AbortSignal.timeout(TIMEOUT_MS) });
        if (r.ok) text += `\n${await r.text()}`;
      } catch { /* skip */ }
    }
    return text.slice(0, 800_000);
  } catch {
    return '';
  }
}

/**
 * Executa todos os probes RLS/Storage/Auth generalistas.
 */
export async function runSupabaseRlsAudit(context, opts = {}) {
  const { supabaseUrl, anonKey, bundleText: bundleTextIn = '' } = context || {};
  const { log = null, writeProbes = true, tables = SUPABASE_SENSITIVE_TABLES, targetUrl = '' } = opts;
  const findings = [];
  const results = {};

  if (!supabaseUrl || !anonKey) {
    return { findings: [], summary: { skipped: 'sem supabaseUrl ou anonKey' }, exposed: [] };
  }

  let bundleText = bundleTextIn;
  if (!bundleText && targetUrl) {
    log?.('[supabase-audit] Buscando bundles JS para scan service_role', 'info');
    bundleText = await fetchClientBundleText(targetUrl);
  }

  findings.push(...detectServiceRoleExposure(bundleText, { anonKey }));
  findings.push(...probeRealtimeHints(bundleText, { supabaseUrl }));
  const lifetime = analyzeAnonKeyLifetime(anonKey);
  if (lifetime) findings.push(lifetime);

  try {
    const { findings: rlsFindings, exposed } = await probeRlsReadTables(supabaseUrl, anonKey, log, tables);
    findings.push(...rlsFindings);
    results.rlsRead = exposed.length ? `${exposed.length} tabela(s)` : 'ok';
    if (writeProbes && exposed.length) {
      const wf = await probeRlsWriteTables(supabaseUrl, anonKey, log, exposed);
      findings.push(...wf);
      results.rlsWrite = wf.length ? 'vulneravel' : 'ok';
    }
  } catch (e) {
    log?.(`[supabase-audit] RLS probe erro: ${e.message}`, 'warn');
    results.rlsRead = 'erro';
  }

  for (const [name, fn] of [
    ['storage', () => probeStorageExposure(supabaseUrl, anonKey, log)],
    ['auth', () => probeAuthMisconfig(supabaseUrl, anonKey, log)],
    ['rpc', () => probeRpcExposure(supabaseUrl, anonKey, log)],
    ['edgeFunctions', () => probeEdgeFunctions(supabaseUrl, anonKey, log)],
  ]) {
    try {
      const r = await fn();
      const arr = Array.isArray(r) ? r : r ? [r] : [];
      findings.push(...arr);
      results[name] = arr.length ? `${arr.length} achado(s)` : 'ok';
    } catch (e) {
      log?.(`[supabase-audit] ${name} probe erro: ${e.message}`, 'warn');
      results[name] = 'erro';
    }
  }

  try {
    const gql = await probeSupabaseGraphql(supabaseUrl, anonKey, log);
    if (gql) findings.push(gql);
    results.graphql = gql ? 'vulneravel' : 'ok';
  } catch (e) {
    results.graphql = 'erro';
  }

  return { findings, summary: { results }, exposed: [] };
}
