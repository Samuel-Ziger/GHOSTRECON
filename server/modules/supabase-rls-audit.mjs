/**
 * supabase-rls-audit.mjs
 *
 * Probes generalistas Supabase além dos achados específicos de campo:
 * RLS desabilitado/permissivo, Storage público, Auth misconfig, GraphQL,
 * RPC, Edge Functions, Service Role no cliente, Realtime hints.
 */

import https from 'node:https';
import http from 'node:http';
import { AsyncLocalStorage } from 'node:async_hooks';
import {
  combineAbortSignals,
  isAbortError,
  throwIfAborted,
} from './http-utils.js';
import { readResponseSnippet } from './module-runner.mjs';

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
  supabase_rls_disabled_read: ['Leitura pública observada', 'Política de acesso não verificada', 'Revisão de RLS'],
  supabase_rls_authenticated_read: ['Leitura autenticada observada', 'Autorização por objeto não verificada'],
  supabase_rls_write_anon: ['RLS Desabilitado', 'Política RLS com true', 'Bypass de RLS por lógica falha', 'Mass Assignment'],
  supabase_rls_update_anon: ['Política RLS Excessivamente Permissiva', 'IDOR em tabelas Supabase', 'Horizontal Privilege Escalation'],
  supabase_service_role_exposed: ['Candidato a credencial Service Role', 'Service Role em aplicação cliente', 'Validade não verificada'],
  supabase_storage_public_list: ['Listagem pública observada', 'Bucket público', 'Intenção de publicação não verificada'],
  supabase_storage_upload_anon: ['Upload Arbitrário de Arquivos', 'Storage Bucket Excessivamente Permissivo'],
  supabase_open_signup: ['Cadastro público configurado', 'Intenção do produto não verificada'],
  supabase_user_enumeration: ['Enumeração de Usuários', 'Reset de Senha Enumerável'],
  supabase_graphql_introspection: ['Introspecção GraphQL observada', 'Impacto não verificado'],
  supabase_rpc_exposed: ['RPC sem Controle de Acesso', 'Exposição de Funções Sensíveis', 'Escalada de Privilégio via RPC'],
  supabase_edge_function_public: ['Resposta pública de Edge Function observada', 'Autorização e impacto não verificados'],
  supabase_realtime_hint: ['Realtime Channel Exposure', 'Canal Realtime sem autenticação'],
  supabase_jwt_long_lived: ['Excessive Session Lifetime', 'JWT reutilizável'],
};

function makeFinding({ type, value, score, url, meta, owasp, mitre, cvss }) {
  const prio = score >= 85 ? 'critical' : score >= 70 ? 'high' : score >= 50 ? 'med' : score >= 30 ? 'low' : 'info';
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

const requestImplContext = new AsyncLocalStorage();

function abortReason(signal) {
  return signal?.reason || new DOMException('The operation was aborted', 'AbortError');
}

async function networkRequest(
  url,
  { method = 'GET', headers = {}, body = null, signal = null } = {},
) {
  throwIfAborted(signal);
  return new Promise((resolve, reject) => {
    let parsed;
    try { parsed = new URL(url); } catch { return resolve({ status: null, headers: {}, body: '', error: 'invalid_url' }); }
    if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) {
      return resolve({ status: null, headers: {}, body: '', error: 'invalid_url' });
    }
    const mod = parsed.protocol === 'https:' ? https : http;
    let settled = false;
    let req = null;
    const finishResolve = (value) => {
      if (settled) return;
      settled = true;
      signal?.removeEventListener('abort', onAbort);
      resolve(value);
    };
    const finishReject = (error) => {
      if (settled) return;
      settled = true;
      signal?.removeEventListener('abort', onAbort);
      reject(error);
    };
    const onAbort = () => {
      const reason = abortReason(signal);
      req?.destroy(reason);
      finishReject(reason);
    };
    signal?.addEventListener('abort', onAbort, { once: true });
    if (signal?.aborted) return onAbort();
    req = mod.request({
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
      res.on('end', () => finishResolve({ status: res.statusCode, headers: resHeaders, body: buf, error: null }));
    });
    req.on('error', (e) => {
      if (isAbortError(e, signal)) finishReject(abortReason(signal));
      else finishResolve({ status: null, headers: {}, body: '', error: e.message });
    });
    req.on('timeout', () => {
      finishResolve({ status: null, headers: {}, body: '', error: 'timeout' });
      req.destroy();
    });
    if (body) req.write(body);
    req.end();
  });
}

async function rawRequest(url, options = {}) {
  const context = requestImplContext.getStore() || {};
  const requestImpl = typeof context === 'function' ? context : context.requestImpl;
  const signal = options.signal || context.signal || null;
  const urlAllowed = context.urlAllowed || null;
  throwIfAborted(signal);
  if (typeof urlAllowed === 'function' && urlAllowed(url) !== true) {
    return { status: null, headers: {}, body: '', error: 'out_of_scope' };
  }
  const result = typeof requestImpl === 'function'
    ? await requestImpl(url, { ...options, signal })
    : await networkRequest(url, { ...options, signal });
  throwIfAborted(signal);
  return result;
}

function withRequestImpl(requestImpl, signal, urlAllowed, fn) {
  throwIfAborted(signal);
  return requestImplContext.run({ requestImpl, signal, urlAllowed }, fn);
}

function rethrowAbort(error) {
  const signal = requestImplContext.getStore()?.signal || null;
  if (isAbortError(error, signal)) throw error;
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

const SUPABASE_PUBLISHABLE_KEY_FULL_RE = /^sb_publishable_[A-Za-z0-9_-]{8,512}$/;
const SUPABASE_SECRET_KEY_PREFIX_RE = /^sb_secret_/i;

function hostedSupabaseProjectRef(supabaseUrl) {
  try {
    const hostname = new URL(String(supabaseUrl || '')).hostname.toLowerCase();
    return hostname.match(/^([a-z0-9]{8,30})\.supabase\.co$/)?.[1] || null;
  } catch {
    return null;
  }
}

/**
 * Aceita somente as duas credenciais públicas suportadas pelo Supabase:
 * publishable key opaca ou JWT legado com role=anon. A assinatura do JWT não
 * é verificada aqui; o gateway remoto continua responsável por validá-la.
 */
export function validateSupabasePublicApiKey(key, supabaseUrl = null) {
  const candidate = String(key || '').trim();
  if (!candidate || candidate.length > 2_048) {
    return { ok: false, reason: 'public_api_key_missing_or_too_large' };
  }
  if (SUPABASE_SECRET_KEY_PREFIX_RE.test(candidate)) {
    return { ok: false, reason: 'secret_key_refused' };
  }
  if (SUPABASE_PUBLISHABLE_KEY_FULL_RE.test(candidate)) {
    return {
      ok: true,
      reason: null,
      keyType: 'publishable',
      signatureVerified: null,
      claims: null,
    };
  }
  if (candidate.startsWith('sb_')) {
    return { ok: false, reason: 'non_publishable_opaque_key_refused' };
  }

  const parts = candidate.split('.');
  if (
    parts.length !== 3
    || parts.some((part) => !/^[A-Za-z0-9_-]{2,}$/.test(part))
  ) {
    return { ok: false, reason: 'public_api_key_invalid' };
  }
  const claims = decodeJwtPayload(candidate);
  const role = String(claims?.role || '');
  if (role === 'service_role') return { ok: false, reason: 'service_role_refused' };
  if (role !== 'anon') return { ok: false, reason: 'non_anon_jwt_refused' };

  const projectRef = hostedSupabaseProjectRef(supabaseUrl);
  if (projectRef) {
    const claimRef = String(claims?.ref || '').trim().toLowerCase();
    if (!claimRef || claimRef !== projectRef) {
      return { ok: false, reason: 'anon_key_project_mismatch' };
    }
  }
  return {
    ok: true,
    reason: null,
    keyType: 'legacy_anon_jwt',
    signatureVerified: false,
    claims,
  };
}

export function validateSupabaseUserToken(token, supabaseUrl, { now = () => Date.now() } = {}) {
  const configuredToken = String(token || '').trim();
  const parts = configuredToken.split('.');
  const claims = parts.length === 3 ? decodeJwtPayload(configuredToken) : null;
  if (!claims) return { ok: false, reason: 'invalid_jwt' };

  const role = String(claims.role || '');
  const subject = String(claims.sub || '').trim();
  if (role === 'service_role') return { ok: false, reason: 'service_role_refused' };
  if (role !== 'authenticated' || !subject) return { ok: false, reason: 'non_user_token_refused' };

  let issuerMatches = false;
  try {
    const project = new URL(supabaseUrl);
    const issuer = new URL(String(claims.iss || ''));
    const projectPort = project.port || (project.protocol === 'https:' ? '443' : '80');
    const issuerPort = issuer.port || (issuer.protocol === 'https:' ? '443' : '80');
    issuerMatches = project.protocol === issuer.protocol
      && project.hostname.toLowerCase() === issuer.hostname.toLowerCase()
      && projectPort === issuerPort
      && /^\/auth\/v1\/?$/.test(issuer.pathname);
  } catch {
    issuerMatches = false;
  }
  if (!issuerMatches) return { ok: false, reason: 'issuer_project_mismatch' };

  const nowSeconds = Math.floor(Number(typeof now === 'function' ? now() : now) / 1000);
  if (!Number.isFinite(nowSeconds)) return { ok: false, reason: 'clock_invalid' };
  if (!Number.isSafeInteger(claims.exp) || claims.exp <= 0) {
    return { ok: false, reason: 'token_exp_missing_or_invalid' };
  }
  if (claims.exp <= nowSeconds) {
    return { ok: false, reason: 'token_expired' };
  }
  if (Number.isFinite(Number(claims.nbf)) && Number(claims.nbf) > nowSeconds + 30) {
    return { ok: false, reason: 'token_not_yet_valid' };
  }
  return { ok: true, reason: null, signatureVerified: false };
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

export async function discoverSupabaseRestTables(supabaseUrl, anonKey, log = null) {
  const url = `${supabaseUrl}/rest/v1/`;
  const res = await rawRequest(url, {
    headers: {
      ...sbHeaders(anonKey),
      Accept: 'application/openapi+json, application/json',
    },
  });
  if (res.status !== 200) return [];
  const doc = parseJsonObject(res.body);
  const tables = new Set();
  for (const route of Object.keys(doc?.paths || {})) {
    const match = route.match(/^\/([^/?{}]+)$/);
    if (!match) continue;
    let name;
    try { name = decodeURIComponent(match[1]); } catch { continue; }
    if (/^[a-zA-Z0-9_]{1,80}$/.test(name)) tables.add(name);
  }
  const out = [...tables].slice(0, 60);
  log?.(`[supabase-audit] Schema REST: ${out.length} tabela(s) descoberta(s)`, 'info');
  return out;
}

const SUPABASE_URL_RE = /https?:\/\/[a-z0-9]{8,30}\.supabase\.co/gi;
const SUPABASE_URL_ENV_RE = /(?:NEXT_PUBLIC_|VITE_|PUBLIC_|REACT_APP_)?SUPABASE_URL\s*[:=]\s*['"](https?:\/\/[^'"]+\.supabase\.co)['"]/gi;
const SUPABASE_JWT_RE = /\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{3,})\b/g;
const SUPABASE_PUBLISHABLE_KEY_RE = /\b(sb_publishable_[A-Za-z0-9_-]{8,512})\b/g;

/**
 * Extrai URL, anon key, tokens de usuário e service_role do HTML/JS do alvo.
 */
export function extractSupabaseCredentials(text) {
  const empty = {
    supabaseUrl: null,
    anonKey: null,
    authTokens: [],
    serviceRoleKey: null,
    authenticatedTokenCandidates: 0,
    serviceRoleCandidates: 0,
    rejectedPublicKeyCandidates: 0,
  };
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
  let authenticatedTokenCandidates = 0;
  let serviceRoleCandidates = 0;
  let rejectedPublicKeyCandidates = 0;
  const seen = new Set();

  SUPABASE_PUBLISHABLE_KEY_RE.lastIndex = 0;
  const publishableMatch = SUPABASE_PUBLISHABLE_KEY_RE.exec(cap);
  if (publishableMatch) anonKey = publishableMatch[1];

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
      // Credenciais privilegiadas observadas no cliente são reportadas por
      // detectServiceRoleExposure; nunca são devolvidas para uso operacional.
      serviceRoleCandidates += 1;
    } else if (role === 'anon') {
      const candidateUrl = supabaseUrl || (claims.ref
        ? `https://${String(claims.ref).toLowerCase()}.supabase.co`
        : null);
      const validation = validateSupabasePublicApiKey(jwt, candidateUrl);
      if (validation.ok) {
        anonKey = anonKey || jwt;
        if (!supabaseUrl && claims.ref) supabaseUrl = candidateUrl;
      } else {
        rejectedPublicKeyCandidates += 1;
      }
    } else if (role === 'authenticated' && claims.sub) {
      // Tokens de usuário encontrados em bundle não constituem autorização
      // para reutilizar uma sessão, mesmo em probes de leitura.
      authenticatedTokenCandidates += 1;
    } else if (/supabase/i.test(iss) || role) {
      // Um issuer textual não transforma JWT de usuário/custom role em anon
      // key. Registrar a rejeição sem devolver a credencial para uso.
      rejectedPublicKeyCandidates += 1;
    }
  }

  return {
    supabaseUrl,
    anonKey,
    authTokens: [],
    serviceRoleKey: null,
    authenticatedTokenCandidates,
    serviceRoleCandidates,
    rejectedPublicKeyCandidates,
  };
}

/**
 * Resolve um JWT autenticado para probes somente leitura.
 *
 * Criação de sessão/conta e uso de service_role exigem gates separados. A
 * simples presença de um token no ambiente ou no bundle nunca habilita writes.
 */
export async function resolveSupabaseAuthToken(
  supabaseUrl,
  anonKey,
  {
    bundleText = '',
    log = null,
    envToken = null,
    writeProbes = false,
    allowServiceRole = false,
    requestImpl = null,
    signal = null,
    urlAllowed = null,
    now = () => Date.now(),
  } = {},
) {
  return withRequestImpl(requestImpl, signal, urlAllowed, async () => {
  if (writeProbes === true || allowServiceRole === true) {
    log?.('[supabase-audit] Write/service_role recusado: o auditor geral é somente leitura', 'warn');
  }
  const configuredToken = String(envToken || '').trim();
  if (configuredToken) {
    const validation = validateSupabaseUserToken(configuredToken, supabaseUrl, { now });
    if (!validation.ok) {
      const rejectedReason = validation.reason;
      log?.(`[supabase-audit] Token autenticado explícito recusado (${rejectedReason}); valor omitido`, 'warn');
      return {
        authToken: null,
        apiKey: anonKey,
        source: null,
        rejectedReason,
      };
    }
    return {
      authToken: configuredToken,
      apiKey: anonKey,
      source: 'operator_config',
      rejectedReason: null,
      signatureVerified: validation.signatureVerified,
    };
  }

  const extracted = extractSupabaseCredentials(bundleText);
  if (extracted.authenticatedTokenCandidates || extracted.serviceRoleCandidates) {
    log?.('[supabase-audit] Credencial privilegiada/de usuário observada no bundle; reutilização recusada', 'warn');
  }
  return { authToken: null, apiKey: anonKey, source: null, rejectedReason: null };
  });
}

/**
 * Descobre credenciais Supabase no alvo (HTML + bundles JS).
 */
export async function discoverSupabaseFromTarget(
  targetUrl,
  {
    fetchImpl = null,
    log = null,
    maxFiles = 8,
    signal = null,
    urlAllowed = null,
  } = {},
) {
  log?.('[supabase-audit] Extraindo URL/key dos bundles do alvo', 'info');
  const bundleText = await fetchClientBundleText(targetUrl, {
    fetchImpl,
    maxFiles,
    signal,
    urlAllowed,
  });
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
        value: 'JWT com claim service_role observado no cliente (credencial candidata; validade não testada)',
        score: 48,
        url: null,
        meta: {
          role: 'service_role',
          iss: claims.iss || null,
          evidenceStatus: 'static_credential_candidate',
          signatureVerified: false,
          credentialValidated: false,
          impactVerified: false,
          recommendation: 'Confirmar validade e vínculo ao projeto; se válidos, rotacionar e remover do cliente',
        },
        owasp: 'A07:2021',
        mitre: 'T1552',
        cvss: null,
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
        value: 'Literal semelhante a service_role / SUPABASE_SERVICE_ROLE observado no bundle (candidato)',
        score: 42,
        url: null,
        meta: {
          pattern: 'service_role_literal',
          evidenceStatus: 'static_credential_candidate',
          credentialValidated: false,
          impactVerified: false,
        },
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
export async function probeRlsReadTables(
  supabaseUrl,
  anonKey,
  log,
  tables = SUPABASE_SENSITIVE_TABLES,
  { authToken = null, accessContext = authToken ? 'authenticated' : 'anonymous' } = {},
) {
  const findings = [];
  const exposed = [];
  const outcomes = [];
  const authenticated = accessContext === 'authenticated' && Boolean(authToken);
  const outcomeAccessContext = authenticated ? 'authenticated' : 'anonymous';

  for (const table of [...new Set(tables)].filter((name) => typeof name === 'string' && /^[A-Za-z_][A-Za-z0-9_]{0,62}$/.test(name)).slice(0, 30)) {
    const url = `${supabaseUrl}/rest/v1/${encodeURIComponent(table)}?select=*&limit=3`;
    const res = await rawRequest(url, {
      headers: sbHeaders(anonKey, authenticated ? authToken : null),
    });
    if (res.status !== 200 || res.error) {
      outcomes.push({
        table,
        status: res.status || null,
        outcome: res.error
          ? (res.error === 'timeout' ? 'timeout' : res.error === 'out_of_scope' ? 'out_of_scope' : 'request_error')
          : [401, 403].includes(res.status)
            ? 'denied'
            : res.status === 429
              ? 'rate_limited'
              : 'http_inconclusive',
        accessContext: outcomeAccessContext,
      });
      continue;
    }

    let rows;
    try { rows = JSON.parse(res.body); } catch { rows = null; }
    if (!Array.isArray(rows) || rows.some((row) => !row || typeof row !== 'object' || Array.isArray(row))) {
      outcomes.push({
        table,
        status: res.status,
        outcome: 'invalid_response',
        accessContext: outcomeAccessContext,
      });
      continue;
    }
    outcomes.push({
      table,
      status: res.status,
      outcome: rows.length ? 'observed_rows' : 'empty_response',
      accessContext: outcomeAccessContext,
    });
    if (rows.length === 0) {
      log?.(
        `[supabase-audit] RLS read ${authenticated ? 'autenticado' : 'anônimo'}: ${table} respondeu sem linhas; resultado inconclusivo`,
        'info',
      );
      continue;
    }
    exposed.push({
      table,
      rowCount: rows.length,
      columns: rows[0] ? Object.keys(rows[0]).slice(0, 20) : [],
      accessContext: outcomeAccessContext,
    });
    log?.(
      `[supabase-audit] RLS read ${authenticated ? 'autenticado' : 'anônimo'}: ${table} retornou ${rows.length} row(s)`,
      authenticated ? 'info' : 'warn',
    );

    const sensitiveCols = (rows[0] ? Object.keys(rows[0]) : []).filter((c) =>
      /email|password|token|secret|stripe|credit|ssn|cpf|phone|role|admin|privilege/i.test(c),
    );

    findings.push(makeFinding({
      type: authenticated ? 'supabase_rls_authenticated_read' : 'supabase_rls_disabled_read',
      value: `${authenticated ? 'Leitura autenticada' : 'Leitura pública'} observada: tabela "${table}" (${rows.length} row(s)); política/impacto não verificados`,
      score: authenticated ? (sensitiveCols.length ? 28 : 18) : (sensitiveCols.length ? 56 : 28),
      url,
      meta: {
        table,
        rowCount: rows.length,
        columns: rows[0] ? Object.keys(rows[0]).slice(0, 15) : [],
        sensitiveColumns: sensitiveCols,
        evidenceStatus: 'observed_rows',
        accessContext: authenticated ? 'authenticated_user_token' : 'anonymous_publishable_key',
        tokenSignatureVerified: authenticated ? false : null,
        confidence: 'medium',
        accessPolicyVerified: false,
        impactVerified: false,
        note: 'Confirmar se os dados são intencionalmente públicos antes de classificar como RLS incorreta.',
      },
      owasp: 'A01:2021',
      mitre: 'T1213',
    }));
  }

  if (exposed.length >= 3) {
    findings.push(makeFinding({
      type: authenticated ? 'supabase_rls_authenticated_read' : 'supabase_rls_disabled_read',
      value: `${exposed.length} tabelas retornaram linhas ${authenticated ? 'ao usuário autenticado' : 'públicas'}; quantidade não comprova RLS desabilitado`,
      score: authenticated ? 18 : 28,
      url: `${supabaseUrl}/rest/v1/`,
      meta: {
        tables: exposed.map((e) => e.table),
        evidenceStatus: 'observed_rows',
        accessContext: authenticated ? 'authenticated_user_token' : 'anonymous_publishable_key',
        accessPolicyVerified: false,
        impactVerified: false,
      },
      owasp: 'A01:2021',
    }));
  }

  return { findings, exposed, outcomes };
}

/**
 * Probe RLS write: INSERT/PATCH anônimo com cleanup.
 */
export async function probeRlsWriteTables(
  supabaseUrl,
  anonKey,
  log,
  exposedTables = [],
  { writeProbes = false } = {},
) {
  if (writeProbes === true) {
    log?.('[supabase-audit] Write probe recusado: requer módulo laboratorial separado e confirmação destrutiva', 'warn');
  }
  return [];
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
    const publicBuckets = Array.isArray(buckets) ? buckets.filter((bucket) => bucket?.public === true) : [];
    if (!publicBuckets.length) return findings;
    log?.(`[supabase-audit] Storage: ${publicBuckets.length} bucket(s) declarado(s) público(s)`, 'info');
    findings.push(makeFinding({
      type: 'supabase_storage_public_inventory',
      value: `Storage: ${publicBuckets.length} bucket(s) marcado(s) como público(s)`,
      score: 18,
      url: bucketsUrl,
      meta: {
        buckets: publicBuckets.map((bucket) => bucket.name || bucket.id).slice(0, 20),
        evidenceStatus: 'configuration_inventory',
        note: 'Bucket público pode ser intencional; objetos expostos são avaliados separadamente.',
      },
      owasp: 'A01:2021',
      mitre: 'T1530',
    }));

    for (const bucketDef of publicBuckets.slice(0, 12)) {
      const bucket = String(bucketDef?.name || bucketDef?.id || '');
      if (!bucket || !/^[a-zA-Z0-9._-]{1,100}$/.test(bucket)) continue;
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
          value: `Storage bucket "${bucket}": listagem pública observada (${items.length} objeto(s) na amostra)`,
          score: 24,
          url: listUrl,
          meta: {
            bucket,
            sampleCount: items.slice(0, 3).length,
            objectNamesPersisted: false,
            evidenceStatus: 'public_inventory',
            impactVerified: false,
            note: 'Bucket público pode ser intencional; conteúdo e autorização dos objetos não foram avaliados.',
          },
          owasp: 'A01:2021',
        }));
      }
    }

    }
  }

  return findings;
}

/**
 * Auth: signup aberto, enumeração, JWT lifetime.
 */
export async function probeAuthMisconfig(
  supabaseUrl,
  anonKey,
  log,
  { writeProbes = false } = {},
) {
  const findings = [];
  const settingsUrl = `${supabaseUrl}/auth/v1/settings`;
  const settingsRes = await rawRequest(settingsUrl, { headers: sbHeaders(anonKey) });

  if (settingsRes.status === 200) {
    let settings = null;
    try { settings = JSON.parse(settingsRes.body); } catch { /* skip */ }

    // Resposta vazia ou campo ausente é inconclusivo. Só descreva cadastro
    // público quando o endpoint declarar isso de forma explícita.
    const publicSignupConfigured = settings?.disable_signup === false;
    if (publicSignupConfigured) {
      const signupUrl = `${supabaseUrl}/auth/v1/signup`;
      log?.('[supabase-audit] Auth: configuração indica cadastro público (inventário)', 'info');
      findings.push(makeFinding({
        type: 'supabase_open_signup',
        value: 'Configuração Supabase indica cadastro público habilitado (inventário)',
        score: 18,
        url: signupUrl,
        meta: {
          verifiedByWriteProbe: false,
          source: 'auth_settings',
          evidenceStatus: 'configuration_inventory',
          note: 'Cadastro público pode ser requisito do produto; nenhuma conta foi criada.',
        },
        owasp: 'A07:2021',
      }));
    }

    if (settings?.external?.anonymous === true || settings?.external?.anonymous_users === true) {
      findings.push(makeFinding({
        type: 'supabase_open_signup',
        value: 'Autenticação anônima habilitada no projeto Supabase (inventário)',
        score: 18,
        url: settingsUrl,
        meta: { anonymous: true, evidenceStatus: 'configuration_inventory' },
        owasp: 'A07:2021',
      }));
    }
  }

  if (writeProbes === true) {
    log?.('[supabase-audit] Probes mutáveis de signup/recover recusados no auditor geral', 'warn');
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

  let document = null;
  try { document = JSON.parse(res.body || ''); } catch { /* resposta inconclusiva */ }
  const queryType = document?.data?.__schema?.queryType?.name;
  if (res.status === 200 && typeof queryType === 'string' && /^[_A-Za-z][_0-9A-Za-z]{0,127}$/.test(queryType)) {
    log?.('[supabase-audit] GraphQL introspection observada (inventário)', 'info');
    return makeFinding({
      type: 'supabase_graphql_introspection',
      value: 'GraphQL introspection disponível via Supabase (inventário)',
      score: 18,
      url,
      meta: {
        evidenceStatus: 'observed_inventory',
        queryType,
        impactVerified: false,
        note: 'Introspecção não é vulnerabilidade por si só.',
      },
      owasp: 'A01:2021',
      mitre: 'T1190',
    });
  }
  return null;
}

/**
 * RPC exposure — POST em funções comuns.
 */
export async function probeRpcExposure(
  supabaseUrl,
  anonKey,
  log,
  { writeProbes = false } = {},
) {
  if (writeProbes === true) {
    log?.('[supabase-audit] RPC POST recusado: requer capability separada e lista explícita do operador', 'warn');
  }
  return [];
}

/**
 * Edge Functions — probe paths comuns (sem auth).
 */
export async function probeEdgeFunctions(supabaseUrl, anonKey, log, functionNames = []) {
  const findings = [];
  for (const fn of functionNames.slice(0, 20)) {
    const url = `${supabaseUrl}/functions/v1/${fn}`;
    const res = await rawRequest(url, { headers: sbHeaders(anonKey) });
    if (res.status === 200 || res.status === 405) {
      findings.push(makeFinding({
        type: 'supabase_edge_function_public',
        value: `Edge Function "${fn}" respondeu sem contexto autenticado (inventário HTTP ${res.status})`,
        score: 20,
        url,
        meta: {
          function: fn,
          status: res.status,
          evidenceStatus: 'unauthenticated_inventory',
          note: 'HTTP 200/405 não prova ausência de autorização ou impacto.',
        },
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
      value: 'Realtime Supabase referenciado no cliente (inventário)',
      score: publicChannel ? 24 : 16,
      url: supabaseUrl,
      meta: { publicChannelHint: publicChannel, evidenceStatus: 'static_inventory' },
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
      value: `Anon key Supabase de longa duração (~${Math.round(ttlDays)} dias; inventário)`,
      score: 12,
      url: null,
      meta: {
        exp: claims.exp,
        ttlDays: Math.round(ttlDays),
        evidenceStatus: 'configuration_inventory',
        note: 'Anon keys são públicas e frequentemente longevas; revisar RLS e rotação, não tratar como segredo.',
      },
      owasp: 'A07:2021',
    });
  }
  return null;
}

/**
 * Busca bundles JS do alvo para detectar service_role no cliente.
 */
export async function fetchClientBundleText(
  targetUrl,
  {
    fetchImpl = null,
    maxFiles = 6,
    signal = null,
    urlAllowed = null,
  } = {},
) {
  const fetchFn = fetchImpl || globalThis.fetch;
  const fileLimit = Math.min(12, Math.max(0, Math.floor(Number(maxFiles) || 0)));
  if (!fetchFn || !targetUrl) return '';
  throwIfAborted(signal);
  if (typeof urlAllowed === 'function' && urlAllowed(targetUrl) !== true) return '';
  try {
    const res = await fetchFn(targetUrl, {
      redirect: 'manual',
      headers: { 'User-Agent': UA, Accept: 'text/html,*/*' },
      signal: combineAbortSignals(signal, TIMEOUT_MS),
    });
    if (res.url && typeof urlAllowed === 'function' && urlAllowed(res.url) !== true) return '';
    const html = await readResponseSnippet(res, 512 * 1024);
    const jsUrls = [];
    const re = /(?:src|href)\s*=\s*["']([^"']+\.(?:js|mjs))(?:\?[^"']*)?["']/gi;
    let m;
    while ((m = re.exec(html)) !== null && jsUrls.length < fileLimit) {
      let u;
      try { u = new URL(m[1], targetUrl).href; } catch { continue; }
      if (!jsUrls.includes(u)) jsUrls.push(u);
    }
    let text = html;
    for (const u of jsUrls) {
      throwIfAborted(signal);
      if (typeof urlAllowed === 'function' && urlAllowed(u) !== true) continue;
      try {
        const r = await fetchFn(u, {
          redirect: 'manual',
          headers: { 'User-Agent': UA },
          signal: combineAbortSignals(signal, TIMEOUT_MS),
        });
        if (r.url && typeof urlAllowed === 'function' && urlAllowed(r.url) !== true) continue;
        if (r.ok) text += `\n${await readResponseSnippet(r, 512 * 1024)}`;
      } catch (error) {
        if (isAbortError(error, signal)) throw error;
        /* skip */
      }
    }
    return text.slice(0, 800_000);
  } catch (error) {
    if (isAbortError(error, signal)) throw error;
    return '';
  }
}

/**
 * Executa todos os probes RLS/Storage/Auth generalistas.
 */
export async function runSupabaseRlsAudit(context, opts = {}) {
  return withRequestImpl(opts.requestImpl, opts.signal, opts.urlAllowed, async () => {
  const {
    supabaseUrl,
    anonKey,
    authToken: requestedAuthToken = null,
    bundleText: bundleTextIn = '',
  } = context || {};
  const { log = null, writeProbes = false, tables = null, targetUrl = '' } = opts;
  const findings = [];
  const results = {};
  let exposedRows = [];
  const authTokenValidation = requestedAuthToken
    ? validateSupabaseUserToken(requestedAuthToken, supabaseUrl, { now: opts.now })
    : { ok: false, reason: 'not_configured' };
  const authToken = authTokenValidation.ok ? String(requestedAuthToken) : null;

  if (requestedAuthToken && !authTokenValidation.ok) {
    log?.(`[supabase-audit] Contexto autenticado recusado no runner (${authTokenValidation.reason}); valor omitido`, 'warn');
  }

  if (writeProbes === true) {
    log?.('[supabase-audit] writeProbes ignorado: auditor geral permanentemente somente leitura', 'warn');
  }

  if (!supabaseUrl || !anonKey) {
    return { findings: [], summary: { skipped: 'sem supabaseUrl ou anonKey' }, exposed: [] };
  }
  const publicApiKeyValidation = validateSupabasePublicApiKey(anonKey, supabaseUrl);
  if (!publicApiKeyValidation.ok) {
    log?.(`[supabase-audit] Chave pública recusada (${publicApiKeyValidation.reason}); nenhuma requisição foi enviada`, 'warn');
    return {
      findings: [],
      summary: {
        skipped: 'unsafe_or_invalid_public_api_key',
        apiKeyRejectedReason: publicApiKeyValidation.reason,
        results: {},
      },
      exposed: [],
    };
  }
  if (typeof opts.urlAllowed === 'function' && opts.urlAllowed(supabaseUrl) !== true) {
    log?.('[supabase-audit] Endpoint Supabase fora do escopo autorizado — RLS audit ignorado', 'info');
    return {
      findings: [],
      summary: { skipped: 'supabase_out_of_scope', results: {} },
      exposed: [],
    };
  }

  let bundleText = bundleTextIn;
  if (!bundleText && targetUrl) {
    log?.('[supabase-audit] Buscando bundles JS para scan service_role', 'info');
    bundleText = await fetchClientBundleText(targetUrl, {
      fetchImpl: opts.fetchImpl || null,
      signal: opts.signal,
      urlAllowed: opts.urlAllowed,
    });
  }

  findings.push(...detectServiceRoleExposure(bundleText, { anonKey }));
  findings.push(...probeRealtimeHints(bundleText, { supabaseUrl }));
  const lifetime = analyzeAnonKeyLifetime(anonKey);
  if (lifetime) findings.push(lifetime);

  try {
    const effectiveTables = Array.isArray(tables)
      ? tables
      : await discoverSupabaseRestTables(supabaseUrl, anonKey, log);
    const anonymousRead = await probeRlsReadTables(
      supabaseUrl,
      anonKey,
      log,
      effectiveTables,
    );
    findings.push(...anonymousRead.findings);
    exposedRows = [...anonymousRead.exposed];
    results.rlsRead = anonymousRead.exposed.length
      ? `${anonymousRead.exposed.length} tabela(s)`
      : 'no_rows_observed_inconclusive';
    results.rlsReadOutcomes = anonymousRead.outcomes;
    if (authToken) {
      // O segundo passe é inventário de leitura no contexto de um usuário
      // explicitamente configurado. Não é apresentado como acesso público ou
      // bypass, e fica limitado para preservar o orçamento do módulo.
      const authenticatedTables = effectiveTables.slice(0, 12);
      const authenticatedRead = await probeRlsReadTables(
        supabaseUrl,
        anonKey,
        log,
        authenticatedTables,
        { authToken, accessContext: 'authenticated' },
      );
      findings.push(...authenticatedRead.findings);
      exposedRows.push(...authenticatedRead.exposed);
      results.rlsReadAuthenticated = authenticatedRead.exposed.length
        ? `${authenticatedRead.exposed.length} tabela(s)`
        : 'no_rows_observed_inconclusive';
      results.rlsReadAuthenticatedOutcomes = authenticatedRead.outcomes;
      results.authenticatedTableCoverage = authenticatedTables.length;
    } else {
      results.rlsReadAuthenticated = 'not_run_without_explicit_user_token';
    }
    results.schemaTables = effectiveTables.length;
  } catch (e) {
    rethrowAbort(e);
    log?.(`[supabase-audit] RLS probe erro: ${e.message}`, 'warn');
    results.rlsRead = 'erro';
  }

  for (const [name, fn] of [
    ['storage', () => probeStorageExposure(supabaseUrl, anonKey, log)],
    ['auth', () => probeAuthMisconfig(supabaseUrl, anonKey, log, { writeProbes: false })],
    ['edgeFunctions', () => probeEdgeFunctions(supabaseUrl, anonKey, log, opts.edgeFunctions || [])],
  ]) {
    try {
      const r = await fn();
      const arr = Array.isArray(r) ? r : r ? [r] : [];
      findings.push(...arr);
      results[name] = arr.length ? `${arr.length} achado(s)` : 'not_observed_inconclusive';
    } catch (e) {
      rethrowAbort(e);
      log?.(`[supabase-audit] ${name} probe erro: ${e.message}`, 'warn');
      results[name] = 'erro';
    }
  }

  try {
    const gql = await probeSupabaseGraphql(supabaseUrl, anonKey, log);
    if (gql) findings.push(gql);
    results.graphql = gql ? 'inventory' : 'not_observed';
  } catch (e) {
    rethrowAbort(e);
    results.graphql = 'erro';
  }

  results.writeProbes = 'disabled';
  results.authenticatedToken = authToken
    ? 'operator_config_unverified_signature'
    : `not_used:${authTokenValidation.reason}`;
  return { findings, summary: { results, writeProbes: false, coverageVerified: false, status: 'partial' }, exposed: exposedRows };
  });
}
