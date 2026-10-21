/**
 * token-validator.js
 *
 * Analisa offline um token/segredo encontrado e, apenas com `network:true`,
 * valida se ainda está vivo:
 *   1. Deteta tipo (JWT genérico, Supabase JWT, API key)
 *   2. Verifica expiração offline no claim `exp` do JWT
 *   3. Opcionalmente faz probes HTTP com os headers de auth corretos
 *   4. Devolve status: 'valid' | 'expired' | 'invalid' | 'revoked' | 'probable' | 'unknown'
 */

import https from 'node:https';
import http from 'node:http';
import { safeSecretReference } from './secret-safety.js';

const TIMEOUT_MS = 8_000;
const UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';

// Três partes base64url separadas por ponto — heurística JWT
const JWT_RE = /^[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*$/;

// ── HELPERS ──────────────────────────────────────────────────────────

/**
 * Remove wrappers como "[JWT] eyJ..." ou "Bearer eyJ..." e devolve o token cru.
 */
export function extractRawToken(value) {
  const s = String(value || '').trim();
  const m1 = s.match(/^\[[^\]]+\]\s*(.+)$/s);
  if (m1) return m1[1].trim();
  const m2 = s.match(/^Bearer\s+(.+)$/is);
  if (m2) return m2[1].trim();
  return s;
}

function b64urlDecode(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Buffer.from(s, 'base64').toString('utf8');
}

/** Decode JWT sem verificar assinatura. */
function parseJwt(token) {
  const parts = String(token || '').split('.');
  if (parts.length < 2) return null;
  try {
    return {
      header:  JSON.parse(b64urlDecode(parts[0])),
      payload: JSON.parse(b64urlDecode(parts[1])),
    };
  } catch(_) { return null; }
}

function detectTokenType(rawToken, parsed) {
  if (!parsed) return 'api_key';
  const { payload, header } = parsed;
  if (
    payload.role === 'anon' ||
    payload.role === 'service_role' ||
    (typeof payload.iss === 'string' && /supabase/i.test(payload.iss)) ||
    (typeof header.typ === 'string' && /JWT/i.test(header.typ) && /supabase/i.test(JSON.stringify(payload)))
  ) return 'supabase_jwt';
  return 'jwt';
}

function originOf(url) {
  try { const u = new URL(url); return `${u.protocol}//${u.host}`; }
  catch(_) { return null; }
}

/** Extrai a base URL do Supabase a partir do iss ou da URL fonte. */
function supabaseOrigin(sourceUrl, parsed) {
  const iss = parsed?.payload?.iss;
  if (iss) {
    try { const u = new URL(iss); return `${u.protocol}//${u.host}`; } catch(_) {}
  }
  try {
    const u = new URL(sourceUrl);
    if (/supabase\.(co|io)/.test(u.hostname)) return `${u.protocol}//${u.hostname}`;
  } catch(_) {}
  return null;
}

// ── PROBE HTTP ────────────────────────────────────────────────────────

async function probe(url, headers = {}, method = 'GET', { signal = null } = {}) {
  if (signal?.aborted) throw signal.reason || new DOMException('The operation was aborted', 'AbortError');
  return new Promise((resolve, reject) => {
    let parsed;
    try { parsed = new URL(url); } catch(_) { return resolve({ status: null, error: 'invalid_url' }); }

    const mod = parsed.protocol === 'https:' ? https : http;
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      signal?.removeEventListener('abort', onAbort);
      resolve(value);
    };
    const fail = (error) => {
      if (settled) return;
      settled = true;
      signal?.removeEventListener('abort', onAbort);
      reject(error);
    };
    const req = mod.request(
      {
        hostname: parsed.hostname,
        port:     parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
        path:     parsed.pathname + parsed.search,
        method,
        timeout:  TIMEOUT_MS,
        headers:  { 'User-Agent': UA, Accept: 'application/json, */*', ...headers },
      },
      (res) => {
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (c) => { body += c; if (body.length > 2048) req.destroy(); });
        res.on('end', () => finish({ status: res.statusCode, body }));
      },
    );
    const onAbort = () => {
      const error = signal?.reason || new DOMException('The operation was aborted', 'AbortError');
      req.destroy(error);
      fail(error);
    };
    req.on('error', (e) => {
      if (signal?.aborted) fail(signal.reason || e);
      else finish({ status: null, error: e.message });
    });
    req.on('timeout', () => {
      req.destroy();
      finish({ status: null, error: 'timeout' });
    });
    signal?.addEventListener('abort', onAbort, { once: true });
    if (signal?.aborted) {
      onAbort();
      return;
    }
    req.end();
  });
}

/**
 * Interpreta o status HTTP no contexto de validação de token.
 *
 * 401 = token rejeitado (não autenticado)
 * 403/429 = inconclusivos sem baseline sem credencial
 * 200-299 = ok
 */
function statusMeaning(status) {
  if (!status)           return 'network_error';
  if (status === 401)    return 'rejected';
  if (status === 403)    return 'forbidden';
  if (status === 429)    return 'rate_limited';
  if (status >= 200 && status < 300) return 'ok';
  if (status >= 400 && status < 500) return 'rejected';
  return 'unknown';
}

// ── VALIDAÇÃO PRINCIPAL ───────────────────────────────────────────────

/**
 * Valida um token encontrado num recon. O default é estritamente offline.
 *
 * @param {string} rawValue  - Valor do finding (pode ter wrapper "[JWT] eyJ...")
 * @param {string} sourceUrl - URL onde o token foi encontrado
 * @returns {Promise<TokenValidationResult>}
 */
export async function validateToken(
  rawValue,
  sourceUrl,
  {
    network = false,
    probeImpl = null,
    signal = null,
    urlAllowed = null,
  } = {},
) {
  if (signal?.aborted) throw signal.reason || new DOMException('The operation was aborted', 'AbortError');
  const raw = extractRawToken(rawValue);
  const safeRef = safeSecretReference(rawValue);

  /** @type {TokenValidationResult} */
  const result = {
    status:          'unknown',
    tokenType:       'unknown',
    checkedAt:       new Date().toISOString(),
    evidence:        '',
    probes:          [],
    offlineExpired:  false,
    tokenFingerprint: safeRef.fingerprint,
    tokenRef:        safeRef.ref,
  };

  if (!raw || raw.length < 8) {
    result.evidence = 'token muito curto para validar';
    return result;
  }

  const isJwtLike = JWT_RE.test(raw);
  const parsed    = isJwtLike ? parseJwt(raw) : null;
  result.tokenType = detectTokenType(raw, parsed);

  // ── Verificação offline de expiração (JWT) ─────────────────────────
  if (parsed?.payload) {
    result.jwtClaims = {
      iss:  parsed.payload.iss,
      aud:  parsed.payload.aud,
      role: parsed.payload.role,
      exp:  parsed.payload.exp,
      iat:  parsed.payload.iat,
      nbf:  parsed.payload.nbf,
    };
    const exp = Number(parsed.payload.exp || 0);
    const now = Math.floor(Date.now() / 1000);
    if (exp && exp < now) {
      result.offlineExpired = true;
      result.expiredAt = new Date(exp * 1000).toISOString();
      result.expiredAgo = `${Math.round((now - exp) / 60)} min atrás`;
    } else if (exp) {
      result.offlineExpired = false;
      result.expiresAt = new Date(exp * 1000).toISOString();
      result.expiresIn = `em ${Math.round((exp - now) / 60)} min`;
    } else {
      result.noExpiration = true; // sem exp = token "eterno" (risco)
    }
  }

  if (network !== true) {
    if (result.offlineExpired) {
      result.status = 'expired';
      result.evidence = `JWT expirado offline (${result.expiredAt || 'exp inválido'})`;
    } else if (parsed?.payload) {
      result.status = 'probable';
      result.evidence = 'estrutura JWT detectada; validação de rede não autorizada';
    } else {
      result.evidence = 'segredo detectado; validação de rede não autorizada';
    }
    return result;
  }

  const runProbe = typeof probeImpl === 'function' ? probeImpl : probe;
  const mayProbe = (url) => {
    if (typeof urlAllowed !== 'function') return true;
    try {
      return urlAllowed(url) === true;
    } catch {
      return false;
    }
  };
  const executeProbe = async (url, headers, method = 'GET') => {
    if (signal?.aborted) throw signal.reason || new DOMException('The operation was aborted', 'AbortError');
    if (!mayProbe(url)) return { status: null, error: 'out_of_scope', skipped: true };
    return runProbe(url, headers, method, { signal });
  };
  const origin = originOf(sourceUrl);

  if (result.tokenType === 'jwt') {
    result.status = result.offlineExpired ? 'expired' : 'probable';
    result.evidence = result.offlineExpired
      ? `JWT expirado offline (${result.expiredAt || 'exp inválido'})`
      : 'JWT parseado offline; nenhum endpoint seguro específico do emissor foi identificado';
    return result;
  }
  if (result.tokenType === 'api_key') {
    result.status = 'unknown';
    result.evidence = 'API key não enviada: provedor e endpoint de validação não determinados';
    return result;
  }

  // ── SUPABASE JWT ───────────────────────────────────────────────────
  if (result.tokenType === 'supabase_jwt') {
    const role = String(parsed?.payload?.role || '');
    if (role === 'anon') {
      result.status = 'public_configuration';
      result.evidence = 'Supabase anon/publishable key é pública por design; revisar RLS, não tratar como segredo vivo';
      return result;
    }
    if (role === 'service_role') {
      result.status = 'probable';
      result.evidence = 'claim service_role observada; rede omitida para não exercer privilégio elevado';
      return result;
    }
    const base = supabaseOrigin(sourceUrl, parsed) || origin;
    if (!base) {
      result.evidence = 'sem URL Supabase para validar';
      if (result.offlineExpired) result.status = 'expired';
      return result;
    }
    if (!mayProbe(base)) {
      result.status = result.offlineExpired ? 'expired' : 'probable';
      result.evidence = 'origem Supabase fora do escopo autorizado; probe omitido';
      result.probes.push({ url: base, status: null, error: 'out_of_scope', skipped: true });
      return result;
    }

    const userUrl = `${base}/auth/v1/user`;
    const r2 = await executeProbe(userUrl, {
      apikey:        raw,
      Authorization: `Bearer ${raw}`,
    });
    result.probes.push({ url: userUrl, status: r2.status, error: r2.error || null });

    const m2 = statusMeaning(r2.status);
    if (m2 === 'ok') {
      result.status   = 'valid';
      result.evidence = `Supabase /auth/v1/user → HTTP ${r2.status}`;
    } else if (m2 === 'rejected') {
      result.status = result.offlineExpired ? 'expired' : 'invalid';
      result.evidence = `Supabase /auth/v1/user → HTTP ${r2.status} — token rejeitado`;
    } else {
      result.status = result.offlineExpired ? 'expired' : 'probable';
      result.evidence = `Supabase /auth/v1/user inconclusivo (${r2.status || r2.error || 'sem resposta'})`;
    }

    return result;
  }

  return result;
}
