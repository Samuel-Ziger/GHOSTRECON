/**
 * token-validator.js
 *
 * Valida ativamente se um token/segredo encontrado ainda está vivo:
 *   1. Deteta tipo (JWT genérico, Supabase JWT, API key)
 *   2. Verifica expiração offline no claim `exp` do JWT
 *   3. Faz probes HTTP com os headers de auth corretos
 *   4. Devolve status: 'valid' | 'expired' | 'invalid' | 'revoked' | 'probable' | 'unknown'
 */

import https from 'node:https';
import http from 'node:http';

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

async function probe(url, headers = {}, method = 'GET') {
  return new Promise((resolve) => {
    let parsed;
    try { parsed = new URL(url); } catch(_) { return resolve({ status: null, error: 'invalid_url' }); }

    const mod = parsed.protocol === 'https:' ? https : http;
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
        res.on('end', () => resolve({ status: res.statusCode, body }));
      },
    );
    req.on('error', (e) => resolve({ status: null, error: e.message }));
    req.on('timeout', () => { req.destroy(); resolve({ status: null, error: 'timeout' }); });
    req.end();
  });
}

/**
 * Interpreta o status HTTP no contexto de validação de token.
 *
 * 401 = token rejeitado (não autenticado)
 * 403 = autenticado mas sem permissão → token VÁLIDO
 * 429 = rate-limited → token aceite, é válido
 * 200-299 = ok
 */
function statusMeaning(status) {
  if (!status)           return 'network_error';
  if (status === 401)    return 'rejected';
  if (status === 403)    return 'authenticated'; // forbidden mas autenticado = válido
  if (status === 429)    return 'authenticated'; // rate-limited = aceite
  if (status >= 200 && status < 300) return 'ok';
  if (status >= 400 && status < 500) return 'rejected';
  return 'unknown';
}

// ── VALIDAÇÃO PRINCIPAL ───────────────────────────────────────────────

/**
 * Valida um token encontrado num recon.
 *
 * @param {string} rawValue  - Valor do finding (pode ter wrapper "[JWT] eyJ...")
 * @param {string} sourceUrl - URL onde o token foi encontrado
 * @returns {Promise<TokenValidationResult>}
 */
export async function validateToken(rawValue, sourceUrl) {
  const raw = extractRawToken(rawValue);

  /** @type {TokenValidationResult} */
  const result = {
    status:          'unknown',
    tokenType:       'unknown',
    checkedAt:       new Date().toISOString(),
    evidence:        '',
    probes:          [],
    offlineExpired:  false,
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
      sub:  parsed.payload.sub,
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

  const origin = originOf(sourceUrl);

  // ── SUPABASE JWT ───────────────────────────────────────────────────
  if (result.tokenType === 'supabase_jwt') {
    const base = supabaseOrigin(sourceUrl, parsed) || origin;
    if (!base) {
      result.evidence = 'sem URL Supabase para validar';
      if (result.offlineExpired) result.status = 'expired';
      return result;
    }

    // Probe 1: /rest/v1/ — responde 200 para anon key válida
    const r1 = await probe(`${base}/rest/v1/`, {
      apikey:        raw,
      Authorization: `Bearer ${raw}`,
    });
    result.probes.push({ url: `${base}/rest/v1/`, status: r1.status, error: r1.error || null });

    const m1 = statusMeaning(r1.status);
    if (m1 === 'ok' || m1 === 'authenticated') {
      result.status   = 'valid';
      result.evidence = `Supabase /rest/v1/ → HTTP ${r1.status} — anon key aceite`;
    } else if (m1 === 'rejected') {
      result.status   = result.offlineExpired ? 'expired' : 'invalid';
      result.evidence = `Supabase /rest/v1/ → HTTP ${r1.status} — token rejeitado`;
    }

    // Probe 2: /auth/v1/user — para tokens de utilizador (não anon)
    const r2 = await probe(`${base}/auth/v1/user`, {
      apikey:        raw,
      Authorization: `Bearer ${raw}`,
    });
    result.probes.push({ url: `${base}/auth/v1/user`, status: r2.status, error: r2.error || null });

    const m2 = statusMeaning(r2.status);
    if ((m2 === 'ok' || m2 === 'authenticated') && result.status !== 'valid') {
      result.status   = 'valid';
      result.evidence = `Supabase /auth/v1/user → HTTP ${r2.status}`;
    }

    return result;
  }

  // ── JWT GENÉRICO ───────────────────────────────────────────────────
  if (result.tokenType === 'jwt') {
    const urls = [];
    if (sourceUrl) urls.push(sourceUrl);
    if (origin) {
      urls.push(`${origin}/api/me`);
      urls.push(`${origin}/api/user`);
      urls.push(`${origin}/api/v1/me`);
      if (!urls.includes(`${origin}/`)) urls.push(`${origin}/`);
    }

    for (const url of urls.slice(0, 5)) {
      const r = await probe(url, { Authorization: `Bearer ${raw}` });
      const m = statusMeaning(r.status);
      result.probes.push({ url, status: r.status, error: r.error || null });

      if (m === 'authenticated') {
        result.status   = 'valid';
        result.evidence = `Bearer → ${url} HTTP ${r.status} (auth confirmado)`;
        break;
      }
      if (m === 'ok') {
        // 200 num path de API é sinal positivo; no root pode ser página pública
        if (/\/api\//.test(url)) {
          result.status   = 'valid';
          result.evidence = `Bearer → ${url} HTTP ${r.status}`;
          break;
        }
        if (result.status === 'unknown') {
          result.status   = 'probable';
          result.evidence = `Bearer → ${url} HTTP ${r.status} (não confirmado como auth-required)`;
        }
      }
      if (m === 'rejected' && result.status !== 'valid') {
        result.status   = result.offlineExpired ? 'expired' : 'invalid';
        result.evidence = `Bearer → ${url} HTTP ${r.status}`;
        break;
      }
    }

    // Fallback offline se rede não foi conclusiva
    if (result.status === 'unknown' && result.offlineExpired) {
      result.status   = 'expired';
      result.evidence = `JWT expirado offline (exp=${parsed?.payload?.exp}, ${result.expiredAgo})`;
    }
    return result;
  }

  // ── API KEY GENÉRICA ────────────────────────────────────────────────
  const urlsToTry = [];
  if (sourceUrl) urlsToTry.push(sourceUrl);
  if (origin && origin !== sourceUrl) urlsToTry.push(`${origin}/`);

  for (const url of urlsToTry.slice(0, 2)) {
    const strategies = [
      { header: { Authorization: `Bearer ${raw}` },  label: 'Bearer'   },
      { header: { 'X-Api-Key': raw },                label: 'X-Api-Key' },
      { header: { Authorization: `token ${raw}` },   label: 'token'     },
    ];

    for (const { header, label } of strategies) {
      const r = await probe(url, header);
      const m = statusMeaning(r.status);
      result.probes.push({ url, method: label, status: r.status, error: r.error || null });

      if (m === 'authenticated') {
        result.status   = 'valid';
        result.evidence = `${label}: ${url} HTTP ${r.status} (auth confirmado)`;
        break;
      }
      if (m === 'ok' && /api|graphql/.test(url) && result.status !== 'valid') {
        result.status   = 'probable';
        result.evidence = `${label}: ${url} HTTP ${r.status}`;
      }
      if (m === 'rejected' && result.status !== 'valid' && result.status !== 'probable') {
        result.status   = 'invalid';
        result.evidence = `${label}: ${url} HTTP ${r.status}`;
      }
    }
    if (result.status === 'valid') break;
  }

  return result;
}
