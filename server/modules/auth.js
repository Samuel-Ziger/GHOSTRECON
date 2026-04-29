/**
 * GHOSTRECON — Auth + RBAC (P0)
 *
 * Provides authentication (JWT HS256/RS256 + static API keys) and authorization
 * (role-based + per-route scopes) for the Express API. Pure-Node — no extra deps.
 *
 * Env (see .env.example):
 *   AUTH_MODE          apikey | jwt | disabled                (default: apikey)
 *   AUTH_DISABLE       "1"  → bypass (dev only, loud warn)    (default: "0")
 *   AUTH_API_KEYS      pipe-separated  "<key>:<role>|..."     (role ∈ viewer|operator|red|admin)
 *   AUTH_API_KEYS_FILE path to a file with the same format    (one entry per line OK)
 *   AUTH_JWT_SECRET    HS256 shared secret
 *   AUTH_JWT_PUBLIC_KEY  PEM (RS256). Either string or path.
 *   AUTH_JWT_AUDIENCE  (optional) expected `aud` claim
 *   AUTH_JWT_ISSUER    (optional) expected `iss` claim
 *   AUTH_DEFAULT_ROLE  fallback role for loopback when AUTH_DISABLE=1 (default: admin)
 *   AUTH_AUDIT_DIR     dir for NDJSON audit log (default: <repo>/logs)
 *   AUTH_AUDIT_DISABLE "1" disables audit log to file (always logs to stderr)
 *
 * Headers accepted:
 *   Authorization: Bearer <jwt-or-apikey>
 *   X-API-Key: <apikey>
 *
 * Usage:
 *   import { initAuth, requireAuth, requireScope, requireAnyScope, audit } from './modules/auth.js';
 *   initAuth();                      // boot — validates config, prints summary
 *   app.use(requireAuth({ allowlist: [/^\/api\/health$/, /^\/api\/csrf-token$/] }));
 *   app.post('/api/recon/stream', requireScope('recon.run', { intrusiveCheck: deriveIntrusive }), handler);
 */

import { createHmac, createPublicKey, createVerify, timingSafeEqual, randomBytes, createHash } from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.join(__dirname, '..', '..');

// ─────────────────────────────────────────────────────────────────────────────
// Roles → scopes map (single source of truth — keep in sync with docs)
// ─────────────────────────────────────────────────────────────────────────────
export const ROLE_SCOPES = Object.freeze({
  viewer: ['recon.read'],
  operator: [
    'recon.read',
    'recon.run',
    'brain.write',
    'notes.write',
    'validation.write',
    'evidence.capture',
    'cve.enrich',
  ],
  red: [
    'recon.read',
    'recon.run',
    'recon.intrusive',
    'brain.write',
    'notes.write',
    'validation.write',
    'evidence.capture',
    'cve.enrich',
    'ai.run',
    'shannon.run',
    'project.write',
    'engagement.write',
    'team.lock',
  ],
  admin: ['*'],
});

const VALID_ROLES = new Set(Object.keys(ROLE_SCOPES));

function scopesForRole(role) {
  if (!role) return [];
  if (role === 'admin') return ['*'];
  return ROLE_SCOPES[role] || [];
}

function principalHasScope(principal, scope) {
  if (!principal) return false;
  const set = principal._scopeSet;
  if (set?.has('*')) return true;
  if (set?.has(scope)) return true;
  // Allow finer namespace matching: "team.lock" granted by "team.*"
  const dot = scope.indexOf('.');
  if (dot > 0) {
    const wildcard = `${scope.slice(0, dot)}.*`;
    if (set?.has(wildcard)) return true;
  }
  return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// Config loading
// ─────────────────────────────────────────────────────────────────────────────
const STATE = {
  ready: false,
  mode: 'apikey',
  disabled: false,
  defaultRole: 'admin',
  apiKeys: new Map(),     // sha256(rawKey) → { role, label, scopes }
  jwt: {
    hsSecret: null,
    rsKey: null,
    audience: null,
    issuer: null,
  },
  auditDir: path.join(REPO_ROOT, 'logs'),
  auditDisable: false,
};

function loadApiKeysFromString(raw, source = 'env') {
  if (!raw) return 0;
  const entries = String(raw)
    .split(/[|\n]/)
    .map((s) => s.trim())
    .filter(Boolean);
  let n = 0;
  for (const entry of entries) {
    const parts = entry.split(':');
    if (parts.length < 2) {
      console.error(`[auth] api key entry ignorada (formato esperado key:role[:label]) — origem ${source}`);
      continue;
    }
    const [key, role, ...rest] = parts;
    if (!VALID_ROLES.has(role)) {
      console.error(`[auth] role inválida "${role}" em entry; aceitas: ${[...VALID_ROLES].join(',')}`);
      continue;
    }
    if (key.length < 24) {
      console.error('[auth] api key com menos de 24 chars rejeitada (entropia insuficiente)');
      continue;
    }
    const hash = _sha256(key);
    STATE.apiKeys.set(hash, {
      role,
      label: rest.join(':') || `${source}#${n + 1}`,
      scopes: scopesForRole(role),
    });
    n++;
  }
  return n;
}

function _sha256(s) {
  return createHash('sha256').update(String(s), 'utf8').digest('hex');
}

function loadJwtConfig() {
  const hs = process.env.AUTH_JWT_SECRET?.trim();
  if (hs) STATE.jwt.hsSecret = hs;
  const rsRaw = process.env.AUTH_JWT_PUBLIC_KEY?.trim();
  if (rsRaw) {
    try {
      let pem = rsRaw;
      // Allow path-to-file
      if (!rsRaw.includes('BEGIN') && fs.existsSync(rsRaw)) {
        pem = fs.readFileSync(rsRaw, 'utf8');
      }
      STATE.jwt.rsKey = createPublicKey(pem);
    } catch (e) {
      console.error(`[auth] AUTH_JWT_PUBLIC_KEY inválida: ${e.message}`);
    }
  }
  STATE.jwt.audience = process.env.AUTH_JWT_AUDIENCE?.trim() || null;
  STATE.jwt.issuer = process.env.AUTH_JWT_ISSUER?.trim() || null;
}

export function initAuth() {
  if (STATE.ready) return STATE;
  const mode = String(process.env.AUTH_MODE || 'apikey').trim().toLowerCase();
  STATE.mode = ['apikey', 'jwt', 'disabled'].includes(mode) ? mode : 'apikey';
  STATE.disabled = String(process.env.AUTH_DISABLE || '').trim() === '1' || STATE.mode === 'disabled';
  STATE.defaultRole = (process.env.AUTH_DEFAULT_ROLE || 'admin').trim().toLowerCase();
  if (!VALID_ROLES.has(STATE.defaultRole)) STATE.defaultRole = 'admin';
  STATE.auditDir = process.env.AUTH_AUDIT_DIR?.trim() || path.join(REPO_ROOT, 'logs');
  STATE.auditDisable = String(process.env.AUTH_AUDIT_DISABLE || '').trim() === '1';

  // Load API keys (from env + optional file)
  const fromEnv = loadApiKeysFromString(process.env.AUTH_API_KEYS || '', 'env');
  let fromFile = 0;
  const file = process.env.AUTH_API_KEYS_FILE?.trim();
  if (file) {
    try {
      const raw = fs.readFileSync(file, 'utf8');
      fromFile = loadApiKeysFromString(raw, `file:${path.basename(file)}`);
    } catch (e) {
      console.error(`[auth] AUTH_API_KEYS_FILE não pôde ser lido: ${e.message}`);
    }
  }
  loadJwtConfig();

  if (!STATE.auditDisable) {
    try { fs.mkdirSync(STATE.auditDir, { recursive: true }); } catch { /* ignore */ }
  }

  // Boot summary (no secrets ever)
  const summary = {
    mode: STATE.mode,
    disabled: STATE.disabled,
    apiKeys: STATE.apiKeys.size,
    apiKeysSources: { env: fromEnv, file: fromFile },
    jwt: {
      hs256: Boolean(STATE.jwt.hsSecret),
      rs256: Boolean(STATE.jwt.rsKey),
      audience: STATE.jwt.audience,
      issuer: STATE.jwt.issuer,
    },
    audit: STATE.auditDisable ? 'stderr' : STATE.auditDir,
  };
  console.log('[auth] boot', JSON.stringify(summary));

  if (STATE.disabled) {
    console.warn('\x1b[33m[auth] AUTH_DISABLE=1 — toda autenticação está DESLIGADA. NUNCA use isto em produção.\x1b[0m');
  } else if (STATE.mode === 'apikey' && STATE.apiKeys.size === 0 && !STATE.jwt.hsSecret && !STATE.jwt.rsKey) {
    console.error('\x1b[31m[auth] AUTH_MODE=apikey sem AUTH_API_KEYS configuradas — todas rotas privilegiadas vão devolver 401.\x1b[0m');
  } else if (STATE.mode === 'jwt' && !STATE.jwt.hsSecret && !STATE.jwt.rsKey) {
    console.error('\x1b[31m[auth] AUTH_MODE=jwt sem AUTH_JWT_SECRET nem AUTH_JWT_PUBLIC_KEY — todas rotas privilegiadas vão devolver 401.\x1b[0m');
  }

  STATE.ready = true;
  return STATE;
}

// ─────────────────────────────────────────────────────────────────────────────
// Token extraction + verification
// ─────────────────────────────────────────────────────────────────────────────
function extractToken(req) {
  const auth = String(req.headers['authorization'] || '').trim();
  if (auth.toLowerCase().startsWith('bearer ')) {
    return { kind: 'bearer', value: auth.slice(7).trim() };
  }
  const apik = String(req.headers['x-api-key'] || '').trim();
  if (apik) return { kind: 'apikey', value: apik };
  return null;
}

function constantTimeEq(a, b) {
  const ab = Buffer.from(String(a), 'utf8');
  const bb = Buffer.from(String(b), 'utf8');
  if (ab.length !== bb.length) {
    // Still call timingSafeEqual to keep timing similar
    const pad = Buffer.alloc(Math.max(ab.length, bb.length));
    try { timingSafeEqual(pad, pad); } catch { /* ignore */ }
    return false;
  }
  return timingSafeEqual(ab, bb);
}

function verifyApiKey(raw) {
  if (!raw) return null;
  const hash = _sha256(raw);
  // Walk all entries to keep timing constant relative to map size, but bail on match
  let matched = null;
  for (const [k, v] of STATE.apiKeys.entries()) {
    if (constantTimeEq(k, hash)) {
      matched = { ...v };
    }
  }
  if (!matched) return null;
  return {
    sub: `apikey:${matched.label}`,
    role: matched.role,
    scopes: matched.scopes,
    via: 'apikey',
  };
}

function b64UrlDecode(s) {
  s = String(s).replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Buffer.from(s, 'base64');
}

function verifyJwt(token) {
  const parts = String(token).split('.');
  if (parts.length !== 3) return null;
  const [headerB64, payloadB64, sigB64] = parts;
  let header, payload;
  try {
    header = JSON.parse(b64UrlDecode(headerB64).toString('utf8'));
    payload = JSON.parse(b64UrlDecode(payloadB64).toString('utf8'));
  } catch {
    return null;
  }
  const alg = String(header?.alg || '').toUpperCase();
  const signingInput = `${headerB64}.${payloadB64}`;
  const sig = b64UrlDecode(sigB64);

  if (alg === 'HS256') {
    if (!STATE.jwt.hsSecret) return null;
    const expected = createHmac('sha256', STATE.jwt.hsSecret).update(signingInput).digest();
    if (sig.length !== expected.length || !timingSafeEqual(sig, expected)) return null;
  } else if (alg === 'RS256') {
    if (!STATE.jwt.rsKey) return null;
    const v = createVerify('RSA-SHA256');
    v.update(signingInput);
    v.end();
    if (!v.verify(STATE.jwt.rsKey, sig)) return null;
  } else {
    return null; // never accept "none" or unknown alg
  }

  const now = Math.floor(Date.now() / 1000);
  if (payload.exp && Number(payload.exp) < now) return null;
  if (payload.nbf && Number(payload.nbf) > now) return null;
  if (STATE.jwt.audience) {
    const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (!aud.includes(STATE.jwt.audience)) return null;
  }
  if (STATE.jwt.issuer && payload.iss !== STATE.jwt.issuer) return null;

  const role = String(payload.role || '').toLowerCase();
  if (!VALID_ROLES.has(role)) return null;

  let scopes = scopesForRole(role);
  if (Array.isArray(payload.scopes) && payload.scopes.length) {
    // Token may further restrict scopes; never expand beyond role's set
    const roleSet = new Set(scopes);
    if (role === 'admin') {
      scopes = payload.scopes.map((s) => String(s));
    } else {
      scopes = payload.scopes.map((s) => String(s)).filter((s) => roleSet.has(s) || roleSet.has('*'));
    }
  }
  return {
    sub: payload.sub || 'jwt:unknown',
    role,
    scopes,
    via: 'jwt',
    exp: payload.exp || null,
  };
}

function clientIp(req) {
  return String(
    req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress || '_',
  );
}

function isLoopback(ip) {
  return ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1';
}

// ─────────────────────────────────────────────────────────────────────────────
// Audit log
// ─────────────────────────────────────────────────────────────────────────────
let _auditFd = { date: '', stream: null };
function auditWrite(line) {
  if (STATE.auditDisable) {
    process.stderr.write(`[audit] ${line}\n`);
    return;
  }
  const today = new Date().toISOString().slice(0, 10);
  if (_auditFd.date !== today) {
    if (_auditFd.stream) try { _auditFd.stream.end(); } catch { /* ignore */ }
    const file = path.join(STATE.auditDir, `audit-${today}.ndjson`);
    try {
      fs.mkdirSync(STATE.auditDir, { recursive: true });
      _auditFd.stream = fs.createWriteStream(file, { flags: 'a' });
      _auditFd.date = today;
    } catch (e) {
      process.stderr.write(`[audit] falha a abrir ${file}: ${e.message}\n[audit] ${line}\n`);
      return;
    }
  }
  _auditFd.stream.write(`${line}\n`);
}

export function audit(req, principal, decision, extra = {}) {
  const entry = {
    ts: new Date().toISOString(),
    decision,                                      // 'allow' | 'deny'
    method: req.method,
    route: (req.originalUrl || req.url || '').split('?')[0],
    ip: clientIp(req),
    ua: String(req.headers['user-agent'] || '').slice(0, 200),
    sub: principal?.sub || null,
    role: principal?.role || null,
    via: principal?.via || null,
    ...extra,
  };
  try {
    auditWrite(JSON.stringify(entry));
  } catch {
    // never let audit failures break a request
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Middlewares
// ─────────────────────────────────────────────────────────────────────────────
function attachPrincipal(req, principal) {
  if (!principal) return;
  principal._scopeSet = new Set(principal.scopes || []);
  if (principal.role === 'admin') principal._scopeSet.add('*');
  req.principal = principal;
}

/**
 * requireAuth({ allowlist: RegExp[] })
 *   - allowlist matches `req.path` (no querystring); matched routes skip auth.
 *   - If AUTH_DISABLE=1, attaches a synthetic loopback principal with AUTH_DEFAULT_ROLE.
 */
export function requireAuth(opts = {}) {
  if (!STATE.ready) initAuth();
  const allow = Array.isArray(opts.allowlist) ? opts.allowlist : [];

  return function authMw(req, res, next) {
    const url = (req.originalUrl || req.url || '').split('?')[0];
    if (allow.some((re) => re.test(url))) return next();

    if (STATE.disabled) {
      // Only attach synthetic principal for loopback. Remote requests stay unauthenticated.
      if (isLoopback(clientIp(req))) {
        attachPrincipal(req, {
          sub: 'auth-disabled:loopback',
          role: STATE.defaultRole,
          scopes: scopesForRole(STATE.defaultRole),
          via: 'disabled',
        });
        return next();
      }
    }

    const tok = extractToken(req);
    if (!tok) {
      audit(req, null, 'deny', { reason: 'no_token' });
      res.status(401).json({ ok: false, error: 'auth required' });
      return;
    }

    let principal = null;
    if (tok.kind === 'apikey' || (tok.kind === 'bearer' && !tok.value.includes('.'))) {
      principal = verifyApiKey(tok.value);
    } else if (tok.kind === 'bearer') {
      // Try JWT first, then API key as fallback (some setups put apikey in Bearer)
      principal = verifyJwt(tok.value) || verifyApiKey(tok.value);
    }

    if (!principal) {
      audit(req, null, 'deny', { reason: 'invalid_token' });
      res.status(401).json({ ok: false, error: 'invalid token' });
      return;
    }

    attachPrincipal(req, principal);
    next();
  };
}

/**
 * requireScope(scope, opts)
 *   opts.intrusiveCheck(req) → true → also requires 'recon.intrusive'
 *   opts.escalateScope        scope to also require if intrusiveCheck returns truthy
 *                             (default: 'recon.intrusive')
 */
export function requireScope(scope, opts = {}) {
  return function scopeMw(req, res, next) {
    const principal = req.principal;
    if (!principal) {
      audit(req, null, 'deny', { reason: 'no_principal', scope });
      res.status(401).json({ ok: false, error: 'auth required' });
      return;
    }
    if (!principalHasScope(principal, scope)) {
      audit(req, principal, 'deny', { reason: 'missing_scope', scope });
      res.status(403).json({ ok: false, error: `missing scope: ${scope}` });
      return;
    }
    if (typeof opts.intrusiveCheck === 'function') {
      let intrusive = false;
      try { intrusive = Boolean(opts.intrusiveCheck(req)); } catch { /* ignore */ }
      if (intrusive) {
        const escalate = opts.escalateScope || 'recon.intrusive';
        if (!principalHasScope(principal, escalate)) {
          audit(req, principal, 'deny', { reason: 'missing_intrusive_scope', scope: escalate });
          res.status(403).json({
            ok: false,
            error: `missing scope: ${escalate} (rota com módulos/perfil intrusivos)`,
          });
          return;
        }
      }
    }
    audit(req, principal, 'allow', { scope });
    next();
  };
}

export function requireAnyScope(scopes) {
  const list = Array.isArray(scopes) ? scopes : [scopes];
  return function anyScopeMw(req, res, next) {
    const principal = req.principal;
    if (!principal) {
      res.status(401).json({ ok: false, error: 'auth required' });
      return;
    }
    if (list.some((s) => principalHasScope(principal, s))) {
      audit(req, principal, 'allow', { scope: list.join('|') });
      next();
      return;
    }
    audit(req, principal, 'deny', { reason: 'missing_any_scope', scope: list.join('|') });
    res.status(403).json({ ok: false, error: `missing any scope: ${list.join(', ')}` });
  };
}

export function requireRole(role) {
  return function roleMw(req, res, next) {
    const principal = req.principal;
    if (!principal) {
      res.status(401).json({ ok: false, error: 'auth required' });
      return;
    }
    if (principal.role === 'admin' || principal.role === role) {
      audit(req, principal, 'allow', { roleRequired: role });
      next();
      return;
    }
    audit(req, principal, 'deny', { reason: 'role_mismatch', roleRequired: role });
    res.status(403).json({ ok: false, error: `role required: ${role}` });
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers exported for the recon route to derive intrusive flag
// ─────────────────────────────────────────────────────────────────────────────
const INTRUSIVE_MODULE_PREFIXES = [
  'kali_',
  'sqlmap',
  'sandbox_exec',
  'sandbox-exec',
  'cloud_bruteforce',
  'cloud-bruteforce',
  'browser_xss',
  'browser-xss',
  'race_',
  'cred_spray',
  'cred-spray',
  'shannon_whitebox',
];
const INTRUSIVE_MODULES_EXACT = new Set([
  'sqlmap',
  'shannon_whitebox',
  'browser_xss_verify',
  'sandbox_exec',
]);

export function reconBodyIsIntrusive(body = {}) {
  if (!body || typeof body !== 'object') return false;
  if (body.kaliMode === true) return true;
  const profile = String(body.opsecProfile || '').toLowerCase();
  if (profile === 'aggressive') return true;
  const modules = Array.isArray(body.modules) ? body.modules : [];
  for (const m of modules) {
    const n = String(m || '').toLowerCase();
    if (INTRUSIVE_MODULES_EXACT.has(n)) return true;
    if (INTRUSIVE_MODULE_PREFIXES.some((p) => n.startsWith(p))) return true;
  }
  return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// Token issuance helpers (for CLI / smoke tests / ad-hoc generation)
// ─────────────────────────────────────────────────────────────────────────────
export function generateApiKey(bytes = 32) {
  return randomBytes(bytes).toString('base64url');
}

export function signJwtHs256(payload, secret = process.env.AUTH_JWT_SECRET) {
  if (!secret) throw new Error('AUTH_JWT_SECRET ausente');
  const header = { alg: 'HS256', typ: 'JWT' };
  const enc = (obj) =>
    Buffer.from(JSON.stringify(obj), 'utf8')
      .toString('base64')
      .replace(/=+$/g, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_');
  const head = enc(header);
  const body = enc({
    iat: Math.floor(Date.now() / 1000),
    ...payload,
  });
  const sig = createHmac('sha256', secret)
    .update(`${head}.${body}`)
    .digest('base64')
    .replace(/=+$/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
  return `${head}.${body}.${sig}`;
}

// Test/inspection helper — never expose secrets
export function _authStateForTests() {
  return {
    ready: STATE.ready,
    mode: STATE.mode,
    disabled: STATE.disabled,
    defaultRole: STATE.defaultRole,
    apiKeys: STATE.apiKeys.size,
    jwt: { hs256: Boolean(STATE.jwt.hsSecret), rs256: Boolean(STATE.jwt.rsKey) },
  };
}
