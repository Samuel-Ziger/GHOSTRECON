import { randomBytes } from 'node:crypto';
import { clientIp } from '../lib/client-ip.mjs';

export function createCsrfProtection({ ttlMs = 2 * 60 * 60 * 1000 } = {}) {
  const csrfTokens = new Map();

  function cleanupExpiredCsrfTokens(now = Date.now()) {
    for (const [token, entry] of csrfTokens.entries()) {
      if (!entry?.expiresAt || entry.expiresAt <= now) csrfTokens.delete(token);
    }
  }

  function issueCsrfToken(req) {
    cleanupExpiredCsrfTokens();
    const token = randomBytes(24).toString('hex');
    csrfTokens.set(token, { ip: clientIp(req), expiresAt: Date.now() + ttlMs });
    return token;
  }

  function validateCsrfToken(req) {
    cleanupExpiredCsrfTokens();
    const token = String(req.headers['x-csrf-token'] || '').trim();
    if (!token) return false;
    const entry = csrfTokens.get(token);
    if (!entry) return false;
    if (entry.ip !== clientIp(req)) return false;
    if (entry.expiresAt <= Date.now()) {
      csrfTokens.delete(token);
      return false;
    }
    return true;
  }

  /** Middleware helper para rotas register*Routes. */
  function requireCsrf(req, res) {
    if (!validateCsrfToken(req)) {
      res.status(403).json({ ok: false, error: 'CSRF' });
      return false;
    }
    return true;
  }

  return {
    CSRF_TTL_MS: ttlMs,
    issueCsrfToken,
    validateCsrfToken,
    requireCsrf,
  };
}
