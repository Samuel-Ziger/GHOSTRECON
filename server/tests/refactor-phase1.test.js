import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createCsrfProtection } from '../middleware/csrf.mjs';
import { createNextProxyMiddleware } from '../lib/create-next-proxy.mjs';
import { sevToPrio, sevToScore } from '../lib/severity.mjs';
import { isSha256FingerprintHex } from '../modules/db-common.js';

describe('refactor phase 1 — shared infra', () => {
  it('CSRF issue + validate', () => {
    const { issueCsrfToken, validateCsrfToken } = createCsrfProtection({ ttlMs: 60_000 });
    const req = {
      socket: { remoteAddress: '127.0.0.1' },
      headers: {},
    };
    const token = issueCsrfToken(req);
    req.headers['x-csrf-token'] = token;
    assert.equal(validateCsrfToken(req), true);
    req.headers['x-csrf-token'] = 'invalid';
    assert.equal(validateCsrfToken(req), false);
  });

  it('createNextProxyMiddleware ignora paths fora do prefixo', () => {
    const mw = createNextProxyMiddleware({
      prefix: '/ghostmap',
      defaultPort: 3020,
      offlineTitle: 'x',
      offlineBodyHtml: 'y',
      enabled: true,
    })();
    let nextCalled = false;
    const req = { path: '/api/health', url: '/api/health', method: 'GET', headers: {} };
    const res = {};
    mw(req, res, () => {
      nextCalled = true;
    });
    assert.equal(nextCalled, true);
  });

  it('severity helpers', () => {
    assert.equal(sevToPrio('critical'), 'high');
    assert.equal(sevToScore('low'), 42);
  });

  it('isSha256FingerprintHex centralizado em db-common', () => {
    assert.equal(isSha256FingerprintHex('a'.repeat(64)), true);
    assert.equal(isSha256FingerprintHex('short'), false);
  });
});
