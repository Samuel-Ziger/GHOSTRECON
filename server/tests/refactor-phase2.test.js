import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import { createCsrfProtection } from '../middleware/csrf.mjs';
import { createHttpHistoryStore } from '../lib/http-history.mjs';
import { registerAllRoutes } from '../app/register-routes.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const indexSrc = fs.readFileSync(path.join(__dirname, '../index.js'), 'utf8');

describe('refactor phase 2 — rotas HTTP extraídas', () => {
  it('index.js não define rotas app.get/post inline', () => {
    const inlineRoutes = indexSrc.match(/^app\.(get|post|put|delete|patch)\(/gm) || [];
    assert.equal(inlineRoutes.length, 0, `rotas inline restantes: ${inlineRoutes.join(', ')}`);
  });

  it('registerAllRoutes monta sem erro com deps mínimos', () => {
    const app = express();
    const httpHistory = createHttpHistoryStore();
    const { CSRF_TTL_MS, issueCsrfToken, validateCsrfToken, requireCsrf } = createCsrfProtection();
    const ghostProxy = {
      status: () => ({ running: false }),
      start: async () => ({}),
      stop: async () => ({}),
      setMitm: () => {},
      caCertPath: '/tmp/ca.crt',
    };

    registerAllRoutes(app, {
      runPipeline: async () => {},
      ROOT: path.join(__dirname, '../..'),
      ghostProxy,
      httpHistory,
      issueCsrfToken,
      validateCsrfToken,
      requireCsrf,
      CSRF_TTL_MS,
      allowReconRequest: () => true,
      reconHttpHistory: httpHistory.entries,
    });

    const stack = app._router?.stack || [];
    assert.ok(stack.length > 10, 'esperava dezenas de handlers após registerAllRoutes');
  });
});
