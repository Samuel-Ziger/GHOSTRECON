import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { registerNewApiRoutes } from '../modules/api-extensions.js';
import { getEngagement } from '../modules/engagement.mjs';

function jsonResponse() {
  return {
    statusCode: 200,
    body: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(body) {
      this.body = body;
      return this;
    },
  };
}

test('endpoint de autorização manual persiste somente escopo derivado do alvo', async () => {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-manual-auth-'));
  const previousDir = process.env.GHOSTRECON_ENGAGEMENT_DIR;
  process.env.GHOSTRECON_ENGAGEMENT_DIR = tempDir;
  try {
    const routes = new Map();
    const app = {
      get(pathname, ...handlers) { routes.set(`GET ${pathname}`, handlers); },
      post(pathname, ...handlers) { routes.set(`POST ${pathname}`, handlers); },
      delete(pathname, ...handlers) { routes.set(`DELETE ${pathname}`, handlers); },
    };
    registerNewApiRoutes(app, { requireCsrf: () => true });
    const handlers = routes.get('POST /api/engagements/manual-authorization');
    assert.ok(Array.isArray(handlers));
    assert.ok(handlers.length >= 2, 'rota deve manter middleware RBAC antes do handler');

    const res = jsonResponse();
    await handlers.at(-1)({
      body: {
        target: 'https://app.example.test/path',
        authorizationConfirmed: true,
        basis: 'owned',
        includeSubdomains: true,
        exclusions: ['blocked.app.example.test'],
        // Estes campos arbitrários não podem controlar o registro persistido.
        id: 'ATTACKER-CONTROLLED',
        scopeDomains: ['evil.example'],
        durationMs: Number.MAX_SAFE_INTEGER,
      },
    }, res);

    assert.equal(res.statusCode, 200);
    assert.equal(res.body.ok, true);
    assert.match(res.body.engagement.id, /^MANUAL-/);
    assert.deepEqual(res.body.engagement.scopeDomains, [
      'app.example.test',
      '*.app.example.test',
    ]);
    assert.equal(res.body.engagement.scopeDomains.includes('evil.example'), false);

    const stored = await getEngagement(res.body.engagement.id);
    assert.equal(stored.roeSigned, true);
    assert.deepEqual(stored.exclusions, ['blocked.app.example.test']);
    assert.equal(stored.id, res.body.engagement.id);
  } finally {
    if (previousDir == null) delete process.env.GHOSTRECON_ENGAGEMENT_DIR;
    else process.env.GHOSTRECON_ENGAGEMENT_DIR = previousDir;
    await fs.rm(tempDir, { recursive: true, force: true });
  }
});
