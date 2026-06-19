import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import express from 'express';
import { registerVigoliumRoutes } from '../routes/vigolium.mjs';
import {
  getVigoliumServerStatus,
  resolveVigoliumServerConfig,
  serverEndpointFor,
  vigoliumServerFetch,
} from '../../bridge/vigolium-server-client.mjs';

async function withServer(handler, fn) {
  const server = http.createServer(handler);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  try {
    return await fn(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

async function withExpressApp(app, fn) {
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  try {
    return await fn(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

describe('vigolium server client', () => {
  it('detecta server nao configurado', () => {
    const cfg = resolveVigoliumServerConfig({});
    assert.equal(cfg.configured, false);
    assert.equal(serverEndpointFor('findings'), '/api/findings');
    assert.equal(serverEndpointFor('agent-sessions'), '/api/agent/sessions');
    assert.equal(serverEndpointFor('agent-status'), '/api/agent/status');
    assert.equal(serverEndpointFor('unknown'), null);
  });

  it('faz status e proxy com bearer auth', async () => {
    const seen = [];
    await withServer((req, res) => {
      seen.push({ url: req.url, auth: req.headers.authorization || '' });
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ ok: true, url: req.url }));
    }, async (baseUrl) => {
      const env = {
        GHOSTRECON_VIGOLIUM_SERVER: baseUrl,
        GHOSTRECON_VIGOLIUM_API_KEY: 'secret-token',
      };
      const status = await getVigoliumServerStatus({ env, timeoutMs: 2000 });
      assert.equal(status.ok, true);
      assert.equal(status.baseUrl, baseUrl);

      const out = await vigoliumServerFetch('/api/findings', {
        env,
        query: { severity: 'high', tag: ['xss', 'sqli'] },
      });
      assert.equal(out.ok, true);
      assert.match(out.url, /severity=high/);
      assert.match(out.url, /tag=xss/);
      assert.match(out.url, /tag=sqli/);
    });

    assert.equal(seen[0].url, '/api/modules?limit=1');
    assert.equal(seen[0].auth, 'Bearer secret-token');
    assert.equal(seen[1].auth, 'Bearer secret-token');
  });
});

describe('vigolium report route', () => {
  it('serve HTML report de .runtime/vigolium-reports com escopo recon.read', async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-vig-route-'));
    const reportDir = path.join(root, '.runtime', 'vigolium-reports');
    await fs.mkdir(reportDir, { recursive: true });
    await fs.writeFile(path.join(reportDir, 'sample.html'), '<!doctype html><title>Vigolium</title>', 'utf8');

    const app = express();
    app.use((req, _res, next) => {
      req.principal = { role: 'admin', scopes: ['*'], _scopeSet: new Set(['*']) };
      next();
    });
    registerVigoliumRoutes(app, { ROOT: root });

    await withExpressApp(app, async (baseUrl) => {
      const list = await fetch(`${baseUrl}/api/vigolium/reports`);
      assert.equal(list.status, 200);
      const listJson = await list.json();
      assert.equal(listJson.total, 1);
      assert.equal(listJson.reports[0].file, 'sample.html');
      assert.equal(listJson.reports[0].url, '/api/vigolium/reports/sample.html');

      const ok = await fetch(`${baseUrl}/api/vigolium/reports/sample.html`);
      assert.equal(ok.status, 200);
      assert.match(ok.headers.get('content-type') || '', /text\/html/);
      assert.match(await ok.text(), /Vigolium/);

      const missing = await fetch(`${baseUrl}/api/vigolium/reports/..%2Fsecret.html`);
      assert.equal(missing.status, 404);
    });

    await fs.rm(root, { recursive: true, force: true });
  });

  it('importa report HTML externo para .runtime/vigolium-reports', async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-vig-import-'));
    const external = path.join(root, 'external-report.html');
    await fs.writeFile(external, '<!doctype html><title>External Vigolium</title>', 'utf8');

    const app = express();
    app.use(express.json({ limit: '1mb' }));
    app.use((req, _res, next) => {
      req.principal = { role: 'admin', scopes: ['*'], _scopeSet: new Set(['*']) };
      next();
    });
    registerVigoliumRoutes(app, { ROOT: root });

    await withExpressApp(app, async (baseUrl) => {
      const imported = await fetch(`${baseUrl}/api/vigolium/reports/import`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sourcePath: external, name: 'from-vigo.html' }),
      });
      assert.equal(imported.status, 200);
      const j = await imported.json();
      assert.equal(j.ok, true);
      assert.match(j.report.file, /import-from-vigo\.html$/);

      const opened = await fetch(`${baseUrl}${j.report.url}`);
      assert.equal(opened.status, 200);
      assert.match(await opened.text(), /External Vigolium/);
    });

    await fs.rm(root, { recursive: true, force: true });
  });
});
