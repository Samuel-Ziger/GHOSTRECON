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

  it('proxy público remove HTTP cru, segredos e caminhos locais da resposta Vigolium', async () => {
    const oldServer = process.env.GHOSTRECON_VIGOLIUM_SERVER;
    const oldApiKey = process.env.GHOSTRECON_VIGOLIUM_API_KEY;
    const secret = 'opaque-proxy-response-fixture';
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-vig-proxy-public-'));
    try {
      await withServer((_req, res) => {
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({
          ok: true,
          request: {
            method: 'POST',
            url: `https://example.test/private?token=${secret}`,
            headers: {
              Authorization: `Bearer ${secret}`,
              Cookie: `sid=${secret}`,
              'Content-Type': 'application/json',
            },
            body: `{"password":"${secret}"}`,
          },
          response: {
            status: 200,
            headers: { 'Set-Cookie': `sid=${secret}` },
            body: `{"access_token":"${secret}"}`,
          },
          curl: `curl -H 'Authorization: Bearer ${secret}' https://example.test`,
          session_dir: `/tmp/${secret}`,
        }));
      }, async (vigoliumBaseUrl) => {
        process.env.GHOSTRECON_VIGOLIUM_SERVER = vigoliumBaseUrl;
        process.env.GHOSTRECON_VIGOLIUM_API_KEY = secret;
        const app = express();
        app.use((req, _res, next) => {
          req.principal = { role: 'admin', scopes: ['*'], _scopeSet: new Set(['*']) };
          next();
        });
        registerVigoliumRoutes(app, { ROOT: root });

        await withExpressApp(app, async (baseUrl) => {
          const response = await fetch(`${baseUrl}/api/vigolium/server/http-records`);
          assert.equal(response.status, 200);
          const body = await response.json();
          const serialized = JSON.stringify(body);
          assert.equal(serialized.includes(secret), false);
          assert.equal(serialized.includes('/tmp/'), false);
          assert.match(serialized, /REDACTED/);
          assert.match(serialized, /LOCAL_PATH/);
          assert.equal(body.data.request.body, '[REDACTED_BODY]');
          assert.equal(body.data.response.body, '[REDACTED_BODY]');
          assert.equal(body.data.curl, '[REDACTED_CURL]');
        });
      });
    } finally {
      if (oldServer == null) delete process.env.GHOSTRECON_VIGOLIUM_SERVER;
      else process.env.GHOSTRECON_VIGOLIUM_SERVER = oldServer;
      if (oldApiKey == null) delete process.env.GHOSTRECON_VIGOLIUM_API_KEY;
      else process.env.GHOSTRECON_VIGOLIUM_API_KEY = oldApiKey;
      await fs.rm(root, { recursive: true, force: true });
    }
  });
});

describe('vigolium report route', () => {
  it('serve HTML report de .runtime/vigolium-reports com escopo recon.read', async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-vig-route-'));
    const reportDir = path.join(root, '.runtime', 'vigolium-reports');
    const reportSecret = 'route-report-secret-fixture';
    await fs.mkdir(reportDir, { recursive: true });
    await fs.writeFile(
      path.join(reportDir, 'sample.html'),
      `<!doctype html><title>Vigolium</title><pre>Authorization: Bearer ${reportSecret}\nCookie: sid=${reportSecret}\n${root}/private/session.json</pre><script>globalThis.leaked=true</script>`,
      'utf8',
    );

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
      assert.equal(listJson.reports[0].origin, 'runtime');
      assert.equal('path' in listJson.reports[0], false);
      assert.equal(JSON.stringify(listJson).includes(root), false);

      const ok = await fetch(`${baseUrl}/api/vigolium/reports/sample.html`);
      assert.equal(ok.status, 200);
      assert.match(ok.headers.get('content-type') || '', /text\/html/);
      assert.match(ok.headers.get('content-security-policy') || '', /sandbox/);
      assert.match(ok.headers.get('content-security-policy') || '', /default-src 'none'/);
      const body = await ok.text();
      assert.match(body, /Vigolium/);
      assert.equal(body.includes(reportSecret), false);
      assert.equal(body.includes(root), false);

      const missing = await fetch(`${baseUrl}/api/vigolium/reports/..%2Fsecret.html`);
      assert.equal(missing.status, 404);
    });

    await fs.rm(root, { recursive: true, force: true });
  });

  it('importa report HTML externo para .runtime/vigolium-reports', async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-vig-import-'));
    const external = path.join(root, 'external-report.html');
    const reportSecret = 'import-report-secret-fixture';
    await fs.writeFile(
      external,
      `<!doctype html><title>External Vigolium</title><pre>Cookie: sid=${reportSecret}\n${external}</pre>`,
      'utf8',
    );

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
      assert.equal(j.importedFrom, 'local-file');
      assert.equal(j.report.origin, 'imported-local-file');
      assert.equal('path' in j.report, false);
      assert.equal(JSON.stringify(j).includes(root), false);
      assert.equal(JSON.stringify(j).includes(external), false);

      const opened = await fetch(`${baseUrl}${j.report.url}`);
      assert.equal(opened.status, 200);
      const body = await opened.text();
      assert.match(body, /External Vigolium/);
      assert.equal(body.includes(reportSecret), false);
      assert.equal(body.includes(external), false);
      const stored = await fs.readFile(path.join(root, '.runtime', 'vigolium-reports', j.report.file), 'utf8');
      assert.equal(stored.includes(reportSecret), false);
    });

    await fs.rm(root, { recursive: true, force: true });
  });

  it('auth-config público omite segredos e caminhos; arquivo fica 0600 em diretório 0700', async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-vig-auth-route-'));
    const secret = 'opaque-route-auth-fixture';
    const app = express();
    app.use(express.json({ limit: '1mb' }));
    app.use((req, _res, next) => {
      req.principal = { role: 'admin', scopes: ['*'], _scopeSet: new Set(['*']) };
      next();
    });
    registerVigoliumRoutes(app, { ROOT: root });

    await withExpressApp(app, async (baseUrl) => {
      for (const save of [false, true]) {
        const response = await fetch(`${baseUrl}/api/vigolium/auth-config`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            save,
            name: 'route-auth',
            sessions: [{
              name: 'admin',
              cookie: `sid=${secret}`,
              bearer: secret,
              login: { username: 'operator', password: secret },
              login_request: `POST /login password=${secret}`,
            }],
          }),
        });
        assert.equal(response.status, 200);
        const body = await response.json();
        const serialized = JSON.stringify(body);
        assert.equal(body.ok, true);
        assert.equal(serialized.includes(secret), false);
        assert.equal(serialized.includes(root), false);
        assert.equal('filePath' in body, false);
        assert.equal(body.config.sessions[0].hasCookie, true);
        assert.equal(body.config.sessions[0].hasAuthorization, true);
        assert.equal(body.config.sessions[0].hasLogin, true);
      }

      const filePath = path.join(root, '.runtime', 'vigolium-sessions', 'route-auth.json');
      const saved = await fs.readFile(filePath, 'utf8');
      assert.equal(saved.includes(secret), true);
      if (process.platform !== 'win32') {
        assert.equal((await fs.stat(path.dirname(filePath))).mode & 0o777, 0o700);
        assert.equal((await fs.stat(filePath)).mode & 0o777, 0o600);
      }
    });

    await fs.rm(root, { recursive: true, force: true });
  });
});
