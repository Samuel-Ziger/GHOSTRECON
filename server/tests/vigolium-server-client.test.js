import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
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

describe('vigolium server client', () => {
  it('detecta server nao configurado', () => {
    const cfg = resolveVigoliumServerConfig({});
    assert.equal(cfg.configured, false);
    assert.equal(serverEndpointFor('findings'), '/api/findings');
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
