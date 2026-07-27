import assert from 'node:assert/strict';
import test from 'node:test';

import { registerProxyTunnelRoutes } from '../routes/proxy-tunnel.mjs';

function captureToolPathHandler(validateCsrfToken = () => true) {
  const routes = new Map();
  const app = {
    get(pathname, ...handlers) {
      routes.set(`GET ${pathname}`, handlers);
    },
    post(pathname, ...handlers) {
      routes.set(`POST ${pathname}`, handlers);
    },
  };
  registerProxyTunnelRoutes(app, {
    validateCsrfToken,
    ROOT: '/tmp/ghostrecon-tool-path-route',
    ghostProxy: {
      status: () => ({}),
      start: async () => ({}),
      stop: async () => {},
      setMitm: () => {},
      caCert: null,
    },
  });
  return routes.get('POST /api/tool-path-refresh').at(-1);
}

function responseRecorder() {
  return {
    statusCode: 200,
    payload: null,
    status(value) {
      this.statusCode = value;
      return this;
    },
    json(value) {
      this.payload = value;
      return this;
    },
  };
}

test('refresh de ferramentas não altera PATH global durante o runtime', () => {
  const handler = captureToolPathHandler();
  const originalPath = process.env.PATH;
  const res = responseRecorder();

  handler({ body: {} }, res);

  assert.equal(process.env.PATH, originalPath);
  assert.equal(res.statusCode, 409);
  assert.equal(res.payload?.error, 'PATH_REFRESH_RESTART_REQUIRED');
});

test('refresh de ferramentas continua exigindo CSRF', () => {
  const handler = captureToolPathHandler(() => false);
  const res = responseRecorder();

  handler({ body: {} }, res);

  assert.equal(res.statusCode, 403);
  assert.equal(res.payload?.error, 'CSRF');
});

