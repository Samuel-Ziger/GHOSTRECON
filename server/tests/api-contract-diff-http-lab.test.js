import http from 'node:http';
import test from 'node:test';
import assert from 'node:assert/strict';

import {
  fetchOpenApiContracts,
  runApiContractDiff,
} from '../modules/api-contract-diff.mjs';

async function listenLoopback(server) {
  return new Promise((resolve, reject) => {
    const onError = (error) => reject(error);
    server.once('error', onError);
    server.listen(0, '127.0.0.1', () => {
      server.removeListener('error', onError);
      resolve(server.address());
    });
  });
}

async function closeServer(server) {
  server.closeAllConnections?.();
  if (!server.listening) return;
  await new Promise((resolve) => server.close(resolve));
}

async function startLab(t, handler) {
  const server = http.createServer(handler);
  let address;
  try {
    address = await listenLoopback(server);
  } catch (error) {
    await closeServer(server);
    if (['EPERM', 'EACCES'].includes(error?.code)) {
      t.skip(`sandbox não permite bind loopback: ${error.code}`);
      return null;
    }
    throw error;
  }
  t.after(() => closeServer(server));
  return {
    server,
    origin: `http://127.0.0.1:${address.port}`,
    port: address.port,
  };
}

test('lab HTTP real segue redirect interno e processa JSON fragmentado', async (t) => {
  const requests = [];
  const lab = await startLab(t, (req, res) => {
    requests.push(req.url);
    if (req.url === '/openapi.json') {
      res.writeHead(302, { location: '/contracts/current.json' });
      res.end();
      return;
    }
    if (req.url === '/contracts/current.json') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.write('{"openapi":"3.1.0","paths":{');
      res.end('"/health":{"get":{"responses":{"200":{"description":"ok"}}}}}}');
      return;
    }
    res.writeHead(404).end();
  });
  if (!lab) return;

  const result = await fetchOpenApiContracts({
    origins: [lab.origin],
    domain: '127.0.0.1',
    detailed: true,
    fetchImpl: globalThis.fetch,
  });
  assert.equal(result.status, 'done');
  assert.equal(result.summaries.length, 1);
  assert.equal(result.summaries[0].url, `${lab.origin}/openapi.json`);
  assert.equal(result.summaries[0].resolvedUrl, `${lab.origin}/contracts/current.json`);
  assert.deepEqual(requests, [
    '/openapi.json',
    '/openapi.yaml',
    '/contracts/current.json',
    '/openapi.yml',
    '/swagger.json',
    '/swagger.yaml',
    '/swagger.yml',
    '/v2/api-docs',
    '/v3/api-docs',
    '/api-docs/swagger.json',
    '/swagger/v1/swagger.json',
  ]);
});

test('lab HTTP real bloqueia redirect para hostname fora do escopo antes do request', async (t) => {
  let captured = 0;
  const lab = await startLab(t, (req, res) => {
    if (req.url === '/openapi.json') {
      res.writeHead(302, { location: `http://localhost:${lab.port}/capture` });
      res.end();
      return;
    }
    if (req.url === '/capture') captured += 1;
    res.writeHead(404).end();
  });
  if (!lab) return;

  const result = await fetchOpenApiContracts({
    origins: [lab.origin],
    domain: '127.0.0.1',
    detailed: true,
    fetchImpl: globalThis.fetch,
  });
  assert.equal(result.status, 'partial');
  assert.equal(result.outcomes[0].state, 'scope_denied');
  assert.equal(result.outcomes[0].reason, 'redirect_out_of_scope');
  assert.equal(captured, 0);
});

test('lab HTTP real cancela body e conexão quando o deadline vence', async (t) => {
  let resolveClosed;
  let resolveStarted;
  const responseClosed = new Promise((resolve) => { resolveClosed = resolve; });
  const responseStarted = new Promise((resolve) => { resolveStarted = resolve; });
  const lab = await startLab(t, (req, res) => {
    if (req.url !== '/openapi.json') {
      res.writeHead(404).end();
      return;
    }
    res.on('close', resolveClosed);
    res.writeHead(200, { 'content-type': 'application/json' });
    res.write('{');
    resolveStarted();
  });
  if (!lab) return;

  const pending = runApiContractDiff({
    origins: [lab.origin],
    domain: '127.0.0.1',
    timeoutMs: 1_000,
    fetchImpl: globalThis.fetch,
  });
  await Promise.race([
    responseStarted,
    new Promise((_, reject) => setTimeout(() => reject(new Error('lab_request_not_started')), 2_000)),
  ]);
  const result = await pending;
  assert.equal(result.status, 'timeout');
  assert.equal(result.reason, 'module_deadline_exhausted');
  assert.equal(result.metrics.coverage.deadlineReached, true);
  const closed = await Promise.race([
    responseClosed.then(() => true),
    new Promise((resolve) => setTimeout(() => resolve(false), 1_000)),
  ]);
  assert.equal(closed, true);
});
