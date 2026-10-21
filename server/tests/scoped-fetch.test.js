import test from 'node:test';
import assert from 'node:assert/strict';
import { fetchScoped } from '../modules/scoped-fetch.mjs';

test('fetchScoped bloqueia redirect fora do escopo', async () => {
  const calls = [];
  let redirectsClosed = 0;
  const fetchImpl = async (url) => {
    calls.push(url);
    if (String(url).includes('in-scope.test')) {
      return {
        status: 302,
        ok: false,
        url,
        headers: {
          get(name) {
            return String(name).toLowerCase() === 'location'
              ? 'https://evil.test/leak'
              : null;
          },
        },
        body: { cancel: async () => { redirectsClosed += 1; } },
      };
    }
    return { status: 200, ok: true, url, headers: { get: () => null }, text: async () => 'ok' };
  };

  await assert.rejects(
    () => fetchScoped('https://in-scope.test/path', {
      fetchImpl,
      urlAllowed: (u) => String(u).includes('in-scope.test'),
    }),
    (error) => error?.code === 'OUT_OF_SCOPE',
  );
  assert.equal(calls.length, 1);
  assert.equal(calls[0], 'https://in-scope.test/path');
  assert.equal(redirectsClosed, 1);
});

test('fetchScoped segue redirect dentro do escopo', async () => {
  const calls = [];
  let redirectsClosed = 0;
  const fetchImpl = async (url) => {
    calls.push(url);
    if (url.endsWith('/old')) {
      return {
        status: 301,
        ok: false,
        url,
        headers: {
          get(name) {
            return String(name).toLowerCase() === 'location' ? '/new' : null;
          },
        },
        body: { cancel: async () => { redirectsClosed += 1; } },
      };
    }
    return {
      status: 200,
      ok: true,
      url,
      headers: { get: () => null },
      text: async () => 'body',
    };
  };

  const res = await fetchScoped('https://in-scope.test/old', {
    fetchImpl,
    urlAllowed: (u) => String(u).startsWith('https://in-scope.test/'),
  });
  assert.equal(res.status, 200);
  assert.deepEqual(calls, ['https://in-scope.test/old', 'https://in-scope.test/new']);
  assert.equal(redirectsClosed, 1);
});

test('fetchScoped expõe URL final opcional sem alterar o retorno legado', async () => {
  const fetchImpl = async (url) => {
    if (url.endsWith('/old')) {
      return {
        status: 302,
        ok: false,
        url: '',
        headers: { get: () => '/new' },
        body: { cancel: async () => {} },
      };
    }
    return {
      status: 200,
      ok: true,
      url: '',
      headers: { get: () => null },
      body: { cancel: async () => {} },
    };
  };
  const result = await fetchScoped('https://in-scope.test/old', {
    fetchImpl,
    urlAllowed: (url) => new URL(url).hostname === 'in-scope.test',
    returnMeta: true,
  });
  assert.equal(result.response.status, 200);
  assert.equal(result.url, 'https://in-scope.test/new');
  assert.equal(result.redirects, 1);
});

test('redirect progride mesmo quando body.cancel nunca assenta', async () => {
  const calls = [];
  const result = await Promise.race([
    fetchScoped('https://in-scope.test/old', {
      fetchImpl: async (url) => {
        calls.push(url);
        if (url.endsWith('/old')) {
          return {
            status: 302,
            ok: false,
            url,
            headers: { get: () => '/new' },
            body: { cancel: () => new Promise(() => {}) },
          };
        }
        return { status: 200, ok: true, url, headers: { get: () => null } };
      },
      urlAllowed: (url) => new URL(url).hostname === 'in-scope.test',
      returnMeta: true,
    }),
    new Promise((_, reject) => setTimeout(() => reject(new Error('redirect_cleanup_timeout')), 100)),
  ]);
  assert.equal(result.url, 'https://in-scope.test/new');
  assert.equal(calls.length, 2);
});

test('abort de fetch assenta sem esperar cancelamento tardio do body', async () => {
  const controller = new AbortController();
  let resolveFetch;
  const pending = fetchScoped('https://in-scope.test/spec', {
    fetchImpl: () => new Promise((resolve) => { resolveFetch = resolve; }),
    signal: controller.signal,
    urlAllowed: () => true,
  });
  queueMicrotask(() => controller.abort(new Error('operator_cancelled')));
  await Promise.race([
    assert.rejects(pending, /operator_cancelled/),
    new Promise((_, reject) => setTimeout(() => reject(new Error('fetch_abort_timeout')), 100)),
  ]);
  resolveFetch({
    status: 200,
    ok: true,
    url: 'https://in-scope.test/spec',
    headers: { get: () => null },
    body: { cancel: () => new Promise(() => {}) },
  });
  await new Promise((resolve) => setImmediate(resolve));
});
