import test from 'node:test';
import assert from 'node:assert/strict';
import { fetchScoped } from '../modules/scoped-fetch.mjs';

test('fetchScoped bloqueia redirect fora do escopo', async () => {
  const calls = [];
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
});

test('fetchScoped segue redirect dentro do escopo', async () => {
  const calls = [];
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
});
