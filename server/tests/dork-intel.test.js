import test from 'node:test';
import assert from 'node:assert/strict';
import { runDorkIntel, validateDorkResult } from '../modules/dork-intel.mjs';

test('runDorkIntel não transforma query em finding e valida resultado real', async () => {
  const searches = [];
  const result = await runDorkIntel({
    target: 'example.com',
    apiKey: 'synthetic',
    cx: 'synthetic',
    dorks: [
      { mod: 'sqlerrors', query: 'site:example.com sql syntax' },
      { mod: 'sqlerrors', query: 'site:example.com mysql error' },
    ],
    searchImpl: async (query) => {
      searches.push(query);
      return [{ link: 'https://app.example.com/error', title: 'Erro' }];
    },
    fetchImpl: async () => new Response('SQL syntax error near value in MySQL', {
      status: 200,
      headers: { 'content-type': 'text/html; charset=utf-8' },
    }),
    urlAllowed: (url) => new URL(url).hostname.endsWith('example.com'),
  });
  assert.equal(searches.length, 1);
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].type, 'osint_candidate');
  assert.doesNotMatch(JSON.stringify(result.findings[0]), /site:example\.com/);
});

test('runDorkIntel sem provider retorna vazio', async () => {
  const result = await runDorkIntel({ target: 'example.com', dorks: [{ mod: 'login', query: 'x' }], apiKey: '', cx: '' });
  assert.deepEqual(result.findings, []);
  assert.equal(result.metrics.status, 'provider_not_configured');
});

test('validateDorkResult rejeita soft-404 e redirect fora do escopo', async () => {
  const soft = await validateDorkResult('https://example.com/config.yml', 'config', {
    fetchImpl: async () => new Response('<title>404 Not Found</title>', {
      status: 200,
      headers: { 'content-type': 'text/html' },
    }),
    urlAllowed: () => true,
  });
  assert.equal(soft.reason, 'soft_404');

  const redirect = await validateDorkResult('https://example.com/login', 'login', {
    fetchImpl: async () => new Response('', { status: 302, headers: { location: 'https://outside.invalid/' } }),
    urlAllowed: (url) => new URL(url).hostname === 'example.com',
  });
  assert.equal(redirect.reason, 'redirect_out_of_scope');
});

