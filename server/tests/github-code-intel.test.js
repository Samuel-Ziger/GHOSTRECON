import test from 'node:test';
import assert from 'node:assert/strict';
import { githubCodeSearch, validateGithubCodeHit } from '../modules/github.js';

test('githubCodeSearch aceita fetch injetável e retorna URL de conteúdo', async () => {
  const result = await githubCodeSearch('example.com', '', {
    fetchImpl: async () => new Response(JSON.stringify({
      total_count: 1,
      items: [{
        path: '.env',
        sha: 'abc',
        url: 'https://api.github.com/repos/acme/site/contents/.env',
        html_url: 'https://github.com/acme/site/blob/main/.env',
        repository: { full_name: 'acme/site' },
      }],
    }), { status: 200, headers: { 'content-type': 'application/json' } }),
  });
  assert.equal(result.ok, true);
  assert.match(result.items[0].api_url, /^https:\/\/api\.github\.com\//);
});

test('validateGithubCodeHit só classifica após conteúdo confirmar alvo e padrão', async () => {
  const raw = 'ghp_abcdefghijklmnopqrstuvwxyz1234567890';
  const content = `TARGET=example.com\nGITHUB_TOKEN=${raw}\n`;
  const result = await validateGithubCodeHit({
    repo: 'acme/site',
    path: 'config/.env',
    api_url: 'https://api.github.com/repos/acme/site/contents/config/.env',
    html_url: 'https://github.com/acme/site/blob/main/config/.env',
  }, {
    target: 'example.com',
    fetchImpl: async () => new Response(JSON.stringify({
      encoding: 'base64',
      content: Buffer.from(content).toString('base64'),
    }), { status: 200, headers: { 'content-type': 'application/json' } }),
  });
  assert.equal(result.status, 'classified');
  assert.equal(result.findings.length, 1);
  assert.doesNotMatch(JSON.stringify(result.findings), new RegExp(raw));
  assert.match(result.findings[0].value, /…/);
});

test('validateGithubCodeHit recusa conteúdo sem relação com alvo', async () => {
  const result = await validateGithubCodeHit({
    api_url: 'https://api.github.com/repos/acme/site/contents/.env',
  }, {
    target: 'example.com',
    fetchImpl: async () => new Response(JSON.stringify({
      encoding: 'base64',
      content: Buffer.from('GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz1234567890').toString('base64'),
    }), { status: 200 }),
  });
  assert.equal(result.status, 'target_relation_not_confirmed');
  assert.deepEqual(result.findings, []);
});

