import test from 'node:test';
import assert from 'node:assert/strict';

import {
  isPublicPasteUrl,
  pasteResultReferencesTarget,
  redactPasteSearchText,
  runPastebinIntel,
} from '../modules/pastebin-intel.mjs';

test('paste intelligence aceita apenas hosts públicos conhecidos', () => {
  assert.equal(isPublicPasteUrl('https://pastebin.com/abc123'), true);
  assert.equal(isPublicPasteUrl('https://pastebin.com.evil.test/abc123'), false);
  assert.equal(isPublicPasteUrl('https://example.com/paste'), false);
});

test('paste intelligence exige referência textual ao alvo', () => {
  assert.equal(pasteResultReferencesTarget({
    link: 'https://pastebin.com/abc123',
    title: 'Example Corp',
    snippet: 'contact security@example.test',
  }, 'example.test'), true);
  assert.equal(pasteResultReferencesTarget({
    link: 'https://pastebin.com/abc123',
    title: 'Outro alvo',
    snippet: 'sem relação',
  }, 'example.test'), false);
  assert.equal(pasteResultReferencesTarget({
    link: 'https://pastebin.com/abc123',
    title: 'notexample.test',
    snippet: 'domínio diferente',
  }, 'example.test'), false);
});

test('paste intelligence redige material sensível de snippets', () => {
  const safe = redactPasteSearchText('password=hunter2 token: abcdefghijklmno Bearer abc.def.ghi-jkl');
  assert.doesNotMatch(safe, /hunter2|abcdefghijklmno|abc\.def/);
  assert.match(safe, /redacted/);
});

test('paste intelligence retorna somente candidatos reais do provider', async () => {
  const calls = [];
  const result = await runPastebinIntel({
    target: 'app.example.test',
    apiKey: 'fixture-key',
    cx: 'fixture-cx',
    searchImpl: async (query) => {
      calls.push(query);
      return [
        {
          link: 'https://pastebin.com/abc123',
          title: 'app.example.test configuration',
          snippet: 'api_key=super-secret-value',
        },
        {
          link: 'https://evil.test/not-a-paste',
          title: 'app.example.test',
          snippet: 'password=x',
        },
      ];
    },
  });
  assert.equal(calls.length, 2);
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].type, 'public_paste_reference');
  assert.equal(result.findings[0].verification.classification, 'candidate');
  assert.doesNotMatch(result.findings[0].meta, /super-secret-value/);
  assert.doesNotMatch(JSON.stringify(result.findings[0]), /super-secret-value/);
  assert.match(result.findings[0].meta, /snippet_persisted=no/);
});

test('paste intelligence sem provider não simula finding', async () => {
  const result = await runPastebinIntel({ target: 'example.test', apiKey: '', cx: '' });
  assert.deepEqual(result.findings, []);
  assert.equal(result.metrics.status, 'provider_not_configured');
});

test('paste intelligence respeita cancelamento antes do provider', async () => {
  const controller = new AbortController();
  controller.abort(new Error('operator stop'));
  let calls = 0;
  await assert.rejects(runPastebinIntel({
    target: 'example.test',
    apiKey: 'fixture-key',
    cx: 'fixture-cx',
    signal: controller.signal,
    searchImpl: async () => {
      calls += 1;
      return [];
    },
  }), /operator stop/);
  assert.equal(calls, 0);
});
