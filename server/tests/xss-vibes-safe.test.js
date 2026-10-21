import test from 'node:test';
import assert from 'node:assert/strict';

import {
  classifyXssReflection,
  runSafeXssVibesAudit,
} from '../modules/xss-vibes-safe.mjs';

const marker = Object.freeze({ core: 'GRXSS_FIXTURE', value: 'GRXSS_FIXTURE_<>"\'&_GRXSS_FIXTURE' });

test('XSS safe distingue reflexão raw, encoded e ausente', () => {
  assert.deepEqual(classifyXssReflection('<p>none</p>', marker), {
    reflected: false,
    raw: false,
    context: 'none',
  });
  assert.equal(classifyXssReflection(`<div>${marker.value}</div>`, marker).raw, true);
  const encoded = classifyXssReflection(`<div>GRXSS_FIXTURE_&lt;&gt;&quot;&#39;&amp;_GRXSS_FIXTURE</div>`, marker);
  assert.equal(encoded.reflected, true);
  assert.equal(encoded.raw, false);
});

test('XSS safe exige reflexão repetível e nunca chama de confirmado', async () => {
  const requests = [];
  const result = await runSafeXssVibesAudit({
    urls: ['https://target.test/search?q=hello'],
    markerFactory: () => marker,
    urlAllowed: (url) => new URL(url).hostname === 'target.test',
    fetchImpl: async (url, init) => {
      requests.push({ url, init });
      return new Response(`<html><body>${new URL(url).searchParams.get('q')}</body></html>`, { status: 200, headers: { 'content-type': 'text/html' } });
    },
  });
  assert.equal(requests.length, 2);
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].type, 'xss_reflection_candidate');
  assert.equal(result.findings[0].verification.classification, 'candidate');
  assert.equal(result.findings[0].prio, 'med');
  assert.ok(requests.every(({ init }) => init.redirect === 'manual'));
});

test('XSS safe rebaixa reflexão encoded para inventário', async () => {
  const encoded = marker.value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
  const result = await runSafeXssVibesAudit({
    urls: ['https://target.test/search?q=hello'],
    markerFactory: () => marker,
    urlAllowed: () => true,
    fetchImpl: async () => new Response(`<html>${encoded}</html>`, { status: 200 }),
  });
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].type, 'input_reflection_encoded');
  assert.equal(result.findings[0].verification.classification, 'inventory');
  assert.equal(result.findings[0].prio, 'info');
});

test('XSS safe bloqueia fora de escopo e cancelamento', async () => {
  let requests = 0;
  const blocked = await runSafeXssVibesAudit({
    urls: ['https://outside.test/search?q=x'],
    urlAllowed: () => false,
    fetchImpl: async () => {
      requests += 1;
      return new Response('no');
    },
  });
  assert.equal(requests, 0);
  assert.equal(blocked.metrics.blockedByScope, 1);

  const controller = new AbortController();
  controller.abort(new Error('operator stop'));
  await assert.rejects(
    runSafeXssVibesAudit({
      urls: ['https://target.test/search?q=x'],
      signal: controller.signal,
      markerFactory: () => marker,
      fetchImpl: async () => new Response('no'),
    }),
    /operator stop/,
  );
});

test('XSS safe isola erro de rede e não cria finding', async () => {
  const result = await runSafeXssVibesAudit({
    urls: ['https://target.test/search?q=x'],
    urlAllowed: () => true,
    markerFactory: () => marker,
    fetchImpl: async () => { throw new Error('fixture network failure'); },
  });
  assert.deepEqual(result.findings, []);
  assert.equal(result.metrics.requestErrors, 1);
});
