import test from 'node:test';
import assert from 'node:assert/strict';

import { runSqliDeepVerification } from '../modules/sqli-deep-verify.mjs';

function endpoint(url) {
  return { type: 'endpoint', value: url };
}

function response(body, status = 200) {
  return new Response(body, { status, headers: { 'content-type': 'text/html' } });
}

test('SQLi deep trata transição de erro repetida como provável, sem superestimar', async () => {
  const requests = [];
  const result = await runSqliDeepVerification({
    findings: [endpoint('https://target.test/item?id=1')],
    urlAllowed: (url) => new URL(url).hostname === 'target.test',
    fetchImpl: async (url) => {
      requests.push(url);
      const value = new URL(url).searchParams.get('id');
      if (value.endsWith("'")) return response('You have an error in your SQL syntax near quote');
      return response('stable product page');
    },
  });
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].verification.classification, 'probable');
  assert.equal(result.findings[0].prio, 'med');
  assert.equal(result.findings[0].verification.evidence.evidenceKind, 'repeated_database_error_transition');
  assert.ok(requests.every((url) => !/UNION|SLEEP|BENCHMARK|OR.+1.+1/i.test(decodeURIComponent(url))));
});

test('SQLi deep aceita diferencial booleano estável apenas como provável', async () => {
  const result = await runSqliDeepVerification({
    findings: [endpoint('https://target.test/item?id=1')],
    urlAllowed: () => true,
    fetchImpl: async (url) => {
      const value = new URL(url).searchParams.get('id');
      if (/AND 1=2/.test(value)) return response('empty result');
      return response('stable product page');
    },
  });
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].verification.classification, 'probable');
  assert.equal(result.findings[0].prio, 'med');
});

test('SQLi deep ignora baseline instável e login', async () => {
  let sequence = 0;
  const result = await runSqliDeepVerification({
    findings: [
      endpoint('https://target.test/item?id=1'),
      endpoint('https://target.test/login?username=user'),
    ],
    urlAllowed: () => true,
    fetchImpl: async () => response(`dynamic-${sequence++}`),
  });
  assert.deepEqual(result.findings, []);
  assert.equal(result.metrics.endpoints, 1);
  assert.equal(result.metrics.unstableBaselines, 1);
});

test('SQLi deep bloqueia fora de escopo sem rede', async () => {
  let requests = 0;
  const result = await runSqliDeepVerification({
    findings: [endpoint('https://outside.test/item?id=1')],
    urlAllowed: () => false,
    fetchImpl: async () => {
      requests += 1;
      return response('should not happen');
    },
  });
  assert.equal(requests, 0);
  assert.equal(result.metrics.blockedByScope, 1);
});

test('SQLi deep propaga cancelamento antes da rede', async () => {
  const controller = new AbortController();
  controller.abort(new Error('operator cancelled'));
  await assert.rejects(
    runSqliDeepVerification({
      findings: [endpoint('https://target.test/item?id=1')],
      signal: controller.signal,
      fetchImpl: async () => response('no'),
    }),
    /operator cancelled/,
  );
});

test('SQLi deep isola erro de rede e não cria finding', async () => {
  const result = await runSqliDeepVerification({
    findings: [endpoint('https://target.test/item?id=1')],
    urlAllowed: () => true,
    fetchImpl: async () => { throw new Error('fixture network failure'); },
  });
  assert.deepEqual(result.findings, []);
  assert.equal(result.metrics.requestErrors, 1);
});
