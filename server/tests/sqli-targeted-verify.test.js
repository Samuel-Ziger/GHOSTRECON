import test from 'node:test';
import assert from 'node:assert/strict';
import {
  runSqliTargetedVerify,
  selectSqliInsertionPoint,
} from '../modules/sqli-targeted-verify.mjs';

test('seleciona query name e body observado sem allowlist excludente', () => {
  assert.equal(selectSqliInsertionPoint({ url: 'https://lab.invalid/search?name=T-Shirt' }, 'name')?.location, 'query');
  assert.equal(selectSqliInsertionPoint({
    url: 'https://lab.invalid/search', method: 'POST', contentType: 'application/json', body: JSON.stringify({ custom_filter: 'blue' }),
  }, 'custom_filter')?.location, 'body');
  assert.equal(selectSqliInsertionPoint({ url: 'https://lab.invalid/?access_token=x' }, 'access_token'), null);
});

test('coordenador entrega body/auth/método intactos ao scanner injetado e limita budget', async () => {
  let received;
  const result = await runSqliTargetedVerify({
    allowActive: true,
    allowNonGetReplay: true,
    requestBudget: 999,
    parameter: 'name',
    requestSpec: {
      method: 'POST', origin: 'https://lab.invalid', absoluteUrl: 'https://lab.invalid/products/search',
      contentType: 'application/x-www-form-urlencoded', body: 'name=T-Shirt&category=shirts', auth: { cookie: 'sid=memory-only' },
    },
    urlAllowed: () => true,
    bodyScanner: async (ctx) => {
      received = ctx;
      return { status: 'done', findings: [{ type: 'sqli', score: 64 }], metrics: { requestsAttempted: 12 } };
    },
  });
  assert.equal(received.requestSpec.method, 'POST');
  assert.equal(received.requestSpec.body, 'name=T-Shirt&category=shirts');
  assert.equal(received.requestSpec.auth.cookie, 'sid=memory-only');
  assert.equal(received.budget, 48);
  assert.equal(result.findings.length, 1);
  assert.equal(result.metrics.requestsAttempted, 12);
});

test('gates ativo/escopo/controle ausente impedem scanner', async () => {
  let calls = 0;
  const common = {
    requestSpec: { origin: 'https://lab.invalid', url: 'https://lab.invalid/?name=x' }, parameter: 'name',
    queryScanner: async () => { calls += 1; return { findings: [] }; },
  };
  assert.equal((await runSqliTargetedVerify(common)).reason, 'active_not_authorized');
  assert.equal((await runSqliTargetedVerify({ ...common, allowActive: true, urlAllowed: () => false })).reason, 'out_of_exact_origin_scope');
  assert.equal(calls, 0);
});

test('budget abaixo do mínimo não é ampliado silenciosamente', async () => {
  let calls = 0;
  const result = await runSqliTargetedVerify({
    allowActive: true,
    requestBudget: 2,
    requestSpec: { origin: 'https://lab.invalid', url: 'https://lab.invalid/?name=x' },
    parameter: 'name',
    urlAllowed: () => true,
    queryScanner: async () => { calls += 1; return { findings: [] }; },
  });
  assert.equal(result.status, 'skipped');
  assert.equal(result.reason, 'request_budget_below_safe_minimum');
  assert.equal(calls, 0);
});

test('scanner query padrão muta somente o parâmetro explicitamente escolhido', async () => {
  const seen = [];
  const result = await runSqliTargetedVerify({
    allowActive: true,
    requestBudget: 7,
    requestSpec: {
      origin: 'https://lab.invalid',
      url: 'https://lab.invalid/search?id=123&custom_filter=blue',
    },
    parameter: 'custom_filter',
    urlAllowed: () => true,
    fetchImpl: async (url) => {
      seen.push(new URL(url));
      return new Response('stable', { status: 200 });
    },
  });
  assert.equal(result.metrics.requestsAttempted, 7);
  assert.ok(seen.every((url) => url.searchParams.get('id') === '123'));
  assert.ok(seen.some((url) => url.searchParams.get('custom_filter') !== 'blue'));
});

test('scanner body padrão preserva método e demais campos', async () => {
  const seen = [];
  const result = await runSqliTargetedVerify({
    allowActive: true,
    allowNonGetReplay: true,
    requestBudget: 7,
    requestSpec: {
      method: 'POST',
      origin: 'https://lab.invalid',
      url: 'https://lab.invalid/search',
      contentType: 'application/json',
      body: JSON.stringify({ id: 123, custom_filter: 'blue' }),
    },
    parameter: 'custom_filter',
    urlAllowed: () => true,
    fetchImpl: async (_url, init) => {
      seen.push({ method: init.method, body: JSON.parse(init.body) });
      return new Response('stable', { status: 200 });
    },
  });
  assert.equal(result.metrics.requestsAttempted, 7);
  assert.ok(seen.every((request) => request.method === 'POST' && request.body.id === 123));
  assert.ok(seen.some((request) => request.body.custom_filter !== 'blue'));
});

test('DELETE é recusado e POST exige capability mutável explícita', async () => {
  let calls = 0;
  const common = {
    allowActive: true,
    requestBudget: 7,
    parameter: 'name',
    urlAllowed: () => true,
    fetchImpl: async () => { calls += 1; return new Response('ok'); },
  };
  const deletion = await runSqliTargetedVerify({
    ...common,
    requestSpec: { method: 'DELETE', origin: 'https://lab.invalid', url: 'https://lab.invalid/?name=x' },
  });
  const post = await runSqliTargetedVerify({
    ...common,
    requestSpec: { method: 'POST', origin: 'https://lab.invalid', url: 'https://lab.invalid/?name=x' },
  });
  assert.equal(deletion.reason, 'unsafe_request_method_rejected');
  assert.equal(post.reason, 'post_replay_requires_mutating_capability');
  assert.equal(calls, 0);
});
