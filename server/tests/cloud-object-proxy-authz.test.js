import test from 'node:test';
import assert from 'node:assert/strict';

import {
  analyzeCloudObjectProxyAuthz,
  runCloudObjectProxyAuthz,
} from '../modules/cloud-object-proxy-authz.mjs';

test('confirma objeto do owner para outra persona e trata NoSuchKey de URL como controle SSRF negativo', () => {
  const result = analyzeCloudObjectProxyAuthz({
    owner: { status: 200, body: 'fixture-owner-object' },
    crossPersona: { status: 200, body: 'fixture-owner-object' },
    missingControl: { status: 404, text: '<Code>NoSuchKey</Code>' },
    urlShapedControl: { status: 404, text: '<Code>NoSuchKey</Code>' },
  });
  assert.equal(result.state, 'confirmed');
  assert.equal(result.ssrfControl, 'negative');
  assert.equal(result.findings[0].type, 'cloud_object_proxy_bola');
  assert.doesNotMatch(JSON.stringify(result), /fixture-owner-object/);
});

test('nega confirmação quando acesso cruzado é bloqueado, objeto difere ou controle missing falha', () => {
  const base = {
    owner: { status: 200, body: 'owner-object' },
    missingControl: { status: 404, text: 'NoSuchKey' },
    urlShapedControl: { status: 404, text: 'NoSuchKey' },
  };
  assert.equal(analyzeCloudObjectProxyAuthz({ ...base, crossPersona: { status: 403 } }).findings.length, 0);
  assert.equal(analyzeCloudObjectProxyAuthz({ ...base, crossPersona: { status: 200, body: 'other-object' } }).findings.length, 0);
  assert.equal(analyzeCloudObjectProxyAuthz({
    ...base,
    crossPersona: { status: 200, body: 'owner-object' },
    missingControl: { status: 200, body: 'generic fallback' },
  }).findings.length, 0);
});

test('200 vazio ou resposta genérica não provam identidade do objeto', () => {
  const controls = {
    missingControl: { status: 404, text: 'NoSuchKey' },
    urlShapedControl: { status: 404, text: 'NoSuchKey' },
  };
  for (const value of [undefined, '', 'ok', '{"ok":true}']) {
    const observation = value === undefined ? { status: 200 } : { status: 200, text: value };
    const result = analyzeCloudObjectProxyAuthz({
      owner: observation,
      crossPersona: observation,
      ...controls,
    });
    assert.equal(result.findings.length, 0, String(value));
    assert.equal(result.reason, 'owner_baseline_not_available');
  }
});

test('runner exige gate, scope guard, personas distintas e origem exata sem fazer rede ao recusar', async () => {
  let calls = 0;
  const transport = async () => { calls += 1; return { status: 200, body: 'x' }; };
  const baseCase = {
    endpointOrigin: 'https://lab.invalid',
    ownerUrl: 'https://lab.invalid/object?key=owner%2Fcard.json',
    crossUrl: 'https://lab.invalid/object?key=owner%2Fcard.json',
    missingControlUrl: 'https://lab.invalid/object?key=missing.json',
    urlShapedControlUrl: 'https://lab.invalid/object?key=http%3A%2F%2F127.0.0.1%2Fmetadata',
    ownerAuthRef: 'auth:owner',
    crossAuthRef: 'auth:other',
  };
  assert.equal((await runCloudObjectProxyAuthz({ cases: [baseCase], transport })).reason, 'active_not_authorized');
  assert.equal((await runCloudObjectProxyAuthz({ cases: [baseCase], transport, allowActive: true })).reason, 'scope_guard_required');
  const samePersona = await runCloudObjectProxyAuthz({
    cases: [{ ...baseCase, crossAuthRef: 'auth:owner' }], transport, allowActive: true, urlAllowed: () => true,
  });
  assert.equal(samePersona.outcomes[0].reason, 'distinct_personas_required');
  const outside = await runCloudObjectProxyAuthz({
    cases: [{ ...baseCase, crossUrl: 'https://other.invalid/object?key=x' }],
    transport,
    allowActive: true,
    urlAllowed: () => true,
  });
  assert.equal(outside.outcomes[0].reason, 'missing_or_out_of_exact_origin_scope');
  assert.equal(calls, 0);
});

test('runner usa quatro GETs dentro do budget e não persiste object key na URL do finding', async () => {
  const seen = [];
  const key = 'owner/private/card.json';
  const encode = encodeURIComponent;
  const result = await runCloudObjectProxyAuthz({
    allowActive: true,
    requestBudget: 4,
    urlAllowed: (url) => new URL(url).origin === 'https://lab.invalid',
    cases: [{
      id: 'object-proxy',
      endpointOrigin: 'https://lab.invalid',
      ownerUrl: `https://lab.invalid/object?key=${encode(key)}`,
      crossUrl: `https://lab.invalid/object?key=${encode(key)}`,
      missingControlUrl: 'https://lab.invalid/object?key=ghostrecon-missing-fixture',
      urlShapedControlUrl: 'https://lab.invalid/object?key=http%3A%2F%2F127.0.0.1%2Fmetadata',
      ownerAuthRef: 'auth:owner',
      crossAuthRef: 'auth:other',
    }],
    transport: async ({ url, method, authRef }) => {
      seen.push({ url, method, authRef });
      if (url.includes('ghostrecon-missing') || url.includes('127.0.0.1')) {
        return { status: 404, text: '<Code>NoSuchKey</Code>' };
      }
      return { status: 200, body: 'same-object-fixture' };
    },
  });
  assert.equal(seen.length, 4);
  assert.ok(seen.every((row) => row.method === 'GET'));
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].url, 'https://lab.invalid/');
  assert.doesNotMatch(JSON.stringify(result), /owner\/private|card\.json|same-object-fixture/);
});

test('runner propaga cancelamento e budget inválido não executa requests', async () => {
  const controller = new AbortController();
  controller.abort(new DOMException('fixture timeout', 'TimeoutError'));
  let calls = 0;
  const args = {
    allowActive: true,
    urlAllowed: () => true,
    cases: [{
      endpointOrigin: 'https://lab.invalid',
      ownerUrl: 'https://lab.invalid/a', crossUrl: 'https://lab.invalid/a',
      missingControlUrl: 'https://lab.invalid/missing', urlShapedControlUrl: 'https://lab.invalid/url',
      ownerAuthRef: 'a', crossAuthRef: 'b',
    }],
    transport: async () => { calls += 1; return { status: 200 }; },
  };
  await assert.rejects(runCloudObjectProxyAuthz({ ...args, signal: controller.signal }), /fixture timeout/);
  const invalidBudget = await runCloudObjectProxyAuthz({ ...args, requestBudget: Number.NaN });
  assert.equal(invalidBudget.metrics.requestsAttempted, 0);
  assert.equal(calls, 0);
});
