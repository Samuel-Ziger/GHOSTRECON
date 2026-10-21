import test from 'node:test';
import assert from 'node:assert/strict';

import { tryGraphqlMinimalProbe } from '../modules/openapi-harvest.js';

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

test('graphql-probe: confirma endpoint e trata introspecção como inventário', async () => {
  const calls = [];
  const findings = await tryGraphqlMinimalProbe(
    ['https://api.example.com/graphql'],
    'example.com',
    [],
    [],
    null,
    null,
    {
      fetchImpl: async (_url, init) => {
        calls.push(JSON.parse(init.body));
        if (calls.length === 1) return jsonResponse({ data: { __typename: 'Query' } });
        return jsonResponse({ data: { __schema: { queryType: { name: 'Query' } } } });
      },
      urlAllowed: () => true,
    },
  );

  assert.equal(calls.length, 2);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].type, 'graphql_introspection_inventory');
  assert.equal(findings[0].prio, 'info');
});

test('graphql-probe: resposta contendo apenas errors não vira achado', async () => {
  const findings = await tryGraphqlMinimalProbe(
    ['https://api.example.com/graphql'],
    'example.com',
    [],
    [],
    null,
    null,
    {
      fetchImpl: async () => jsonResponse({ errors: [{ message: 'denied' }] }),
      urlAllowed: () => true,
    },
  );
  assert.deepEqual(findings, []);
});

test('graphql-probe: escopo recusado impede qualquer request', async () => {
  let called = false;
  const findings = await tryGraphqlMinimalProbe(
    ['https://outside.invalid/graphql'],
    'example.com',
    [],
    [],
    null,
    null,
    {
      fetchImpl: async () => {
        called = true;
        return jsonResponse({ data: { __typename: 'Query' } });
      },
      urlAllowed: () => false,
    },
  );
  assert.equal(called, false);
  assert.deepEqual(findings, []);
});
