import test from 'node:test';
import assert from 'node:assert/strict';

import { moduleRunners } from '../modules/module-registry-runners.mjs';
import { API_CONTRACT_CANONICALIZATION_VERSION } from '../modules/api-contract-diff.mjs';

function openApiDocument({ includeCreate = false } = {}) {
  return {
    openapi: '3.1.0',
    info: { title: 'Telemetry fixture', version: '1.0.0' },
    paths: {
      '/pets': {
        get: {
          operationId: 'listPets',
          responses: { 200: { description: 'ok' } },
        },
        ...(includeCreate
          ? {
              post: {
                operationId: 'createPet',
                responses: { 201: { description: 'created' } },
              },
            }
          : {}),
      },
    },
  };
}

function contractFetch(document) {
  return async (url) => {
    if (new URL(url).pathname === '/openapi.json') {
      return new Response(JSON.stringify(document), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }
    return new Response('', {
      status: 404,
      headers: { 'content-type': 'application/json' },
    });
  };
}

function runnerState(overrides = {}) {
  return {
    apiContractTimeoutMs: 10_000,
    domain: 'example.test',
    originByHost: new Map([
      ['api.example.test', { origin: 'https://api.example.test' }],
    ]),
    outOfScopeList: [],
    modules: ['api_contract_diff'],
    listRunsFn: async () => [],
    getRunByIdFn: async () => null,
    log() {},
    ...overrides,
  };
}

test('runner separa findings, contratos, snapshots, mudanças e versões na telemetria', async () => {
  const initial = await moduleRunners.api_contract_diff(runnerState({
    fetchImpl: contractFetch(openApiDocument()),
  }));
  assert.equal(initial.findings.length, 1);
  assert.equal(initial.resultCount, 1);
  assert.equal(initial.outcomeMetrics.contracts, 1);
  assert.equal(initial.outcomeMetrics.snapshotsMaterialized, 1);
  assert.equal(initial.outcomeMetrics.changes, 0);
  assert.equal(
    initial.outcomeMetrics.canonicalizationVersion,
    API_CONTRACT_CANONICALIZATION_VERSION,
  );
  assert.equal(initial.outcomeMetrics.baselineBytesRead, 0);
  assert.equal(initial.outcomeMetrics.baselineByteLimitReached, false);

  const storedRun = {
    id: 1,
    target: 'example.test',
    created_at: '2026-09-13T12:00:00.000Z',
    findings: initial.findings,
  };
  const changed = await moduleRunners.api_contract_diff(runnerState({
    fetchImpl: contractFetch(openApiDocument({ includeCreate: true })),
    listRunsFn: async () => [{
      id: storedRun.id,
      target: storedRun.target,
      created_at: storedRun.created_at,
    }],
    getRunByIdFn: async () => storedRun,
  }));

  assert.equal(changed.findings.filter((finding) => finding.type === 'api_contract_snapshot').length, 1);
  assert.equal(changed.findings.filter((finding) => finding.type === 'api_contract_diff').length, 1);
  assert.equal(changed.resultCount, changed.findings.length);
  assert.equal(changed.resultCount, 2);
  assert.equal(changed.outcomeMetrics.contracts, 1);
  assert.equal(changed.outcomeMetrics.snapshotsMaterialized, 1);
  assert.equal(changed.outcomeMetrics.changes, 1);
  assert.ok(Number.isSafeInteger(changed.outcomeMetrics.snapshotSchemaVersion));
  assert.equal(
    changed.outcomeMetrics.canonicalizationVersion,
    API_CONTRACT_CANONICALIZATION_VERSION,
  );
  assert.ok(changed.outcomeMetrics.baselineBytesRead > 0);
  assert.ok(changed.outcomeMetrics.baselineBytesRetained > 0);
  assert.ok(changed.outcomeMetrics.baselineByteLimit > 0);
  assert.equal(changed.outcomeMetrics.baselineByteLimitReached, false);
  assert.equal(typeof changed.outcomeMetrics.deadlineReached, 'boolean');
  assert.equal(typeof changed.outcomeMetrics.complete, 'boolean');
});
