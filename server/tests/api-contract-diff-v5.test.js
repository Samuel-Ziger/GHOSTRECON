import { createHash } from 'node:crypto';
import test from 'node:test';
import assert from 'node:assert/strict';

import {
  API_CONTRACT_CANONICALIZATION_VERSION,
  collectOpenApiSummary,
  createApiContractSnapshot,
  diffOpenApiSummaries,
  extractApiContractSnapshots,
  fetchOpenApiContracts,
  findPreviousApiContractSnapshots,
  migrateApiContractSummary,
  previousApiContractSnapshotFor,
  runApiContractDiff,
} from '../modules/api-contract-diff.mjs';
import {
  parseJsonDocumentInWorker,
  parseYamlDocumentInWorker,
} from '../modules/api-contract-parser-worker.mjs';
import { serializeFindingsForRunSnapshot } from '../modules/finding-serialize.js';

const SPEC_PATHS = [
  '/openapi.json',
  '/openapi.yaml',
  '/openapi.yml',
  '/swagger.json',
  '/swagger.yaml',
  '/swagger.yml',
  '/v2/api-docs',
  '/v3/api-docs',
  '/api-docs/swagger.json',
  '/swagger/v1/swagger.json',
];

function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function sha256(value) {
  return createHash('sha256').update(String(value)).digest('hex');
}

function response(body, {
  status = 200,
  contentType = 'application/json',
  headers = {},
} = {}) {
  return new Response(typeof body === 'string' ? body : JSON.stringify(body), {
    status,
    headers: { 'content-type': contentType, ...headers },
  });
}

function notFound() {
  return response('', { status: 404 });
}

function smallDocument(route = '/health') {
  return {
    openapi: '3.1.0',
    info: { title: 'Fixture API', version: '1' },
    paths: {
      [route]: {
        get: {
          parameters: [{
            name: 'limit',
            in: 'query',
            required: false,
            schema: { type: 'integer' },
          }],
          responses: {
            200: {
              description: 'ok',
              content: {
                'application/json': {
                  schema: { type: 'object', required: ['ok'], properties: { ok: { type: 'boolean' } } },
                },
              },
            },
          },
        },
      },
    },
  };
}

function canonicalizationV4(summaryInput) {
  const summary = structuredClone(summaryInput);
  summary.canonicalizationVersion = 4;
  delete summary.sourceAliases;
  delete summary.referenceResolution;
  summary.hash = sha256(stableJson({
    schemaVersion: summary.schemaVersion,
    canonicalizationVersion: summary.canonicalizationVersion,
    version: summary.version,
    title: summary.title,
    apiVersion: summary.apiVersion,
    serversSignature: summary.serversSignature,
    componentsSignature: summary.componentsSignature,
    rootContractSignature: summary.rootContractSignature,
    pathItemsSignature: summary.pathItemsSignature,
    webhooksSignature: summary.webhooksSignature,
    pathCount: summary.pathCount,
    webhookCount: summary.webhookCount,
    operationCount: summary.operationCount,
    paramCount: summary.paramCount,
    operationsWithoutSecurity: summary.operationsWithoutSecurity,
    securitySchemes: summary.securitySchemes,
    operations: summary.operations,
    redactionPolicyHash: summary.compatibility.redactionPolicyHash,
  }));
  return summary;
}

function canonicalizationV3(summaryInput) {
  const summary = structuredClone(summaryInput);
  summary.canonicalizationVersion = 3;
  delete summary.sourceAliases;
  delete summary.referenceResolution;
  summary.hash = sha256(stableJson({
    schemaVersion: summary.schemaVersion,
    canonicalizationVersion: summary.canonicalizationVersion,
    version: summary.version,
    title: summary.title,
    apiVersion: summary.apiVersion,
    serversSignature: summary.serversSignature,
    componentsSignature: summary.componentsSignature,
    rootContractSignature: summary.rootContractSignature,
    pathItemsSignature: summary.pathItemsSignature,
    webhooksSignature: summary.webhooksSignature,
    pathCount: summary.pathCount,
    webhookCount: summary.webhookCount,
    operationCount: summary.operationCount,
    paramCount: summary.paramCount,
    operationsWithoutSecurity: summary.operationsWithoutSecurity,
    securitySchemes: summary.securitySchemes,
    operations: summary.operations,
  }));
  return summary;
}

function canonicalizationV5(summaryInput) {
  const summary = structuredClone(summaryInput);
  summary.canonicalizationVersion = 5;
  delete summary.referenceResolution.unresolvedInternalReferences;
  summary.hash = sha256(stableJson({
    schemaVersion: summary.schemaVersion,
    canonicalizationVersion: summary.canonicalizationVersion,
    version: summary.version,
    title: summary.title,
    apiVersion: summary.apiVersion,
    serversSignature: summary.serversSignature,
    componentsSignature: summary.componentsSignature,
    rootContractSignature: summary.rootContractSignature,
    pathItemsSignature: summary.pathItemsSignature,
    webhooksSignature: summary.webhooksSignature,
    pathCount: summary.pathCount,
    webhookCount: summary.webhookCount,
    operationCount: summary.operationCount,
    paramCount: summary.paramCount,
    operationsWithoutSecurity: summary.operationsWithoutSecurity,
    securitySchemes: summary.securitySchemes,
    operations: summary.operations,
    redactionPolicyHash: summary.compatibility.redactionPolicyHash,
    referenceResolution: summary.referenceResolution,
  }));
  return summary;
}

function canonicalizationV6(summaryInput) {
  const summary = structuredClone(summaryInput);
  summary.canonicalizationVersion = 6;
  summary.hash = sha256(stableJson({
    schemaVersion: summary.schemaVersion,
    canonicalizationVersion: summary.canonicalizationVersion,
    version: summary.version,
    title: summary.title,
    apiVersion: summary.apiVersion,
    serversSignature: summary.serversSignature,
    componentsSignature: summary.componentsSignature,
    rootContractSignature: summary.rootContractSignature,
    pathItemsSignature: summary.pathItemsSignature,
    webhooksSignature: summary.webhooksSignature,
    pathCount: summary.pathCount,
    webhookCount: summary.webhookCount,
    operationCount: summary.operationCount,
    paramCount: summary.paramCount,
    operationsWithoutSecurity: summary.operationsWithoutSecurity,
    securitySchemes: summary.securitySchemes,
    operations: summary.operations,
    redactionPolicyHash: summary.compatibility.redactionPolicyHash,
    referenceResolution: summary.referenceResolution,
  }));
  return summary;
}

function canonicalizationV7(summaryInput) {
  const summary = structuredClone(summaryInput);
  summary.canonicalizationVersion = 7;
  summary.hash = sha256(stableJson({
    schemaVersion: summary.schemaVersion,
    canonicalizationVersion: summary.canonicalizationVersion,
    version: summary.version,
    title: summary.title,
    apiVersion: summary.apiVersion,
    serversSignature: summary.serversSignature,
    componentsSignature: summary.componentsSignature,
    rootContractSignature: summary.rootContractSignature,
    pathItemsSignature: summary.pathItemsSignature,
    webhooksSignature: summary.webhooksSignature,
    pathCount: summary.pathCount,
    webhookCount: summary.webhookCount,
    operationCount: summary.operationCount,
    paramCount: summary.paramCount,
    operationsWithoutSecurity: summary.operationsWithoutSecurity,
    securitySchemes: summary.securitySchemes,
    operations: summary.operations,
    redactionPolicyHash: summary.compatibility.redactionPolicyHash,
    referenceResolution: summary.referenceResolution,
  }));
  return summary;
}

test('v8 produz o mesmo contrato semântico para JSON e YAML equivalentes', async () => {
  const yaml = [
    'openapi: 3.1.0',
    'info:',
    '  title: Fixture API',
    '  version: "1"',
    'paths:',
    '  /health:',
    '    get:',
    '      parameters:',
    '        - name: limit',
    '          in: query',
    '          required: false',
    '          schema:',
    '            type: integer',
    '      responses:',
    '        200:',
    '          description: ok',
    '          content:',
    '            application/json:',
    '              schema:',
    '                type: object',
    '                required:',
    '                  - ok',
    '                properties:',
    '                  ok:',
    '                    type: boolean',
  ].join('\n');
  const calls = [];
  const result = await fetchOpenApiContracts({
    origins: ['https://api.example.test'],
    domain: 'example.test',
    detailed: true,
    fetchImpl: async (url) => {
      calls.push(url);
      const pathname = new URL(url).pathname;
      if (pathname === '/openapi.json') return response(smallDocument());
      if (pathname === '/openapi.yaml') {
        return response(yaml, { contentType: 'application/openapi+yaml' });
      }
      return notFound();
    },
  });

  assert.equal(API_CONTRACT_CANONICALIZATION_VERSION, 8);
  assert.equal(result.status, 'done');
  assert.equal(result.coverage.complete, true);
  assert.equal(result.coverage.candidatesEvaluated, SPEC_PATHS.length);
  assert.equal(calls.length, SPEC_PATHS.length);
  assert.equal(result.summaries.length, 2);
  const [json, parsedYaml] = result.summaries;
  assert.match(json.url, /openapi\.json$/);
  assert.match(parsedYaml.url, /openapi\.yaml$/);
  assert.equal(json.hash, parsedYaml.hash);
  assert.equal(diffOpenApiSummaries(json, parsedYaml).changed, false);
  assert.deepEqual(parsedYaml.referenceResolution, json.referenceResolution);
});

test('YAML inválido, profundidade e tamanho excessivos falham com outcomes determinísticos', async () => {
  const scanYaml = (body, headers = {}) => fetchOpenApiContracts({
    origins: ['https://api.example.test'],
    domain: 'example.test',
    detailed: true,
    fetchImpl: async (url) => new URL(url).pathname === '/openapi.yaml'
      ? response(body, { contentType: 'application/yaml', headers })
      : notFound(),
  });

  const duplicateKey = await scanYaml([
    'openapi: 3.1.0',
    'openapi: 3.0.3',
    'paths: {}',
  ].join('\n'));
  const invalid = duplicateKey.outcomes.find((item) => item.url.endsWith('/openapi.yaml'));
  assert.equal(duplicateKey.status, 'partial');
  assert.equal(invalid?.state, 'invalid_yaml');
  assert.equal(invalid?.reason, 'YAML_PARSE_ERROR');

  const deepLines = ['openapi: 3.1.0', 'paths: {}', 'x-deep:'];
  for (let index = 0; index < 70; index += 1) {
    deepLines.push(`${'  '.repeat(index + 1)}level_${index}:`);
  }
  deepLines.push(`${'  '.repeat(71)}leaf: true`);
  const tooDeep = await scanYaml(deepLines.join('\n'));
  const depthOutcome = tooDeep.outcomes.find((item) => item.url.endsWith('/openapi.yaml'));
  assert.equal(tooDeep.status, 'partial');
  assert.equal(depthOutcome?.state, 'invalid_yaml');
  assert.equal(depthOutcome?.reason, 'YAML_DEPTH_LIMIT');

  const oversized = await scanYaml('openapi: 3.1.0\npaths: {}', {
    'content-length': '2000001',
  });
  const sizeOutcome = oversized.outcomes.find((item) => item.url.endsWith('/openapi.yaml'));
  assert.equal(oversized.status, 'partial');
  assert.equal(sizeOutcome?.state, 'response_too_large');

  const streamedOversized = await scanYaml('x'.repeat(2_000_001));
  const streamedSizeOutcome = streamedOversized.outcomes
    .find((item) => item.url.endsWith('/openapi.yaml'));
  assert.equal(streamedOversized.status, 'partial');
  assert.equal(streamedSizeOutcome?.state, 'response_too_large');
});

test('JSON com BOM e tags YAML core válidas são aceitos; tag desconhecida falha fechada', async () => {
  const document = smallDocument('/bom');
  const bomResult = await fetchOpenApiContracts({
    origins: ['https://api.example.test'],
    domain: 'example.test',
    detailed: true,
    fetchImpl: async (url) => new URL(url).pathname === '/openapi.json'
      ? response(`\uFEFF${JSON.stringify(document)}`)
      : notFound(),
  });
  assert.equal(bomResult.status, 'done');
  assert.equal(bomResult.summaries.length, 1);
  assert.equal(
    bomResult.summaries[0].hash,
    collectOpenApiSummary(document, {
      url: 'https://api.example.test/openapi.json',
    }).hash,
  );

  const coreTagged = await parseYamlDocumentInWorker([
    'openapi: !!str 3.1.0',
    'info:',
    '  title: Tagged',
    '  version: !!str 1',
    'paths: {}',
  ].join('\n'));
  assert.equal(coreTagged.openapi, '3.1.0');
  assert.equal(coreTagged.info.version, '1');
  await assert.rejects(
    parseYamlDocumentInWorker('openapi: !unknown 3.1.0\npaths: {}'),
    (error) => error?.code === 'YAML_UNSUPPORTED_TAG',
  );
});

test('parser JSON rejeita chaves duplicadas inclusive após decodificar escapes', async () => {
  await assert.rejects(
    parseJsonDocumentInWorker('{"responses":{"200":{},"\\u0032\\u0030\\u0030":{}}}'),
    (error) => error?.code === 'JSON_DUPLICATE_KEY',
  );
  await assert.rejects(
    parseJsonDocumentInWorker('{"outer":{"name":1,"name":2}}'),
    (error) => error?.code === 'JSON_DUPLICATE_KEY',
  );
  assert.deepEqual(
    await parseJsonDocumentInWorker('{"left":{"name":1},"right":{"name":2}}'),
    { left: { name: 1 }, right: { name: 2 } },
  );
  await assert.rejects(
    parseJsonDocumentInWorker('{"openapi":"3.1.0",}'),
    (error) => error?.code === 'JSON_PARSE_ERROR',
  );

  const result = await fetchOpenApiContracts({
    origins: ['https://api.example.test'],
    domain: 'example.test',
    detailed: true,
    pauseImpl: async () => {},
    fetchImpl: async (url) => (
      new URL(url).pathname === '/openapi.json'
        ? response('{"openapi":"3.1.0","paths":{},"paths":{"/hidden":{}}}')
        : notFound()
    ),
  });
  assert.equal(result.status, 'partial');
  assert.ok(result.outcomes.some(
    (item) => item.state === 'invalid_json' && item.reason === 'JSON_DUPLICATE_KEY',
  ));
  assert.equal(result.summaries.length, 0);
});

test('cancelamento encerra o worker YAML enquanto a análise está pendente', async () => {
  const source = `items:\n${Array.from({ length: 50_000 }, (_, index) => `  - ${index}`).join('\n')}`;
  const controller = new AbortController();
  const reason = new Error('operator_cancelled');
  const pending = parseYamlDocumentInWorker(source, { signal: controller.signal });
  queueMicrotask(() => controller.abort(reason));
  await assert.rejects(pending, (error) => error === reason);

  const alreadyCancelled = new AbortController();
  const earlyReason = new Error('cancelled_before_start');
  alreadyCancelled.abort(earlyReason);
  await assert.rejects(
    parseYamlDocumentInWorker('openapi: 3.1.0\npaths: {}', {
      signal: alreadyCancelled.signal,
    }),
    (error) => error === earlyReason,
  );
});

test('cancelamento encerra também o worker JSON enquanto a análise está pendente', async () => {
  const source = JSON.stringify({
    openapi: '3.1.0',
    paths: {},
    values: Array.from({ length: 100_000 }, (_, index) => index),
  });
  const controller = new AbortController();
  const reason = new Error('operator_cancelled_json');
  const pending = parseJsonDocumentInWorker(source, { signal: controller.signal });
  queueMicrotask(() => controller.abort(reason));
  await assert.rejects(pending, (error) => error === reason);

  const alreadyCancelled = new AbortController();
  const earlyReason = new Error('json_cancelled_before_start');
  alreadyCancelled.abort(earlyReason);
  await assert.rejects(
    parseJsonDocumentInWorker('{"openapi":"3.1.0","paths":{}}', {
      signal: alreadyCancelled.signal,
    }),
    (error) => error === earlyReason,
  );
});

test('v8 coleta múltiplos specs e consolida aliases pelo URL resolvido', async () => {
  let sharedRequests = 0;
  const calls = [];
  const result = await fetchOpenApiContracts({
    origins: ['https://api.example.test'],
    domain: 'example.test',
    detailed: true,
    fetchImpl: async (url) => {
      calls.push(url);
      const pathname = new URL(url).pathname;
      if (['/openapi.json', '/openapi.yaml'].includes(pathname)) {
        return response('', { status: 302, headers: { location: '/contracts/shared.json' } });
      }
      if (pathname === '/contracts/shared.json') {
        sharedRequests += 1;
        return response(smallDocument('/shared'));
      }
      if (pathname === '/swagger.json') return response(smallDocument('/independent'));
      return notFound();
    },
  });

  assert.equal(result.status, 'done');
  assert.equal(result.discoveryPolicy, 'all_known_per_origin_v1');
  assert.equal(result.summaries.length, 2);
  assert.equal(result.coverage.contractsUnique, 2);
  assert.equal(result.coverage.duplicates, 1);
  assert.equal(sharedRequests, 2);
  assert.equal(calls.length, SPEC_PATHS.length + 2);
  const shared = result.summaries.find((item) => item.resolvedUrl.endsWith('/contracts/shared.json'));
  assert.deepEqual(shared?.sourceAliases, [
    'https://api.example.test/openapi.json',
    'https://api.example.test/openapi.yaml',
  ]);
  assert.ok(result.outcomes.some((item) => item.state === 'duplicate_contract'));

  const extracted = extractApiContractSnapshots({
    id: 41,
    findings: [{
      type: 'api_contract_snapshot',
      verification: { evidence: { apiContractSnapshot: createApiContractSnapshot(shared) } },
    }],
  });
  assert.equal(extracted.length, 1);
  assert.deepEqual(extracted[0].summary.sourceAliases, shared.sourceAliases);
});

test('conteúdo divergente no mesmo URL resolvido é conflito parcial, não baseline ambíguo', async () => {
  const conflictFetch = () => {
    let sharedRequests = 0;
    return async (url) => {
      const pathname = new URL(url).pathname;
      if (['/openapi.json', '/openapi.yaml'].includes(pathname)) {
        return response('', { status: 302, headers: { location: '/contracts/shared.json' } });
      }
      if (pathname === '/contracts/shared.json') {
        sharedRequests += 1;
        return response(smallDocument(sharedRequests === 1 ? '/first' : '/second'));
      }
      return notFound();
    };
  };
  const result = await fetchOpenApiContracts({
    origins: ['https://api.example.test'],
    domain: 'example.test',
    detailed: true,
    fetchImpl: conflictFetch(),
  });

  assert.equal(result.status, 'partial');
  assert.equal(result.summaries.length, 0);
  assert.equal(result.coverage.contractsUnique, 0);
  assert.equal(result.coverage.contractsDiscardedByConflict, 1);
  assert.equal(result.coverage.duplicates, 1);
  assert.equal(result.coverage.candidatesInconclusive, 1);
  const conflict = result.outcomes.find((item) => item.state === 'duplicate_contract_conflict');
  assert.ok(conflict);
  assert.match(conflict.summaryHash, /^[a-f0-9]{64}$/);

  const run = await runApiContractDiff({
    origins: ['https://api.example.test'],
    domain: 'example.test',
    fetchImpl: conflictFetch(),
  });
  assert.equal(run.status, 'partial');
  assert.deepEqual(run.summaries, []);
  assert.equal(run.findings.some((item) => item.type === 'api_contract_snapshot'), false);
  assert.equal(run.findings.some((item) => item.type === 'api_contract_diff'), false);
});

test('referências externas são detect-only, tornam a execução parcial e nunca viram baseline', async () => {
  const sourceUrl = 'https://api.example.test/openapi.json';
  const externalDocument = {
    openapi: '3.1.0',
    paths: {
      '/items': {
        get: {
          responses: {
            200: { $ref: 'https://schemas.outside.test/common.yaml#/components/responses/Ok' },
          },
        },
      },
    },
  };
  const partial = collectOpenApiSummary(externalDocument, { url: sourceUrl });
  assert.deepEqual(partial.referenceResolution.issueCodes, ['external_references_unresolved']);
  assert.equal(partial.referenceResolution.mode, 'detect_only_v1');
  assert.equal(partial.referenceResolution.status, 'partial');
  assert.equal(partial.referenceResolution.referencesSeen, 1);
  assert.equal(partial.referenceResolution.externalReferences, 1);
  assert.equal(partial.referenceResolution.unresolvedExternalReferences, 1);
  assert.throws(
    () => diffOpenApiSummaries(partial, partial),
    (error) => error?.code === 'API_CONTRACT_INCOMPLETE_REFERENCE_COVERAGE',
  );

  const envelope = createApiContractSnapshot(partial);
  const extracted = extractApiContractSnapshots({
    id: 51,
    findings: [{
      type: 'api_contract_snapshot',
      verification: { evidence: { apiContractSnapshot: envelope } },
    }],
  });
  assert.equal(extracted.length, 1);
  assert.equal(extracted[0].summary.referenceResolution.status, 'partial');

  const complete = collectOpenApiSummary(smallDocument('/items'), { url: sourceUrl });
  assert.equal(previousApiContractSnapshotFor(complete, [{
    runId: 1,
    summary: partial,
    integrityVerified: true,
  }]), null);
  assert.equal(previousApiContractSnapshotFor(partial, [{
    runId: 2,
    summary: complete,
    integrityVerified: true,
  }]), null);

  const calls = [];
  const run = await runApiContractDiff({
    origins: ['https://api.example.test'],
    domain: 'example.test',
    previousSnapshots: [{ runId: 2, summary: complete, integrityVerified: true }],
    fetchImpl: async (url) => {
      calls.push(url);
      return new URL(url).pathname === '/openapi.json'
        ? response(externalDocument)
        : notFound();
    },
  });
  assert.equal(run.status, 'partial');
  assert.equal(run.findings.filter((item) => item.type === 'api_contract_snapshot').length, 1);
  assert.equal(run.findings.some((item) => item.type === 'api_contract_diff'), false);
  assert.ok(run.outcomes.some((item) => item.state === 'external_ref_unresolved'));
  assert.equal(calls.some((url) => url.includes('schemas.outside.test')), false);
});

test('snapshots v3–v7 permanecem legíveis, mas não cruzam baseline com v8', () => {
  const current = collectOpenApiSummary(smallDocument(), {
    url: 'https://api.example.test/openapi.json',
  });
  const v3 = canonicalizationV3(current);
  const normalizedV3 = migrateApiContractSummary(v3);
  assert.equal(normalizedV3.canonicalizationVersion, 3);
  assert.equal(normalizedV3.referenceResolution, undefined);
  const envelopeV3 = createApiContractSnapshot(normalizedV3);
  assert.equal(extractApiContractSnapshots({
    id: 60,
    findings: [{
      type: 'api_contract_snapshot',
      verification: { evidence: { apiContractSnapshot: envelopeV3 } },
    }],
  })[0]?.summary.canonicalizationVersion, 3);
  assert.throws(
    () => diffOpenApiSummaries(normalizedV3, current),
    (error) => error?.code === 'API_CONTRACT_INCOMPATIBLE_CANONICALIZATION',
  );

  const v4 = canonicalizationV4(current);
  const normalized = migrateApiContractSummary(v4);
  assert.equal(normalized.canonicalizationVersion, 4);
  assert.equal(normalized.referenceResolution, undefined);

  const envelope = createApiContractSnapshot(normalized);
  const extracted = extractApiContractSnapshots({
    id: 61,
    findings: [{
      type: 'api_contract_snapshot',
      verification: { evidence: { apiContractSnapshot: envelope } },
    }],
  });
  assert.equal(extracted.length, 1);
  assert.equal(extracted[0].summary.canonicalizationVersion, 4);
  assert.throws(
    () => diffOpenApiSummaries(normalized, current),
    (error) => error?.code === 'API_CONTRACT_INCOMPATIBLE_CANONICALIZATION',
  );
  assert.equal(previousApiContractSnapshotFor(current, [{ runId: 1, summary: normalized }]), null);
  assert.equal(previousApiContractSnapshotFor(current, [
    { runId: 1, summary: normalized },
    { runId: 2, summary: current, integrityVerified: true },
  ])?.runId, 2);

  const v5 = canonicalizationV5(current);
  const normalizedV5 = migrateApiContractSummary(v5);
  assert.equal(normalizedV5.canonicalizationVersion, 5);
  assert.equal(
    Object.hasOwn(normalizedV5.referenceResolution, 'unresolvedInternalReferences'),
    false,
  );
  assert.equal(diffOpenApiSummaries(normalizedV5, normalizedV5).changed, false);
  assert.throws(
    () => diffOpenApiSummaries(normalizedV5, current),
    (error) => error?.code === 'API_CONTRACT_INCOMPATIBLE_CANONICALIZATION',
  );
  assert.equal(previousApiContractSnapshotFor(current, [{
    runId: 3,
    summary: normalizedV5,
    integrityVerified: true,
  }]), null);

  const v6 = canonicalizationV6(current);
  const normalizedV6 = migrateApiContractSummary(v6);
  assert.equal(normalizedV6.canonicalizationVersion, 6);
  assert.equal(diffOpenApiSummaries(normalizedV6, normalizedV6).changed, false);
  const envelopeV6 = createApiContractSnapshot(normalizedV6);
  const extractedV6 = extractApiContractSnapshots({
    id: 62,
    findings: [{
      type: 'api_contract_snapshot',
      verification: { evidence: { apiContractSnapshot: envelopeV6 } },
    }],
  });
  assert.equal(extractedV6.length, 1);
  assert.equal(extractedV6[0].summary.canonicalizationVersion, 6);
  assert.throws(
    () => diffOpenApiSummaries(normalizedV6, current),
    (error) => error?.code === 'API_CONTRACT_INCOMPATIBLE_CANONICALIZATION',
  );
  assert.equal(previousApiContractSnapshotFor(current, [{
    runId: 4,
    summary: normalizedV6,
    integrityVerified: true,
  }]), null);

  const v7 = canonicalizationV7(current);
  const normalizedV7 = migrateApiContractSummary(v7);
  assert.equal(normalizedV7.canonicalizationVersion, 7);
  assert.equal(diffOpenApiSummaries(normalizedV7, normalizedV7).changed, false);
  const envelopeV7 = createApiContractSnapshot(normalizedV7);
  assert.equal(extractApiContractSnapshots({
    id: 63,
    findings: [{
      type: 'api_contract_snapshot',
      verification: { evidence: { apiContractSnapshot: envelopeV7 } },
    }],
  })[0]?.summary.canonicalizationVersion, 7);
  assert.throws(
    () => diffOpenApiSummaries(normalizedV7, current),
    (error) => error?.code === 'API_CONTRACT_INCOMPATIBLE_CANONICALIZATION',
  );
  assert.equal(previousApiContractSnapshotFor(current, [{
    runId: 5,
    summary: normalizedV7,
    integrityVerified: true,
  }]), null);
});

test('snapshot persistido rejeita versão canônica impossível ou divergente da origem', () => {
  const current = collectOpenApiSummary(smallDocument(), {
    url: 'https://api.example.test/openapi.json',
  });
  for (const invalid of [
    { ...structuredClone(current), version: '99.0', sourceDocumentVersion: '99.0' },
    { ...structuredClone(current), version: '3.1', sourceDocumentVersion: '3.0.3' },
    { ...structuredClone(current), sourceDocumentVersion: '3.1.invalid' },
  ]) {
    invalid.hash = '0'.repeat(64);
    assert.throws(
      () => migrateApiContractSummary(invalid),
      (error) => error?.code === 'API_CONTRACT_INCONSISTENT_VERSION',
    );
  }
});

test('summary corrente sem envelope é legível, mas a busca persistida não o promove a baseline', async () => {
  const target = 'example.test';
  const summary = collectOpenApiSummary(smallDocument(), {
    url: 'https://api.example.test/openapi.json',
  });
  const rawRun = {
    id: 71,
    target,
    created_at: '2026-09-11T10:00:00.000Z',
    findings: [{
      type: 'api_contract_snapshot',
      verification: { evidence: { apiContractSummary: summary } },
    }],
  };

  const readable = extractApiContractSnapshots(rawRun);
  assert.equal(readable.length, 1);
  assert.equal(readable[0].summary.hash, summary.hash);
  assert.equal(readable[0].integrityVerified, false);

  const candidates = await findPreviousApiContractSnapshots({
    target,
    listRunsFn: async () => [{ id: rawRun.id, target }],
    getRunByIdFn: async () => rawRun,
  });
  assert.deepEqual(candidates, []);
  assert.equal(previousApiContractSnapshotFor(summary, candidates), null);
});

test('snapshot partial mais novo não oculta envelope complete mais antigo', async () => {
  const target = 'example.test';
  const sourceUrl = 'https://api.example.test/openapi.json';
  const complete = collectOpenApiSummary(smallDocument(), { url: sourceUrl });
  const partial = collectOpenApiSummary({
    openapi: '3.1.0',
    paths: {
      '/health': {
        get: {
          responses: {
            200: { $ref: './shared.yaml#/components/responses/Ok' },
          },
        },
      },
    },
  }, { url: sourceUrl });
  assert.equal(complete.referenceResolution.status, 'complete');
  assert.equal(partial.referenceResolution.status, 'partial');

  const persistedRuns = new Map([
    [72, {
      id: 72,
      target,
      created_at: '2026-09-11T12:00:00.000Z',
      findings: [{
        type: 'api_contract_snapshot',
        verification: {
          evidence: { apiContractSnapshot: createApiContractSnapshot(partial) },
        },
      }],
    }],
    [71, {
      id: 71,
      target,
      created_at: '2026-09-11T11:00:00.000Z',
      findings: [{
        type: 'api_contract_snapshot',
        verification: {
          evidence: { apiContractSnapshot: createApiContractSnapshot(complete) },
        },
      }],
    }],
  ]);

  const candidates = await findPreviousApiContractSnapshots({
    target,
    listRunsFn: async () => [
      { id: 72, target },
      { id: 71, target },
    ],
    getRunByIdFn: async (id) => persistedRuns.get(id),
  });
  assert.equal(candidates.length, 1);
  assert.equal(candidates[0].runId, 71);
  assert.equal(candidates[0].integrityVerified, true);
  assert.equal(candidates[0].summary.referenceResolution.status, 'complete');
  assert.equal(previousApiContractSnapshotFor(complete, candidates)?.runId, 71);
});

test('ordena newest-first sem ocultar baseline antigo com alias exclusiva', async () => {
  const target = 'example.test';
  const aliasA = 'https://api.example.test/openapi.json';
  const aliasB = 'https://api.example.test/swagger.json';
  const aliasC = 'https://api.example.test/v3/api-docs';
  const newer = collectOpenApiSummary(smallDocument(), {
    url: aliasA,
    sourceAliases: [aliasA, aliasB],
  });
  const older = collectOpenApiSummary(smallDocument(), {
    url: aliasB,
    sourceAliases: [aliasB, aliasC],
  });
  const persistedRuns = new Map([
    [81, {
      id: 81,
      target,
      created_at: '2026-09-11T12:00:00.000Z',
      findings: [{
        type: 'api_contract_snapshot',
        verification: {
          evidence: { apiContractSnapshot: createApiContractSnapshot(newer) },
        },
      }],
    }],
    [80, {
      id: 80,
      target,
      created_at: '2026-09-11T10:00:00.000Z',
      findings: [{
        type: 'api_contract_snapshot',
        verification: {
          evidence: { apiContractSnapshot: createApiContractSnapshot(older) },
        },
      }],
    }],
  ]);

  const candidates = await findPreviousApiContractSnapshots({
    target,
    // A fonte deliberadamente retorna oldest-first; o seletor deve ordenar.
    listRunsFn: async () => [
      { id: 80, target, created_at: '2026-09-11T10:00:00.000Z' },
      { id: 81, target, created_at: '2026-09-11T12:00:00.000Z' },
    ],
    getRunByIdFn: async (id) => persistedRuns.get(id),
  });
  assert.deepEqual(candidates.map((item) => item.runId), [81, 80]);
  assert.equal(candidates.every((item) => item.integrityVerified === true), true);

  const currentSharedAlias = collectOpenApiSummary(smallDocument(), {
    url: aliasB,
    sourceAliases: [aliasB],
  });
  assert.equal(previousApiContractSnapshotFor(currentSharedAlias, candidates)?.runId, 81);

  const currentExclusiveAlias = collectOpenApiSummary(smallDocument(), {
    url: aliasC,
    sourceAliases: [aliasC],
  });
  assert.equal(previousApiContractSnapshotFor(currentExclusiveAlias, candidates)?.runId, 80);
});

test('resolvedUrl comum vincula baselines coletados por aliases diferentes', () => {
  const resolvedUrl = 'https://api.example.test/contracts/release.json';
  const previous = collectOpenApiSummary(smallDocument(), {
    url: 'https://api.example.test/openapi.json',
    resolvedUrl,
    sourceAliases: ['https://api.example.test/openapi.json'],
  });
  const current = collectOpenApiSummary(smallDocument(), {
    url: 'https://api.example.test/swagger.json',
    resolvedUrl,
    sourceAliases: ['https://api.example.test/swagger.json'],
  });
  const match = previousApiContractSnapshotFor(current, [{
    runId: 82,
    summary: previous,
    integrityVerified: true,
  }]);
  assert.equal(match?.runId, 82);
});

test('extração normaliza fragmento e retorna somente proveniência allowlisted', () => {
  const summary = collectOpenApiSummary(smallDocument(), {
    url: 'https://api.example.test/openapi.json',
  });
  const envelope = createApiContractSnapshot(summary);
  envelope.provenance.sourceUrl = `${envelope.provenance.sourceUrl}#private-fragment`;
  envelope.provenance.unknownField = 'must-not-survive';
  envelope.provenance.referenceResolution.unknownNestedField = 'must-not-survive';

  const extracted = extractApiContractSnapshots({
    id: 91,
    findings: [{
      type: 'api_contract_snapshot',
      verification: { evidence: { apiContractSnapshot: envelope } },
    }],
  });
  assert.equal(extracted.length, 1);
  assert.equal(extracted[0].integrityVerified, true);
  assert.equal(extracted[0].provenance.sourceUrl, summary.url);
  assert.equal(JSON.stringify(extracted[0].provenance).includes('private-fragment'), false);
  assert.equal(Object.hasOwn(extracted[0].provenance, 'unknownField'), false);
  assert.equal(
    Object.hasOwn(extracted[0].provenance.referenceResolution, 'unknownNestedField'),
    false,
  );
  assert.deepEqual(Object.keys(extracted[0].provenance).sort(), [
    'detailLevel',
    'moduleId',
    'redactionPolicyHash',
    'referenceResolution',
    'resolvedSourceUrl',
    'sourceAliases',
    'sourceDocumentVersion',
    'sourceSnapshotSchemaVersion',
    'sourceUrl',
  ]);
});

test('scanner de refs ignora dados literais, conta Example Object e reconhece self-ref resolvida', () => {
  const literal = collectOpenApiSummary({
    openapi: '3.1.0',
    paths: {
      '/payload': {
        get: { responses: { 200: { description: 'ok' } } },
      },
    },
    components: {
      schemas: {
        Payload: {
          type: 'object',
          'x-fixture': { $ref: 'https://outside.test/from-extension.json' },
          example: { $ref: 'https://outside.test/from-example.json' },
          default: { $ref: 'https://outside.test/from-default.json' },
          const: { $ref: 'https://outside.test/from-const.json' },
          enum: [{ $ref: 'https://outside.test/from-enum.json' }],
        },
      },
    },
    'x-root-fixture': { $ref: 'https://outside.test/from-root-extension.json' },
  }, { url: 'https://api.example.test/openapi.json' });
  assert.equal(literal.referenceResolution.status, 'complete');
  assert.equal(literal.referenceResolution.referencesSeen, 0);
  assert.equal(literal.referenceResolution.externalReferences, 0);

  const exampleObject = collectOpenApiSummary({
    openapi: '3.1.0',
    paths: { '/payload': { get: { responses: { 200: {} } } } },
    components: {
      examples: {
        Shared: { $ref: 'https://schemas.outside.test/examples.yaml#/Shared' },
      },
    },
  }, { url: 'https://api.example.test/openapi.json' });
  assert.equal(exampleObject.referenceResolution.status, 'partial');
  assert.equal(exampleObject.referenceResolution.referencesSeen, 1);
  assert.equal(exampleObject.referenceResolution.externalReferences, 1);

  const resolvedUrl = 'https://api.example.test/contracts/current.json';
  const selfReferences = collectOpenApiSummary({
    openapi: '3.1.0',
    paths: { '/payload': { get: { responses: { 200: {} } } } },
    components: {
      schemas: {
        Absolute: { $ref: `${resolvedUrl}#/components/schemas/Target` },
        Relative: { $ref: './current.json#/components/schemas/Target' },
        Target: { type: 'string' },
      },
    },
  }, {
    url: 'https://api.example.test/openapi.json',
    resolvedUrl,
  });
  assert.equal(selfReferences.referenceResolution.status, 'complete');
  assert.equal(selfReferences.referenceResolution.referencesSeen, 2);
  assert.equal(selfReferences.referenceResolution.externalReferences, 0);
  assert.equal(selfReferences.referenceResolution.unresolvedExternalReferences, 0);
});

test('v8 falha fechado para ponteiro local ausente e não o promove a baseline', () => {
  const sourceUrl = 'https://api.example.test/openapi.json';
  const missing = collectOpenApiSummary({
    openapi: '3.1.0',
    paths: {
      '/items': {
        get: {
          responses: {
            200: { $ref: '#/components/responses/Missing' },
          },
        },
      },
    },
    components: { responses: {} },
  }, { url: sourceUrl });
  assert.equal(missing.referenceResolution.status, 'partial');
  assert.equal(missing.referenceResolution.referencesSeen, 1);
  assert.equal(missing.referenceResolution.unresolvedExternalReferences, 0);
  assert.equal(missing.referenceResolution.unresolvedInternalReferences, 1);
  assert.deepEqual(missing.referenceResolution.issueCodes, ['internal_references_unresolved']);

  const complete = collectOpenApiSummary({
    openapi: '3.1.0',
    paths: {
      '/items': {
        get: {
          responses: {
            200: { $ref: '#/components/responses/Ok' },
          },
        },
      },
    },
    components: { responses: { Ok: { description: 'ok' } } },
  }, { url: sourceUrl });
  assert.equal(complete.referenceResolution.status, 'complete');
  assert.equal(complete.referenceResolution.unresolvedInternalReferences, 0);
  assert.equal(previousApiContractSnapshotFor(complete, [{
    runId: 1,
    summary: missing,
    integrityVerified: true,
  }]), null);
  assert.throws(
    () => diffOpenApiSummaries(missing, complete),
    (error) => error?.code === 'API_CONTRACT_INCOMPLETE_REFERENCE_COVERAGE',
  );
});

test('v8 valida discriminator.mapping, operationRef, $self, $id e anchors incorporadas', () => {
  const embedded = collectOpenApiSummary({
    openapi: '3.2.0',
    $self: 'https://schemas.example.test/root.json',
    paths: {
      '/items': {
        get: {
          responses: {
            200: {
              description: 'ok',
              links: {
                done: { operationRef: '#/paths/~1callback/post' },
              },
            },
          },
        },
      },
      '/callback': {
        post: { responses: { 204: { description: 'done' } } },
      },
    },
    components: {
      schemas: {
        Base: {
          $id: 'base.json',
          oneOf: [{ type: 'object' }],
          discriminator: {
            propertyName: 'kind',
            mapping: { cat: 'Cat' },
            defaultMapping: 'Cat',
          },
        },
        Cat: { type: 'object' },
        Embedded: {
          $id: 'embedded.json',
          $anchor: 'EmbeddedType',
          type: 'string',
        },
        EmbeddedRef: { $ref: 'embedded.json#EmbeddedType' },
      },
    },
  }, { url: 'https://api.example.test/openapi.json' });
  assert.equal(embedded.referenceResolution.status, 'complete');
  assert.equal(embedded.referenceResolution.referencesSeen, 4);
  assert.equal(embedded.referenceResolution.unresolvedExternalReferences, 0);
  assert.equal(embedded.referenceResolution.unresolvedInternalReferences, 0);

  const operationRefExternal = collectOpenApiSummary({
    openapi: '3.1.0',
    paths: {
      '/items': {
        get: {
          responses: {
            200: {
              description: 'ok',
              links: {
                remote: {
                  operationRef: 'https://schemas.outside.test/callbacks.yaml#/notify/post',
                },
              },
            },
          },
        },
      },
    },
  }, { url: 'https://api.example.test/openapi.json' });
  assert.equal(operationRefExternal.referenceResolution.status, 'partial');
  assert.equal(operationRefExternal.referenceResolution.unresolvedExternalReferences, 1);
});

test('v8 rejeita cobertura ambígua ou malformada de referências', () => {
  const summarize = (components, paths = {
    '/items': { get: { responses: { 200: { description: 'ok' } } } },
  }) => collectOpenApiSummary({
    openapi: '3.1.0',
    paths,
    components,
  }, { url: 'https://api.example.test/openapi.json' });

  const invalidValue = summarize({ schemas: { Invalid: { $ref: { target: 'no' } } } });
  assert.equal(invalidValue.referenceResolution.status, 'partial');
  assert.equal(invalidValue.referenceResolution.referencesSeen, 1);
  assert.ok(invalidValue.referenceResolution.issueCodes.includes('invalid_reference_value'));

  const malformedPointer = summarize({
    schemas: {
      'Bad~2Key': { type: 'string' },
      Ref: { $ref: '#/components/schemas/Bad~2Key' },
    },
  });
  assert.equal(malformedPointer.referenceResolution.unresolvedInternalReferences, 1);

  const wrongOperationTarget = summarize(
    {},
    {
      '/items': {
        get: {
          responses: {
            200: {
              description: 'ok',
              links: { invalid: { operationRef: '#/components' } },
            },
          },
        },
      },
    },
  );
  assert.equal(wrongOperationTarget.referenceResolution.unresolvedInternalReferences, 1);

  const percentEncodedAnchor = summarize({
    schemas: {
      Anchored: { $anchor: 'foo', type: 'string' },
      Ref: { $ref: '#%66oo' },
    },
  });
  assert.equal(percentEncodedAnchor.referenceResolution.status, 'complete');

  const duplicateAnchor = summarize({
    schemas: {
      First: { $anchor: 'same', type: 'string' },
      Second: { $anchor: 'same', type: 'number' },
    },
  });
  assert.equal(duplicateAnchor.referenceResolution.status, 'partial');
  assert.ok(duplicateAnchor.referenceResolution.issueCodes.includes('duplicate_reference_anchor'));
});

test('scanner de refs respeita dados literais, keywords de Schema e versão OpenAPI', () => {
  const swaggerExamples = collectOpenApiSummary({
    swagger: '2.0',
    paths: {
      '/items': {
        get: {
          responses: {
            200: {
              description: 'ok',
              examples: {
                'application/json': { $ref: 'https://literal.example.test/value.json' },
              },
            },
          },
        },
      },
    },
  }, { url: 'https://api.example.test/swagger.json' });
  assert.equal(swaggerExamples.referenceResolution.status, 'complete');
  assert.equal(swaggerExamples.referenceResolution.referencesSeen, 0);

  const unknownSchemaKeyword = collectOpenApiSummary({
    openapi: '3.1.0',
    paths: { '/items': { get: { responses: { 200: { description: 'ok' } } } } },
    components: {
      schemas: {
        Value: {
          type: 'string',
          customAnnotation: { $ref: 'https://literal.example.test/annotation.json' },
          $recursiveRef: 'https://literal.example.test/legacy-dialect.json',
          discriminator: { propertyName: 'kind', defaultMapping: 'IgnoredIn31' },
        },
      },
    },
  }, { url: 'https://api.example.test/openapi.json' });
  assert.equal(unknownSchemaKeyword.referenceResolution.status, 'complete');
  assert.equal(unknownSchemaKeyword.referenceResolution.referencesSeen, 0);

  const summarizeVersionedOperationRef = (version, target, additions = {}) => collectOpenApiSummary({
    openapi: version,
    paths: {
      '/source': {
        get: {
          responses: {
            200: {
              description: 'ok',
              links: { next: { operationRef: target } },
            },
          },
        },
      },
      ...additions.paths,
    },
    ...(additions.webhooks ? { webhooks: additions.webhooks } : {}),
  }, { url: 'https://api.example.test/openapi.json' });
  const invalid30Webhook = summarizeVersionedOperationRef(
    '3.0.3',
    '#/webhooks/notify/post',
    { webhooks: { notify: { post: { responses: { 200: { description: 'ok' } } } } } },
  );
  assert.equal(invalid30Webhook.referenceResolution.unresolvedInternalReferences, 1);
  const invalid31Query = summarizeVersionedOperationRef(
    '3.1.0',
    '#/paths/~1target/query',
    { paths: { '/target': { query: { responses: { 200: { description: 'ok' } } } } } },
  );
  assert.equal(invalid31Query.referenceResolution.unresolvedInternalReferences, 1);
  const invalid31Additional = summarizeVersionedOperationRef(
    '3.1.0',
    '#/paths/~1target/additionalOperations/COPY',
    {
      paths: {
        '/target': {
          additionalOperations: { COPY: { responses: { 200: { description: 'ok' } } } },
        },
      },
    },
  );
  assert.equal(invalid31Additional.referenceResolution.unresolvedInternalReferences, 1);
});

test('refs internas exigem tipo de alvo compatível e não só ponteiro existente', () => {
  const responseToSchema = collectOpenApiSummary({
    openapi: '3.1.0',
    paths: {
      '/items': {
        get: { responses: { 200: { $ref: '#/components/schemas/FakeResponse' } } },
      },
    },
    components: { schemas: { FakeResponse: { type: 'object', responses: {} } } },
  }, { url: 'https://api.example.test/openapi.json' });
  assert.equal(responseToSchema.referenceResolution.status, 'partial');
  assert.equal(responseToSchema.referenceResolution.unresolvedInternalReferences, 1);
  assert.ok(responseToSchema.referenceResolution.issueCodes.includes('reference_target_type_mismatch'));

  const pathItemToSchema = collectOpenApiSummary({
    openapi: '3.1.0',
    paths: { '/items': { $ref: '#/components/schemas/FakePathItem' } },
    components: { schemas: { FakePathItem: { type: 'object', get: { responses: {} } } } },
  }, { url: 'https://api.example.test/openapi.json' });
  assert.equal(pathItemToSchema.referenceResolution.status, 'partial');
  assert.equal(pathItemToSchema.operationCount, 0);

  const pathItemToPrimitive = collectOpenApiSummary({
    openapi: '3.1.0',
    paths: { '/items': { $ref: '#/components/pathItems/NotAPathItem' } },
    components: { pathItems: { NotAPathItem: 42 } },
  }, { url: 'https://api.example.test/openapi.json' });
  assert.equal(pathItemToPrimitive.referenceResolution.status, 'partial');
  assert.equal(pathItemToPrimitive.referenceResolution.unresolvedInternalReferences, 1);
  assert.ok(pathItemToPrimitive.referenceResolution.issueCodes.includes(
    'reference_target_type_mismatch',
  ));

  const discriminatorToResponse = collectOpenApiSummary({
    openapi: '3.1.0',
    paths: { '/items': { get: { responses: { 200: { description: 'ok' } } } } },
    components: {
      schemas: {
        Base: {
          type: 'object',
          discriminator: {
            propertyName: 'kind',
            mapping: { wrong: '#/components/responses/NotASchema' },
          },
        },
      },
      responses: { NotASchema: { description: 'not a schema' } },
    },
  }, { url: 'https://api.example.test/openapi.json' });
  assert.equal(discriminatorToResponse.referenceResolution.status, 'partial');
  assert.equal(discriminatorToResponse.referenceResolution.unresolvedInternalReferences, 1);
  assert.ok(discriminatorToResponse.referenceResolution.issueCodes.includes('reference_target_type_mismatch'));
});

test('refs preservam role de requestBody e aceitam Schema booleano somente em alvo Schema', () => {
  const source = { url: 'https://api.example.test/openapi.json' };
  const valid = collectOpenApiSummary({
    openapi: '3.1.0',
    paths: {
      '/items': {
        post: {
          requestBody: { $ref: '#/components/requestBodies/Payload' },
          responses: { 204: { description: 'ok' } },
        },
      },
    },
    components: {
      requestBodies: {
        Payload: { content: { 'application/json': { schema: { type: 'object' } } } },
      },
      schemas: {
        Disabled: false,
        DisabledRef: { $ref: '#/components/schemas/Disabled' },
      },
    },
  }, source);
  assert.equal(valid.referenceResolution.status, 'complete');
  assert.equal(valid.referenceResolution.referencesSeen, 2);
  assert.equal(valid.referenceResolution.unresolvedInternalReferences, 0);

  const wrongBooleanTarget = collectOpenApiSummary({
    openapi: '3.1.0',
    paths: {
      '/items': {
        post: {
          requestBody: { required: false },
          responses: { 204: { description: 'ok' } },
        },
      },
    },
    components: {
      schemas: { Wrong: { $ref: '#/paths/~1items/post/requestBody/required' } },
    },
  }, source);
  assert.equal(wrongBooleanTarget.referenceResolution.status, 'partial');
  assert.equal(wrongBooleanTarget.referenceResolution.unresolvedInternalReferences, 1);
  assert.ok(wrongBooleanTarget.referenceResolution.issueCodes.includes(
    'reference_target_type_mismatch',
  ));
});

test('dados runtime de Link são opacos e additionalOperations não aceita método fixo', () => {
  const source = { url: 'https://api.example.test/openapi.json' };
  const linkLiteral = collectOpenApiSummary({
    openapi: '3.1.0',
    paths: {
      '/items': {
        get: {
          responses: {
            200: {
              description: 'ok',
              links: {
                next: {
                  operationId: 'nextPage',
                  parameters: {
                    id: { $ref: 'https://literal.example.test/parameter.json' },
                  },
                  requestBody: { $ref: 'https://literal.example.test/body.json' },
                },
              },
            },
          },
        },
      },
    },
  }, source);
  assert.equal(linkLiteral.referenceResolution.status, 'complete');
  assert.equal(linkLiteral.referenceResolution.referencesSeen, 0);

  const fixedAdditionalOperation = collectOpenApiSummary({
    openapi: '3.2.0',
    paths: {
      '/source': {
        get: {
          responses: {
            200: {
              description: 'ok',
              links: {
                invalid: {
                  operationRef: '#/components/pathItems/Target/additionalOperations/POST',
                },
              },
            },
          },
        },
      },
    },
    components: {
      pathItems: {
        Target: {
          additionalOperations: {
            POST: { responses: { 200: { description: 'invalid duplicate' } } },
          },
        },
      },
    },
  }, source);
  assert.equal(fixedAdditionalOperation.referenceResolution.status, 'partial');
  assert.equal(fixedAdditionalOperation.referenceResolution.unresolvedInternalReferences, 1);
});

test('scanner aplica keywords do draft correto e falha fechado para dialeto desconhecido', () => {
  const source = { url: 'https://api.example.test/openapi.json' };
  const path = {
    '/items': { get: { responses: { 200: { description: 'ok' } } } },
  };
  for (const document of [
    {
      swagger: '2.0',
      paths: path,
      definitions: {
        Value: { type: 'string', if: { $ref: 'https://literal.example.test/v2.json' } },
      },
    },
    {
      openapi: '3.0.3',
      paths: path,
      components: {
        schemas: {
          Value: { type: 'string', if: { $ref: 'https://literal.example.test/v30.json' } },
        },
      },
    },
    {
      openapi: '3.1.0',
      paths: path,
      components: {
        schemas: {
          Value: {
            type: 'string',
            additionalItems: { $ref: 'https://literal.example.test/v31.json' },
          },
        },
      },
    },
  ]) {
    const summary = collectOpenApiSummary(document, source);
    assert.equal(summary.referenceResolution.status, 'complete');
    assert.equal(summary.referenceResolution.referencesSeen, 0);
  }

  const withoutAnnotation = {
    openapi: '3.1.0',
    paths: path,
    components: { schemas: { Value: { type: 'string' } } },
  };
  const withAnnotation = structuredClone(withoutAnnotation);
  withAnnotation.components.schemas.Value.customAnnotation = { color: 'red' };
  assert.equal(
    collectOpenApiSummary(withoutAnnotation, source).hash,
    collectOpenApiSummary(withAnnotation, source).hash,
  );

  const unsupportedRoot = collectOpenApiSummary({
    ...withoutAnnotation,
    jsonSchemaDialect: 'https://dialects.example.test/custom',
  }, source);
  assert.equal(unsupportedRoot.referenceResolution.status, 'partial');
  assert.ok(unsupportedRoot.referenceResolution.issueCodes.includes('unsupported_schema_dialect'));

  const unsupportedNested = structuredClone(withoutAnnotation);
  unsupportedNested.components.schemas.Value.$schema = 'https://dialects.example.test/custom';
  const nestedSummary = collectOpenApiSummary(unsupportedNested, source);
  assert.equal(nestedSummary.referenceResolution.status, 'partial');
  assert.ok(nestedSummary.referenceResolution.issueCodes.includes('unsupported_schema_dialect'));

  const standardDialect = collectOpenApiSummary({
    ...withoutAnnotation,
    jsonSchemaDialect: 'https://json-schema.org/draft/2020-12/schema#',
  }, source);
  assert.equal(standardDialect.referenceResolution.status, 'complete');
  const standardDialectWithoutFragment = collectOpenApiSummary({
    ...withoutAnnotation,
    jsonSchemaDialect: 'https://json-schema.org/draft/2020-12/schema',
  }, source);
  assert.equal(standardDialect.hash, standardDialectWithoutFragment.hash);
});

test('v8 preserva contexto de subschema, ignora examples e normaliza URIs equivalentes', () => {
  const sourceUrl = 'https://api.example.test/openapi.json';
  const nestedResource = collectOpenApiSummary({
    openapi: '3.1.0',
    paths: { '/items': { get: { responses: { 200: { description: 'ok' } } } } },
    components: {
      schemas: {
        Container: {
          allOf: [{ $id: 'embedded.json', $anchor: 'Embedded', type: 'string' }],
        },
        Ref: { $ref: 'embedded.json#Embedded' },
        LiteralExamples: {
          type: 'object',
          examples: [{ $ref: 'https://outside.test/is-instance-data.json' }],
        },
        EmptyId: { $id: '', type: 'string' },
      },
    },
  }, { url: sourceUrl });
  assert.equal(nestedResource.referenceResolution.status, 'complete');
  assert.equal(nestedResource.referenceResolution.referencesSeen, 1);

  const makeDocument = (reference) => ({
    openapi: '3.1.0',
    paths: {
      '/items': {
        get: { responses: { 200: { $ref: reference } } },
      },
    },
    components: { responses: { Ok: { description: 'ok' } } },
  });
  const relative = collectOpenApiSummary(
    makeDocument('#/components/responses/Ok'),
    { url: sourceUrl },
  );
  const absolute = collectOpenApiSummary(
    makeDocument(`${sourceUrl}#/components/responses/Ok`),
    { url: sourceUrl },
  );
  const encoded = collectOpenApiSummary(
    makeDocument('#%2Fcomponents%2Fresponses%2FOk'),
    { url: sourceUrl },
  );
  assert.equal(relative.hash, absolute.hash);
  assert.equal(relative.hash, encoded.hash);
  assert.equal(relative.referenceResolution.referenceSetHash, absolute.referenceResolution.referenceSetHash);
  assert.equal(relative.referenceResolution.referenceSetHash, encoded.referenceResolution.referenceSetHash);
  assert.equal(diffOpenApiSummaries(relative, absolute).changed, false);
  assert.equal(diffOpenApiSummaries(relative, encoded).changed, false);
});

test('v8 não usa a posição em allOf como identidade de recurso $id', () => {
  const makeDocument = (reverse = false) => ({
    openapi: '3.1.0',
    paths: {
      '/items': { get: { responses: { 200: { description: 'ok' } } } },
    },
    components: {
      schemas: {
        Container: {
          allOf: reverse
            ? [
                { $id: 'number.json', type: 'number' },
                { $id: 'string.json', type: 'string' },
              ]
            : [
                { $id: 'string.json', type: 'string' },
                { $id: 'number.json', type: 'number' },
              ],
        },
        StringValue: { $ref: 'string.json' },
        NumberValue: { $ref: 'number.json' },
      },
    },
  });
  const before = collectOpenApiSummary(makeDocument(), {
    url: 'https://api.example.test/openapi.json',
  });
  const reordered = collectOpenApiSummary(makeDocument(true), {
    url: 'https://api.example.test/openapi.json',
  });
  assert.equal(before.referenceResolution.status, 'complete');
  assert.equal(reordered.referenceResolution.status, 'complete');
  assert.equal(before.hash, reordered.hash);
  assert.equal(diffOpenApiSummaries(before, reordered).changed, false);
});

test('v8 normaliza $self e $id relativos ou absolutos para a mesma URI', () => {
  const makeDocument = ({ self, schemaId }) => ({
    openapi: '3.2.0',
    $self: self,
    paths: {
      '/items': { get: { responses: { 200: { description: 'ok' } } } },
    },
    components: {
      schemas: {
        Value: { $id: schemaId, type: 'string' },
        ValueRef: { $ref: 'schema.json' },
      },
    },
  });
  const sourceUrl = 'https://api.example.test/root.json';
  const relative = collectOpenApiSummary(makeDocument({
    self: './root.json',
    schemaId: './schema.json',
  }), { url: sourceUrl });
  const absolute = collectOpenApiSummary(makeDocument({
    self: sourceUrl,
    schemaId: 'https://api.example.test/schema.json',
  }), { url: sourceUrl });
  assert.equal(relative.referenceResolution.status, 'complete');
  assert.equal(absolute.referenceResolution.status, 'complete');
  assert.equal(relative.hash, absolute.hash);
  assert.equal(diffOpenApiSummaries(relative, absolute).changed, false);
});

test('v8 exige que operationRef interno aponte por JSON Pointer para Operation Object', () => {
  const summarizeOperationRef = (operationRef, additions = {}) => collectOpenApiSummary({
    openapi: '3.2.0',
    paths: {
      '/source': {
        get: {
          responses: {
            200: {
              description: 'ok',
              links: { next: { operationRef } },
            },
          },
        },
      },
      '/target': {
        get: { responses: { 200: { description: 'target' } } },
      },
    },
    components: {
      pathItems: {
        Shared: {
          post: { responses: { 204: { description: 'shared' } } },
        },
      },
      callbacks: {
        SharedCallback: {
          '{$request.body#/callbackUrl}': {
            post: { responses: { 202: { description: 'callback' } } },
          },
        },
      },
      schemas: {
        Anchored: { $anchor: 'SchemaAnchor', type: 'string' },
        Fake: {
          responses: {},
          callbacks: {
            nested: {
              path: { get: { responses: {} } },
            },
          },
        },
      },
    },
    ...additions,
  }, { url: 'https://api.example.test/openapi.json' });

  assert.equal(
    summarizeOperationRef('#/paths/~1target/get').referenceResolution.status,
    'complete',
  );
  assert.equal(
    summarizeOperationRef('#/components/pathItems/Shared/post').referenceResolution.status,
    'complete',
  );
  assert.equal(
    summarizeOperationRef(
      '#/components/callbacks/SharedCallback/%7B$request.body%23~1callbackUrl%7D/post',
    ).referenceResolution.status,
    'complete',
  );
  assert.equal(
    summarizeOperationRef(
      '#/paths/~1target/additionalOperations/COPY',
      {
        paths: {
          '/source': {
            get: {
              responses: {
                200: {
                  description: 'ok',
                  links: {
                    next: {
                      operationRef: '#/paths/~1target/additionalOperations/COPY',
                    },
                  },
                },
              },
            },
          },
          '/target': {
            additionalOperations: {
              COPY: { responses: { 200: { description: 'copied' } } },
            },
          },
        },
      },
    ).referenceResolution.status,
    'complete',
  );
  for (const invalid of [
    '',
    '#SchemaAnchor',
    '#/components/schemas/Fake',
    '#/components/schemas/Fake/callbacks/nested/path/get',
  ]) {
    const summary = summarizeOperationRef(invalid);
    assert.equal(summary.referenceResolution.status, 'partial');
    assert.equal(summary.referenceResolution.unresolvedInternalReferences, 1);
  }
});

test('v8 normaliza defaults contextuais equivalentes de Parameter Object', () => {
  const implicit = smallDocument('/items');
  const explicit = structuredClone(implicit);
  Object.assign(explicit.paths['/items'].get.parameters[0], {
    style: 'form',
    explode: true,
    deprecated: false,
    allowEmptyValue: false,
    allowReserved: false,
  });
  const implicitSummary = collectOpenApiSummary(implicit, {
    url: 'https://api.example.test/openapi.json',
  });
  const explicitSummary = collectOpenApiSummary(explicit, {
    url: 'https://api.example.test/openapi.json',
  });
  assert.equal(implicitSummary.hash, explicitSummary.hash);
  assert.equal(diffOpenApiSummaries(implicitSummary, explicitSummary).changed, false);
});

test('v8 normaliza defaults de Parameter e Request Body também em components', () => {
  const implicit = {
    openapi: '3.1.0',
    paths: {
      '/items': {
        post: {
          parameters: [{ $ref: '#/components/parameters/Query' }],
          requestBody: { $ref: '#/components/requestBodies/Payload' },
          responses: { 204: { description: 'ok' } },
        },
      },
    },
    components: {
      parameters: {
        Query: { name: 'q', in: 'query', schema: { type: 'string' } },
      },
      requestBodies: {
        Payload: {
          content: {
            'application/json': { schema: { type: 'object' } },
          },
        },
      },
    },
  };
  const explicit = structuredClone(implicit);
  Object.assign(explicit.components.parameters.Query, {
    required: false,
    deprecated: false,
    allowEmptyValue: false,
    allowReserved: false,
    style: 'form',
    explode: true,
  });
  explicit.components.requestBodies.Payload.required = false;

  const source = { url: 'https://api.example.test/openapi.json' };
  const implicitSummary = collectOpenApiSummary(implicit, source);
  const explicitSummary = collectOpenApiSummary(explicit, source);
  assert.equal(implicitSummary.hash, explicitSummary.hash);
  assert.equal(diffOpenApiSummaries(implicitSummary, explicitSummary).changed, false);

  explicit.components.parameters.Query.explode = false;
  assert.notEqual(collectOpenApiSummary(explicit, source).hash, implicitSummary.hash);
});

test('v8 normaliza defaults equivalentes de Header Object em todos os contextos', () => {
  const implicit = {
    openapi: '3.1.0',
    paths: {
      '/upload': {
        post: {
          requestBody: {
            content: {
              'multipart/form-data': {
                schema: { type: 'object' },
                encoding: {
                  file: {
                    headers: {
                      'X-Chunk': { schema: { type: 'integer' } },
                    },
                  },
                },
              },
            },
          },
          responses: {
            200: {
              description: 'ok',
              headers: {
                'X-Rate-Limit': { schema: { type: 'integer' } },
              },
            },
          },
        },
      },
    },
    components: {
      headers: {
        Shared: { schema: { type: 'string' } },
      },
    },
  };
  const explicit = structuredClone(implicit);
  const headers = [
    explicit.paths['/upload'].post.responses[200].headers['X-Rate-Limit'],
    explicit.paths['/upload'].post.requestBody.content['multipart/form-data']
      .encoding.file.headers['X-Chunk'],
    explicit.components.headers.Shared,
  ];
  for (const header of headers) {
    Object.assign(header, {
      required: false,
      deprecated: false,
      style: 'simple',
      explode: false,
    });
  }

  const source = { url: 'https://api.example.test/openapi.json' };
  const implicitSummary = collectOpenApiSummary(implicit, source);
  const explicitSummary = collectOpenApiSummary(explicit, source);
  assert.equal(implicitSummary.hash, explicitSummary.hash);
  assert.equal(diffOpenApiSummaries(implicitSummary, explicitSummary).changed, false);

  const changed = structuredClone(explicit);
  changed.components.headers.Shared.required = true;
  assert.notEqual(collectOpenApiSummary(changed, source).hash, implicitSummary.hash);

  const contentBranch = structuredClone(implicit);
  contentBranch.components.headers.Shared = {
    content: { 'text/plain': { schema: { type: 'string' } } },
    style: 'simple',
  };
  const contentWithoutStyle = structuredClone(contentBranch);
  delete contentWithoutStyle.components.headers.Shared.style;
  assert.notEqual(
    collectOpenApiSummary(contentBranch, source).hash,
    collectOpenApiSummary(contentWithoutStyle, source).hash,
  );

  const swaggerImplicit = {
    swagger: '2.0',
    paths: {
      '/items': {
        get: {
          responses: {
            200: {
              description: 'ok',
              headers: { 'X-Values': { type: 'array', items: { type: 'string' } } },
            },
          },
        },
      },
    },
  };
  const swaggerExplicit = structuredClone(swaggerImplicit);
  swaggerExplicit.paths['/items'].get.responses[200]
    .headers['X-Values'].collectionFormat = 'csv';
  assert.equal(
    collectOpenApiSummary(swaggerImplicit, source).hash,
    collectOpenApiSummary(swaggerExplicit, source).hash,
  );
  swaggerExplicit.paths['/items'].get.responses[200]
    .headers['X-Values'].collectionFormat = 'ssv';
  assert.notEqual(
    collectOpenApiSummary(swaggerImplicit, source).hash,
    collectOpenApiSummary(swaggerExplicit, source).hash,
  );
});

test('duplicata partial permanece inconclusiva na cobertura', async () => {
  const partialDocument = {
    openapi: '3.1.0',
    paths: {
      '/items': {
        get: {
          responses: {
            200: { $ref: 'https://schemas.outside.test/common.yaml#/Ok' },
          },
        },
      },
    },
  };
  const result = await fetchOpenApiContracts({
    origins: ['https://api.example.test'],
    domain: 'example.test',
    detailed: true,
    fetchImpl: async (url) => {
      const pathname = new URL(url).pathname;
      if (['/openapi.json', '/openapi.yaml'].includes(pathname)) {
        return response('', { status: 302, headers: { location: '/contracts/shared.json' } });
      }
      if (pathname === '/contracts/shared.json') return response(partialDocument);
      return notFound();
    },
  });

  assert.equal(result.status, 'partial');
  assert.equal(result.summaries.length, 1);
  assert.equal(result.coverage.duplicates, 1);
  assert.equal(result.coverage.candidatesEvaluated, 10);
  assert.equal(result.coverage.candidatesConclusive, 8);
  assert.equal(result.coverage.candidatesInconclusive, 2);
  assert.equal(result.coverage.complete, false);
  assert.ok(result.outcomes.some((item) => item.state === 'external_ref_unresolved'));
  assert.ok(result.outcomes.some((item) => item.state === 'duplicate_contract'));
});

test('limite de aliases aceita 250 totais e rejeita fallback distinto como o 251º', () => {
  const aliases = Array.from(
    { length: 250 },
    (_, index) => `https://api.example.test/contracts/${index}.json`,
  );
  const atLimit = collectOpenApiSummary(smallDocument(), {
    url: aliases[0],
    sourceAliases: aliases,
  });
  assert.equal(atLimit.sourceAliases.length, 250);
  const roundtrip = extractApiContractSnapshots({
    id: 92,
    findings: [{
      type: 'api_contract_snapshot',
      verification: {
        evidence: { apiContractSnapshot: createApiContractSnapshot(atLimit) },
      },
    }],
  });
  assert.equal(roundtrip.length, 1);
  assert.equal(roundtrip[0].summary.sourceAliases.length, 250);
  assert.deepEqual(roundtrip[0].summary.sourceAliases, atLimit.sourceAliases);

  assert.throws(
    () => collectOpenApiSummary(smallDocument(), {
      url: 'https://api.example.test/contracts/fallback-distinct.json',
      sourceAliases: aliases,
    }),
    (error) => error?.code === 'API_CONTRACT_ALIAS_LIMIT',
  );
});

test('100 snapshots pequenos serializam integralmente sob o limite default', () => {
  const previousLimit = process.env.GHOSTRECON_FINDINGS_SNAPSHOT_MAX_BYTES;
  try {
    delete process.env.GHOSTRECON_FINDINGS_SNAPSHOT_MAX_BYTES;
    const findings = Array.from({ length: 100 }, (_, index) => {
      const summary = collectOpenApiSummary(smallDocument(`/resource-${index}`), {
        url: `https://api.example.test/contracts/${index}.json`,
      });
      return {
        type: 'api_contract_snapshot',
        prio: 'info',
        score: 22,
        value: `snapshot ${index}`,
        meta: 'source=api_contract_diff',
        url: summary.url,
        verification: {
          classification: 'noisy',
          confidenceScore: 1,
          verifiedAt: '2026-09-11T12:00:00.000Z',
          evidence: {
            evidenceHash: summary.hash,
            apiContractSnapshot: createApiContractSnapshot(summary),
          },
        },
      };
    });

    const serialized = serializeFindingsForRunSnapshot(findings);
    assert.equal(typeof serialized, 'string');
    assert.ok(Buffer.byteLength(serialized, 'utf8') < 32_000_000);
    const payload = JSON.parse(serialized);
    assert.equal(payload.truncated, false);
    assert.equal(payload.count, 100);
    assert.equal(payload.findings.length, 100);
    assert.equal(extractApiContractSnapshots({ id: 93, findings: payload.findings }).length, 100);
  } finally {
    if (previousLimit == null) delete process.env.GHOSTRECON_FINDINGS_SNAPSHOT_MAX_BYTES;
    else process.env.GHOSTRECON_FINDINGS_SNAPSHOT_MAX_BYTES = previousLimit;
  }
});

test('coletor usa concorrência 2 com commit determinístico e serializa em stealth', async () => {
  const exercise = async (modules) => {
    let active = 0;
    let maxActive = 0;
    const completed = [];
    const result = await fetchOpenApiContracts({
      origins: ['https://api.example.test'],
      domain: 'example.test',
      modules,
      detailed: true,
      pauseImpl: async () => {},
      fetchImpl: async (url) => {
        const pathname = new URL(url).pathname;
        active += 1;
        maxActive = Math.max(maxActive, active);
        try {
          await new Promise((resolve) => setTimeout(
            resolve,
            pathname === '/openapi.json' ? 12 : 1,
          ));
          completed.push(pathname);
          return notFound();
        } finally {
          active -= 1;
        }
      },
    });
    return { result, maxActive, completed };
  };

  const normal = await exercise([]);
  assert.equal(normal.maxActive, 2);
  assert.equal(normal.result.coverage.effectiveConcurrency, 2);
  assert.deepEqual(
    normal.result.outcomes.slice(0, 2).map((item) => new URL(item.url).pathname),
    ['/openapi.json', '/openapi.yaml'],
  );
  assert.deepEqual(normal.completed.slice(0, 2), ['/openapi.yaml', '/openapi.json']);

  const stealth = await exercise(['stealth_requests']);
  assert.equal(stealth.maxActive, 1);
  assert.equal(stealth.result.coverage.effectiveConcurrency, 1);
});

test('deadline próprio preserva snapshot parcial; cancelamento do operador relança a razão', async () => {
  const hangingFetch = (controller = null) => async (url, init = {}) => {
    const pathname = new URL(url).pathname;
    if (pathname === '/openapi.json') {
      if (controller) setTimeout(() => controller.abort(controller._reason), 10);
      return response(smallDocument('/preserved'));
    }
    if (pathname === '/openapi.yaml') {
      return new Promise((resolve, reject) => {
        const keepAlive = setTimeout(() => resolve(notFound()), 2_000);
        const onAbort = () => {
          clearTimeout(keepAlive);
          reject(init.signal?.reason || new DOMException('aborted', 'AbortError'));
        };
        init.signal?.addEventListener('abort', onAbort, { once: true });
        if (init.signal?.aborted) onAbort();
      });
    }
    return notFound();
  };

  const timed = await runApiContractDiff({
    origins: ['https://api.example.test'],
    domain: 'example.test',
    timeoutMs: 90,
    fetchImpl: hangingFetch(),
  });
  assert.equal(timed.status, 'timeout');
  assert.equal(timed.reason, 'module_deadline_exhausted');
  assert.equal(timed.summaries.length, 1);
  assert.equal(timed.findings.filter((item) => item.type === 'api_contract_snapshot').length, 1);
  assert.equal(timed.metrics.coverage.deadlineReached, true);
  assert.equal(timed.metrics.coverage.candidatesAbortedByDeadline, 1);
  assert.equal(timed.metrics.coverage.candidatesSkippedByDeadline, 8);
  assert.ok(timed.outcomes.some((item) => item.state === 'module_deadline_exhausted'));

  const controller = new AbortController();
  const reason = new Error('operator_cancelled_exactly');
  controller._reason = reason;
  await assert.rejects(
    runApiContractDiff({
      origins: ['https://api.example.test'],
      domain: 'example.test',
      timeoutMs: 1_000,
      signal: controller.signal,
      fetchImpl: hangingFetch(controller),
    }),
    (error) => error === reason,
  );
});

test('timeout por request continua a coleta sem ser confundido com deadline do módulo', async () => {
  const result = await fetchOpenApiContracts({
    origins: ['https://api.example.test'],
    domain: 'example.test',
    detailed: true,
    timeoutMs: 1_000,
    perRequestTimeoutMs: 25,
    fetchImpl: async (url, init = {}) => {
      if (new URL(url).pathname !== '/openapi.json') return notFound();
      return new Promise((resolve, reject) => {
        const keepAlive = setTimeout(() => resolve(notFound()), 2_000);
        const onAbort = () => {
          clearTimeout(keepAlive);
          reject(init.signal?.reason || new DOMException('aborted', 'AbortError'));
        };
        init.signal?.addEventListener('abort', onAbort, { once: true });
        if (init.signal?.aborted) onAbort();
      });
    },
  });
  assert.equal(result.status, 'partial');
  assert.equal(result.coverage.deadlineReached, false);
  assert.equal(result.coverage.candidatesEvaluated, SPEC_PATHS.length);
  assert.ok(result.outcomes.some((item) => item.state === 'timeout'));
  assert.equal(result.outcomes.some((item) => item.state === 'module_deadline_exhausted'), false);
});

test('scanner de referências interrompe mapa escalar assim que o deadline vence', () => {
  const originalNow = Date.now;
  let virtualNow = 1_000;
  let scalarReads = 0;
  const rawProperties = Object.fromEntries(Array.from(
    { length: 512 },
    (_, index) => [`field_${index}`, true],
  ));
  const properties = new Proxy(rawProperties, {
    get(target, property, receiver) {
      if (typeof property === 'string' && property.startsWith('field_')) {
        scalarReads += 1;
        virtualNow = 2_000;
      }
      return Reflect.get(target, property, receiver);
    },
  });
  Date.now = () => virtualNow;
  try {
    assert.throws(
      () => collectOpenApiSummary({
        openapi: '3.1.0',
        paths: {},
        components: {
          schemas: {
            Large: { type: 'object', properties },
          },
        },
      }, { deadlineAt: 1_500 }),
      (error) => error?.code === 'API_CONTRACT_DEADLINE',
    );
    assert.ok(
      scalarReads < Object.keys(rawProperties).length,
      `deadline deveria interromper antes de ler 512 escalares; leu ${scalarReads}`,
    );
  } finally {
    Date.now = originalNow;
  }
});

test('deadline explícito resiste a starvation e aceita timeouts fracionários', async () => {
  let calls = 0;
  const startedAt = Date.now();
  const timed = await fetchOpenApiContracts({
    origins: ['https://api.example.test'],
    domain: 'example.test',
    detailed: true,
    timeoutMs: 5.9,
    pauseImpl: async () => {},
    fetchImpl: async () => {
      calls += 1;
      const busyUntil = Date.now() + 8;
      while (Date.now() < busyUntil) {
        // Simula parser/transporte síncrono que impede o timer de disparar.
      }
      return notFound();
    },
  });
  assert.equal(timed.status, 'timeout');
  assert.equal(timed.coverage.deadlineReached, true);
  assert.ok(calls <= 2, `esperava no máximo um lote, recebeu ${calls} requests`);
  assert.ok(Date.now() - startedAt < 250);

  const fractional = await fetchOpenApiContracts({
    origins: ['https://api.example.test'],
    domain: 'example.test',
    detailed: true,
    timeoutMs: 500.5,
    perRequestTimeoutMs: 100.5,
    pauseImpl: async () => {},
    fetchImpl: async () => notFound(),
  });
  assert.equal(fractional.status, 'done');
});

test('pause que ignora AbortSignal não prende o coletor além do deadline', async () => {
  const startedAt = Date.now();
  const result = await fetchOpenApiContracts({
    origins: ['https://api.example.test'],
    domain: 'example.test',
    detailed: true,
    timeoutMs: 20,
    pauseImpl: async () => new Promise(() => {}),
    fetchImpl: async () => notFound(),
  });
  assert.equal(result.status, 'timeout');
  assert.equal(result.coverage.deadlineReached, true);
  assert.ok(Date.now() - startedAt < 250);
});

test('pause síncrona que cruza o deadline não inicia requests tardias', async () => {
  let calls = 0;
  const result = await fetchOpenApiContracts({
    origins: ['https://api.example.test'],
    domain: 'example.test',
    detailed: true,
    timeoutMs: 5,
    pauseImpl: async () => {
      const busyUntil = Date.now() + 8;
      while (Date.now() < busyUntil) {
        // Simula uma política síncrona que bloqueia o timer do AbortSignal.
      }
    },
    fetchImpl: async () => {
      calls += 1;
      return notFound();
    },
  });
  assert.equal(result.status, 'timeout');
  assert.equal(calls, 0);
  assert.equal(result.coverage.candidatesConclusive, 0);
});

test('materialização detecta deadline após busca síncrona custosa de baseline', async () => {
  const sourceUrl = 'https://api.example.test/openapi.json';
  const previous = collectOpenApiSummary(smallDocument(), { url: sourceUrl });
  const baselineRows = [{
    runId: 701,
    summary: previous,
    integrityVerified: true,
  }];
  const delayedBaselines = new Proxy(baselineRows, {
    get(target, property, receiver) {
      if (property !== Symbol.iterator) return Reflect.get(target, property, receiver);
      return function* delayedIterator() {
        const busyUntil = Date.now() + 120;
        while (Date.now() < busyUntil) {
          // Exercita o checkpoint imediatamente posterior à seleção do baseline.
        }
        yield* target;
      };
    },
  });
  const result = await runApiContractDiff({
    origins: ['https://api.example.test'],
    domain: 'example.test',
    timeoutMs: 80.9,
    previousSnapshots: delayedBaselines,
    fetchImpl: async (url) => (
      new URL(url).pathname === '/openapi.json'
        ? response(smallDocument())
        : notFound()
    ),
  });
  assert.equal(result.status, 'timeout');
  assert.equal(result.reason, 'materialization_deadline_exhausted');
  assert.equal(result.metrics.snapshotsMaterialized, 1);
  assert.equal(result.findings.filter((item) => item.type === 'api_contract_snapshot').length, 1);
  assert.equal(result.findings.some((item) => item.type === 'api_contract_diff'), false);
});
