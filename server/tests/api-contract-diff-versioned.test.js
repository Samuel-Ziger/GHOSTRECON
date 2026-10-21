import { createHash } from 'node:crypto';
import test from 'node:test';
import assert from 'node:assert/strict';

import {
  API_CONTRACT_CANONICALIZATION_VERSION,
  API_CONTRACT_SNAPSHOT_FORMAT,
  API_CONTRACT_SNAPSHOT_SCHEMA_VERSION,
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
import { moduleRunners } from '../modules/module-registry-runners.mjs';

function baseDocument() {
  return {
    openapi: '3.1.0',
    info: { title: 'Example API', version: '1.0.0', description: 'documentação A' },
    servers: [{ url: 'https://api.example.test/v1' }],
    security: [{ oauth: ['write', 'read'] }],
    paths: {
      '/users': {
        parameters: [{ name: 'tenant', in: 'header', required: true, schema: { type: 'string' } }],
        post: {
          operationId: 'createUser',
          tags: ['users', 'write'],
          parameters: [
            { name: 'verbose', in: 'query', schema: { type: 'boolean' } },
            { name: 'limit', in: 'query', schema: { type: 'integer', minimum: 1 } },
          ],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['email', 'name'],
                  properties: { name: { type: 'string' }, email: { type: 'string' } },
                },
              },
            },
          },
          responses: {
            201: {
              description: 'created',
              content: { 'application/json': { schema: { $ref: '#/components/schemas/User' } } },
            },
          },
        },
      },
    },
    components: {
      securitySchemes: {
        oauth: {
          type: 'oauth2',
          flows: {
            clientCredentials: {
              tokenUrl: 'https://id.example.test/token',
              scopes: { read: 'read', write: 'write' },
            },
          },
        },
      },
      schemas: {
        User: {
          type: 'object',
          required: ['id', 'email'],
          properties: { id: { type: 'string' }, email: { type: 'string' } },
        },
      },
    },
  };
}

function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function legacyV1Summary() {
  const summary = {
    schemaVersion: 1,
    url: 'https://api.example.test/openapi.json',
    version: '3.0.3',
    title: 'Legacy API',
    apiVersion: '1',
    pathCount: 1,
    operationCount: 1,
    paramCount: 1,
    securitySchemes: [{ name: 'bearer', type: 'http', scheme: 'bearer', in: '' }],
    operationsWithoutSecurity: 0,
    operations: [{
      id: 'GET /users',
      method: 'GET',
      path: '/users',
      operationId: 'listUsers',
      tags: ['users'],
      params: ['query:limit'],
      requestBody: false,
      responses: ['200'],
      hasSecurity: true,
    }],
  };
  summary.hash = createHash('sha256').update(stableJson({
    version: summary.version,
    title: summary.title,
    apiVersion: summary.apiVersion,
    securitySchemes: summary.securitySchemes,
    operations: summary.operations,
  })).digest('hex');
  return summary;
}

function jsonResponse(body, status = 200, headers = {}) {
  return new Response(typeof body === 'string' ? body : JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });
}

test('snapshot v2 é determinístico para reordenações semanticamente equivalentes', () => {
  const first = baseDocument();
  const second = structuredClone(first);
  second.info.description = 'documentação alterada sem mudar contrato';
  second.paths['/users'].post.tags.reverse();
  second.paths['/users'].post.parameters.reverse();
  second.paths['/users'].post.requestBody.content['application/json'].schema.required.reverse();
  second.components.schemas.User.required.reverse();
  second.security[0].oauth.reverse();

  const a = collectOpenApiSummary(first, {
    url: 'https://api.example.test/openapi.json?z=2&a=1#fragment',
  });
  const b = collectOpenApiSummary(second, {
    url: 'https://api.example.test/openapi.json?a=1&z=2',
  });
  assert.equal(a.schemaVersion, API_CONTRACT_SNAPSHOT_SCHEMA_VERSION);
  assert.equal(a.canonicalizationVersion, API_CONTRACT_CANONICALIZATION_VERSION);
  assert.equal(a.url, 'https://api.example.test/openapi.json?a=1&z=2');
  assert.equal(a.hash, b.hash);
  assert.equal(diffOpenApiSummaries(a, b).changed, false);

  const envelope = createApiContractSnapshot(a);
  assert.equal(envelope.format, API_CONTRACT_SNAPSHOT_FORMAT);
  assert.equal(envelope.summaryHash, a.hash);
  assert.equal(envelope.provenance.sourceUrl, a.url);
});

test('diff semântico identifica schemas, respostas, autenticação e servidor alterados', () => {
  const before = baseDocument();
  const after = structuredClone(before);
  after.servers[0].url = 'https://api.example.test/v2';
  after.paths['/users'].post.security = [];
  after.paths['/users'].post.parameters[0].schema.type = 'string';
  after.paths['/users'].post.requestBody.content['application/json'].schema.properties.name.maxLength = 80;
  after.paths['/users'].post.responses[201].content['application/json'].schema = {
    type: 'object', properties: { id: { type: 'integer' } },
  };

  const a = collectOpenApiSummary(before, { url: 'https://api.example.test/openapi.json' });
  const b = collectOpenApiSummary(after, { url: 'https://api.example.test/openapi.json' });
  const diff = diffOpenApiSummaries(a, b);
  assert.equal(diff.changed, true);
  assert.equal(diff.serversChanged, true);
  assert.deepEqual(diff.securityRegressions, ['POST /users']);
  const operation = diff.modifiedOperations.find((item) => item.id === 'POST /users');
  assert.ok(operation);
  assert.ok(operation.changes.includes('parameter_contract'));
  assert.ok(operation.changes.includes('request_body_contract'));
  assert.ok(operation.changes.includes('response_contract'));
  assert.ok(operation.changes.includes('security_requirement'));
});

test('Swagger 2 reconhece body parameter herdado do Path Item', () => {
  const summary = collectOpenApiSummary({
    swagger: '2.0',
    paths: {
      '/items': {
        parameters: [{ name: 'body', in: 'body', schema: { type: 'object' } }],
        post: { responses: { 204: { description: 'ok' } } },
      },
    },
  }, { url: 'https://api.example.test/swagger.json' });
  assert.equal(summary.operations[0].requestBody, true);
  assert.match(summary.operations[0].requestBodySignature, /^sha256:/);
});

test('migra snapshot v1 de forma explícita e recusa integridade adulterada', () => {
  const legacy = legacyV1Summary();
  const migrated = migrateApiContractSummary(legacy);
  assert.equal(migrated.schemaVersion, 2);
  assert.equal(migrated.compatibility.sourceSchemaVersion, 1);
  assert.equal(migrated.compatibility.detailLevel, 'legacy_v1');
  assert.ok(migrated.compatibility.lossyFields.includes('response_schemas'));

  assert.throws(
    () => migrateApiContractSummary({ ...legacy, hash: '0'.repeat(64) }),
    (error) => error?.code === 'API_CONTRACT_INTEGRITY_MISMATCH',
  );
});

test('diff compatível com snapshot v1 compara somente dimensões compartilhadas', () => {
  const legacy = legacyV1Summary();
  // Esses contadores não integravam o hash v1 e não podem declarar mudança.
  legacy.pathCount = 99;
  const currentDocument = {
    openapi: '3.0.3',
    info: { title: 'Legacy API', version: '1' },
    security: [{ bearer: [] }],
    paths: {
      '/users': {
        get: {
          operationId: 'listUsers',
          tags: ['users'],
          parameters: [{ name: 'limit', in: 'query', schema: { type: 'integer' } }],
          responses: { 200: { description: 'ok' } },
        },
      },
    },
    components: {
      securitySchemes: {
        bearer: { type: 'http', scheme: 'bearer' },
      },
    },
  };
  const current = collectOpenApiSummary(currentDocument, { url: legacy.url });
  const equal = diffOpenApiSummaries(legacy, current);
  assert.notEqual(migrateApiContractSummary(legacy).hash, current.hash);
  assert.equal(equal.comparisonDetail, 'legacy_compatible');
  assert.equal(equal.changed, false);
  assert.equal(equal.unclassifiedContractChanged, false);

  const expandedDocument = structuredClone(currentDocument);
  expandedDocument.paths['/health'] = {
    get: { responses: { 200: { description: 'ok' } } },
  };
  const expanded = collectOpenApiSummary(expandedDocument, { url: legacy.url });
  const changed = diffOpenApiSummaries(legacy, expanded);
  assert.equal(changed.changed, true);
  assert.deepEqual(changed.addedOperations, ['GET /health']);
  assert.equal(previousApiContractSnapshotFor(current, [
    { runId: 1, summary: legacy },
  ]), null);
});

test('snapshot v2 recusa contadores, hash e proveniência inconsistentes', () => {
  const summary = collectOpenApiSummary(baseDocument(), {
    url: 'https://api.example.test/openapi.json',
  });
  assert.throws(
    () => migrateApiContractSummary({ ...summary, operationCount: 99 }),
    (error) => error?.code === 'API_CONTRACT_INCONSISTENT_SUMMARY',
  );
  assert.throws(
    () => migrateApiContractSummary({ ...summary, hash: 'f'.repeat(64) }),
    (error) => error?.code === 'API_CONTRACT_INTEGRITY_MISMATCH',
  );

  const envelope = createApiContractSnapshot(summary);
  const run = {
    id: 7,
    created_at: '2026-09-09T12:00:00.000Z',
    findings: [{
      type: 'api_contract_snapshot',
      verification: { evidence: { apiContractSnapshot: envelope } },
    }],
  };
  assert.equal(extractApiContractSnapshots(run).length, 1);
  envelope.provenance.sourceUrl = 'https://other.example.test/openapi.json';
  assert.deepEqual(extractApiContractSnapshots(run), []);

  const reassigned = createApiContractSnapshot(summary);
  reassigned.summary.url = 'https://other.example.test/openapi.json';
  reassigned.summary.resolvedUrl = 'https://other.example.test/openapi.json';
  reassigned.provenance.sourceUrl = reassigned.summary.url;
  reassigned.provenance.resolvedSourceUrl = reassigned.summary.resolvedUrl;
  assert.deepEqual(extractApiContractSnapshots({
    ...run,
    findings: [{
      type: 'api_contract_snapshot',
      verification: { evidence: { apiContractSnapshot: reassigned } },
    }],
  }), []);
});

test('coleta tenta paths seguintes, preserva outcomes e não usa rede real', async () => {
  const calls = [];
  const result = await fetchOpenApiContracts({
    origins: ['https://api.example.test'],
    domain: 'example.test',
    detailed: true,
    fetchImpl: async (url) => {
      calls.push(url);
      const pathname = new URL(url).pathname;
      if (pathname === '/openapi.json') return jsonResponse('{invalid');
      if (pathname === '/swagger.json') return jsonResponse(baseDocument());
      return jsonResponse('', 404);
    },
  });
  assert.equal(result.status, 'partial');
  assert.equal(result.summaries.length, 1);
  assert.equal(result.outcomes[0].state, 'invalid_json');
  assert.equal(result.outcomes[3].state, 'done');
  assert.equal(result.coverage.candidatesEvaluated, 10);
  assert.equal(result.coverage.candidatesInconclusive, 1);
  assert.deepEqual(calls, [
    'https://api.example.test/openapi.json',
    'https://api.example.test/openapi.yaml',
    'https://api.example.test/openapi.yml',
    'https://api.example.test/swagger.json',
    'https://api.example.test/swagger.yaml',
    'https://api.example.test/swagger.yml',
    'https://api.example.test/v2/api-docs',
    'https://api.example.test/v3/api-docs',
    'https://api.example.test/api-docs/swagger.json',
    'https://api.example.test/swagger/v1/swagger.json',
  ]);
});

test('falha HTTP sem contrato produz cobertura parcial em vez de negativo falso', async () => {
  const result = await runApiContractDiff({
    origins: ['https://api.example.test'],
    domain: 'example.test',
    fetchImpl: async (url) => url.endsWith('/openapi.json')
      ? jsonResponse({ error: 'temporary' }, 500)
      : jsonResponse('', 404),
  });
  assert.equal(result.status, 'partial');
  assert.equal(result.summaries.length, 0);
  assert.ok(result.outcomes.some((outcome) => outcome.state === 'http_error'));
  assert.equal(result.metrics.status, 'partial');
});

test('origem ausente é skipped e resposta negada deixa cobertura parcial', async () => {
  const skipped = await runApiContractDiff({
    origins: [],
    domain: 'example.test',
    fetchImpl: async () => { throw new Error('unexpected network'); },
  });
  assert.equal(skipped.status, 'skipped');
  assert.equal(skipped.reason, 'no_http_origins_in_scope');
  assert.deepEqual(skipped.outcomes, []);

  const denied = await runApiContractDiff({
    origins: ['https://example.test'],
    domain: 'example.test',
    fetchImpl: async () => jsonResponse('', 403),
  });
  assert.equal(denied.status, 'partial');
  assert.equal(denied.outcomes.every((outcome) => outcome.state === 'denied'), true);
});

test('escopo e cancelamento falham antes de qualquer request', async () => {
  let calls = 0;
  const scoped = await fetchOpenApiContracts({
    origins: ['https://outside.test'],
    domain: 'example.test',
    detailed: true,
    fetchImpl: async () => { calls += 1; throw new Error('unexpected'); },
  });
  assert.equal(calls, 0);
  assert.equal(scoped.status, 'partial');
  assert.ok(scoped.outcomes.every((outcome) => outcome.state === 'scope_denied'));

  const controller = new AbortController();
  controller.abort(new Error('operator_cancelled'));
  await assert.rejects(runApiContractDiff({
    origins: ['https://api.example.test'],
    domain: 'example.test',
    signal: controller.signal,
    fetchImpl: async () => { calls += 1; throw new Error('unexpected'); },
  }), /operator_cancelled/);
  assert.equal(calls, 0);
});

test('deadline durante fetch cancela requests e retorna timeout cooperativo', async () => {
  let calls = 0;
  const result = await runApiContractDiff({
    origins: ['https://api.example.test'],
    domain: 'example.test',
    timeoutMs: 10,
    fetchImpl: async (_url, { signal }) => {
      calls += 1;
      return new Promise((resolve, reject) => {
        const fallback = setTimeout(() => reject(new Error('timeout signal was not propagated')), 250);
        signal.addEventListener('abort', () => {
          clearTimeout(fallback);
          reject(signal.reason);
        }, { once: true });
      });
    },
  });
  assert.equal(result.status, 'timeout');
  assert.equal(result.reason, 'module_deadline_exhausted');
  assert.equal(result.metrics.coverage.deadlineReached, true);
  // Sob carga, o deadline pode vencer antes do primeiro fetch; em nenhum caso
  // deve iniciar trabalho além da concorrência configurada.
  assert.ok(calls <= 2);
});

test('busca de baseline rejeita espera pendente quando operador cancela', async () => {
  const controller = new AbortController();
  const pending = findPreviousApiContractSnapshots({
    target: 'example.test',
    signal: controller.signal,
    listRunsFn: async () => new Promise(() => {}),
    getRunByIdFn: async () => { throw new Error('must_not_run'); },
  });
  queueMicrotask(() => controller.abort(new Error('operator_cancelled')));
  await assert.rejects(pending, /operator_cancelled/);
});

test('limites e formatos inválidos falham fechados com código determinístico', () => {
  assert.throws(
    () => collectOpenApiSummary({ openapi: '2.9.0', paths: {} }),
    (error) => error?.code === 'API_CONTRACT_UNSUPPORTED_VERSION',
  );
  assert.throws(
    () => collectOpenApiSummary({ openapi: '3.9.0', paths: {} }),
    (error) => error?.code === 'API_CONTRACT_UNSUPPORTED_VERSION',
  );
  assert.throws(
    () => collectOpenApiSummary({
      openapi: '3.1.0',
      paths: { users: { get: { responses: {} } } },
    }),
    (error) => error?.code === 'API_CONTRACT_INVALID_PATH',
  );
  assert.throws(
    () => collectOpenApiSummary({
      openapi: '3.1.0',
      paths: { '/x': { get: { responses: { 999: {} } } } },
    }),
    (error) => error?.code === 'API_CONTRACT_INVALID_RESPONSE_CODE',
  );
  assert.throws(
    () => collectOpenApiSummary({
      openapi: '3.1.0',
      paths: {
        '/x': {
          get: { responses: { default: {}, DEFAULT: {} } },
        },
      },
    }),
    (error) => error?.code === 'API_CONTRACT_DUPLICATE_RESPONSE',
  );
});

test('headers HTTP equivalentes por caixa não geram diff e override continua determinístico', () => {
  const before = {
    openapi: '3.0.3',
    paths: {
      '/items': {
        parameters: [{ name: 'X-Trace', in: 'header', schema: { type: 'string' } }],
        get: {
          parameters: [
            { name: 'x-trace', in: 'header', schema: { type: 'integer' } },
            { name: 'Authorization', in: 'header', schema: { type: 'string' } },
          ],
          responses: {
            200: {
              description: 'ok',
              headers: { 'X-Rate-Limit': { schema: { type: 'integer' } } },
            },
          },
        },
      },
    },
    components: {
      securitySchemes: {
        key: { type: 'apiKey', in: 'header', name: 'X-API-Key' },
      },
      responses: {
        Shared: {
          headers: { 'Content-Type': { schema: { type: 'string' } } },
        },
      },
    },
  };
  const after = structuredClone(before);
  after.paths['/items'].parameters[0].name = 'x-trace';
  after.paths['/items'].get.parameters[0].name = 'X-TRACE';
  after.paths['/items'].get.parameters[1].name = 'authorization';
  after.paths['/items'].get.responses[200].headers = {
    'x-rate-limit': { schema: { type: 'integer' } },
    'Content-Type': { schema: { type: 'array' } },
  };
  after.components.securitySchemes.key.name = 'x-api-key';
  after.components.responses.Shared.headers['content-type'] = {
    schema: { type: 'integer' },
  };
  delete after.components.responses.Shared.headers['Content-Type'];

  const a = collectOpenApiSummary(before, { url: 'https://api.example.test/openapi.json' });
  const b = collectOpenApiSummary(after, { url: 'https://api.example.test/openapi.json' });
  assert.deepEqual(a.operations[0].params, ['header:x-trace']);
  assert.equal(a.hash, b.hash);
  assert.equal(diffOpenApiSummaries(a, b).changed, false);
});

test('mudança residual simultânea a resposta permanece na evidência da operação', () => {
  const before = {
    openapi: '3.1.0',
    paths: {
      '/events': {
        post: {
          servers: [{ url: 'https://api.example.test/v1' }],
          responses: { 200: { description: 'ok' } },
        },
      },
    },
  };
  const after = structuredClone(before);
  after.paths['/events'].post.servers[0].url = 'https://api.example.test/v2';
  after.paths['/events'].post.responses = { 201: { description: 'created' } };
  const diff = diffOpenApiSummaries(
    collectOpenApiSummary(before),
    collectOpenApiSummary(after),
  );
  assert.deepEqual(diff.modifiedOperations, [{
    id: 'POST /events',
    changes: ['responses', 'response_contract', 'operation_contract'],
  }]);
});

test('nome documental de body Swagger 2 não altera o contrato', () => {
  const before = {
    swagger: '2.0',
    paths: {
      '/items': {
        post: {
          parameters: [{ name: 'payload', in: 'body', schema: { type: 'object' } }],
          responses: { 204: { description: 'ok' } },
        },
      },
    },
  };
  const after = structuredClone(before);
  after.paths['/items'].post.parameters[0].name = 'bodyDocumentadoComOutroNome';
  const a = collectOpenApiSummary(before, { url: 'https://api.example.test/swagger.json' });
  const b = collectOpenApiSummary(after, { url: 'https://api.example.test/swagger.json' });
  assert.deepEqual(a.operations[0].params, ['body:']);
  assert.equal(diffOpenApiSummaries(a, b).changed, false);
});

test('webhooks 3.1, QUERY 3.2, callbacks/componentes e XML entram no diff semântico', () => {
  const before = {
    openapi: '3.1.0',
    info: { title: 'Events', version: '1' },
    paths: {},
    webhooks: {
      payment: {
        post: {
          responses: { 200: { $ref: '#/components/responses/Ack' } },
        },
      },
    },
    components: {
      responses: {
        Ack: {
          description: 'ack',
          headers: { trace: { $ref: '#/components/headers/Trace' } },
          links: { retry: { $ref: '#/components/links/Retry' } },
        },
      },
      headers: { Trace: { schema: { type: 'string' } } },
      links: { Retry: { operationId: 'retryPayment' } },
      callbacks: {
        Notify: {
          '{$request.body#/callbackUrl}': {
            post: { responses: { 200: { description: 'ok' } } },
          },
        },
      },
      schemas: {
        XmlItem: { type: 'object', xml: { name: 'OldItem', wrapped: true } },
      },
    },
  };
  const after = structuredClone(before);
  after.webhooks.payment.post.responses = { 204: { description: 'accepted' } };
  after.webhooks.refund = { post: { responses: { 202: { description: 'queued' } } } };
  after.components.headers.Trace.schema.type = 'integer';
  after.components.links.Retry.operationId = 'retryPaymentV2';
  after.components.callbacks.Notify['{$request.body#/callbackUrl}'].post.responses = {
    204: { description: 'ok' },
  };
  after.components.schemas.XmlItem.xml.name = 'NewItem';

  const a = collectOpenApiSummary(before, { url: 'https://api.example.test/openapi.json' });
  const b = collectOpenApiSummary(after, { url: 'https://api.example.test/openapi.json' });
  const diff = diffOpenApiSummaries(a, b);
  assert.equal(a.webhookCount, 1);
  assert.equal(b.webhookCount, 2);
  assert.equal(diff.changed, true);
  assert.equal(diff.componentsChanged, true);
  assert.deepEqual(diff.addedWebhooks, ['WEBHOOK POST "refund"']);
  assert.equal(diff.modifiedWebhooks[0]?.id, 'WEBHOOK POST "payment"');

  const query = collectOpenApiSummary({
    openapi: '3.2.0',
    paths: { '/search': { query: { responses: { 200: { description: 'ok' } } } } },
  });
  assert.equal(query.operations[0].id, 'QUERY /search');
});

test('assinaturas de superfície detectam renome e modificação de Path Items/webhooks sem operações', () => {
  const beforeDocument = {
    openapi: '3.1.0',
    paths: { '/old': {} },
    webhooks: { oldEvent: {} },
  };
  const renamedDocument = {
    openapi: '3.1.0',
    paths: { '/new': {} },
    webhooks: { newEvent: {} },
  };
  const before = collectOpenApiSummary(beforeDocument);
  const renamed = collectOpenApiSummary(renamedDocument);
  const renamedDiff = diffOpenApiSummaries(before, renamed);
  assert.equal(before.operationCount, 0);
  assert.equal(renamed.operationCount, 0);
  assert.equal(before.pathCount, renamed.pathCount);
  assert.equal(before.webhookCount, renamed.webhookCount);
  assert.notEqual(before.pathItemsSignature, renamed.pathItemsSignature);
  assert.notEqual(before.webhooksSignature, renamed.webhooksSignature);
  assert.equal(renamedDiff.changed, true);
  assert.equal(renamedDiff.pathItemsChanged, true);
  assert.equal(renamedDiff.webhooksChanged, true);
  assert.equal(renamedDiff.unclassifiedContractChanged, false);

  const modifiedDocument = structuredClone(beforeDocument);
  modifiedDocument.paths['/old'].parameters = [
    { name: 'tenant', in: 'query', schema: { type: 'string' } },
  ];
  modifiedDocument.webhooks.oldEvent.servers = [{ url: 'https://events.example.test/v2' }];
  const modified = collectOpenApiSummary(modifiedDocument);
  const modifiedDiff = diffOpenApiSummaries(before, modified);
  assert.equal(modified.operationCount, 0);
  assert.equal(modified.pathCount, before.pathCount);
  assert.equal(modified.webhookCount, before.webhookCount);
  assert.equal(modifiedDiff.changed, true);
  assert.equal(modifiedDiff.pathItemsChanged, true);
  assert.equal(modifiedDiff.webhooksChanged, true);

  const annotationOnlyDocument = structuredClone(beforeDocument);
  annotationOnlyDocument.paths['/old'].description = 'documentação nova';
  annotationOnlyDocument.webhooks.oldEvent.summary = 'documentação nova';
  const annotationOnly = collectOpenApiSummary(annotationOnlyDocument);
  assert.equal(diffOpenApiSummaries(before, annotationOnly).changed, false);
});

test('canonicalização anterior é validada, mas nunca comparada silenciosamente com a atual', () => {
  const current = collectOpenApiSummary({
    openapi: '3.0.3',
    paths: { '/health': { get: { responses: { 200: {} } } } },
  }, { url: 'https://api.example.test/openapi.json' });
  const legacy = structuredClone(current);
  legacy.canonicalizationVersion = 2;
  delete legacy.webhookCount;
  delete legacy.rootContractSignature;
  delete legacy.pathItemsSignature;
  delete legacy.webhooksSignature;
  legacy.operations.forEach((operation) => {
    operation.path = operation.route;
    delete operation.route;
    delete operation.surface;
  });
  legacy.hash = createHash('sha256').update(stableJson({
    schemaVersion: legacy.schemaVersion,
    canonicalizationVersion: legacy.canonicalizationVersion,
    version: legacy.version,
    title: legacy.title,
    apiVersion: legacy.apiVersion,
    serversSignature: legacy.serversSignature,
    componentsSignature: legacy.componentsSignature,
    pathCount: legacy.pathCount,
    operationCount: legacy.operationCount,
    paramCount: legacy.paramCount,
    operationsWithoutSecurity: legacy.operationsWithoutSecurity,
    securitySchemes: legacy.securitySchemes,
    operations: legacy.operations,
  })).digest('hex');

  const normalized = migrateApiContractSummary(legacy);
  assert.equal(normalized.canonicalizationVersion, 2);
  const legacyEnvelope = createApiContractSnapshot(normalized);
  assert.equal(legacyEnvelope.canonicalizationVersion, 2);
  assert.equal(extractApiContractSnapshots({
    id: 10,
    findings: [{
      type: 'api_contract_snapshot',
      verification: { evidence: { apiContractSnapshot: legacyEnvelope } },
    }],
  }).length, 1);
  assert.throws(
    () => diffOpenApiSummaries(normalized, current),
    (error) => error?.code === 'API_CONTRACT_INCOMPATIBLE_CANONICALIZATION',
  );
  assert.equal(previousApiContractSnapshotFor(current, [
    { runId: 1, summary: normalized },
    { runId: 2, summary: current, integrityVerified: true },
  ])?.runId, 2);
});

test('redirect interno limitado é seguido e redirect externo é negado antes da segunda request', async () => {
  const internalCalls = [];
  const internal = await fetchOpenApiContracts({
    origins: ['https://api.example.test'],
    domain: 'example.test',
    detailed: true,
    fetchImpl: async (url) => {
      internalCalls.push(url);
      if (url.endsWith('/openapi.json')) {
        return jsonResponse('', 302, { location: '/contracts/current.json' });
      }
      if (url.endsWith('/contracts/current.json')) return jsonResponse(baseDocument());
      return jsonResponse('', 404);
    },
  });
  assert.equal(internal.status, 'done');
  assert.equal(internal.summaries[0].url, 'https://api.example.test/openapi.json');
  assert.equal(internal.summaries[0].resolvedUrl, 'https://api.example.test/contracts/current.json');
  assert.deepEqual(internalCalls, [
    'https://api.example.test/openapi.json',
    'https://api.example.test/openapi.yaml',
    'https://api.example.test/contracts/current.json',
    'https://api.example.test/openapi.yml',
    'https://api.example.test/swagger.json',
    'https://api.example.test/swagger.yaml',
    'https://api.example.test/swagger.yml',
    'https://api.example.test/v2/api-docs',
    'https://api.example.test/v3/api-docs',
    'https://api.example.test/api-docs/swagger.json',
    'https://api.example.test/swagger/v1/swagger.json',
  ]);

  const externalCalls = [];
  const external = await fetchOpenApiContracts({
    origins: ['https://api.example.test'],
    domain: 'example.test',
    detailed: true,
    fetchImpl: async (url) => {
      externalCalls.push(url);
      if (url.endsWith('/openapi.json')) {
        return jsonResponse('', 302, { location: 'https://outside.test/stolen' });
      }
      return jsonResponse('', 404);
    },
  });
  assert.equal(external.status, 'partial');
  assert.equal(external.outcomes[0].state, 'scope_denied');
  assert.equal(external.outcomes[0].reason, 'redirect_out_of_scope');
  assert.equal(externalCalls.length, 10);
  assert.equal(externalCalls.some((url) => url.includes('outside.test')), false);
});

test('limite streamado e abort durante body cancelam a fonte do corpo', async () => {
  let oversizedCancelled = 0;
  const oversized = await fetchOpenApiContracts({
    origins: ['https://api.example.test'],
    domain: 'example.test',
    detailed: true,
    fetchImpl: async (url) => {
      if (!url.endsWith('/openapi.json')) return jsonResponse('', 404);
      return new Response(new ReadableStream({
        pull(controller) {
          controller.enqueue(new Uint8Array(2_000_100));
        },
        cancel() { oversizedCancelled += 1; },
      }), { headers: { 'content-type': 'application/json' } });
    },
  });
  assert.equal(oversized.outcomes[0].state, 'response_too_large');
  assert.equal(oversizedCancelled, 1);

  const controller = new AbortController();
  let bodyCancelled = 0;
  let pulls = 0;
  await assert.rejects(runApiContractDiff({
    origins: ['https://api.example.test'],
    domain: 'example.test',
    signal: controller.signal,
    fetchImpl: async () => new Response(new ReadableStream({
      pull(streamController) {
        pulls += 1;
        if (pulls === 1) {
          streamController.enqueue(new TextEncoder().encode('{'));
          queueMicrotask(() => controller.abort(new Error('operator_cancelled')));
        }
        return undefined;
      },
      cancel() { bodyCancelled += 1; },
    }), { headers: { 'content-type': 'application/json' } }),
  }), /operator_cancelled/);
  assert.equal(bodyCancelled, 2);
});

test('extensões, nomes de domínio e método QUERY respeitam o contexto da versão', () => {
  const extension = collectOpenApiSummary({
    openapi: '3.1.0',
    paths: {
      'x-company': { description: 'extensão válida' },
      '/ok': { get: { responses: { 200: { description: 'ok' } } } },
    },
  });
  assert.equal(extension.pathCount, 1);
  assert.deepEqual(extension.operations.map((operation) => operation.id), ['GET /ok']);

  const before = {
    openapi: '3.1.0',
    paths: {},
    components: {
      schemas: {
        Thing: {
          type: 'object',
          properties: {
            headers: { type: 'string', description: 'documentação A' },
            constructor: { type: 'string' },
            prototype: { type: 'integer' },
          },
        },
      },
    },
  };
  const annotationOnly = structuredClone(before);
  annotationOnly.components.schemas.Thing.properties.headers.description = 'documentação B';
  const contractChange = structuredClone(before);
  contractChange.components.schemas.Thing.properties.constructor.type = 'integer';
  const a = collectOpenApiSummary(before);
  const b = collectOpenApiSummary(annotationOnly);
  const c = collectOpenApiSummary(contractChange);
  assert.equal(diffOpenApiSummaries(a, b).changed, false);
  assert.equal(diffOpenApiSummaries(a, c).componentsChanged, true);

  const query31 = collectOpenApiSummary({
    openapi: '3.1.0',
    paths: { '/search': { query: { responses: { 200: { description: 'ok' } } } } },
  });
  assert.deepEqual(query31.operations, []);
});

test('ordenação canônica é ordinal e mudança de Path Item vazio não fica invisível', () => {
  const ordered = collectOpenApiSummary({
    openapi: '3.1.0',
    paths: {
      '/ä': { get: { responses: { 200: { description: 'ok' } } } },
      '/z': { get: { responses: { 200: { description: 'ok' } } } },
    },
  });
  assert.deepEqual(ordered.operations.map((operation) => operation.id), ['GET /z', 'GET /ä']);

  const before = collectOpenApiSummary({ openapi: '3.1.0', paths: {}, components: {} });
  const after = collectOpenApiSummary({ openapi: '3.1.0', paths: { '/reserved': {} } });
  const diff = diffOpenApiSummaries(before, after);
  assert.equal(diff.changed, true);
  assert.equal(diff.pathCountDelta, 1);
  assert.equal(diff.unclassifiedContractChanged, false);
});

test('descrição de scope OAuth Swagger 2 é anotativa', () => {
  const before = {
    swagger: '2.0',
    paths: { '/health': { get: { responses: { 200: { description: 'ok' } } } } },
    securityDefinitions: {
      oauth: {
        type: 'oauth2',
        flow: 'application',
        tokenUrl: 'https://id.example.test/token',
        scopes: { read: 'Leitura A' },
      },
    },
  };
  const after = structuredClone(before);
  after.securityDefinitions.oauth.scopes.read = 'Leitura B';
  const a = collectOpenApiSummary(before);
  const b = collectOpenApiSummary(after);
  assert.equal(diffOpenApiSummaries(a, b).changed, false);
});

test('OpenAPI 3.2 additionalOperations participa da identidade e do contrato de resposta', () => {
  const before = {
    openapi: '3.2.0',
    paths: {
      '/files': {
        additionalOperations: {
          COPY: { responses: { 200: { description: 'copied' } } },
          MOVE: { responses: { 204: { description: 'moved' } } },
        },
      },
    },
  };
  const after = structuredClone(before);
  after.paths['/files'].additionalOperations.COPY.responses = {
    201: { description: 'copied' },
  };
  const a = collectOpenApiSummary(before);
  const b = collectOpenApiSummary(after);
  assert.deepEqual(a.operations.map((operation) => operation.id), ['COPY /files', 'MOVE /files']);
  const diff = diffOpenApiSummaries(a, b);
  assert.equal(diff.changed, true);
  assert.deepEqual(diff.modifiedOperations, [{ id: 'COPY /files', changes: ['responses', 'response_contract'] }]);

  const recased = structuredClone(before);
  recased.paths['/files'].additionalOperations.copy =
    recased.paths['/files'].additionalOperations.COPY;
  delete recased.paths['/files'].additionalOperations.COPY;
  const caseDiff = diffOpenApiSummaries(a, collectOpenApiSummary(recased));
  assert.deepEqual(caseDiff.removedOperations, ['COPY /files']);
  assert.deepEqual(caseDiff.addedOperations, ['copy /files']);

  const exactCase = collectOpenApiSummary({
    openapi: '3.2.0',
    paths: {
      '/wire': {
        GET: { responses: { 200: {} } },
        additionalOperations: {
          post: { responses: { 202: {} } },
          Get: { responses: { 203: {} } },
        },
      },
    },
  });
  assert.deepEqual(exactCase.operations.map((operation) => operation.id), [
    'Get /wire',
    'post /wire',
  ]);
  const normalizedExactCase = migrateApiContractSummary(exactCase);
  assert.deepEqual(normalizedExactCase.operations.map((operation) => operation.method), [
    'Get',
    'post',
  ]);
  assert.throws(
    () => collectOpenApiSummary({
      openapi: '3.2.0',
      paths: {
        '/wire': {
          additionalOperations: { POST: { responses: { 200: {} } } },
        },
      },
    }),
    (error) => error?.code === 'API_CONTRACT_DUPLICATE_OPERATION',
  );
});

test('redirect com release final rotativa mantém identidade pelo URL solicitado', async () => {
  const run = async (release, route, previousSnapshots = []) => runApiContractDiff({
    origins: ['https://api.example.test'],
    domain: 'example.test',
    previousSnapshots,
    fetchImpl: async (url) => {
      if (url.endsWith('/openapi.json')) {
        return jsonResponse('', 302, { location: `/contracts/${release}.json` });
      }
      if (url.endsWith(`/contracts/${release}.json`)) {
        return jsonResponse({
          openapi: '3.1.0',
          paths: { [route]: { get: { responses: { 200: { description: 'ok' } } } } },
        });
      }
      return jsonResponse('', 404);
    },
  });
  const first = await run('release-1', '/v1');
  const second = await run('release-2', '/v2', [{
    runId: 77,
    createdAt: '2026-09-10T00:00:00.000Z',
    summary: first.summaries[0],
    integrityVerified: true,
  }]);
  assert.equal(first.summaries[0].url, 'https://api.example.test/openapi.json');
  assert.match(first.summaries[0].resolvedUrl, /release-1/);
  const diff = second.findings.find((finding) => finding.type === 'api_contract_diff');
  assert.ok(diff);
  assert.equal(diff.verification.evidence.apiContractDiff.previousRunId, 77);
  assert.deepEqual(diff.verification.evidence.apiContractDiff.addedOperations, ['GET /v2']);
  assert.deepEqual(diff.verification.evidence.apiContractDiff.removedOperations, ['GET /v1']);
});

test('outcome de erro após redirect nunca expõe query sensível', async () => {
  const result = await fetchOpenApiContracts({
    origins: ['https://api.example.test'],
    domain: 'example.test',
    detailed: true,
    fetchImpl: async (url) => {
      if (url.endsWith('/openapi.json')) {
        return jsonResponse('', 302, {
          location: '/private/spec.json?token=fixture-secret-value',
        });
      }
      if (url.includes('/private/spec.json')) return jsonResponse('', 403);
      return jsonResponse('', 404);
    },
  });
  assert.equal(result.outcomes[0].state, 'denied');
  assert.match(result.outcomes[0].url, /token=%5BREDACTED%5D/);
  assert.equal(JSON.stringify(result.outcomes).includes('fixture-secret-value'), false);
});

test('canonicaliza defaults, querystring, HTTP security e patch da versão sem falso diff', () => {
  const before = {
    openapi: '3.2.0',
    paths: {
      '/search': {
        post: {
          parameters: [{ name: 'rawA', in: 'querystring', content: { 'text/plain': {} } }],
          requestBody: { content: { 'application/json': { schema: { type: 'object' } } } },
          responses: { 200: { description: 'ok' } },
        },
      },
    },
    components: {
      securitySchemes: { bearer: { type: 'http', scheme: 'Bearer', bearerFormat: 'JWT' } },
    },
  };
  const after = structuredClone(before);
  after.openapi = '3.2.1';
  after.paths['/search'].post.parameters[0] = {
    ...after.paths['/search'].post.parameters[0],
    name: 'rawB',
    required: false,
    deprecated: false,
    allowEmptyValue: false,
  };
  after.paths['/search'].post.requestBody.required = false;
  after.components.securitySchemes.bearer.scheme = 'bearer';
  after.components.securitySchemes.bearer.bearerFormat = 'opaque-documentation-hint';
  const a = collectOpenApiSummary(before);
  const b = collectOpenApiSummary(after);
  assert.equal(a.version, '3.2');
  assert.equal(b.version, '3.2');
  assert.notEqual(a.sourceDocumentVersion, b.sourceDocumentVersion);
  assert.equal(diffOpenApiSummaries(a, b).changed, false);
});

test('$self e combinação de parâmetros de Path Item/operação são preservados', () => {
  const parameters = (prefix, count) => Array.from({ length: count }, (_, index) => ({
    name: `${prefix}${index}`,
    in: 'query',
    schema: { type: 'string' },
  }));
  const before = {
    openapi: '3.2.0',
    $self: 'https://api.example.test/contracts/root.json',
    paths: {
      '/bulk': {
        parameters: parameters('path', 65),
        get: {
          parameters: parameters('operation', 65),
          responses: { 200: { description: 'ok' } },
        },
      },
    },
  };
  const after = structuredClone(before);
  after.$self = 'https://api.example.test/contracts/next.json';
  const a = collectOpenApiSummary(before);
  const b = collectOpenApiSummary(after);
  assert.equal(a.operations[0].params.length, 130);
  assert.equal(extractApiContractSnapshots({
    id: 1,
    findings: [{
      type: 'api_contract_snapshot',
      verification: { evidence: { apiContractSnapshot: createApiContractSnapshot(a) } },
    }],
  }).length, 1);
  assert.equal(diffOpenApiSummaries(a, b).rootContractChanged, true);
});

test('mudança da política extra de redação exige novo baseline sem ocultar histórico compatível', async () => {
  const previous = process.env.GHOSTRECON_AUTO_REDACT_EXTRA;
  try {
    process.env.GHOSTRECON_AUTO_REDACT_EXTRA = 'foobar';
    const redacted = collectOpenApiSummary({
      openapi: '3.1.0',
      paths: { '/foobar': { get: { responses: { 200: {} } } } },
    }, { url: 'https://api.example.test/openapi.json' });
    delete process.env.GHOSTRECON_AUTO_REDACT_EXTRA;
    const plain = collectOpenApiSummary({
      openapi: '3.1.0',
      paths: { '/foobar': { get: { responses: { 200: {} } } } },
    }, { url: 'https://api.example.test/openapi.json' });
    assert.notEqual(
      redacted.compatibility.redactionPolicyHash,
      plain.compatibility.redactionPolicyHash,
    );
    assert.equal(previousApiContractSnapshotFor(plain, [{
      runId: 1,
      summary: redacted,
      integrityVerified: true,
    }]), null);
    assert.throws(
      () => diffOpenApiSummaries(redacted, plain),
      (error) => error?.code === 'API_CONTRACT_INCOMPATIBLE_CANONICALIZATION',
    );
    const persisted = new Map([
      [1, {
        id: 1,
        target: 'example.test',
        findings: [{
          type: 'api_contract_snapshot',
          verification: { evidence: { apiContractSnapshot: createApiContractSnapshot(redacted) } },
        }],
      }],
      [2, {
        id: 2,
        target: 'example.test',
        findings: [{
          type: 'api_contract_snapshot',
          verification: { evidence: { apiContractSnapshot: createApiContractSnapshot(plain) } },
        }],
      }],
    ]);
    const candidates = await findPreviousApiContractSnapshots({
      target: 'example.test',
      listRunsFn: async () => [
        { id: 1, target: 'example.test' },
        { id: 2, target: 'example.test' },
      ],
      getRunByIdFn: async (id) => persisted.get(id),
    });
    assert.equal(candidates.length, 2);
    assert.equal(previousApiContractSnapshotFor(plain, candidates)?.runId, 2);
  } finally {
    if (previous == null) delete process.env.GHOSTRECON_AUTO_REDACT_EXTRA;
    else process.env.GHOSTRECON_AUTO_REDACT_EXTRA = previous;
  }
});

test('limite de origens produz outcome parcial explícito', async () => {
  const result = await fetchOpenApiContracts({
    origins: Array.from({ length: 30 }, (_, index) => `https://api-${index}.example.test`),
    domain: 'example.test',
    detailed: true,
    fetchImpl: async () => jsonResponse('', 404),
  });
  assert.equal(result.status, 'partial');
  assert.ok(result.outcomes.some((outcome) => outcome.state === 'origin_limit'));
  assert.equal(result.discoveryPolicy, 'all_known_per_origin_v1');
});

test('deadline do runner inclui a leitura do baseline persistido', async () => {
  const keepEventLoopAlive = setTimeout(() => {}, 1_000);
  try {
    await assert.rejects(moduleRunners.api_contract_diff({
      apiContractTimeoutMs: 10,
      domain: 'example.test',
      originByHost: new Map(),
      outOfScopeList: [],
      modules: ['api_contract_diff'],
      listRunsFn: async () => new Promise(() => {}),
      getRunByIdFn: async () => { throw new Error('não deve executar'); },
      log() {},
    }), (error) => error?.name === 'TimeoutError' || /timeout/i.test(String(error?.message)));
  } finally {
    clearTimeout(keepEventLoopAlive);
  }
});
