import test from 'node:test';
import assert from 'node:assert/strict';

import {
  getRunById as getPgRunById,
  listRunsForTarget as listPgRunsForTarget,
  saveRun as savePgRun,
} from '../modules/db-pg.js';
import {
  getRunById as getSupabaseRunById,
  listRunsForTarget as listSupabaseRunsForTarget,
  saveRun as saveSupabaseRun,
} from '../modules/db-supabase.js';
import {
  collectOpenApiSummary,
  createApiContractSnapshot,
  extractApiContractSnapshots,
} from '../modules/api-contract-diff.mjs';
import { serializeFindingsForRunSnapshot } from '../modules/finding-serialize.js';

function snapshotFinding() {
  const summary = collectOpenApiSummary({
    openapi: '3.1.0',
    paths: { '/health': { get: { responses: { 200: { description: 'ok' } } } } },
  }, { url: 'https://api.example.test/openapi.json' });
  return {
    type: 'api_contract_snapshot',
    prio: 'info',
    score: 22,
    value: 'snapshot',
    url: 'https://api.example.test/openapi.json',
    verification: {
      evidence: {
        apiContractSnapshot: {
          ...createApiContractSnapshot(summary),
        },
      },
    },
  };
}

function payload(findings = [snapshotFinding()]) {
  return {
    target: 'example.test',
    exactMatch: true,
    modules: ['api_contract_diff'],
    stats: {},
    findings,
    correlation: null,
    findingsJson: JSON.stringify({ schemaVersion: 1, findings }),
  };
}

function pgFake({ missingSnapshotColumn = false } = {}) {
  const calls = [];
  const sql = (first, ...values) => {
    if (!Array.isArray(first) || !Object.hasOwn(first, 'raw')) return { bulk: first };
    const text = first.join(' ? ').replace(/\s+/g, ' ').trim().toLowerCase();
    calls.push({ text, values });
    if (text.includes('insert into runs')) {
      if (missingSnapshotColumn && text.includes('findings_json')) {
        return Promise.reject(new Error('column findings_json does not exist'));
      }
      return Promise.resolve([{ id: 41 }]);
    }
    if (text.includes('insert into findings')) return Promise.resolve([]);
    return Promise.resolve([]);
  };
  sql.json = (value) => value;
  return { sql, calls };
}

function supabaseFake({ missingSnapshotColumn = false } = {}) {
  const calls = [];
  const mutationResult = (data) => ({
    eq() { return this; },
    select() { return this; },
    maybeSingle() { return Promise.resolve({ data, error: null }); },
    then(resolve, reject) {
      return Promise.resolve({ data, error: null }).then(resolve, reject);
    },
  });
  return {
    calls,
    client: {
      from(table) {
        return {
          insert(row) {
            calls.push({ action: 'insert', table, row });
            if (table === 'runs') {
              return {
                select() {
                  return {
                    async single() {
                      if (missingSnapshotColumn && row.findings_json) {
                        return {
                          data: null,
                          error: { message: "column 'findings_json' was not found in schema cache" },
                        };
                      }
                      return { data: { id: 52 }, error: null };
                    },
                  };
                },
              };
            }
            return Promise.resolve({ error: null });
          },
          update(patch) {
            calls.push({ action: 'update', table, patch });
            return mutationResult({ id: 52 });
          },
          delete() {
            calls.push({ action: 'delete', table });
            return mutationResult([{ id: 52 }]);
          },
        };
      },
    },
  };
}

async function quietDbErrors(fn) {
  const previousError = console.error;
  const previousWarn = console.warn;
  console.error = () => {};
  console.warn = () => {};
  try {
    return await fn();
  } finally {
    console.error = previousError;
    console.warn = previousWarn;
  }
}

test('Postgres e Supabase preservam snapshot ou falham fechado sem downgrade silencioso', async () => {
  const mergeIntelFn = async () => ({ newArtifacts: 0, alreadyKnown: 0, totalKnownForTarget: 0 });

  const pgOk = pgFake();
  const untrustedPayload = { ...payload(), findingsJson: '{"findings":[]}' };
  const pgSaved = await savePgRun(untrustedPayload, { sql: pgOk.sql, mergeIntelFn });
  assert.equal(pgSaved.runId, 41);
  assert.equal(pgSaved.snapshotPersisted, true);
  const pgRunInsert = pgOk.calls.find((call) => call.text.includes('insert into runs'));
  assert.equal(
    pgRunInsert.values.some((value) => value?.findings?.[0]?.type === 'api_contract_snapshot'),
    true,
  );
  const pgSnapshotPayload = pgRunInsert.values.find(
    (value) => value?.findings?.[0]?.type === 'api_contract_snapshot',
  );
  const pgReadTexts = [];
  const pgReadSql = (first, ...values) => {
    const text = first.join(' ? ').replace(/\s+/g, ' ').trim().toLowerCase();
    pgReadTexts.push(text);
    if (text.includes('select id, target') && text.includes('where target')) {
      return Promise.resolve([{
        id: 41,
        target: 'example.test',
        created_at: '2026-09-09T12:00:00.000Z',
        stats_json: {},
      }]);
    }
    if (text.includes('select * from runs')) {
      return Promise.resolve([{
        id: 41,
        target: 'example.test',
        exact_match: true,
        modules_json: ['api_contract_diff'],
        stats_json: {},
        correlation_json: null,
        findings_json: pgSnapshotPayload,
        created_at: '2026-09-09T12:00:00.000Z',
      }]);
    }
    if (text.includes('from findings')) return Promise.resolve([]);
    throw new Error(`query PG inesperada: ${text} (${values.length})`);
  };
  pgReadSql.json = (value) => value;
  const pgListed = await listPgRunsForTarget('example.test', 10, { sql: pgReadSql });
  assert.equal(pgListed[0]?.id, 41);
  const pgLoaded = await getPgRunById(41, { sql: pgReadSql });
  assert.equal(extractApiContractSnapshots(pgLoaded).length, 1);
  assert.equal(
    pgReadTexts
      .filter((text) => text.includes('from runs'))
      .every((text) => text.includes("persistence_state = 'complete'")),
    true,
  );

  const pgMissing = pgFake({ missingSnapshotColumn: true });
  const pgRefused = await quietDbErrors(() => savePgRun(
    payload(),
    { sql: pgMissing.sql, mergeIntelFn },
  ));
  assert.equal(pgRefused, null);
  assert.equal(pgMissing.calls.filter((call) => call.text.includes('insert into runs')).length, 1);

  const sbOk = supabaseFake();
  const sbSaved = await saveSupabaseRun(untrustedPayload, { client: sbOk.client, mergeIntelFn });
  assert.equal(sbSaved.runId, 52);
  assert.equal(sbSaved.snapshotPersisted, true);
  assert.equal(sbOk.calls[0].row.findings_json.findings[0].type, 'api_contract_snapshot');
  assert.equal(sbOk.calls[0].row.persistence_state, 'pending');
  assert.deepEqual(
    sbOk.calls.find((call) => call.action === 'update' && call.table === 'runs')?.patch,
    { persistence_state: 'complete' },
  );
  const sbRunRow = {
    id: 52,
    target: 'example.test',
    exact_match: true,
    modules_json: ['api_contract_diff'],
    stats_json: {},
    correlation_json: null,
    findings_json: sbOk.calls[0].row.findings_json,
    persistence_state: 'complete',
    created_at: '2026-09-09T12:00:00.000Z',
  };
  const sbReadFilters = [];
  const sbReadClient = {
    from(table) {
      const builder = {
        select() { return this; },
        eq(column, value) {
          sbReadFilters.push({ table, column, value });
          return this;
        },
        order() { return this; },
        limit() { return this; },
        maybeSingle() {
          return Promise.resolve({ data: table === 'runs' ? sbRunRow : null, error: null });
        },
        then(resolve, reject) {
          return Promise.resolve({
            data: table === 'runs' ? [sbRunRow] : [],
            error: null,
          }).then(resolve, reject);
        },
      };
      return builder;
    },
  };
  const sbListed = await listSupabaseRunsForTarget(
    'example.test',
    10,
    { client: sbReadClient },
  );
  assert.equal(sbListed[0]?.id, 52);
  const sbLoaded = await getSupabaseRunById(52, { client: sbReadClient });
  assert.equal(extractApiContractSnapshots(sbLoaded).length, 1);
  assert.equal(
    sbReadFilters.filter((filter) => (
      filter.table === 'runs'
      && filter.column === 'persistence_state'
      && filter.value === 'complete'
    )).length,
    2,
  );

  const sbMissing = supabaseFake({ missingSnapshotColumn: true });
  const sbRefused = await quietDbErrors(() => saveSupabaseRun(
    payload(),
    { client: sbMissing.client, mergeIntelFn },
  ));
  assert.equal(sbRefused, null);
  assert.equal(
    sbMissing.calls.filter((call) => call.action === 'insert' && call.table === 'runs').length,
    1,
  );
});

test('downgrade legado continua explícito para finding sem baseline estrutural', async () => {
  const regularFinding = {
    type: 'intel', prio: 'info', score: 1, value: 'inventário',
  };
  const mergeIntelFn = async () => ({ newArtifacts: 0, alreadyKnown: 0, totalKnownForTarget: 0 });

  const pg = pgFake({ missingSnapshotColumn: true });
  const pgSaved = await quietDbErrors(() => savePgRun(
    payload([regularFinding]),
    { sql: pg.sql, mergeIntelFn },
  ));
  assert.equal(pgSaved.runId, 41);
  assert.equal(pgSaved.snapshotPersisted, false);
  assert.equal(pg.calls.filter((call) => call.text.includes('insert into runs')).length, 2);

  const sb = supabaseFake({ missingSnapshotColumn: true });
  const sbSaved = await quietDbErrors(() => saveSupabaseRun(
    payload([regularFinding]),
    { client: sb.client, mergeIntelFn },
  ));
  assert.equal(sbSaved.runId, 52);
  assert.equal(sbSaved.snapshotPersisted, false);
  assert.equal(
    sb.calls.filter((call) => call.action === 'insert' && call.table === 'runs').length,
    2,
  );
});

test('orçamento insuficiente recusa snapshot em vez de alegar persistência', async () => {
  const previous = process.env.GHOSTRECON_FINDINGS_SNAPSHOT_MAX_BYTES;
  process.env.GHOSTRECON_FINDINGS_SNAPSHOT_MAX_BYTES = '100';
  try {
    const findings = [snapshotFinding()];
    assert.equal(serializeFindingsForRunSnapshot(findings), null);
    const pg = pgFake();
    const saved = await quietDbErrors(() => savePgRun(
      payload(findings),
      { sql: pg.sql, mergeIntelFn: async () => ({}) },
    ));
    assert.equal(saved, null);
    assert.equal(pg.calls.length, 0);
  } finally {
    if (previous == null) delete process.env.GHOSTRECON_FINDINGS_SNAPSHOT_MAX_BYTES;
    else process.env.GHOSTRECON_FINDINGS_SNAPSHOT_MAX_BYTES = previous;
  }
});

test('orçamento NaN ou infinito nunca desativa o teto de serialização', () => {
  const previous = process.env.GHOSTRECON_FINDINGS_SNAPSHOT_MAX_BYTES;
  try {
    for (const invalid of ['NaN', 'Infinity', '-1', '0']) {
      process.env.GHOSTRECON_FINDINGS_SNAPSHOT_MAX_BYTES = invalid;
      assert.equal(serializeFindingsForRunSnapshot([snapshotFinding()], 100), null);
    }
  } finally {
    if (previous == null) delete process.env.GHOSTRECON_FINDINGS_SNAPSHOT_MAX_BYTES;
    else process.env.GHOSTRECON_FINDINGS_SNAPSHOT_MAX_BYTES = previous;
  }
});

test('falha remota de listagem/leitura é distinta de baseline inexistente', async () => {
  const failingPgSql = () => Promise.reject(new Error('pg_fixture_unavailable'));
  await assert.rejects(
    listPgRunsForTarget('example.test', 10, { sql: failingPgSql }),
    (error) => error?.code === 'BASELINE_STORAGE_READ_FAILED'
      && /pg_fixture_unavailable/.test(error.message),
  );
  await assert.rejects(
    getPgRunById(9, { sql: failingPgSql, strict: true }),
    (error) => error?.code === 'BASELINE_STORAGE_READ_FAILED'
      && /pg_fixture_unavailable/.test(error.message),
  );

  const failingSupabase = {
    from() {
      return {
        select() { return this; },
        eq() { return this; },
        order() { return this; },
        limit() { return this; },
        maybeSingle() {
          return Promise.resolve({ data: null, error: { message: 'sb_fixture_unavailable' } });
        },
        then(resolve, reject) {
          return Promise.resolve({ data: null, error: { message: 'sb_fixture_unavailable' } })
            .then(resolve, reject);
        },
      };
    },
  };
  await assert.rejects(
    listSupabaseRunsForTarget('example.test', 10, { client: failingSupabase }),
    (error) => error?.code === 'BASELINE_STORAGE_READ_FAILED'
      && /sb_fixture_unavailable/.test(error.message),
  );
  await assert.rejects(
    getSupabaseRunById(9, { client: failingSupabase, strict: true }),
    (error) => error?.code === 'BASELINE_STORAGE_READ_FAILED'
      && /sb_fixture_unavailable/.test(error.message),
  );
});

test('snapshot exigido é preservado depois de 5000 findings e sob mudança de redação', () => {
  const previousExtra = process.env.GHOSTRECON_AUTO_REDACT_EXTRA;
  try {
    process.env.GHOSTRECON_AUTO_REDACT_EXTRA = 'fixture-custom-secret';
    const required = snapshotFinding();
    process.env.GHOSTRECON_AUTO_REDACT_EXTRA = 'outra-politica-extra';
    const noise = Array.from({ length: 5_001 }, (_, index) => ({
      type: 'inventory',
      prio: 'info',
      score: 1,
      value: `item-${index}`,
    }));
    const serialized = serializeFindingsForRunSnapshot([...noise, required]);
    assert.equal(typeof serialized, 'string');
    const parsed = JSON.parse(serialized);
    assert.equal(parsed.findings.at(-1).type, 'api_contract_snapshot');
    assert.equal(extractApiContractSnapshots({ id: 1, findings: parsed.findings }).length, 1);
  } finally {
    if (previousExtra == null) delete process.env.GHOSTRECON_AUTO_REDACT_EXTRA;
    else process.env.GHOSTRECON_AUTO_REDACT_EXTRA = previousExtra;
  }
});

test('orçamento padrão persiste quatro contratos no limite estrutural', () => {
  const previousBudget = process.env.GHOSTRECON_FINDINGS_SNAPSHOT_MAX_BYTES;
  try {
    delete process.env.GHOSTRECON_FINDINGS_SNAPSHOT_MAX_BYTES;
    const paths = Object.fromEntries(Array.from({ length: 2_500 }, (_, index) => [
      `/resource-${index}`,
      {
        get: { responses: { 200: { description: 'ok' } } },
        post: { responses: { 201: { description: 'ok' } } },
      },
    ]));
    const summary = collectOpenApiSummary(
      { openapi: '3.1.0', paths },
      { url: 'https://api.example.test/openapi.json' },
    );
    assert.equal(summary.operationCount, 5_000);
    const envelope = createApiContractSnapshot(summary);
    const finding = {
      type: 'api_contract_snapshot',
      prio: 'info',
      score: 22,
      value: 'snapshot grande',
      url: summary.url,
      verification: { evidence: { apiContractSnapshot: envelope } },
    };
    const serialized = serializeFindingsForRunSnapshot([
      finding,
      structuredClone(finding),
      structuredClone(finding),
      structuredClone(finding),
    ]);
    assert.equal(typeof serialized, 'string');
    assert.equal(extractApiContractSnapshots({
      id: 2,
      findings: JSON.parse(serialized).findings,
    }).length, 4);
  } finally {
    if (previousBudget == null) delete process.env.GHOSTRECON_FINDINGS_SNAPSHOT_MAX_BYTES;
    else process.env.GHOSTRECON_FINDINGS_SNAPSHOT_MAX_BYTES = previousBudget;
  }
});

test('leituras remotas propagam cancelamento ao transporte', async () => {
  let pgCancelled = false;
  let rejectPgQuery;
  const pgPending = new Promise((_, reject) => {
    rejectPgQuery = reject;
  });
  const pendingQuery = {
    cancel() {
      pgCancelled = true;
      rejectPgQuery(new Error('driver_query_cancelled'));
      return Promise.resolve();
    },
    then(resolve, reject) { return pgPending.then(resolve, reject); },
  };
  const pgSql = () => pendingQuery;
  const pgController = new AbortController();
  const pgRead = listPgRunsForTarget('example.test', 10, {
    sql: pgSql,
    signal: pgController.signal,
  });
  queueMicrotask(() => pgController.abort(new Error('operator_cancelled')));
  await assert.rejects(pgRead, /operator_cancelled/);
  assert.equal(pgCancelled, true);

  let receivedSignal = null;
  const sbClient = {
    from() {
      return {
        select() { return this; },
        eq() { return this; },
        order() { return this; },
        limit() { return this; },
        abortSignal(signal) {
          receivedSignal = signal;
          return new Promise((resolve, reject) => {
            signal.addEventListener('abort', () => reject(signal.reason), { once: true });
          });
        },
      };
    },
  };
  const sbController = new AbortController();
  const sbRead = listSupabaseRunsForTarget('example.test', 10, {
    client: sbClient,
    signal: sbController.signal,
  });
  queueMicrotask(() => sbController.abort(new Error('operator_cancelled')));
  await assert.rejects(sbRead, /operator_cancelled/);
  assert.equal(receivedSignal, sbController.signal);
});
