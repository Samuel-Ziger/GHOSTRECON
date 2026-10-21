import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

import * as db from '../modules/db.js';
import { saveRun as savePgRun } from '../modules/db-pg.js';
import { saveRun as saveSupabaseRun } from '../modules/db-supabase.js';

function findingPayload() {
  return {
    target: 'example.test',
    exactMatch: true,
    modules: ['security_headers'],
    stats: { total: 1 },
    findings: [{
      type: 'security_header',
      prio: 'info',
      score: 10,
      value: 'fixture local',
      url: 'https://example.test/',
    }],
    correlation: null,
  };
}

async function quietDbErrors(fn) {
  const previousError = console.error;
  console.error = () => {};
  try {
    return await fn();
  } finally {
    console.error = previousError;
  }
}

function transactionalPgFake({
  failFindings = false,
  pendingFindings = false,
  cancelNeverConfirms = false,
  rollbackDelayMs = 0,
  afterCommit = null,
} = {}) {
  const state = { runs: [], findings: [] };
  const calls = [];
  let cancelled = false;
  let pendingReject = null;
  let rollbackConfirmed = false;

  const tx = (first, ...values) => {
    if (!Array.isArray(first) || !Object.hasOwn(first, 'raw')) return { bulk: first };
    const text = first.join(' ? ').replace(/\s+/g, ' ').trim().toLowerCase();
    calls.push(text);
    if (text.includes('insert into runs')) {
      state.runs.push({ id: 71 });
      return Promise.resolve([{ id: 71 }]);
    }
    if (text.includes('insert into findings')) {
      if (failFindings) return Promise.reject(new Error('findings_fixture_failed'));
      if (pendingFindings) {
        let cancelledBeforeThen = false;
        return {
          cancel() {
            cancelled = true;
            cancelledBeforeThen = true;
            pendingReject?.(new DOMException('cancelado', 'AbortError'));
            if (cancelNeverConfirms) return new Promise(() => {});
          },
          then(resolve, reject) {
            pendingReject = reject;
            if (cancelledBeforeThen) reject(new DOMException('cancelado', 'AbortError'));
          },
        };
      }
      const bulk = values.find((value) => Array.isArray(value?.bulk));
      state.findings.push(...(bulk?.bulk || []));
      return Promise.resolve([]);
    }
    return Promise.resolve([]);
  };
  tx.json = (value) => value;
  tx.begin = async (callback) => {
    const before = {
      runs: [...state.runs],
      findings: [...state.findings],
    };
    try {
      const result = await callback(tx);
      afterCommit?.();
      return result;
    } catch (error) {
      if (rollbackDelayMs > 0) {
        await new Promise((resolve) => setTimeout(resolve, rollbackDelayMs));
      }
      state.runs.splice(0, state.runs.length, ...before.runs);
      state.findings.splice(0, state.findings.length, ...before.findings);
      rollbackConfirmed = true;
      throw error;
    }
  };
  return {
    sql: tx,
    state,
    calls,
    wasCancelled: () => cancelled,
    rollbackConfirmed: () => rollbackConfirmed,
  };
}

function supabaseWriteFake({
  findingsError = null,
  deleteError = null,
  deletedRows = [{ id: 84 }],
  completionError = null,
  completionData = { id: 84 },
} = {}) {
  const calls = [];
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
                    single() {
                      return Promise.resolve({ data: { id: 84 }, error: null });
                    },
                  };
                },
              };
            }
            return Promise.resolve({ data: null, error: findingsError });
          },
          update(patch) {
            calls.push({ action: 'update', table, patch });
            return {
              eq() { return this; },
              select() { return this; },
              maybeSingle() {
                return Promise.resolve({ data: completionData, error: completionError });
              },
            };
          },
          delete() {
            return {
              eq(column, value) {
                calls.push({ action: 'delete', table, column, value });
                return this;
              },
              select() {
                return Promise.resolve({ data: deletedRows, error: deleteError });
              },
            };
          },
        };
      },
    },
  };
}

test('Postgres confirma run + findings na mesma transação', async () => {
  const fake = transactionalPgFake();
  const controller = new AbortController();
  let mergeOptions = null;
  const saved = await savePgRun(findingPayload(), {
    sql: fake.sql,
    signal: controller.signal,
    mergeIntelFn: async (_target, _runId, _findings, options) => {
      mergeOptions = options;
      return { newArtifacts: 1, alreadyKnown: 0, totalKnownForTarget: 1 };
    },
  });

  assert.equal(saved?.runId, 71);
  assert.equal(fake.state.runs.length, 1);
  assert.equal(fake.state.findings.length, 1);
  assert.equal(mergeOptions?.sql, fake.sql);
  assert.equal(mergeOptions?.signal, controller.signal);
});

test('Postgres reverte o run quando findings falham na transação', async () => {
  const fake = transactionalPgFake({ failFindings: true });
  let mergeCalled = false;
  const saved = await quietDbErrors(() => savePgRun(findingPayload(), {
    sql: fake.sql,
    mergeIntelFn: async () => {
      mergeCalled = true;
      return {};
    },
  }));

  assert.equal(saved, null);
  assert.equal(fake.state.runs.length, 0);
  assert.equal(fake.state.findings.length, 0);
  assert.equal(mergeCalled, false);
});

test('Postgres inclui bounty_intel na mesma transação e reverte falha do merge', async () => {
  const fake = transactionalPgFake();
  const saved = await quietDbErrors(() => savePgRun(findingPayload(), {
    sql: fake.sql,
    mergeIntelFn: async () => ({ error: 'intel_fixture_failed' }),
  }));

  assert.equal(saved, null);
  assert.equal(fake.rollbackConfirmed(), true);
  assert.equal(fake.state.runs.length, 0);
  assert.equal(fake.state.findings.length, 0);
});

test('cancelamento só retorna depois que Postgres confirma o rollback', async () => {
  const fake = transactionalPgFake({ pendingFindings: true, rollbackDelayMs: 15 });
  const controller = new AbortController();
  const reason = new Error('operator_cancelled');
  const pending = savePgRun(findingPayload(), {
    sql: fake.sql,
    signal: controller.signal,
    mergeIntelFn: async () => ({}),
  });
  setImmediate(() => controller.abort(reason));

  await assert.rejects(pending, /operator_cancelled/);
  assert.equal(fake.wasCancelled(), true);
  assert.equal(fake.rollbackConfirmed(), true);
  assert.equal(fake.state.runs.length, 0);
  assert.equal(fake.state.findings.length, 0);
});

test('Postgres mantém sucesso quando aborto chega depois do ponto de commit', async () => {
  const controller = new AbortController();
  const fake = transactionalPgFake({
    afterCommit() { controller.abort(new Error('late_operator_cancel')); },
  });
  const saved = await savePgRun(findingPayload(), {
    sql: fake.sql,
    signal: controller.signal,
    mergeIntelFn: async () => ({ newArtifacts: 1, alreadyKnown: 0, totalKnownForTarget: 1 }),
  });

  assert.equal(controller.signal.aborted, true);
  assert.equal(saved?.runId, 71);
  assert.equal(fake.state.runs.length, 1);
});

test('Postgres falha fatalmente quando o driver não confirma cancelamento', async () => {
  const controller = new AbortController();
  const fake = transactionalPgFake({
    pendingFindings: true,
    cancelNeverConfirms: true,
  });
  const pending = savePgRun(findingPayload(), {
    sql: fake.sql,
    signal: controller.signal,
    mergeIntelFn: async () => ({}),
  });
  setImmediate(() => controller.abort(new Error('operator_cancelled')));

  await assert.rejects(
    pending,
    (error) => error?.code === 'PG_CANCEL_UNCONFIRMED' && error?.fatal === true,
  );
  assert.equal(fake.rollbackConfirmed(), true);
  assert.equal(fake.state.runs.length, 0);
});

test('Supabase apaga o run quando a gravação de findings falha', async () => {
  const fake = supabaseWriteFake({ findingsError: { message: 'findings_fixture_failed' } });
  const saved = await quietDbErrors(() => saveSupabaseRun(findingPayload(), {
    client: fake.client,
    mergeIntelFn: async () => ({}),
  }));

  assert.equal(saved, null);
  assert.deepEqual(
    fake.calls.filter((call) => call.action === 'delete'),
    [{ action: 'delete', table: 'runs', column: 'id', value: 84 }],
  );
});

test('cancelamento alcança o write Supabase e a compensação remove o run incompleto', async () => {
  const calls = [];
  let receivedSignal = null;
  let markFindingsStarted;
  const findingsStarted = new Promise((resolve) => { markFindingsStarted = resolve; });
  const client = {
    from(table) {
      return {
        insert(row) {
          calls.push({ action: 'insert', table, row });
          if (table === 'runs') {
            return {
              select() {
                return {
                  single() {
                    return Promise.resolve({ data: { id: 85 }, error: null });
                  },
                };
              },
            };
          }
          return {
            abortSignal(signal) {
              receivedSignal = signal;
              markFindingsStarted();
              return new Promise((resolve, reject) => {
                signal.addEventListener('abort', () => reject(signal.reason), { once: true });
              });
            },
          };
        },
        delete() {
          return {
            eq(column, value) {
              calls.push({ action: 'delete', table, column, value });
              return this;
            },
            select() {
              return Promise.resolve({ data: [{ id: 85 }], error: null });
            },
          };
        },
      };
    },
  };
  const controller = new AbortController();
  const pending = saveSupabaseRun(findingPayload(), {
    client,
    signal: controller.signal,
    mergeIntelFn: async () => ({}),
  });
  await findingsStarted;
  controller.abort(new Error('operator_cancelled'));

  await assert.rejects(pending, /operator_cancelled/);
  assert.equal(receivedSignal, controller.signal);
  assert.deepEqual(
    calls.filter((call) => call.action === 'delete'),
    [{ action: 'delete', table: 'runs', column: 'id', value: 85 }],
  );
});

test('write Supabase real falha fechado sem service_role; cliente injetado continua permitido', async () => {
  const keys = [
    'SUPABASE_URL',
    'SUPABASE_SERVICE_ROLE_KEY',
    'SUPABASE_ANON_KEY',
    'SUPABASE_KEY',
    'SUPABASE_PUBLISHABLE_KEY',
  ];
  const previous = new Map(keys.map((key) => [key, process.env[key]]));
  try {
    process.env.SUPABASE_URL = 'https://fixture.supabase.co';
    delete process.env.SUPABASE_SERVICE_ROLE_KEY;
    process.env.SUPABASE_ANON_KEY = 'fixture-anon';
    const refused = await quietDbErrors(() => saveSupabaseRun(findingPayload()));
    assert.equal(refused, null);

    const fake = supabaseWriteFake();
    const injected = await saveSupabaseRun(findingPayload(), {
      client: fake.client,
      mergeIntelFn: async () => ({}),
    });
    assert.equal(injected?.runId, 84);
  } finally {
    for (const [key, value] of previous) {
      if (value == null) delete process.env[key];
      else process.env[key] = value;
    }
  }
});

test('Supabase falha explicitamente quando DELETE compensatório erra ou remove zero runs', async () => {
  for (const fake of [
    supabaseWriteFake({
      findingsError: { message: 'findings_fixture_failed' },
      deleteError: { message: 'cleanup_fixture_failed' },
    }),
    supabaseWriteFake({
      findingsError: { message: 'findings_fixture_failed' },
      deletedRows: [],
    }),
  ]) {
    await assert.rejects(
      quietDbErrors(() => saveSupabaseRun(findingPayload(), {
        client: fake.client,
        mergeIntelFn: async () => ({}),
      })),
      (error) => error?.code === 'SUPABASE_CLEANUP_UNCERTAIN',
    );
  }
});

test('Supabase não expõe pending quando a transição para complete falha', async () => {
  for (const fake of [
    supabaseWriteFake({ completionError: { message: 'complete_fixture_failed' } }),
    supabaseWriteFake({ completionData: null }),
  ]) {
    const saved = await quietDbErrors(() => saveSupabaseRun(findingPayload(), {
      client: fake.client,
      mergeIntelFn: async () => ({}),
    }));
    assert.equal(saved, null);
    assert.equal(fake.calls[0].row.persistence_state, 'pending');
    assert.equal(
      fake.calls.some((call) => call.action === 'delete' && call.table === 'runs'),
      true,
    );
  }
});

test('Supabase retorna o commit confirmado quando aborto chega durante índice derivado', async () => {
  const fake = supabaseWriteFake();
  const controller = new AbortController();
  const saved = await saveSupabaseRun(findingPayload(), {
    client: fake.client,
    signal: controller.signal,
    mergeIntelFn: async () => {
      controller.abort(new Error('late_operator_cancel'));
      throw controller.signal.reason;
    },
  });

  assert.equal(saved?.runId, 84);
  assert.equal(saved?.intelMerge?.cancelledAfterCommit, true);
  assert.equal(
    fake.calls.some((call) => call.action === 'delete' && call.table === 'runs'),
    false,
  );
});

test('db.js encaminha AbortSignal ao adapter remoto e respeita pré-cancelamento', async () => {
  const keys = [
    'GHOSTRECON_STORAGE',
    'DATABASE_URL',
    'GHOSTRECON_SUPABASE_AUTO',
    'SUPABASE_URL',
    'SUPABASE_SERVICE_ROLE_KEY',
  ];
  const previous = new Map(keys.map((key) => [key, process.env[key]]));
  try {
    process.env.GHOSTRECON_STORAGE = 'postgres';
    process.env.DATABASE_URL = 'postgresql://fixture.invalid/ghostrecon';
    process.env.GHOSTRECON_SUPABASE_AUTO = '0';
    const controller = new AbortController();
    let receivedSignal = null;
    const result = await db.saveRun(findingPayload(), {
      signal: controller.signal,
      pgAdapter: {
        async saveRun(_payload, options) {
          receivedSignal = options.signal;
          return { runId: 99, intelMerge: {} };
        },
      },
    });
    assert.equal(result?.runId, 99);
    assert.equal(receivedSignal, controller.signal);

    delete process.env.DATABASE_URL;
    process.env.GHOSTRECON_SUPABASE_AUTO = '1';
    process.env.SUPABASE_URL = 'https://fixture.supabase.co';
    process.env.SUPABASE_SERVICE_ROLE_KEY = 'fixture-service-role';
    receivedSignal = null;
    const supabaseResult = await db.saveRun(findingPayload(), {
      signal: controller.signal,
      supabaseAdapter: {
        async saveRun(_payload, options) {
          receivedSignal = options.signal;
          return { runId: 100, intelMerge: {} };
        },
      },
    });
    assert.equal(supabaseResult?.runId, 100);
    assert.equal(receivedSignal, controller.signal);

    const preCancelled = new AbortController();
    preCancelled.abort(new Error('cancelled_before_storage'));
    let called = false;
    await assert.rejects(
      db.saveRun(findingPayload(), {
        signal: preCancelled.signal,
        pgAdapter: { async saveRun() { called = true; } },
      }),
      /cancelled_before_storage/,
    );
    assert.equal(called, false);
  } finally {
    for (const [key, value] of previous) {
      if (value == null) delete process.env[key];
      else process.env[key] = value;
    }
  }
});

test('chave anon isolada não seleciona Supabase como backend de persistência', () => {
  const keys = [
    'GHOSTRECON_STORAGE',
    'DATABASE_URL',
    'GHOSTRECON_SUPABASE_AUTO',
    'SUPABASE_URL',
    'SUPABASE_SERVICE_ROLE_KEY',
    'SUPABASE_ANON_KEY',
    'SUPABASE_KEY',
    'SUPABASE_PUBLISHABLE_KEY',
  ];
  const previous = new Map(keys.map((key) => [key, process.env[key]]));
  try {
    delete process.env.GHOSTRECON_STORAGE;
    delete process.env.DATABASE_URL;
    process.env.GHOSTRECON_SUPABASE_AUTO = '1';
    process.env.SUPABASE_URL = 'https://fixture.supabase.co';
    delete process.env.SUPABASE_SERVICE_ROLE_KEY;
    process.env.SUPABASE_ANON_KEY = 'fixture-anon';
    delete process.env.SUPABASE_KEY;
    delete process.env.SUPABASE_PUBLISHABLE_KEY;
    assert.equal(db.resolveStorageMode(), 'sqlite');

    process.env.SUPABASE_SERVICE_ROLE_KEY = 'fixture-service-role';
    assert.equal(db.resolveStorageMode(), 'postgres');
  } finally {
    for (const [key, value] of previous) {
      if (value == null) delete process.env[key];
      else process.env[key] = value;
    }
  }
});

test('SQL Supabase remove policies abertas e reserva writes para service_role', () => {
  const files = [
    new URL('../../supabase/COPIAR_PARA_SQL_EDITOR.sql', import.meta.url),
    new URL('../../supabase/migrations/20260909000000_api_contract_snapshots.sql', import.meta.url),
  ];
  for (const file of files) {
    const sql = fs.readFileSync(file, 'utf8');
    assert.doesNotMatch(sql, /create\s+policy\s+"ghostrecon_[^"]+_all"/i);
    assert.doesNotMatch(sql, /grant\s+all\s+on\s+table\s+public\.(?:runs|findings|bounty_intel)\s+to\s+anon/i);
    for (const table of ['runs', 'findings', 'bounty_intel']) {
      assert.match(
        sql,
        new RegExp(`revoke\\s+all\\s+on\\s+table\\s+public\\.${table}\\s+from\\s+anon,\\s*authenticated`, 'i'),
      );
      assert.match(
        sql,
        new RegExp(`grant\\s+all\\s+on\\s+table\\s+public\\.${table}\\s+to\\s+service_role`, 'i'),
      );
    }
    for (const sequence of ['runs_id_seq', 'findings_id_seq', 'bounty_intel_id_seq']) {
      assert.match(
        sql,
        new RegExp(`revoke\\s+all\\s+on\\s+sequence\\s+public\\.${sequence}\\s+from\\s+anon,\\s*authenticated`, 'i'),
      );
    }
    assert.match(sql, /persistence_state\s+text\s+not\s+null\s+default\s+'complete'/i);
    assert.match(sql, /check\s*\(persistence_state\s+in\s*\('pending',\s*'complete'\)\)/i);
  }
});

test('schemas Postgres puros evoluem runs antes de criar o indice por estado', () => {
  const files = [
    new URL('../../docs/vps-postgres-schema.sql', import.meta.url),
    new URL('../../WorkFlowVPS/sql/ghostrecon_schema.sql', import.meta.url),
  ];
  for (const file of files) {
    const sql = fs.readFileSync(file, 'utf8').toLowerCase();
    const alterAt = sql.indexOf('alter table public.runs');
    const stateIndexAt = sql.indexOf('create index if not exists runs_target_state_id_idx');
    assert.ok(alterAt >= 0, `${file.pathname}: upgrade de runs ausente`);
    assert.ok(stateIndexAt > alterAt, `${file.pathname}: indice criado antes do upgrade`);
    assert.match(sql, /add column if not exists findings_json jsonb/);
    assert.match(
      sql,
      /add column if not exists persistence_state text not null default 'complete'/,
    );
    assert.match(
      sql,
      /check\s*\(persistence_state\s+in\s*\('pending',\s*'complete'\)\)/,
    );
  }
});
