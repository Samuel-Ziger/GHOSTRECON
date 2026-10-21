/**
 * Postgres direto via DATABASE_URL (conexão Supabase “Direct” ou Session Pooler).
 * Alinhado ao guia Node.js do dashboard Supabase.
 */
import postgres from 'postgres';
import { fingerprintFinding, findingsForRunsTable, norm } from './db-common.js';
import { serializeFindingsForRunSnapshot, parseFindingsSnapshotJson } from './finding-serialize.js';
import { isAbortError, throwIfAborted } from './http-utils.js';

let sqlInstance = null;
const PG_CANCEL_CONFIRM_TIMEOUT_MS = 2_000;

function pgCancelUnconfirmed(cause = null) {
  const error = new Error(
    'Postgres não confirmou o cancelamento da query dentro do limite de limpeza',
    cause ? { cause } : undefined,
  );
  error.code = 'PG_CANCEL_UNCONFIRMED';
  error.fatal = true;
  return error;
}

function waitForSqlCancellation(query, queryPromise) {
  if (typeof query?.cancel !== 'function') {
    return Promise.reject(pgCancelUnconfirmed());
  }
  let timer = null;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(
      () => reject(pgCancelUnconfirmed()),
      PG_CANCEL_CONFIRM_TIMEOUT_MS,
    );
  });
  let cancellation;
  try {
    const requested = query.cancel();
    cancellation = requested && typeof requested.then === 'function'
      ? Promise.resolve(requested)
      : Promise.resolve();
  } catch (error) {
    cancellation = Promise.reject(pgCancelUnconfirmed(error));
  }
  const querySettled = queryPromise.then(
    () => undefined,
    () => undefined,
  );
  // Promise.race instala handlers também na Promise que perder a corrida,
  // evitando rejection tardia não tratada do driver.
  return Promise.race([
    Promise.all([
      cancellation.catch((error) => { throw pgCancelUnconfirmed(error); }),
      querySettled,
    ]),
    timeout,
  ]).finally(() => {
    if (timer) clearTimeout(timer);
  });
}

export function getSql() {
  if (sqlInstance) return sqlInstance;
  const url = process.env.DATABASE_URL?.trim();
  if (!url) {
    throw new Error('DATABASE_URL em falta');
  }
  const forceSsl = String(process.env.GHOSTRECON_DATABASE_SSL || '').trim() === '1';
  const isSupabaseHost = /supabase\.co/i.test(url);
  sqlInstance = postgres(url, {
    ssl: forceSsl || isSupabaseHost ? 'require' : undefined,
    max: 10,
  });
  return sqlInstance;
}

/** Teste rápido de ligação — usado para fallback SQLite quando o Postgres está inacessível. */
export async function probeConnection() {
  try {
    const sql = getSql();
    await sql`select 1 as ok`;
    return { ok: true };
  } catch (e) {
    return { ok: false, error: e?.message || String(e) };
  }
}

function parseJsonField(v) {
  if (v == null) return v;
  if (typeof v === 'object') return v;
  try {
    return JSON.parse(String(v));
  } catch {
    return v;
  }
}

function waitForSqlQuery(query, signal = null) {
  if (!signal) return Promise.resolve(query);
  const queryPromise = Promise.resolve(query);
  return new Promise((resolve, reject) => {
    let settled = false;
    let cancelling = false;
    const cleanup = () => signal.removeEventListener('abort', onAbort);
    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      cleanup();
      callback(value);
    };
    const onAbort = () => {
      if (settled || cancelling) return;
      cancelling = true;
      const reason = signal.reason || new DOMException('cancelado', 'AbortError');
      // Só libera o caller depois que o pedido de cancelamento (quando o driver
      // expõe uma Promise) e a query original terminaram. A rejeição esperada da
      // query cancelada não deve virar unhandled rejection.
      waitForSqlCancellation(query, queryPromise).then(
        () => finish(reject, reason),
        (error) => finish(reject, error),
      );
    };
    signal.addEventListener('abort', onAbort, { once: true });
    queryPromise.then(
      (value) => {
        if (!cancelling) finish(resolve, value);
      },
      (error) => {
        if (!cancelling) finish(reject, error);
      },
    );
    if (signal.aborted) onAbort();
  });
}

function mergeIntelRow(cur, f, runId, now) {
  cur.last_seen = now;
  cur.last_run_id = runId;
  const ns = f.score ?? null;
  if (ns != null && (cur.score == null || ns > cur.score)) {
    cur.score = ns;
    cur.prio = f.prio ?? null;
  }
  if (f.meta) cur.meta = f.meta;
  if (f.url) cur.url = f.url;
}

function newPendingIntelRow(t, fp, f, runId, now) {
  return {
    target: t,
    fp,
    type: f.type ?? null,
    prio: f.prio ?? null,
    score: f.score ?? null,
    value: f.value ?? '',
    meta: f.meta ?? null,
    url: f.url ?? null,
    first_seen: now,
    last_seen: now,
    last_run_id: runId,
  };
}

export async function mergeIntelForTarget(
  target,
  runId,
  findings,
  { sql: sqlOverride = null, signal = null } = {},
) {
  try {
    throwIfAborted(signal);
    const sql = sqlOverride || getSql();
    const t = norm(target);
    const now = new Date().toISOString();
    let newArtifacts = 0;
    let alreadyKnown = 0;

    const fps = [...new Set(findings.map((f) => fingerprintFinding(t, f)))];
    const fromDb = new Map();
    if (fps.length) {
      const chunk = 200;
      for (let i = 0; i < fps.length; i += chunk) {
        const slice = fps.slice(i, i + chunk);
        const rows = await waitForSqlQuery(sql`
          select id, fp, score, prio, meta, url
          from bounty_intel
          where target = ${t} and fp in ${sql(slice)}
        `, signal);
        for (const r of rows) fromDb.set(r.fp, { ...r });
      }
    }

    const pending = new Map();
    const touchedDb = new Set();

    for (const f of findings) {
      const fp = fingerprintFinding(t, f);
      if (fromDb.has(fp)) {
        alreadyKnown++;
        mergeIntelRow(fromDb.get(fp), f, runId, now);
        touchedDb.add(fp);
      } else if (pending.has(fp)) {
        alreadyKnown++;
        mergeIntelRow(pending.get(fp), f, runId, now);
      } else {
        newArtifacts++;
        pending.set(fp, newPendingIntelRow(t, fp, f, runId, now));
      }
    }

    if (pending.size) {
      const toInsert = [...pending.values()];
      const batch = 400;
      for (let i = 0; i < toInsert.length; i += batch) {
        await waitForSqlQuery(
          sql`insert into bounty_intel ${sql(toInsert.slice(i, i + batch))}`,
          signal,
        );
      }
    }

    for (const fp of touchedDb) {
      const cur = fromDb.get(fp);
      await waitForSqlQuery(sql`
        update bounty_intel set
          last_seen = ${cur.last_seen},
          last_run_id = ${cur.last_run_id},
          score = ${cur.score},
          prio = ${cur.prio},
          meta = ${cur.meta},
          url = ${cur.url}
        where id = ${cur.id}
      `, signal);
    }

    const countRows = await waitForSqlQuery(sql`
      select count(*)::int as c from bounty_intel where target = ${t}
    `, signal);
    const totalKnownForTarget = countRows[0]?.c ?? 0;

    return { newArtifacts, alreadyKnown, totalKnownForTarget };
  } catch (e) {
    if (e?.code === 'PG_CANCEL_UNCONFIRMED') throw e;
    if (isAbortError(e, signal)) throw signal?.reason || e;
    console.error('[GHOSTRECON DB intel]', e.message);
    return { newArtifacts: 0, alreadyKnown: 0, totalKnownForTarget: 0, error: e.message };
  }
}

async function persistRunAndFindings(
  sql,
  {
    target,
    exactMatch,
    modules,
    stats,
    correlation,
    snapshot,
    findings,
  },
  { signal = null, mergeIntelFn = mergeIntelForTarget } = {},
) {
  const execute = async (tx) => {
    throwIfAborted(signal);
    const corr = correlation == null ? null : sql.json(correlation);
    const runRows = snapshot
      ? await waitForSqlQuery(tx`
          insert into runs (target, exact_match, modules_json, stats_json, correlation_json, findings_json)
          values (
            ${target},
            ${Boolean(exactMatch)},
            ${sql.json(modules)},
            ${sql.json(stats)},
            ${corr},
            ${sql.json(snapshot)}
          )
          returning id
        `, signal)
      : await waitForSqlQuery(tx`
          insert into runs (target, exact_match, modules_json, stats_json, correlation_json)
          values (
            ${target},
            ${Boolean(exactMatch)},
            ${sql.json(modules)},
            ${sql.json(stats)},
            ${corr}
          )
          returning id
        `, signal);
    const runId = Number(runRows[0]?.id);
    if (!Number.isSafeInteger(runId) || runId <= 0) {
      throw new Error('Postgres não retornou um runId válido');
    }

    const rows = findingsForRunsTable(target, findings).map((finding) => ({
      run_id: runId,
      type: finding.type,
      prio: finding.prio,
      score: finding.score ?? null,
      value: finding.value,
      meta: finding.meta ?? null,
      url: finding.url ?? null,
    }));
    for (let i = 0; i < rows.length; i += 500) {
      throwIfAborted(signal);
      const chunk = rows.slice(i, i + 500);
      if (chunk.length) {
        await waitForSqlQuery(tx`insert into findings ${tx(chunk)}`, signal);
      }
    }
    throwIfAborted(signal);
    const intelMerge = await mergeIntelFn(target, runId, findings, { sql: tx, signal });
    if (intelMerge?.error) {
      const error = new Error(`falha ao atualizar bounty_intel: ${intelMerge.error}`);
      error.code = 'INTEL_MERGE_FAILED';
      throw error;
    }
    throwIfAborted(signal);
    return { runId, intelMerge };
  };

  if (typeof sql.begin === 'function') {
    // As queries internas observam o AbortSignal. A Promise externa precisa
    // chegar ao fim para que postgres.js confirme COMMIT ou ROLLBACK; correr
    // essa Promise contra o aborto devolveria antes da limpeza transacional.
    return sql.begin((tx) => execute(tx));
  }
  return execute(sql);
}

function snapshotPayloadForPg(findingsJson, findings) {
  const raw = apiContractSnapshotRequired(findings)
    ? serializeFindingsForRunSnapshot(findings)
    : findingsJson ?? serializeFindingsForRunSnapshot(findings);
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function apiContractSnapshotRequired(findings) {
  return Array.isArray(findings)
    && findings.some((finding) => finding?.type === 'api_contract_snapshot');
}

function requiredSnapshotError(cause = null) {
  const error = new Error(
    'api_contract_snapshot exige persistência integral em runs.findings_json',
    cause ? { cause } : undefined,
  );
  error.code = 'SNAPSHOT_PERSISTENCE_REQUIRED';
  return error;
}

export async function saveRun(
  { target, exactMatch, modules, stats, findings, correlation, findingsJson = null },
  { sql: sqlOverride = null, mergeIntelFn = mergeIntelForTarget, signal = null } = {},
) {
  try {
    throwIfAborted(signal);
    const sql = sqlOverride || getSql();
    const t = norm(target);
    const snapObj = snapshotPayloadForPg(findingsJson, findings);
    const snapshotRequired = apiContractSnapshotRequired(findings);
    let snapshotPersisted = Boolean(snapObj);
    if (snapshotRequired && !snapObj) throw requiredSnapshotError();

    let committed;
    try {
      committed = await persistRunAndFindings(sql, {
        target: t,
        exactMatch,
        modules,
        stats,
        correlation,
        snapshot: snapObj,
        findings,
      }, { signal, mergeIntelFn });
    } catch (e) {
      if (e?.code === 'PG_CANCEL_UNCONFIRMED') throw e;
      if (isAbortError(e, signal)) throw signal?.reason || e;
      if (!snapObj || !/findings_json/i.test(String(e?.message || e))) throw e;
      if (snapshotRequired) throw requiredSnapshotError(e);
      console.warn('[GHOSTRECON DB] runs.findings_json ausente — grava sem snapshot completo. SQL: ALTER TABLE runs ADD COLUMN findings_json jsonb;');
      snapshotPersisted = false;
      committed = await persistRunAndFindings(sql, {
        target: t,
        exactMatch,
        modules,
        stats,
        correlation,
        snapshot: null,
        findings,
      }, { signal, mergeIntelFn });
    }
    // Ponto de commit: depois que begin() resolveu, a gravação inteira foi
    // confirmada. Um aborto concorrente a partir daqui não converte sucesso em
    // falha aparente nem deixa o caller presumir que houve rollback.
    return { ...committed, snapshotPersisted };
  } catch (e) {
    if (e?.code === 'PG_CANCEL_UNCONFIRMED') throw e;
    if (isAbortError(e, signal)) throw signal?.reason || e;
    console.error('[GHOSTRECON DB]', e.message);
    return null;
  }
}

export async function listRuns(limit = 50, { sql: sqlOverride = null, signal = null } = {}) {
  try {
    const sql = sqlOverride || getSql();
    const lim = Math.min(200, Math.max(1, limit));
    const rows = await waitForSqlQuery(sql`
      select id, target, created_at, stats_json
      from runs
      where persistence_state = 'complete'
      order by id desc
      limit ${lim}
    `, signal);
    return rows.map((r) => ({
      id: r.id,
      target: r.target,
      created_at: r.created_at,
      stats: parseJsonField(r.stats_json),
    }));
  } catch (e) {
    if (e?.code === 'PG_CANCEL_UNCONFIRMED') throw e;
    console.error('[GHOSTRECON DB]', e.message);
    return [];
  }
}

export async function listRunsForTarget(
  target,
  limit = 80,
  { sql: sqlOverride = null, signal = null, strict = true } = {},
) {
  try {
    const sql = sqlOverride || getSql();
    const t = norm(target);
    const lim = Math.min(500, Math.max(1, Number(limit) || 80));
    const rows = await waitForSqlQuery(sql`
      select id, target, created_at, stats_json
      from runs
      where target = ${t} and persistence_state = 'complete'
      order by id desc
      limit ${lim}
    `, signal);
    return rows.map((r) => ({
      id: r.id,
      target: r.target,
      created_at: r.created_at,
      stats: parseJsonField(r.stats_json),
    }));
  } catch (e) {
    if (e?.code === 'PG_CANCEL_UNCONFIRMED') throw e;
    if (signal?.aborted) throw signal.reason || e;
    if (strict) {
      const error = new Error(`falha ao consultar baselines no Postgres: ${e?.message || e}`, { cause: e });
      error.code = 'BASELINE_STORAGE_READ_FAILED';
      throw error;
    }
    console.error('[GHOSTRECON DB]', e.message);
    return [];
  }
}

export async function getRunById(
  id,
  { sql: sqlOverride = null, signal = null, strict = false } = {},
) {
  try {
    const sql = sqlOverride || getSql();
    const runs = await waitForSqlQuery(
      sql`select * from runs where id = ${id} and persistence_state = 'complete' limit 1`,
      signal,
    );
    const run = runs[0];
    if (!run) return null;
    const tableFindings = await waitForSqlQuery(sql`
      select type, prio, score, value, meta, url
      from findings
      where run_id = ${id}
      order by id asc
    `, signal);
    let snap = null;
    const fj = run.findings_json;
    if (fj != null) {
      if (typeof fj === 'string') snap = parseFindingsSnapshotJson(fj);
      else if (Array.isArray(fj.findings)) snap = fj.findings;
      else if (Array.isArray(fj)) snap = fj;
      else
        try {
          snap = parseFindingsSnapshotJson(JSON.stringify(fj));
        } catch {
          snap = null;
        }
    }
    const findings = snap?.length ? snap : tableFindings;
    return {
      id: run.id,
      target: run.target,
      exact_match: Boolean(run.exact_match),
      modules: parseJsonField(run.modules_json),
      stats: parseJsonField(run.stats_json),
      correlation: run.correlation_json != null ? parseJsonField(run.correlation_json) : null,
      created_at: run.created_at,
      findings,
      findingsScopeRows: snap?.length ? tableFindings : undefined,
    };
  } catch (e) {
    if (e?.code === 'PG_CANCEL_UNCONFIRMED') throw e;
    if (signal?.aborted) throw signal.reason || e;
    if (strict) {
      const error = new Error(`falha ao carregar baseline no Postgres: ${e?.message || e}`, { cause: e });
      error.code = 'BASELINE_STORAGE_READ_FAILED';
      throw error;
    }
    console.error('[GHOSTRECON DB]', e.message);
    return null;
  }
}

export async function listIntelForTarget(target, limit = 500) {
  try {
    const sql = getSql();
    const t = String(target).trim().toLowerCase();
    const lim = Math.min(2000, Math.max(1, limit));
    return await sql`
      select type, prio, score, value, meta, url, first_seen, last_seen, last_run_id
      from bounty_intel
      where target = ${t}
      order by last_seen desc
      limit ${lim}
    `;
  } catch (e) {
    console.error('[GHOSTRECON DB]', e.message);
    return [];
  }
}

export async function intelCountForTarget(target) {
  try {
    const sql = getSql();
    const t = String(target).trim().toLowerCase();
    const rows = await sql`
      select count(*)::int as c from bounty_intel where target = ${t}
    `;
    return rows[0]?.c ?? 0;
  } catch {
    return 0;
  }
}
