import { createClient } from '@supabase/supabase-js';
import { fingerprintFinding, findingsForRunsTable, norm } from './db-common.js';
import { serializeFindingsForRunSnapshot, parseFindingsSnapshotJson } from './finding-serialize.js';
import { isAbortError, throwIfAborted } from './http-utils.js';

let readClient = null;
let writeClient = null;
let readClientConfig = null;
let writeClientConfig = null;

function getSupabase({ write = false } = {}) {
  const url = process.env.SUPABASE_URL?.trim();
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY?.trim();
  const key = write
    ? serviceRoleKey
    : serviceRoleKey ||
      process.env.SUPABASE_ANON_KEY?.trim() ||
      process.env.SUPABASE_KEY?.trim() ||
      process.env.SUPABASE_PUBLISHABLE_KEY?.trim();
  if (!url || !key) {
    const error = new Error(
      write
        ? 'SUPABASE_URL e SUPABASE_SERVICE_ROLE_KEY são obrigatórios para persistência'
        : 'SUPABASE_URL e chave de leitura são obrigatórios',
    );
    if (write) error.code = 'SUPABASE_SERVICE_ROLE_REQUIRED';
    throw error;
  }
  const configIdentity = `${url}\u0000${key}`;
  if (write && writeClient && writeClientConfig === configIdentity) return writeClient;
  if (!write && readClient && readClientConfig === configIdentity) return readClient;
  const created = createClient(url, key);
  if (write) {
    writeClient = created;
    writeClientConfig = configIdentity;
  } else {
    readClient = created;
    readClientConfig = configIdentity;
  }
  return created;
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

function withAbortSignal(builder, signal = null) {
  if (!signal || typeof builder?.abortSignal !== 'function') return builder;
  return builder.abortSignal(signal);
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
  { client: clientOverride = null, signal = null } = {},
) {
  try {
    throwIfAborted(signal);
    const sb = clientOverride || getSupabase({ write: true });
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
        const query = sb
          .from('bounty_intel')
          .select('id,fp,score,prio,meta,url')
          .eq('target', t)
          .in('fp', slice);
        const { data: rows, error } = await withAbortSignal(query, signal);
        if (error) throw error;
        for (const r of rows || []) fromDb.set(r.fp, { ...r });
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
        const query = sb.from('bounty_intel').insert(toInsert.slice(i, i + batch));
        const { error } = await withAbortSignal(query, signal);
        if (error) throw error;
      }
    }

    for (const fp of touchedDb) {
      const cur = fromDb.get(fp);
      const { id, ...rest } = cur;
      const patch = {
        last_seen: rest.last_seen,
        last_run_id: rest.last_run_id,
        score: rest.score,
        prio: rest.prio,
        meta: rest.meta,
        url: rest.url,
      };
      const query = sb.from('bounty_intel').update(patch).eq('id', id);
      const { error } = await withAbortSignal(query, signal);
      if (error) throw error;
    }

    const countQuery = sb
      .from('bounty_intel')
      .select('*', { count: 'exact', head: true })
      .eq('target', t);
    const { count, error: cErr } = await withAbortSignal(countQuery, signal);
    if (cErr) throw cErr;

    return { newArtifacts, alreadyKnown, totalKnownForTarget: count ?? 0 };
  } catch (e) {
    if (isAbortError(e, signal)) throw signal?.reason || e;
    console.error('[GHOSTRECON DB intel]', e.message);
    return { newArtifacts: 0, alreadyKnown: 0, totalKnownForTarget: 0, error: e.message };
  }
}

async function compensateRunInsert(sb, runId) {
  if (!Number.isSafeInteger(runId) || runId <= 0) {
    const error = new Error('runId inválido para compensação Supabase');
    error.code = 'SUPABASE_CLEANUP_UNCERTAIN';
    throw error;
  }
  try {
    const cleanupSignal = AbortSignal.timeout(5_000);
    const query = sb.from('runs').delete().eq('id', runId).select('id');
    const { data, error } = await withAbortSignal(query, cleanupSignal);
    if (error) throw error;
    const deleted = Array.isArray(data) ? data : data ? [data] : [];
    if (deleted.length !== 1 || Number(deleted[0]?.id) !== runId) {
      throw new Error(`DELETE não atestou exatamente o run #${runId}`);
    }
    return true;
  } catch (error) {
    const uncertain = new Error(
      `compensação do run Supabase #${runId} não foi confirmada: ${error?.message || error}`,
      { cause: error },
    );
    uncertain.code = 'SUPABASE_CLEANUP_UNCERTAIN';
    throw uncertain;
  }
}

async function markRunComplete(sb, runId, signal) {
  const query = sb
    .from('runs')
    .update({ persistence_state: 'complete' })
    .eq('id', runId)
    .eq('persistence_state', 'pending')
    .select('id')
    .maybeSingle();
  const { data, error } = await withAbortSignal(query, signal);
  if (error) throw error;
  if (Number(data?.id) !== runId) {
    const stateError = new Error(`Supabase não confirmou a conclusão do run #${runId}`);
    stateError.code = 'SUPABASE_COMMIT_UNCONFIRMED';
    throw stateError;
  }
}

function snapshotPayloadForSupabase(findingsJson, findings) {
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
  { client: clientOverride = null, mergeIntelFn = mergeIntelForTarget, signal = null } = {},
) {
  let runId = null;
  let commitConfirmed = false;
  try {
    throwIfAborted(signal);
    // A injeção existe para testes herméticos. No runtime real, somente a
    // service_role pode criar runs e findings.
    const sb = clientOverride || getSupabase({ write: true });
    const t = norm(target);
    const snapObj = snapshotPayloadForSupabase(findingsJson, findings);
    const snapshotRequired = apiContractSnapshotRequired(findings);
    let snapshotPersisted = Boolean(snapObj);
    if (snapshotRequired && !snapObj) throw requiredSnapshotError();
    const baseRow = {
      target: t,
      exact_match: Boolean(exactMatch),
      modules_json: modules,
      stats_json: stats,
      correlation_json: correlation ?? null,
      persistence_state: 'pending',
    };
    let rowPayload = snapObj ? { ...baseRow, findings_json: snapObj } : baseRow;
    let runQuery = sb.from('runs').insert(rowPayload).select('id').single();
    let { data: runRow, error: runErr } = await withAbortSignal(runQuery, signal);
    const errStr = `${String(runErr?.message || '')} ${JSON.stringify(runErr || {})}`;
    if (runErr && snapObj && /findings_json|schema cache.*runs|column.*runs/i.test(errStr)) {
      if (snapshotRequired) throw requiredSnapshotError(runErr);
      console.warn('[GHOSTRECON DB] Supabase: coluna findings_json ausente — grava sem snapshot.');
      snapshotPersisted = false;
      runQuery = sb.from('runs').insert(baseRow).select('id').single();
      ({ data: runRow, error: runErr } = await withAbortSignal(runQuery, signal));
    }
    if (runErr) throw runErr;
    runId = Number(runRow?.id);
    if (!Number.isSafeInteger(runId) || runId <= 0) {
      throw new Error('Supabase não retornou um runId válido');
    }

    const rows = findingsForRunsTable(t, findings).map((f) => ({
      run_id: runId,
      type: f.type,
      prio: f.prio,
      score: f.score ?? null,
      value: f.value,
      meta: f.meta ?? null,
      url: f.url ?? null,
    }));

    const batch = 500;
    for (let i = 0; i < rows.length; i += batch) {
      throwIfAborted(signal);
      const query = sb.from('findings').insert(rows.slice(i, i + batch));
      const { error: fErr } = await withAbortSignal(query, signal);
      if (fErr) throw fErr;
    }
    throwIfAborted(signal);
    await markRunComplete(sb, runId, signal);
    commitConfirmed = true;

    // `runs` + `findings_json` + tabela normalizada formam o commit durável.
    // bounty_intel é um índice derivado e reparável; uma falha ou aborto
    // posterior não transforma um commit confirmado em falha aparente.
    let intelMerge;
    try {
      intelMerge = await mergeIntelFn(t, runId, findings, { client: sb, signal });
    } catch (error) {
      intelMerge = {
        newArtifacts: 0,
        alreadyKnown: 0,
        totalKnownForTarget: 0,
        error: error?.message || String(error),
        cancelledAfterCommit: isAbortError(error, signal),
      };
    }

    return { runId, intelMerge, snapshotPersisted };
  } catch (e) {
    if (!commitConfirmed && runId != null) {
      const sb = clientOverride || writeClient;
      if (sb) {
        try {
          await compensateRunInsert(sb, runId);
        } catch (cleanupError) {
          cleanupError.originalError = e;
          throw cleanupError;
        }
      }
    }
    if (isAbortError(e, signal)) throw signal?.reason || e;
    console.error('[GHOSTRECON DB]', e.message);
    return null;
  }
}

export async function listRuns(limit = 50, { client: clientOverride = null, signal = null } = {}) {
  try {
    const sb = clientOverride || getSupabase();
    const lim = Math.min(200, Math.max(1, limit));
    const query = sb
      .from('runs')
      .select('id, target, created_at, stats_json')
      .eq('persistence_state', 'complete')
      .order('id', { ascending: false })
      .limit(lim);
    const { data, error } = await withAbortSignal(query, signal);
    if (error) throw error;
    return (data || []).map((r) => ({
      id: r.id,
      target: r.target,
      created_at: r.created_at,
      stats: parseJsonField(r.stats_json),
    }));
  } catch (e) {
    console.error('[GHOSTRECON DB]', e.message);
    return [];
  }
}

export async function listRunsForTarget(
  target,
  limit = 80,
  { client: clientOverride = null, signal = null, strict = true } = {},
) {
  try {
    const sb = clientOverride || getSupabase();
    const t = norm(target);
    const lim = Math.min(500, Math.max(1, Number(limit) || 80));
    const query = sb
      .from('runs')
      .select('id, target, created_at, stats_json')
      .eq('target', t)
      .eq('persistence_state', 'complete')
      .order('id', { ascending: false })
      .limit(lim);
    const { data, error } = await withAbortSignal(query, signal);
    if (error) throw error;
    return (data || []).map((r) => ({
      id: r.id,
      target: r.target,
      created_at: r.created_at,
      stats: parseJsonField(r.stats_json),
    }));
  } catch (e) {
    if (signal?.aborted) throw signal.reason || e;
    if (strict) {
      const error = new Error(`falha ao consultar baselines no Supabase: ${e?.message || e}`, { cause: e });
      error.code = 'BASELINE_STORAGE_READ_FAILED';
      throw error;
    }
    console.error('[GHOSTRECON DB]', e.message);
    return [];
  }
}

export async function getRunById(
  id,
  { client: clientOverride = null, signal = null, strict = false } = {},
) {
  try {
    const sb = clientOverride || getSupabase();
    const runQuery = sb
      .from('runs')
      .select('*')
      .eq('id', id)
      .eq('persistence_state', 'complete')
      .maybeSingle();
    const { data: run, error: rErr } = await withAbortSignal(runQuery, signal);
    if (rErr) throw rErr;
    if (!run) return null;
    const findingsQuery = sb
      .from('findings')
      .select('type, prio, score, value, meta, url')
      .eq('run_id', id)
      .order('id', { ascending: true });
    const { data: tableFindings, error: fErr } = await withAbortSignal(findingsQuery, signal);
    if (fErr) throw fErr;
    const fj = run.findings_json;
    let snap = null;
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
    const findings = snap?.length ? snap : tableFindings || [];
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
    if (signal?.aborted) throw signal.reason || e;
    if (strict) {
      const error = new Error(`falha ao carregar baseline no Supabase: ${e?.message || e}`, { cause: e });
      error.code = 'BASELINE_STORAGE_READ_FAILED';
      throw error;
    }
    console.error('[GHOSTRECON DB]', e.message);
    return null;
  }
}

export async function listIntelForTarget(target, limit = 500) {
  try {
    const sb = getSupabase();
    const t = String(target).trim().toLowerCase();
    const lim = Math.min(2000, Math.max(1, limit));
    const { data, error } = await sb
      .from('bounty_intel')
      .select('type, prio, score, value, meta, url, first_seen, last_seen, last_run_id')
      .eq('target', t)
      .order('last_seen', { ascending: false })
      .limit(lim);
    if (error) throw error;
    return data || [];
  } catch (e) {
    console.error('[GHOSTRECON DB]', e.message);
    return [];
  }
}

export async function intelCountForTarget(target) {
  try {
    const sb = getSupabase();
    const t = String(target).trim().toLowerCase();
    const { count, error } = await sb
      .from('bounty_intel')
      .select('*', { count: 'exact', head: true })
      .eq('target', t);
    if (error) throw error;
    return count ?? 0;
  } catch {
    return 0;
  }
}
