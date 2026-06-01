/**
 * Agrega runs do SQLite global (data/bugbounty.db), bases em escopo/.../ghostrecon.db
 * e (quando configurado) Supabase/Postgres — para o GhostDesk e listagens unificadas.
 */
import fs from 'fs';
import path from 'path';
import Database from 'better-sqlite3';
import * as sqlite from './db-sqlite.js';
import * as supabase from './db-supabase.js';
import * as pg from './db-pg.js';
import { parseFindingsSnapshotJson } from './finding-serialize.js';
import { remoteStorageConfigured } from './db.js';

const { SCOPE_DIR } = sqlite;

const LOCAL_RUNS_TTL_MS = Number(process.env.GHOSTDESK_LOCAL_CACHE_MS) || 4000;
const REMOTE_FETCH_MS = Number(process.env.GHOSTRECON_SUPABASE_TIMEOUT_MS) || 5000;
let localRunsCache = null;
let localRunsCacheAt = 0;

function hasDatabaseUrl() {
  return Boolean(process.env.DATABASE_URL?.trim());
}

function hasSupabaseApi() {
  if (hasDatabaseUrl()) return false;
  const url = process.env.SUPABASE_URL?.trim();
  const key =
    process.env.SUPABASE_SERVICE_ROLE_KEY?.trim() ||
    process.env.SUPABASE_ANON_KEY?.trim() ||
    process.env.SUPABASE_KEY?.trim() ||
    process.env.SUPABASE_PUBLISHABLE_KEY?.trim();
  return Boolean(url && key);
}

/** Normaliza id de rota para runRef (ex.: sqlite:1, scope:proj%2Falvo:2). */
export function normalizeRunRef(raw) {
  const s = String(raw ?? '').trim();
  if (!s) return null;
  if (/^(sqlite|scope|supabase|pg):/.test(s)) return s;
  if (/^\d+$/.test(s)) return `sqlite:${s}`;
  return s;
}

function mapRunRow(r, { storageSource, runRef, scopePath = null }) {
  return {
    id: runRef,
    runRef,
    numericId: r.id,
    target: r.target,
    created_at: r.created_at,
    stats: r.stats,
    storageSource,
    scopePath,
  };
}

function listRunsFromSqliteFile(dbPath, { storageSource, scopePath, runRefPrefix }) {
  if (!fs.existsSync(dbPath)) return [];
  const d = new Database(dbPath, { readonly: true });
  try {
    const rows = d
      .prepare(`SELECT id, target, created_at, stats_json FROM runs ORDER BY id DESC`)
      .all();
    return rows.map((r) => {
      const ref =
        storageSource === 'sqlite'
          ? `sqlite:${r.id}`
          : `${runRefPrefix}:${encodeURIComponent(scopePath)}:${r.id}`;
      return mapRunRow(
        {
          id: r.id,
          target: r.target,
          created_at: r.created_at,
          stats: JSON.parse(r.stats_json),
        },
        { storageSource, runRef: ref, scopePath },
      );
    });
  } catch (e) {
    console.error('[GHOSTRECON DB merge]', dbPath, e.message);
    return [];
  } finally {
    d.close();
  }
}

function buildAllLocalRuns() {
  const out = [];
  const mainDb = process.env.GHOSTRECON_DB || path.join(sqlite.DATA_DIR, 'bugbounty.db');
  out.push(...listRunsFromSqliteFile(mainDb, { storageSource: 'sqlite', runRefPrefix: 'sqlite' }));

  if (fs.existsSync(SCOPE_DIR)) {
    let projects = [];
    try {
      projects = fs.readdirSync(SCOPE_DIR);
    } catch {
      projects = [];
    }
    for (const project of projects) {
      const projectDir = path.join(SCOPE_DIR, project);
      let st;
      try {
        st = fs.statSync(projectDir);
      } catch {
        continue;
      }
      if (!st.isDirectory()) continue;
      let scopes = [];
      try {
        scopes = fs.readdirSync(projectDir);
      } catch {
        continue;
      }
      for (const scope of scopes) {
        const rel = `${project}/${scope}`;
        const dbPath = path.join(projectDir, scope, 'ghostrecon.db');
        out.push(
          ...listRunsFromSqliteFile(dbPath, {
            storageSource: 'scope',
            scopePath: rel,
            runRefPrefix: 'scope',
          }),
        );
      }
    }
  }

  out.sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));
  return out;
}

export function invalidateLocalRunsCache() {
  localRunsCache = null;
  localRunsCacheAt = 0;
}

/** Todos os runs em SQLite local (global + `escopo/`), com cache curto. */
export function listAllLocalRuns(limit = 500) {
  const lim = Math.min(2000, Math.max(1, limit));
  const now = Date.now();
  if (!localRunsCache || now - localRunsCacheAt > LOCAL_RUNS_TTL_MS) {
    localRunsCache = buildAllLocalRuns();
    localRunsCacheAt = now;
  }
  return localRunsCache.slice(0, lim);
}

function resolveSqlitePathForRef(ref) {
  if (ref.startsWith('sqlite:')) {
    return process.env.GHOSTRECON_DB || path.join(sqlite.DATA_DIR, 'bugbounty.db');
  }
  if (ref.startsWith('scope:')) {
    const rest = ref.slice(6);
    const lastColon = rest.lastIndexOf(':');
    if (lastColon <= 0) return null;
    try {
      const rel = decodeURIComponent(rest.slice(0, lastColon));
      return path.join(SCOPE_DIR, rel, 'ghostrecon.db');
    } catch {
      return null;
    }
  }
  return null;
}

function numericIdFromRef(ref) {
  if (ref.startsWith('sqlite:')) return Number(ref.slice(7));
  if (ref.startsWith('scope:')) return Number(ref.split(':').pop());
  return NaN;
}

/** Contagem por prioridade sem carregar findings inteiros (rápido para o dashboard). */
export function countPriosForRunRef(refRaw) {
  const ref = normalizeRunRef(refRaw);
  if (!ref || ref.startsWith('supabase:') || ref.startsWith('pg:')) return null;
  const runId = numericIdFromRef(ref);
  if (!Number.isFinite(runId)) return null;

  if (ref.startsWith('sqlite:')) {
    try {
      const d = sqlite.getDb();
      const rows = d
        .prepare(
          `SELECT lower(COALESCE(prio, 'info')) AS p, COUNT(*) AS c
           FROM findings WHERE run_id = ? GROUP BY lower(COALESCE(prio, 'info'))`,
        )
        .all(runId);
      return Object.fromEntries(rows.map((r) => [r.p, r.c]));
    } catch {
      return null;
    }
  }

  const dbPath = resolveSqlitePathForRef(ref);
  if (!dbPath || !fs.existsSync(dbPath)) return null;
  const d = new Database(dbPath, { readonly: true });
  try {
    const rows = d
      .prepare(
        `SELECT lower(COALESCE(prio, 'info')) AS p, COUNT(*) AS c
         FROM findings WHERE run_id = ? GROUP BY lower(COALESCE(prio, 'info'))`,
      )
      .all(runId);
    return Object.fromEntries(rows.map((r) => [r.p, r.c]));
  } catch {
    return null;
  } finally {
    d.close();
  }
}

/** Dashboard: agrega prios com SQL leve (não abre JSON de findings). */
export function rollupSeverityFast(runs, sampleLimit = 12) {
  const byPrio = {};
  for (const r of runs.slice(0, sampleLimit)) {
    const counts = countPriosForRunRef(r.runRef || r.id);
    if (!counts) continue;
    for (const [p, n] of Object.entries(counts)) {
      byPrio[p] = (byPrio[p] || 0) + n;
    }
  }
  return byPrio;
}

async function listRemoteRunsInner(limit) {
  const lim = Math.min(200, Math.max(1, limit));
  if (!remoteStorageConfigured()) return { rows: [], error: 'Supabase não configurado no .env' };
  let rows = [];
  let storageSource = 'supabase';
  if (hasDatabaseUrl()) {
    storageSource = 'pg';
    rows = await pg.listRuns(lim);
  } else if (hasSupabaseApi()) {
    rows = await supabase.listRuns(lim);
  } else {
    return { rows: [], error: 'Credenciais Supabase em falta' };
  }
  const prefix = storageSource === 'pg' ? 'pg' : 'supabase';
  return {
    rows: rows.map((r) => mapRunRow(r, { storageSource: prefix, runRef: `${prefix}:${r.id}` })),
    error: null,
  };
}

async function listRemoteRuns(limit) {
  const lim = Math.min(200, Math.max(1, limit));
  try {
    const out = await Promise.race([
      listRemoteRunsInner(lim),
      new Promise((_, reject) => {
        setTimeout(() => reject(new Error(`Supabase timeout (${REMOTE_FETCH_MS}ms)`)), REMOTE_FETCH_MS);
      }),
    ]);
    return out;
  } catch (e) {
    console.warn('[GHOSTRECON DB Supabase]', e.message);
    return { rows: [], error: e.message };
  }
}

/**
 * Lista unificada: SQLite local (+ escopo); Supabase só com includeSupabase.
 */
export async function listRunsMerged(limit = 100, { includeSupabase = false } = {}) {
  const lim = Math.min(1000, Math.max(1, limit));
  const local = listAllLocalRuns(Math.max(lim, 120));
  let remote = [];
  let remoteError = null;
  if (includeSupabase) {
    const remoteOut = await listRemoteRuns(lim);
    remote = remoteOut.rows;
    remoteError = remoteOut.error;
  }

  const seen = new Set();
  const merged = [];
  for (const r of [...remote, ...local]) {
    const key = `${r.storageSource}:${r.runRef}:${r.target}:${r.created_at}`;
    if (seen.has(key)) continue;
    seen.add(key);
    merged.push(r);
  }
  merged.sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));

  const sources = {};
  for (const r of merged) {
    sources[r.storageSource] = (sources[r.storageSource] || 0) + 1;
  }

  const parts = ['SQLite local'];
  if (sources.scope) parts.push(`escopo (${sources.scope})`);
  if (includeSupabase) {
    if (remote.length) parts.push(hasDatabaseUrl() ? 'Supabase Postgres' : 'Supabase REST');
    else if (remoteError) parts.push('Supabase (erro)');
  }

  return {
    runs: merged.slice(0, lim),
    storage: parts.join(' + '),
    sources,
    includeSupabase,
    remoteConfigured: remoteStorageConfigured(),
    remoteCount: remote.length,
    localCount: local.length,
    remoteError,
  };
}

/** Intel bounty: SQLite local; Supabase opcional com includeSupabase. */
export async function listIntelMerged(target, limit = 500, { includeSupabase = false } = {}) {
  const t = String(target).trim().toLowerCase();
  const lim = Math.min(2000, Math.max(1, limit));
  const local = sqlite.listIntelForTarget(t, lim);
  let remote = [];
  let remoteError = null;

  if (includeSupabase && remoteStorageConfigured()) {
    try {
      if (hasDatabaseUrl()) remote = await pg.listIntelForTarget(t, lim);
      else if (hasSupabaseApi()) remote = await supabase.listIntelForTarget(t, lim);
    } catch (e) {
      console.warn('[GHOSTRECON DB Supabase intel]', e.message);
      remoteError = e.message;
    }
  } else if (includeSupabase) {
    remoteError = 'Supabase não configurado no .env';
  }

  const byKey = new Map();
  for (const row of [...local, ...remote]) {
    const key = `${row.type || ''}|${row.value || ''}|${row.url || ''}`;
    const cur = byKey.get(key);
    if (!cur || String(row.last_seen || '') > String(cur.last_seen || '')) byKey.set(key, row);
  }
  const items = [...byKey.values()].sort((a, b) =>
    String(b.last_seen || '').localeCompare(String(a.last_seen || '')),
  );

  let source = 'SQLite local';
  if (includeSupabase) {
    if (remote.length) source = local.length ? 'SQLite + Supabase' : 'Supabase REST';
    else if (remoteError) source = `SQLite (Supabase: ${remoteError})`;
  }

  return {
    items: items.slice(0, lim),
    totalUnique: items.length,
    source,
    includeSupabase,
    remoteError,
    localCount: local.length,
    remoteCount: remote.length,
  };
}

function getRunFromSqliteFile(dbPath, id) {
  if (!fs.existsSync(dbPath)) return null;
  const d = new Database(dbPath, { readonly: true });
  try {
    const run = d.prepare(`SELECT * FROM runs WHERE id = ?`).get(id);
    if (!run) return null;
    const tableFindings = d
      .prepare(`SELECT type, prio, score, value, meta, url FROM findings WHERE run_id = ? ORDER BY id`)
      .all(id);
    const snap = run.findings_json ? parseFindingsSnapshotJson(run.findings_json) : null;
    const findings = snap?.length ? snap : tableFindings;
    return {
      id: run.id,
      target: run.target,
      exact_match: Boolean(run.exact_match),
      modules: JSON.parse(run.modules_json),
      stats: JSON.parse(run.stats_json),
      correlation: run.correlation_json ? JSON.parse(run.correlation_json) : null,
      created_at: run.created_at,
      findings,
      findingsScopeRows: snap?.length ? tableFindings : undefined,
    };
  } finally {
    d.close();
  }
}

export async function getRunByRef(refRaw) {
  const ref = normalizeRunRef(refRaw);
  if (!ref) return null;

  if (ref.startsWith('sqlite:')) {
    const id = Number(ref.slice(7));
    if (!Number.isFinite(id)) return null;
    const run = sqlite.getRunById(id);
    return run ? { ...run, runRef: ref, storageSource: 'sqlite' } : null;
  }

  if (ref.startsWith('scope:')) {
    const rest = ref.slice(6);
    const lastColon = rest.lastIndexOf(':');
    if (lastColon <= 0) return null;
    const encPath = rest.slice(0, lastColon);
    const id = Number(rest.slice(lastColon + 1));
    if (!Number.isFinite(id)) return null;
    let rel;
    try {
      rel = decodeURIComponent(encPath);
    } catch {
      return null;
    }
    const dbPath = path.join(SCOPE_DIR, rel, 'ghostrecon.db');
    const run = getRunFromSqliteFile(dbPath, id);
    return run
      ? { ...run, id: ref, runRef: ref, storageSource: 'scope', scopePath: rel }
      : null;
  }

  if (ref.startsWith('supabase:') || ref.startsWith('pg:')) {
    const id = Number(ref.split(':')[1]);
    if (!Number.isFinite(id)) return null;
    const run =
      ref.startsWith('pg:') && hasDatabaseUrl()
        ? await pg.getRunById(id)
        : hasSupabaseApi()
          ? await supabase.getRunById(id)
          : null;
    return run ? { ...run, id: ref, runRef: ref, storageSource: ref.startsWith('pg:') ? 'pg' : 'supabase' } : null;
  }

  return null;
}
