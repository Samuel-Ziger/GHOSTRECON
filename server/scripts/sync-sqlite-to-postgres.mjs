#!/usr/bin/env node
import '../load-env.js';

import crypto from 'crypto';
import fs from 'fs';
import Database from 'better-sqlite3';
import postgres from 'postgres';
import { resolveDefaultDbPath } from '../modules/db-sqlite.js';

function argValue(name) {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : '';
}

function hasFlag(name) {
  return process.argv.includes(name);
}

function parseJsonField(v, fallback = null) {
  if (v == null || v === '') return fallback;
  if (typeof v === 'object') return v;
  try {
    return JSON.parse(String(v));
  } catch {
    return fallback;
  }
}

function destinationKey(url) {
  try {
    const u = new URL(url);
    u.username = u.username ? '<user>' : '';
    u.password = u.password ? '<password>' : '';
    return crypto.createHash('sha256').update(u.toString()).digest('hex');
  } catch {
    return crypto.createHash('sha256').update(String(url)).digest('hex');
  }
}

function openLocalDb() {
  const dbPath = argValue('--sqlite') || process.env.GHOSTRECON_SYNC_SQLITE || resolveDefaultDbPath();
  if (!fs.existsSync(dbPath)) {
    throw new Error(`SQLite local nao encontrado: ${dbPath}`);
  }
  const db = new Database(dbPath);
  db.pragma('journal_mode = WAL');
  db.exec(`
    CREATE TABLE IF NOT EXISTS ghostrecon_remote_sync (
      destination TEXT NOT NULL,
      local_run_id INTEGER NOT NULL,
      remote_run_id INTEGER NOT NULL,
      synced_at TEXT NOT NULL,
      PRIMARY KEY (destination, local_run_id)
    );
  `);
  return { db, dbPath };
}

function pendingRuns(db, dest, limit) {
  return db
    .prepare(
      `SELECT r.*
       FROM runs r
       LEFT JOIN ghostrecon_remote_sync s
         ON s.local_run_id = r.id AND s.destination = ?
       WHERE s.local_run_id IS NULL
       ORDER BY r.id ASC
       LIMIT ?`,
    )
    .all(dest, limit);
}

function rowToRunInsert(row, sql) {
  const modules = parseJsonField(row.modules_json, []);
  const stats = parseJsonField(row.stats_json, {});
  const corr = parseJsonField(row.correlation_json, null);
  const findings = parseJsonField(row.findings_json, null);
  return {
    target: String(row.target || '').trim().toLowerCase(),
    exact_match: Boolean(row.exact_match),
    modules_json: sql.json(modules),
    stats_json: sql.json(stats),
    correlation_json: corr == null ? null : sql.json(corr),
    findings_json: findings == null ? null : sql.json(findings),
    created_at: row.created_at || new Date().toISOString(),
  };
}

async function copyRun({ localDb, sql, row, dryRun }) {
  const localRunId = Number(row.id);
  const findings = localDb
    .prepare('SELECT type, prio, score, value, meta, url FROM findings WHERE run_id = ? ORDER BY id ASC')
    .all(localRunId);
  const intel = localDb
    .prepare(
      `SELECT target, fp, type, prio, score, value, meta, url, first_seen, last_seen, last_run_id
       FROM bounty_intel
       WHERE last_run_id = ?
       ORDER BY id ASC`,
    )
    .all(localRunId);

  if (dryRun) {
    return { remoteRunId: null, findings: findings.length, intel: intel.length };
  }

  return await sql.begin(async (tx) => {
    const payload = rowToRunInsert(row, tx);
    const remoteRun = await tx`
      INSERT INTO runs (
        target, exact_match, modules_json, stats_json, correlation_json, findings_json, created_at
      )
      VALUES (
        ${payload.target},
        ${payload.exact_match},
        ${payload.modules_json},
        ${payload.stats_json},
        ${payload.correlation_json},
        ${payload.findings_json},
        ${payload.created_at}
      )
      RETURNING id
    `;
    const remoteRunId = Number(remoteRun[0].id);

    const findingRows = findings.map((f) => ({
      run_id: remoteRunId,
      type: f.type ?? null,
      prio: f.prio ?? null,
      score: f.score ?? null,
      value: f.value ?? null,
      meta: f.meta ?? null,
      url: f.url ?? null,
    }));
    if (findingRows.length) {
      await tx`INSERT INTO findings ${tx(findingRows)}`;
    }

    for (const r of intel) {
      await tx`
        INSERT INTO bounty_intel (
          target, fp, type, prio, score, value, meta, url, first_seen, last_seen, last_run_id
        )
        VALUES (
          ${r.target},
          ${r.fp},
          ${r.type ?? null},
          ${r.prio ?? null},
          ${r.score ?? null},
          ${r.value ?? null},
          ${r.meta ?? null},
          ${r.url ?? null},
          ${r.first_seen},
          ${r.last_seen},
          ${remoteRunId}
        )
        ON CONFLICT (target, fp) DO UPDATE SET
          last_seen = GREATEST(bounty_intel.last_seen, EXCLUDED.last_seen),
          last_run_id = EXCLUDED.last_run_id,
          score = CASE
            WHEN EXCLUDED.score IS NOT NULL AND (bounty_intel.score IS NULL OR EXCLUDED.score > bounty_intel.score)
            THEN EXCLUDED.score
            ELSE bounty_intel.score
          END,
          prio = CASE
            WHEN EXCLUDED.score IS NOT NULL AND (bounty_intel.score IS NULL OR EXCLUDED.score > bounty_intel.score)
            THEN EXCLUDED.prio
            ELSE bounty_intel.prio
          END,
          meta = COALESCE(EXCLUDED.meta, bounty_intel.meta),
          url = COALESCE(EXCLUDED.url, bounty_intel.url)
      `;
    }

    try {
      await tx`
        INSERT INTO ghostrecon_sync_audit (source, local_run_id, remote_run_id, note)
        VALUES (${String(process.env.COMPUTERNAME || process.env.HOSTNAME || 'local')}, ${localRunId}, ${remoteRunId}, ${'sqlite-fallback-sync'})
      `;
    } catch {
      // A tabela de auditoria e opcional; o schema vps-postgres-schema.sql cria ela.
    }

    return { remoteRunId, findings: findings.length, intel: intel.length };
  });
}

async function main() {
  const url = String(process.env.GHOSTRECON_SYNC_DATABASE_URL || process.env.DATABASE_URL || '').trim();
  if (!url) {
    throw new Error('Defina DATABASE_URL ou GHOSTRECON_SYNC_DATABASE_URL apontando para o Postgres da VPS.');
  }

  const limit = Math.min(1000, Math.max(1, Number(argValue('--limit') || process.env.GHOSTRECON_SYNC_LIMIT || 200)));
  const dryRun = hasFlag('--dry-run');
  const { db: localDb, dbPath } = openLocalDb();
  const dest = process.env.GHOSTRECON_SYNC_DESTINATION || destinationKey(url);
  const rows = pendingRuns(localDb, dest, limit);
  const isSupabaseHost = /supabase\.co/i.test(url);
  const sql = postgres(url, { ssl: isSupabaseHost ? 'require' : undefined, max: 1 });

  console.log(`[sync] sqlite=${dbPath}`);
  console.log(`[sync] pendentes=${rows.length} destino=${dest.slice(0, 12)} dryRun=${dryRun}`);

  let synced = 0;
  try {
    const mark = localDb.prepare(
      `INSERT INTO ghostrecon_remote_sync (destination, local_run_id, remote_run_id, synced_at)
       VALUES (@destination, @local_run_id, @remote_run_id, @synced_at)
       ON CONFLICT(destination, local_run_id) DO UPDATE SET
         remote_run_id = excluded.remote_run_id,
         synced_at = excluded.synced_at`,
    );

    for (const row of rows) {
      const out = await copyRun({ localDb, sql, row, dryRun });
      if (!dryRun) {
        mark.run({
          destination: dest,
          local_run_id: Number(row.id),
          remote_run_id: Number(out.remoteRunId),
          synced_at: new Date().toISOString(),
        });
        synced++;
      }
      console.log(
        `[sync] run local #${row.id} -> ${dryRun ? '(dry-run)' : `remote #${out.remoteRunId}`} ` +
          `findings=${out.findings} intel=${out.intel}`,
      );
    }
  } finally {
    await sql.end({ timeout: 5 });
    localDb.close();
  }

  console.log(`[sync] concluido synced=${synced} dryRun=${dryRun}`);
}

main().catch((e) => {
  console.error('[sync]', e?.message || e);
  process.exit(1);
});
