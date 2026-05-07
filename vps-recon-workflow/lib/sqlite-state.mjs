import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import Database from 'better-sqlite3';
import { resolveFromRoot } from './paths.mjs';

function fingerprint(f) {
  if (f && f.fingerprint != null && String(f.fingerprint).trim()) return String(f.fingerprint).trim();
  const stab = `${f?.type ?? ''}|${typeof f?.value === 'string' ? f.value : JSON.stringify(f?.value)}|${f?.url ?? ''}`;
  return crypto.createHash('sha256').update(stab).digest('hex');
}

/** @param {unknown} rawPath */
export function openStateDb(rawPath) {
  const rel = rawPath ? String(rawPath).trim() : './data/workflow-state.db';
  const dbPath = resolveFromRoot(rel);
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  const db = new Database(dbPath);
  db.pragma('journal_mode = WAL');
  db.exec(`
    CREATE TABLE IF NOT EXISTS wf_finding_seen (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      fingerprint TEXT NOT NULL UNIQUE,
      target TEXT,
      payload_json TEXT,
      first_seen TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS wf_cycle (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      started_at TEXT NOT NULL,
      note TEXT,
      targets_processed INTEGER,
      new_findings INTEGER,
      finished_at TEXT
    );
    CREATE INDEX IF NOT EXISTS wf_finding_seen_fp ON wf_finding_seen(fingerprint);
  `);
  return db;
}

/**
 * Insere apenas fingerprints novos. Devolve linhas novas para webhook (objeto flatten leve).
 * @returns {Record<string, unknown>[]}
 */
export function filterInsertNew(db, target, findings) {
  const ins = db.prepare(
    'INSERT OR IGNORE INTO wf_finding_seen (fingerprint, target, payload_json, first_seen) VALUES (@fp, @t, @j, @s)',
  );
  const iso = new Date().toISOString();
  /** @type {Record<string, unknown>[]} */
  const out = [];
  for (const f of findings || []) {
    if (!f || typeof f !== 'object') continue;
    const fp = fingerprint(f);
    const row = {
      fingerprint: fp,
      type: f.type,
      prio: f.prio,
      value: f.value,
      url: f.url,
      targetBucket: target,
      score: f.score,
    };
    const r = ins.run({ fp, t: target, j: JSON.stringify(row), s: iso });
    if (r.changes > 0) out.push(row);
  }
  return out;
}

export function insertCycle(db, note) {
  const started = new Date().toISOString();
  const r = db
    .prepare('INSERT INTO wf_cycle (started_at, note) VALUES (@s, @n)')
    .run({ s: started, n: note || '' });
  return Number(r.lastInsertRowid);
}

export function finalizeCycle(db, cycleId, targetsProcessed, newCount) {
  db.prepare(
    'UPDATE wf_cycle SET finished_at = @f, targets_processed = @tp, new_findings = @n WHERE id = @id',
  ).run({
    f: new Date().toISOString(),
    tp: targetsProcessed,
    n: newCount,
    id: cycleId,
  });
}
