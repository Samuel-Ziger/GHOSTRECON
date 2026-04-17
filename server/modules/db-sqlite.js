import Database from 'better-sqlite3';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { findingsForRunsTable, fingerprintFinding, norm } from './db-common.js';
import { parseFindingsSnapshotJson } from './finding-serialize.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, '..', '..');
export const DATA_DIR = path.join(ROOT, 'data');
/** Raiz local por projeto/escopo — pasta `escopo/` na raiz do repo (ignorada no git). */
export const SCOPE_DIR = path.join(ROOT, 'escopo');
const DEFAULT_DB = path.join(DATA_DIR, 'bugbounty.db');

const SCHEMA_SQL = `
    CREATE TABLE IF NOT EXISTS runs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      target TEXT NOT NULL,
      exact_match INTEGER NOT NULL DEFAULT 0,
      modules_json TEXT NOT NULL,
      stats_json TEXT NOT NULL,
      correlation_json TEXT,
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS findings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      run_id INTEGER NOT NULL,
      type TEXT,
      prio TEXT,
      score INTEGER,
      value TEXT,
      meta TEXT,
      url TEXT,
      FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);

    CREATE TABLE IF NOT EXISTS bounty_intel (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      target TEXT NOT NULL,
      fp TEXT NOT NULL,
      type TEXT,
      prio TEXT,
      score INTEGER,
      value TEXT,
      meta TEXT,
      url TEXT,
      first_seen TEXT NOT NULL,
      last_seen TEXT NOT NULL,
      last_run_id INTEGER,
      UNIQUE(target, fp)
    );
    CREATE INDEX IF NOT EXISTS idx_intel_target ON bounty_intel(target);

    CREATE TABLE IF NOT EXISTS manual_validations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      target TEXT NOT NULL,
      fingerprint TEXT NOT NULL,
      validated_at TEXT NOT NULL,
      snapshot_json TEXT,
      notes TEXT,
      UNIQUE(target, fingerprint)
    );
    CREATE INDEX IF NOT EXISTS idx_manual_val_target ON manual_validations(target);

    CREATE TABLE IF NOT EXISTS brain_categories (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_brain_cat_title ON brain_categories(title);

    CREATE TABLE IF NOT EXISTS brain_links (
      category_id INTEGER NOT NULL,
      target TEXT NOT NULL,
      fingerprint TEXT NOT NULL,
      linked_at TEXT NOT NULL,
      PRIMARY KEY (target, fingerprint),
      FOREIGN KEY (category_id) REFERENCES brain_categories(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_brain_links_category ON brain_links(category_id);
  `;

const BRAIN_CATEGORY_SEED_TITLES = [
  'XSS',
  'SQLi',
  'FTP (anónimo / sem auth)',
  'SSRF',
  'IDOR',
  'RCE',
  'LFI',
  'Open Redirect',
  'XXE',
  'Information Disclosure',
  'Outro',
];

function ensureRunsFindingsJsonColumn(d) {
  try {
    const cols = d.prepare(`PRAGMA table_info(runs)`).all();
    if (!cols.some((c) => c.name === 'findings_json')) {
      d.exec(`ALTER TABLE runs ADD COLUMN findings_json TEXT`);
    }
  } catch {
    /* ignore */
  }
}

function applySqliteSchema(d) {
  d.exec(SCHEMA_SQL);
  ensureRunsFindingsJsonColumn(d);
  ensureBrainSeedCategories(d);
}

function ensureBrainSeedCategories(d) {
  try {
    const n = d.prepare('SELECT COUNT(*) AS c FROM brain_categories').get();
    if ((n?.c ?? 0) > 0) return;
    const now = new Date().toISOString();
    const ins = d.prepare('INSERT INTO brain_categories (title, created_at) VALUES (?, ?)');
    const tx = d.transaction((titles) => {
      for (const t of titles) ins.run(t, now);
    });
    tx(BRAIN_CATEGORY_SEED_TITLES);
  } catch (e) {
    console.error('[GHOSTRECON brain seed]', e?.message || e);
  }
}

let dbInstance = null;

/** Segmento seguro para pasta (projeto ou domínio). */
export function sanitizePathSegment(raw, fallback = 'unnamed') {
  let s = String(raw || '')
    .trim()
    .replace(/\.\./g, '')
    .replace(/[/\\]+/g, '_')
    .replace(/[^a-zA-Z0-9._-]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, 96);
  if (!s) s = fallback;
  return s;
}

/**
 * `escopo/{projeto}/{alvo}/` na raiz do repositório — alvo = domínio (escopo técnico).
 * @returns {string|null} caminho absoluto ou null se sem nome de projeto
 */
export function resolveLocalProjectDbDir(projectName, domain) {
  const p = String(projectName || '').trim();
  if (!p) return null;
  const safeProject = sanitizePathSegment(p);
  const safeScope = sanitizePathSegment(domain, 'scope');
  return path.join(SCOPE_DIR, safeProject, safeScope);
}

export function getDb() {
  if (dbInstance) return dbInstance;
  const dbPath = process.env.GHOSTRECON_DB || DEFAULT_DB;
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  dbInstance = new Database(dbPath);
  dbInstance.pragma('journal_mode = WAL');
  applySqliteSchema(dbInstance);
  return dbInstance;
}

export function mergeIntelForTargetDb(d, target, runId, findings) {
  try {
    const now = new Date().toISOString();
    let newArtifacts = 0;
    let alreadyKnown = 0;

    const sel = d.prepare('SELECT id FROM bounty_intel WHERE target = ? AND fp = ?');
    const ins = d.prepare(
      `INSERT INTO bounty_intel (target, fp, type, prio, score, value, meta, url, first_seen, last_seen, last_run_id)
       VALUES (@target, @fp, @type, @prio, @score, @value, @meta, @url, @first, @last, @run)`,
    );
    const upd = d.prepare(
      `UPDATE bounty_intel SET
         last_seen = @last,
         last_run_id = @run,
         score = CASE WHEN @score > score OR score IS NULL THEN @score ELSE score END,
         prio = CASE WHEN @score > COALESCE(score, 0) THEN @prio ELSE prio END,
         meta = COALESCE(NULLIF(@meta, ''), meta),
         url = COALESCE(NULLIF(@url, ''), url)
       WHERE target = @target AND fp = @fp`,
    );

    const tx = d.transaction((rows) => {
      for (const f of rows) {
        const fp = fingerprintFinding(target, f);
        if (sel.get(target, fp)) {
          upd.run({
            target,
            fp,
            last: now,
            run: runId,
            score: f.score ?? null,
            prio: f.prio ?? null,
            meta: f.meta ?? '',
            url: f.url ?? '',
          });
          alreadyKnown++;
        } else {
          ins.run({
            target,
            fp,
            type: f.type ?? null,
            prio: f.prio ?? null,
            score: f.score ?? null,
            value: f.value ?? '',
            meta: f.meta ?? null,
            url: f.url ?? null,
            first: now,
            last: now,
            run: runId,
          });
          newArtifacts++;
        }
      }
    });
    tx(findings);

    const row = d.prepare('SELECT COUNT(*) AS c FROM bounty_intel WHERE target = ?').get(target);
    const totalKnownForTarget = row?.c ?? 0;

    return { newArtifacts, alreadyKnown, totalKnownForTarget };
  } catch (e) {
    console.error('[GHOSTRECON DB intel]', e.message);
    return { newArtifacts: 0, alreadyKnown: 0, totalKnownForTarget: 0, error: e.message };
  }
}

export function mergeIntelForTarget(target, runId, findings) {
  return mergeIntelForTargetDb(getDb(), target, runId, findings);
}

function saveRunWithDb(d, { target, exactMatch, modules, stats, findings, correlation, findingsJson = null }) {
  const now = new Date().toISOString();
  const insRun = d.prepare(
    `INSERT INTO runs (target, exact_match, modules_json, stats_json, correlation_json, findings_json, created_at)
     VALUES (@target, @exact, @modules, @stats, @corr, @findings_json, @created)`,
  );
  const insFinding = d.prepare(
    `INSERT INTO findings (run_id, type, prio, score, value, meta, url)
     VALUES (@run_id, @type, @prio, @score, @value, @meta, @url)`,
  );

  const runResult = insRun.run({
    target,
    exact: exactMatch ? 1 : 0,
    modules: JSON.stringify(modules),
    stats: JSON.stringify(stats),
    corr: correlation ? JSON.stringify(correlation) : null,
    findings_json: findingsJson,
    created: now,
  });
  const runId = Number(runResult.lastInsertRowid);

  const insertAll = d.transaction((rows) => {
    for (const f of rows) {
      insFinding.run({
        run_id: runId,
        type: f.type,
        prio: f.prio,
        score: f.score ?? null,
        value: f.value,
        meta: f.meta ?? null,
        url: f.url ?? null,
      });
    }
  });
  insertAll(findingsForRunsTable(target, findings));

  const intelMerge = mergeIntelForTargetDb(d, target, runId, findings);
  return { runId, intelMerge };
}

/**
 * Grava run + intel num SQLite dedicado (espelho local ou único quando sem cloud).
 * @returns {{ runId: number, intelMerge: object, dbPath: string } | null}
 */
export function saveRunToProjectDir(projectRootDir, payload) {
  try {
    fs.mkdirSync(projectRootDir, { recursive: true });
    const dbPath = path.join(projectRootDir, 'ghostrecon.db');
    const d = new Database(dbPath);
    d.pragma('journal_mode = WAL');
    applySqliteSchema(d);
    try {
      const out = saveRunWithDb(d, payload);
      return { ...out, dbPath };
    } finally {
      d.close();
    }
  } catch (e) {
    console.error('[GHOSTRECON DB project dir]', e.message);
    return null;
  }
}

export function saveRun({ target, exactMatch, modules, stats, findings, correlation, findingsJson = null }) {
  try {
    const d = getDb();
    return saveRunWithDb(d, { target, exactMatch, modules, stats, findings, correlation, findingsJson });
  } catch (e) {
    console.error('[GHOSTRECON DB]', e.message);
    return null;
  }
}

export function listRuns(limit = 50) {
  try {
    const d = getDb();
    const rows = d
      .prepare(`SELECT id, target, created_at, stats_json FROM runs ORDER BY id DESC LIMIT ?`)
      .all(Math.min(200, Math.max(1, limit)));
    return rows.map((r) => ({
      id: r.id,
      target: r.target,
      created_at: r.created_at,
      stats: JSON.parse(r.stats_json),
    }));
  } catch (e) {
    console.error('[GHOSTRECON DB]', e.message);
    return [];
  }
}

export function getRunById(id) {
  try {
    const d = getDb();
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
  } catch (e) {
    console.error('[GHOSTRECON DB]', e.message);
    return null;
  }
}

export function listIntelForTarget(target, limit = 500) {
  try {
    const d = getDb();
    const t = String(target).trim().toLowerCase();
    return d
      .prepare(
        `SELECT type, prio, score, value, meta, url, first_seen, last_seen, last_run_id
         FROM bounty_intel WHERE target = ? ORDER BY last_seen DESC LIMIT ?`,
      )
      .all(t, Math.min(2000, Math.max(1, limit)));
  } catch (e) {
    console.error('[GHOSTRECON DB]', e.message);
    return [];
  }
}

export function intelCountForTarget(target) {
  try {
    const d = getDb();
    const t = String(target).trim().toLowerCase();
    const r = d.prepare('SELECT COUNT(*) AS c FROM bounty_intel WHERE target = ?').get(t);
    return r?.c ?? 0;
  } catch {
    return 0;
  }
}

function safeJsonParse(s) {
  try {
    return JSON.parse(String(s || 'null'));
  } catch {
    return null;
  }
}

/** Lista validações manuais persistidas para o alvo (fingerprints iguais aos do pipeline). */
export function listManualValidationsForTarget(targetRaw) {
  const d = getDb();
  const target = norm(targetRaw);
  const rows = d
    .prepare(
      `SELECT mv.fingerprint, mv.validated_at, mv.snapshot_json, mv.notes,
              bl.category_id AS brain_category_id,
              bc.title AS brain_category_title
       FROM manual_validations mv
       LEFT JOIN brain_links bl ON bl.target = mv.target AND bl.fingerprint = mv.fingerprint
       LEFT JOIN brain_categories bc ON bc.id = bl.category_id
       WHERE mv.target = ? ORDER BY datetime(mv.validated_at) DESC`,
    )
    .all(target);
  return rows.map((r) => ({
    fingerprint: r.fingerprint,
    validated_at: r.validated_at,
    notes: r.notes || '',
    snapshot: r.snapshot_json ? safeJsonParse(r.snapshot_json) : null,
    brainCategoryId: r.brain_category_id != null ? Number(r.brain_category_id) : null,
    brainCategoryTitle: r.brain_category_title || null,
  }));
}

export function listBrainCategories() {
  const d = getDb();
  ensureBrainSeedCategories(d);
  const rows = d
    .prepare(
      `SELECT c.id, c.title, c.created_at,
        (SELECT COUNT(*) FROM brain_links bl WHERE bl.category_id = c.id) AS link_count
       FROM brain_categories c ORDER BY lower(trim(c.title))`,
    )
    .all();
  return rows.map((r) => ({
    id: Number(r.id),
    title: r.title,
    created_at: r.created_at,
    linkCount: Number(r.link_count) || 0,
  }));
}

export function getBrainCategoryById(idRaw) {
  const d = getDb();
  const cid = Number(idRaw);
  if (!Number.isFinite(cid) || cid < 1) return null;
  const r = d.prepare('SELECT id, title, created_at FROM brain_categories WHERE id = ?').get(cid);
  if (!r) return null;
  return { id: Number(r.id), title: r.title, created_at: r.created_at };
}

export function listBrainLinksForCategory(categoryIdRaw) {
  const d = getDb();
  const cid = Number(categoryIdRaw);
  if (!Number.isFinite(cid) || cid < 1) throw new Error('categoria inválida');
  const rows = d
    .prepare(
      `SELECT bl.target, bl.fingerprint, bl.linked_at, mv.notes, mv.snapshot_json
       FROM brain_links bl
       LEFT JOIN manual_validations mv ON mv.target = bl.target AND mv.fingerprint = bl.fingerprint
       WHERE bl.category_id = ?
       ORDER BY datetime(bl.linked_at) DESC`,
    )
    .all(cid);
  return rows.map((r) => ({
    target: r.target,
    fingerprint: r.fingerprint,
    linked_at: r.linked_at,
    notes: r.notes || '',
    snapshot: r.snapshot_json ? safeJsonParse(r.snapshot_json) : null,
  }));
}

export function createBrainCategory(titleRaw) {
  const d = getDb();
  const title = String(titleRaw || '')
    .trim()
    .slice(0, 120);
  if (!title) throw new Error('título vazio');
  ensureBrainSeedCategories(d);
  const row = d.prepare('SELECT id, title FROM brain_categories WHERE lower(trim(title)) = lower(trim(?))').get(title);
  if (row) return { id: Number(row.id), title: row.title, existing: true };
  const now = new Date().toISOString();
  const info = d.prepare('INSERT INTO brain_categories (title, created_at) VALUES (?, ?)').run(title, now);
  return { id: Number(info.lastInsertRowid), title, existing: false };
}

export function upsertBrainLink({ target: targetRaw, fingerprint, categoryId }) {
  const d = getDb();
  const target = norm(targetRaw);
  const fp = String(fingerprint || '').trim().toLowerCase();
  const cid = Number(categoryId);
  if (!target || !/^[a-z0-9][a-z0-9.-]*[a-z0-9]$/.test(target)) throw new Error('alvo inválido');
  if (!/^[a-f0-9]{64}$/.test(fp)) throw new Error('fingerprint inválido');
  if (!Number.isFinite(cid) || cid < 1) throw new Error('categoria inválida');
  const cat = d.prepare('SELECT id FROM brain_categories WHERE id = ?').get(cid);
  if (!cat) throw new Error('categoria não encontrada');
  const mv = d.prepare('SELECT 1 FROM manual_validations WHERE target = ? AND fingerprint = ?').get(target, fp);
  if (!mv) throw new Error('valida o achado no Reporte antes de ligar ao cérebro');
  const now = new Date().toISOString();
  d.prepare(
    `INSERT INTO brain_links (category_id, target, fingerprint, linked_at)
     VALUES (@cid, @target, @fp, @now)
     ON CONFLICT(target, fingerprint) DO UPDATE SET
       category_id = excluded.category_id,
       linked_at = excluded.linked_at`,
  ).run({ cid, target, fp, now });
  return { ok: true, target, fingerprint: fp, categoryId: cid };
}

export function upsertManualValidation({ target: targetRaw, fingerprint, snapshot, notes }) {
  const d = getDb();
  const target = norm(targetRaw);
  const fp = String(fingerprint || '').trim().toLowerCase();
  if (!target || !/^[a-z0-9][a-z0-9.-]*[a-z0-9]$/.test(target)) throw new Error('alvo inválido');
  if (!/^[a-f0-9]{64}$/.test(fp)) throw new Error('fingerprint inválido');
  const now = new Date().toISOString();
  const snapJson =
    snapshot && typeof snapshot === 'object' ? JSON.stringify(snapshot).slice(0, 12000) : null;
  const n = notes != null ? String(notes).slice(0, 2000) : '';
  d.prepare(
    `INSERT INTO manual_validations (target, fingerprint, validated_at, snapshot_json, notes)
     VALUES (@target, @fp, @now, @snap, @notes)
     ON CONFLICT(target, fingerprint) DO UPDATE SET
       validated_at = excluded.validated_at,
       snapshot_json = COALESCE(excluded.snapshot_json, manual_validations.snapshot_json),
       notes = excluded.notes`,
  ).run({ target, fp, now, snap: snapJson, notes: n });
  return { ok: true };
}

export function deleteManualValidation(targetRaw, fingerprint) {
  const d = getDb();
  const target = norm(targetRaw);
  const fp = String(fingerprint || '').trim().toLowerCase();
  d.prepare('DELETE FROM brain_links WHERE target = ? AND fingerprint = ?').run(target, fp);
  const r = d.prepare('DELETE FROM manual_validations WHERE target = ? AND fingerprint = ?').run(target, fp);
  return { ok: true, changes: r.changes };
}
