/**
 * Team concurrency — locks por alvo + operator trail.
 *
 * Store: JSON em `.ghostrecon-team/locks.json` e `.ghostrecon-team/trail.jsonl`.
 *
 * Locks:
 *   - `acquireLock(target, {operator, ttlMs, purpose})` — retorna token ou `null` se ocupado
 *   - `releaseLock(target, token)` — libera
 *   - `listLocks()` — inspecção
 *   - TTL automático (expirado = auto-release no próximo check)
 *
 * Trail:
 *   - `recordAction({op, target, action, runId, metadata})` — append NDJSON
 *   - `diffByOperator({target, since})` — agrega quem fez o quê num run
 *
 * Sem DB, sem daemon — coordena via file locking cooperativo (atomic rename).
 */

import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';

function teamDir() {
  return path.resolve(process.cwd(), process.env.GHOSTRECON_TEAM_DIR || '.ghostrecon-team');
}
function locksFile() { return path.join(teamDir(), 'locks.json'); }
function trailFile() { return path.join(teamDir(), 'trail.jsonl'); }

async function ensureDir() {
  await fs.mkdir(teamDir(), { recursive: true });
}

async function loadLocks() {
  await ensureDir();
  try {
    const raw = await fs.readFile(locksFile(), 'utf8');
    const j = JSON.parse(raw);
    if (!j || typeof j !== 'object' || !j.locks) return { locks: [] };
    return j;
  } catch {
    return { locks: [] };
  }
}

async function saveLocks(store) {
  await ensureDir();
  // Atomic write: escreve em tmp + rename.
  const tmp = `${locksFile()}.${process.pid}.${Date.now()}.tmp`;
  await fs.writeFile(tmp, JSON.stringify(store, null, 2), 'utf8');
  await fs.rename(tmp, locksFile());
}

function isExpired(lock, now = Date.now()) {
  const expiresAt = lock.acquiredAt + (lock.ttlMs || 600_000);
  return expiresAt < now;
}

function normalizeTarget(t) {
  return String(t || '').trim().toLowerCase();
}

/**
 * Tenta adquirir lock. Retorna `{ok:true, token}` ou `{ok:false, heldBy}`.
 * Se o lock existente está expirado, toma automaticamente.
 */
export async function acquireLock(target, { operator = 'unknown', ttlMs = 600_000, purpose = 'scan' } = {}) {
  const t = normalizeTarget(target);
  if (!t) throw new Error('target inválido');
  const store = await loadLocks();
  const now = Date.now();
  // Drop expirados
  store.locks = (store.locks || []).filter((l) => !isExpired(l, now));

  const existing = store.locks.find((l) => l.target === t);
  if (existing) {
    return { ok: false, heldBy: existing.operator, acquiredAt: existing.acquiredAt, purpose: existing.purpose };
  }
  const token = crypto.randomBytes(12).toString('hex');
  store.locks.push({ target: t, operator, token, ttlMs, purpose, acquiredAt: now });
  await saveLocks(store);
  return { ok: true, token, ttlMs, acquiredAt: now };
}

/**
 * Libera lock (apenas o dono do token). Retorna boolean.
 */
export async function releaseLock(target, token) {
  const t = normalizeTarget(target);
  const store = await loadLocks();
  const before = store.locks.length;
  store.locks = (store.locks || []).filter((l) => !(l.target === t && l.token === token));
  if (store.locks.length !== before) {
    await saveLocks(store);
    return true;
  }
  return false;
}

/**
 * Força release (admin). Use com cuidado.
 */
export async function forceReleaseLock(target) {
  const t = normalizeTarget(target);
  const store = await loadLocks();
  const before = store.locks.length;
  store.locks = (store.locks || []).filter((l) => l.target !== t);
  if (store.locks.length !== before) { await saveLocks(store); return true; }
  return false;
}

export async function listLocks() {
  const store = await loadLocks();
  const now = Date.now();
  return (store.locks || []).map((l) => ({
    target: l.target, operator: l.operator, purpose: l.purpose,
    acquiredAt: new Date(l.acquiredAt).toISOString(),
    expiresAt: new Date(l.acquiredAt + (l.ttlMs || 600_000)).toISOString(),
    expired: isExpired(l, now),
  }));
}

/**
 * Executa fn sob lock (auto-release via finally). Propaga erro de aquisição.
 */
export async function withLock(target, fn, opts = {}) {
  const acq = await acquireLock(target, opts);
  if (!acq.ok) {
    const err = new Error(`target "${target}" já está em lock por ${acq.heldBy} (acquired=${new Date(acq.acquiredAt).toISOString()})`);
    err.code = 'ELOCKED';
    err.heldBy = acq.heldBy;
    throw err;
  }
  try {
    return await fn({ token: acq.token });
  } finally {
    await releaseLock(target, acq.token);
  }
}

// ============================================================================
// Operator trail (quem fez o quê)
// ============================================================================

/**
 * Registra ação num NDJSON append-only.
 *
 * Tipos comuns: run-start, run-complete, finding-added, evidence-captured,
 * finding-validated, finding-suppressed.
 */
export async function recordAction({ operator = 'unknown', target, action, runId = null, metadata = null } = {}) {
  if (!target || !action) throw new Error('target + action obrigatórios');
  await ensureDir();
  const entry = {
    at: new Date().toISOString(),
    operator: String(operator),
    target: normalizeTarget(target),
    action: String(action),
    runId: runId != null ? runId : null,
    metadata: metadata || null,
  };
  await fs.appendFile(trailFile(), `${JSON.stringify(entry)}\n`, 'utf8');
  return entry;
}

async function readTrail() {
  try {
    const raw = await fs.readFile(trailFile(), 'utf8');
    const lines = raw.split('\n').filter(Boolean);
    return lines.map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
  } catch {
    return [];
  }
}

/**
 * Lista trail filtrado.
 */
export async function listTrail({ target = null, operator = null, runId = null, sinceIso = null, limit = 500 } = {}) {
  const all = await readTrail();
  const t = target ? normalizeTarget(target) : null;
  const since = sinceIso ? Date.parse(sinceIso) : null;
  return all.filter((e) => {
    if (t && e.target !== t) return false;
    if (operator && e.operator !== operator) return false;
    if (runId != null && e.runId != runId) return false;
    if (since && Date.parse(e.at) < since) return false;
    return true;
  }).slice(-limit);
}

/**
 * Diff entre operadores: quem adicionou/validou/capturou evidência num alvo.
 * Retorna `{byOperator: {op: {actions, counts}}, runs: [runId]}`.
 */
export async function diffByOperator({ target, sinceIso = null } = {}) {
  const entries = await listTrail({ target, sinceIso, limit: 10_000 });
  const byOperator = {};
  const runs = new Set();
  for (const e of entries) {
    if (e.runId != null) runs.add(e.runId);
    if (!byOperator[e.operator]) byOperator[e.operator] = { actions: [], counts: {} };
    byOperator[e.operator].actions.push(e);
    byOperator[e.operator].counts[e.action] = (byOperator[e.operator].counts[e.action] || 0) + 1;
  }
  return { target: normalizeTarget(target), byOperator, runs: [...runs] };
}
