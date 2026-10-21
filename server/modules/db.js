import * as sqlite from './db-sqlite.js';
import * as supabase from './db-supabase.js';
import * as pg from './db-pg.js';
import { isReconTargetStorageKey } from './recon-target.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

import { fingerprintFinding, norm, isSha256FingerprintHex } from './db-common.js';
import { serializeFindingsForRunSnapshot } from './finding-serialize.js';
import { redactRunPayloadForPersistence } from './finding-redaction.mjs';
import { throwIfAborted } from './http-utils.js';
export { fingerprintFinding, norm, isSha256FingerprintHex } from './db-common.js';
export { resolveLocalProjectDbDir, sanitizePathSegment } from './db-sqlite.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, '..', '..');
const VALIDATE_DIR = path.join(ROOT, 'Validate');

/** 1 = comportamento antigo: Supabase/Postgres como backend principal se estiver no .env */
export function supabaseAutoEnabled() {
  return String(process.env.GHOSTRECON_SUPABASE_AUTO || '').trim() === '1';
}

/** Credenciais remotas presentes (pode usar com interruptor no GhostDesk). */
export function remoteStorageConfigured() {
  if (process.env.DATABASE_URL?.trim()) return true;
  const url = process.env.SUPABASE_URL?.trim();
  const key =
    process.env.SUPABASE_SERVICE_ROLE_KEY?.trim() ||
    process.env.SUPABASE_ANON_KEY?.trim() ||
    process.env.SUPABASE_KEY?.trim() ||
    process.env.SUPABASE_PUBLISHABLE_KEY?.trim();
  return Boolean(url && key);
}

/** Conexão direta Postgres — só automática com GHOSTRECON_SUPABASE_AUTO=1 */
function useDatabaseUrl() {
  const url = process.env.DATABASE_URL?.trim();
  if (!url) return false;
  if (databaseUrlLooksLikeSupabase()) return supabaseAutoEnabled();
  return true;
}

function databaseUrlLooksLikeSupabase() {
  return /supabase\.(co|com)|supabase\.co/i.test(process.env.DATABASE_URL?.trim() || '');
}

function useSupabaseApi() {
  if (!supabaseAutoEnabled()) return false;
  if (useDatabaseUrl()) return false;
  const url = process.env.SUPABASE_URL?.trim();
  // A API REST é um backend de escrita. Chaves anon/publishable podem ser
  // usadas por consumidores estritamente de leitura, mas nunca selecionam a
  // persistência primária do scanner.
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY?.trim();
  return Boolean(url && key);
}

export function isUsingSupabase() {
  return usePostgresPrimary() && ((useDatabaseUrl() && databaseUrlLooksLikeSupabase()) || useSupabaseApi());
}

/**
 * Backend principal de runs/intel.
 * - sqlite | local → sempre SQLite (ignora DATABASE_URL)
 * - postgres | remote → Postgres/Supabase se configurado
 * - vazio → postgres se DATABASE_URL/Supabase auto, senão sqlite
 */
export function resolveStorageMode() {
  const raw = String(process.env.GHOSTRECON_STORAGE || '').trim().toLowerCase();
  if (raw === 'sqlite' || raw === 'local') return 'sqlite';
  if (raw === 'postgres' || raw === 'remote') return 'postgres';
  if (useDatabaseUrl() || useSupabaseApi()) return 'postgres';
  return 'sqlite';
}

export function usePostgresPrimary() {
  return resolveStorageMode() === 'postgres';
}

export function storageLabel() {
  if (!usePostgresPrimary()) {
    const p = sqlite.resolveDefaultDbPath();
    return `SQLite (${p.replace(/^.*\//, '')})`;
  }
  if (useDatabaseUrl()) {
    return databaseUrlLooksLikeSupabase() ? 'Supabase Postgres (DATABASE_URL)' : 'Postgres (DATABASE_URL)';
  }
  if (useSupabaseApi()) return 'Supabase (API REST)';
  return 'SQLite (data/bugbounty.db)';
}

async function postgresReachable() {
  if (!useDatabaseUrl()) return { ok: false, error: 'DATABASE_URL em falta' };
  return pg.probeConnection();
}

function remoteFallbackEnabled() {
  return String(process.env.GHOSTRECON_REMOTE_FALLBACK_SQLITE ?? '1').trim() !== '0';
}

function remoteBackendAvailable() {
  return usePostgresPrimary() && (useDatabaseUrl() || useSupabaseApi());
}

function ensureValidateDir() {
  fs.mkdirSync(VALIDATE_DIR, { recursive: true });
  return VALIDATE_DIR;
}


function normalizeValidationArchiveRecord(row) {
  const target = String(row?.target || '')
    .trim()
    .toLowerCase();
  const fingerprint = String(row?.fingerprint || '')
    .trim()
    .toLowerCase();
  if (!isReconTargetStorageKey(target)) return null;
  if (!isSha256FingerprintHex(fingerprint)) return null;
  return {
    target,
    fingerprint,
    validated_at: String(row?.validated_at || row?.validatedAt || new Date().toISOString()),
    notes: row?.notes != null ? String(row.notes) : '',
    snapshot: row?.snapshot && typeof row.snapshot === 'object' ? row.snapshot : null,
    brainCategoryId:
      row?.brainCategoryId != null && Number.isFinite(Number(row.brainCategoryId))
        ? Number(row.brainCategoryId)
        : null,
    brainCategoryTitle:
      row?.brainCategoryTitle != null && String(row.brainCategoryTitle).trim()
        ? String(row.brainCategoryTitle).trim()
        : null,
  };
}

function validationArchivePath(targetRaw, fingerprintRaw) {
  const target = sqlite.sanitizePathSegment(String(targetRaw || '').trim().toLowerCase(), 'target');
  const fp = String(fingerprintRaw || '').trim().toLowerCase();
  return path.join(ensureValidateDir(), target, `${fp}.json`);
}

function writeValidationArchive(row) {
  const rec = normalizeValidationArchiveRecord(row);
  if (!rec) return;
  const filePath = validationArchivePath(rec.target, rec.fingerprint);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(rec, null, 2), 'utf8');
}

function deleteValidationArchive(targetRaw, fingerprintRaw) {
  const filePath = validationArchivePath(targetRaw, fingerprintRaw);
  try {
    fs.unlinkSync(filePath);
  } catch (e) {
    if (e?.code !== 'ENOENT') throw e;
  }
}

function listValidationArchivesForTarget(targetRaw) {
  const target = String(targetRaw || '')
    .trim()
    .toLowerCase();
  if (!isReconTargetStorageKey(target)) return [];
  const dir = path.join(ensureValidateDir(), sqlite.sanitizePathSegment(target, 'target'));
  if (!fs.existsSync(dir)) return [];
  let names = [];
  try {
    names = fs.readdirSync(dir);
  } catch {
    return [];
  }
  const out = [];
  for (const name of names) {
    if (!name.endsWith('.json')) continue;
    const full = path.join(dir, name);
    try {
      const raw = fs.readFileSync(full, 'utf8');
      const rec = normalizeValidationArchiveRecord(JSON.parse(raw));
      if (rec && rec.target === target) out.push(rec);
    } catch {
      /* ignora ficheiro inválido */
    }
  }
  out.sort((a, b) => String(b.validated_at).localeCompare(String(a.validated_at)));
  return out;
}

/**
 * @param {object} payload
 * @param {string} [payload.localProjectName] nome da pasta projeto; cria `escopo/{nome}/{domínio}/ghostrecon.db`
 * @returns {Promise<{ runId: number, intelMerge: object, localMirrorPath?: string } | null>}
 */
export async function saveRun(
  payload,
  {
    signal = null,
    pgAdapter = pg,
    supabaseAdapter = supabase,
    sqliteAdapter = sqlite,
  } = {},
) {
  throwIfAborted(signal);
  const sanitizedPayload = sanitizeRunPayloadForPersistence(payload);
  const { localProjectName, ...rest } = sanitizedPayload;
  const projectDir = sqlite.resolveLocalProjectDbDir(localProjectName, rest.target);
  const useRemote = remoteBackendAvailable();

  let result = null;
  if (useRemote && useDatabaseUrl()) {
    result = await pgAdapter.saveRun(rest, { signal });
  } else if (useRemote && useSupabaseApi()) {
    result = await supabaseAdapter.saveRun(rest, { signal });
  } else if (projectDir) {
    result = sqliteAdapter.saveRunToProjectDir(projectDir, rest);
  } else {
    result = sqliteAdapter.saveRun(rest);
  }

  if (projectDir && useRemote) {
    throwIfAborted(signal);
    try {
      const mirror = sqliteAdapter.saveRunToProjectDir(projectDir, rest);
      if (mirror?.dbPath) {
        if (result) {
          result = { ...result, localMirrorPath: mirror.dbPath };
        } else {
          result = {
            runId: mirror.runId,
            intelMerge: mirror.intelMerge,
            localMirrorPath: mirror.dbPath,
            remoteSaveFailed: true,
          };
        }
      }
    } catch (e) {
      console.error('[GHOSTRECON local mirror]', e);
    }
  }

  if (!result && useRemote && !projectDir && remoteFallbackEnabled()) {
    throwIfAborted(signal);
    try {
      const fallback = sqliteAdapter.saveRun(rest);
      if (fallback?.dbPath) {
        result = {
          ...fallback,
          localFallbackPath: fallback.dbPath,
          remoteSaveFailed: true,
        };
      }
    } catch (e) {
      console.error('[GHOSTRECON remote fallback]', e);
    }
  }

  if (result?.runId != null && String(localProjectName || '').trim() && Array.isArray(rest.findings)) {
    throwIfAborted(signal);
    try {
      const d = sqlite.getDb();
      const m = sqlite.mergeProjectSecretPeersDb(d, localProjectName, rest.target, result.runId, rest.findings);
      result = { ...result, projectSecretDuplicates: m.duplicates };
    } catch (e) {
      console.warn('[GHOSTRECON project_secret_peers]', e?.message || e);
    }
  }

  return result;
}

/**
 * Último gate antes de qualquer backend de persistência. Não confia no
 * `findingsJson` fornecido pelo chamador: quando existe snapshot, ele é
 * reconstruído exclusivamente a partir dos findings já redigidos.
 */
export function sanitizeRunPayloadForPersistence(payload = {}) {
  const safe = redactRunPayloadForPersistence(payload);
  const requiresStructuredSnapshot = Array.isArray(safe.findings)
    && safe.findings.some((finding) => finding?.type === 'api_contract_snapshot');
  const findingsJson = payload.findingsJson == null && !requiresStructuredSnapshot
    ? null
    : serializeFindingsForRunSnapshot(safe.findings);
  if (requiresStructuredSnapshot && !findingsJson) {
    const error = new Error('api_contract_snapshot não pôde ser serializado com integridade');
    error.code = 'SNAPSHOT_SERIALIZATION_FAILED';
    throw error;
  }
  return {
    ...safe,
    findingsJson,
  };
}

/** Correlação de segredos (value_fp) entre alvos no mesmo nome de projeto — índice em SQLite local. */
export function listProjectSecretDuplicates(projectName) {
  try {
    const d = sqlite.getDb();
    return sqlite.listProjectSecretDuplicatesSqlite(d, sqlite.sanitizePathSegment(String(projectName || '').trim()));
  } catch (e) {
    console.error('[GHOSTRECON listProjectSecretDuplicates]', e.message);
    return [];
  }
}

export async function listRuns(limit) {
  if (usePostgresPrimary()) {
    if (useDatabaseUrl()) {
      const probe = await postgresReachable();
      if (probe.ok) return pg.listRuns(limit);
      if (remoteFallbackEnabled()) {
        console.warn(`[GHOSTRECON DB] Postgres indisponível — listRuns via SQLite: ${probe.error}`);
        return sqlite.listRuns(limit);
      }
      return [];
    }
    if (useSupabaseApi()) return supabase.listRuns(limit);
  }
  return sqlite.listRuns(limit);
}

/**
 * Candidatos de baseline por alvo. Em modo remoto, inclui o SQLite local para
 * que um fallback de persistência continue legível no run seguinte.
 */
export async function listRunsForTarget(
  target,
  limit = 80,
  {
    signal = null,
    localProjectName = '',
    pgAdapter = pg,
    supabaseAdapter = supabase,
    sqliteAdapter = sqlite,
  } = {},
) {
  throwIfAborted(signal);
  const t = norm(target);
  const lim = Math.min(500, Math.max(1, Number(limit) || 80));
  const remoteRows = [];
  const localRows = [];
  const useRemote = remoteBackendAvailable();
  const projectDir = sqlite.resolveLocalProjectDbDir(localProjectName, t);
  let remoteError = null;
  let localError = null;

  try {
    if (useRemote && useDatabaseUrl()) {
      const remote = await pgAdapter.listRunsForTarget(t, lim, { signal });
      remoteRows.push(...remote.map((row) => ({ ...row, _storageSource: 'postgres' })));
    } else if (useRemote && useSupabaseApi()) {
      const remote = await supabaseAdapter.listRunsForTarget(t, lim, { signal });
      remoteRows.push(...remote.map((row) => ({ ...row, _storageSource: 'supabase' })));
    }
  } catch (error) {
    if (signal?.aborted) throw signal.reason || error;
    remoteError = error;
  }
  throwIfAborted(signal);

  try {
    if (projectDir) {
      const local = sqliteAdapter.listRunsForTargetInProjectDir(projectDir, t, lim);
      const projectName = sqlite.sanitizePathSegment(String(localProjectName || '').trim());
      localRows.push(...local.map((row) => ({
        ...row,
        _storageSource: 'sqlite-project',
        _storageProjectName: projectName,
      })));
    } else if (!useRemote || remoteFallbackEnabled()) {
      const local = sqliteAdapter.listRunsForTarget(t, lim, { strict: true });
      localRows.push(...local.map((row) => ({ ...row, _storageSource: 'sqlite' })));
    }
  } catch (error) {
    localError = error;
  }
  throwIfAborted(signal);

  // Um erro remoto não apaga um mirror/fallback comprovadamente legível. Se
  // não há candidato local, mantemos o fail-closed para não confundir falha
  // de storage com inexistência de baseline.
  if (remoteError && localRows.length === 0) throw remoteError;
  if (localError && remoteRows.length === 0) throw localError;
  const degradedErrors = [remoteError, localError].filter(Boolean);
  const rows = [...remoteRows, ...localRows].map((row) => degradedErrors.length
    ? {
        ...row,
        _storageDegraded: true,
        _storageWarning: degradedErrors
          .map((error) => String(error?.message || error).slice(0, 300))
          .join(' | '),
      }
    : row);

  return rows.sort((left, right) => {
    const leftCreated = Date.parse(
      left.created_at instanceof Date ? left.created_at.toISOString() : String(left.created_at || ''),
    );
    const rightCreated = Date.parse(
      right.created_at instanceof Date ? right.created_at.toISOString() : String(right.created_at || ''),
    );
    const byCreated = (Number.isFinite(rightCreated) ? rightCreated : Number.NEGATIVE_INFINITY)
      - (Number.isFinite(leftCreated) ? leftCreated : Number.NEGATIVE_INFINITY);
    if (byCreated) return byCreated;
    return Number(right.id || 0) - Number(left.id || 0);
  });
}

export async function getRunByStorageRef(
  id,
  {
    row = null,
    signal = null,
    localProjectName = '',
    pgAdapter = pg,
    supabaseAdapter = supabase,
    sqliteAdapter = sqlite,
  } = {},
) {
  throwIfAborted(signal);
  const source = row?._storageSource;
  if (source === 'sqlite') return sqliteAdapter.getRunById(id, { strict: true });
  if (source === 'sqlite-project') {
    const projectName = String(localProjectName || row?._storageProjectName || '').trim();
    const projectDir = sqlite.resolveLocalProjectDbDir(projectName, row?.target);
    if (!projectDir) {
      const error = new Error('referência SQLite de projeto sem identidade do projeto');
      error.code = 'PROJECT_STORAGE_REFERENCE_INVALID';
      throw error;
    }
    return sqliteAdapter.getRunByIdFromProjectDir(projectDir, id);
  }
  if (source === 'postgres') return pgAdapter.getRunById(id, { signal, strict: true });
  if (source === 'supabase') return supabaseAdapter.getRunById(id, { signal, strict: true });
  return getRunById(id);
}

export async function getRunById(id) {
  if (usePostgresPrimary()) {
    if (useDatabaseUrl()) {
      const probe = await postgresReachable();
      if (probe.ok) {
        const run = await pg.getRunById(id);
        if (run) return run;
      } else if (remoteFallbackEnabled()) {
        console.warn(`[GHOSTRECON DB] Postgres indisponível — getRunById via SQLite: ${probe.error}`);
      } else {
        return null;
      }
    } else if (useSupabaseApi()) {
      return supabase.getRunById(id);
    }
  }
  return sqlite.getRunById(id);
}

export async function listIntelForTarget(target, limit) {
  if (usePostgresPrimary()) {
    if (useDatabaseUrl()) {
      const probe = await postgresReachable();
      if (probe.ok) return pg.listIntelForTarget(target, limit);
      if (remoteFallbackEnabled()) {
        console.warn(`[GHOSTRECON DB] Postgres indisponível — intel via SQLite: ${probe.error}`);
        return sqlite.listIntelForTarget(target, limit);
      }
      return [];
    }
    if (useSupabaseApi()) return supabase.listIntelForTarget(target, limit);
  }
  return sqlite.listIntelForTarget(target, limit);
}

export async function intelCountForTarget(target) {
  if (usePostgresPrimary()) {
    if (useDatabaseUrl()) {
      const probe = await postgresReachable();
      if (probe.ok) return pg.intelCountForTarget(target);
      if (remoteFallbackEnabled()) {
        return sqlite.intelCountForTarget(target);
      }
      return 0;
    }
    if (useSupabaseApi()) return supabase.intelCountForTarget(target);
  }
  return sqlite.intelCountForTarget(target);
}

/** Validação manual sempre em SQLite local + espelho em `Validate/`. */
export async function listManualValidationsForTarget(target) {
  const fromArchive = listValidationArchivesForTarget(target);
  const archiveByFp = new Map(fromArchive.map((x) => [x.fingerprint, x]));
  try {
    const fromDb = sqlite.listManualValidationsForTarget(target);
    const merged = fromDb.map((x) => {
      const a = archiveByFp.get(String(x.fingerprint || '').toLowerCase());
      return a
        ? {
            ...x,
            notes: a.notes != null ? String(a.notes) : x.notes,
            snapshot: a.snapshot ?? x.snapshot ?? null,
          }
        : x;
    });
    const mergedFp = new Set(merged.map((x) => String(x.fingerprint || '').toLowerCase()));
    for (const a of fromArchive) {
      if (mergedFp.has(a.fingerprint)) continue;
      merged.push({
        fingerprint: a.fingerprint,
        validated_at: a.validated_at,
        notes: a.notes,
        snapshot: a.snapshot,
        brainCategoryId: a.brainCategoryId,
        brainCategoryTitle: a.brainCategoryTitle,
      });
    }
    return merged.sort((a, b) => String(b.validated_at).localeCompare(String(a.validated_at)));
  } catch (e) {
    console.error('[GHOSTRECON manual_validations list]', e?.message || e);
    return fromArchive;
  }
}

export async function upsertManualValidation(row) {
  const out = sqlite.upsertManualValidation(row);
  try {
    writeValidationArchive({
      target: row?.target,
      fingerprint: row?.fingerprint,
      validated_at: new Date().toISOString(),
      snapshot: row?.snapshot ?? null,
      notes: row?.notes ?? '',
    });
  } catch (e) {
    console.error('[GHOSTRECON manual_validations archive write]', e?.message || e);
  }
  return out;
}

export async function deleteManualValidation(target, fingerprint) {
  const out = sqlite.deleteManualValidation(target, fingerprint);
  try {
    deleteValidationArchive(target, fingerprint);
  } catch (e) {
    console.error('[GHOSTRECON manual_validations archive delete]', e?.message || e);
  }
  return out;
}

/** Categorias do «cérebro» sempre em SQLite local. */
export async function listBrainCategories() {
  try {
    return sqlite.listBrainCategories();
  } catch (e) {
    console.error('[GHOSTRECON brain categories]', e?.message || e);
    return [];
  }
}

export async function createBrainCategory(title) {
  return sqlite.createBrainCategory(title);
}

export async function updateBrainCategoryDescription(id, description) {
  return sqlite.updateBrainCategoryDescription(id, description);
}

export async function upsertBrainLink(row) {
  return sqlite.upsertBrainLink(row);
}

export async function getBrainCategoryById(id) {
  try {
    return sqlite.getBrainCategoryById(id);
  } catch {
    return null;
  }
}

export async function listBrainLinksForCategory(categoryId) {
  try {
    return sqlite.listBrainLinksForCategory(categoryId);
  } catch (e) {
    console.error('[GHOSTRECON brain links]', e?.message || e);
    return [];
  }
}
