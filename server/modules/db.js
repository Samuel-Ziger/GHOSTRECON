import * as sqlite from './db-sqlite.js';
import * as supabase from './db-supabase.js';
import * as pg from './db-pg.js';

export { fingerprintFinding, norm } from './db-common.js';
export { resolveLocalProjectDbDir, sanitizePathSegment } from './db-sqlite.js';

/** Conexão direta Postgres (recomendado no Node; IPv4 → Session Pooler no dashboard). */
function useDatabaseUrl() {
  return Boolean(process.env.DATABASE_URL?.trim());
}

function useSupabaseApi() {
  if (useDatabaseUrl()) return false;
  const url = process.env.SUPABASE_URL?.trim();
  const key =
    process.env.SUPABASE_SERVICE_ROLE_KEY?.trim() ||
    process.env.SUPABASE_ANON_KEY?.trim() ||
    process.env.SUPABASE_KEY?.trim() ||
    process.env.SUPABASE_PUBLISHABLE_KEY?.trim();
  return Boolean(url && key);
}

export function isUsingSupabase() {
  return useDatabaseUrl() || useSupabaseApi();
}

export function storageLabel() {
  if (useDatabaseUrl()) return 'Supabase Postgres (DATABASE_URL)';
  if (useSupabaseApi()) return 'Supabase (API REST)';
  return 'SQLite (data/bugbounty.db)';
}

/**
 * @param {object} payload
 * @param {string} [payload.localProjectName] nome da pasta projeto; cria `escopo/{nome}/{domínio}/ghostrecon.db`
 * @returns {Promise<{ runId: number, intelMerge: object, localMirrorPath?: string } | null>}
 */
export async function saveRun(payload) {
  const { localProjectName, ...rest } = payload;
  const projectDir = sqlite.resolveLocalProjectDbDir(localProjectName, rest.target);
  const useRemote = useDatabaseUrl() || useSupabaseApi();

  let result = null;
  if (useDatabaseUrl()) {
    result = await pg.saveRun(rest);
  } else if (useSupabaseApi()) {
    result = await supabase.saveRun(rest);
  } else if (projectDir) {
    result = sqlite.saveRunToProjectDir(projectDir, rest);
  } else {
    result = sqlite.saveRun(rest);
  }

  if (projectDir && useRemote) {
    try {
      const mirror = sqlite.saveRunToProjectDir(projectDir, rest);
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

  return result;
}

export async function listRuns(limit) {
  if (useDatabaseUrl()) return pg.listRuns(limit);
  if (useSupabaseApi()) return supabase.listRuns(limit);
  return sqlite.listRuns(limit);
}

export async function getRunById(id) {
  if (useDatabaseUrl()) return pg.getRunById(id);
  if (useSupabaseApi()) return supabase.getRunById(id);
  return sqlite.getRunById(id);
}

export async function listIntelForTarget(target, limit) {
  if (useDatabaseUrl()) return pg.listIntelForTarget(target, limit);
  if (useSupabaseApi()) return supabase.listIntelForTarget(target, limit);
  return sqlite.listIntelForTarget(target, limit);
}

export async function intelCountForTarget(target) {
  if (useDatabaseUrl()) return pg.intelCountForTarget(target);
  if (useSupabaseApi()) return supabase.intelCountForTarget(target);
  return sqlite.intelCountForTarget(target);
}

/** Validação manual de achados (SQLite local). Com Postgres/Supabase API ainda não persistido — devolve lista vazia. */
export async function listManualValidationsForTarget(target) {
  if (useDatabaseUrl() || useSupabaseApi()) return [];
  try {
    return sqlite.listManualValidationsForTarget(target);
  } catch (e) {
    console.error('[GHOSTRECON manual_validations list]', e?.message || e);
    return [];
  }
}

export async function upsertManualValidation(row) {
  if (useDatabaseUrl() || useSupabaseApi()) {
    throw new Error('Validação manual só persiste em SQLite (sem DATABASE_URL / Supabase nesta versão).');
  }
  return sqlite.upsertManualValidation(row);
}

export async function deleteManualValidation(target, fingerprint) {
  if (useDatabaseUrl() || useSupabaseApi()) {
    throw new Error('Validação manual só persiste em SQLite (sem DATABASE_URL / Supabase nesta versão).');
  }
  return sqlite.deleteManualValidation(target, fingerprint);
}

/** Categorias do «cérebro» (SQLite local). Com Postgres/Supabase devolve lista vazia. */
export async function listBrainCategories() {
  if (useDatabaseUrl() || useSupabaseApi()) return [];
  try {
    return sqlite.listBrainCategories();
  } catch (e) {
    console.error('[GHOSTRECON brain categories]', e?.message || e);
    return [];
  }
}

export async function createBrainCategory(title) {
  if (useDatabaseUrl() || useSupabaseApi()) {
    throw new Error('Cérebro só persiste em SQLite local (sem DATABASE_URL / Supabase nesta versão).');
  }
  return sqlite.createBrainCategory(title);
}

export async function upsertBrainLink(row) {
  if (useDatabaseUrl() || useSupabaseApi()) {
    throw new Error('Cérebro só persiste em SQLite local (sem DATABASE_URL / Supabase nesta versão).');
  }
  return sqlite.upsertBrainLink(row);
}

export async function getBrainCategoryById(id) {
  if (useDatabaseUrl() || useSupabaseApi()) return null;
  try {
    return sqlite.getBrainCategoryById(id);
  } catch {
    return null;
  }
}

export async function listBrainLinksForCategory(categoryId) {
  if (useDatabaseUrl() || useSupabaseApi()) return [];
  try {
    return sqlite.listBrainLinksForCategory(categoryId);
  } catch (e) {
    console.error('[GHOSTRECON brain links]', e?.message || e);
    return [];
  }
}
