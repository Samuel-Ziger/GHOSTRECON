import { normalizeModuleId } from './module-ids.mjs';

/**
 * IDs cuja implementação foi removida deliberadamente. Eles permanecem
 * apenas como tombstones para impedir que clientes/checkpoints antigos virem
 * uma execução vazia anunciada como concluída.
 */
export const RETIRED_MODULE_IDS = Object.freeze([
  'shannon_whitebox',
  'pentestgpt_validate',
]);

const RETIRED = new Set(RETIRED_MODULE_IDS);

export function findRetiredModuleIds(modules = []) {
  const found = [];
  for (const value of Array.isArray(modules) ? modules : []) {
    const id = normalizeModuleId(value);
    if (id && RETIRED.has(id) && !found.includes(id)) found.push(id);
  }
  return found;
}

export function createRetiredModulesError(modules = []) {
  const retiredModules = findRetiredModuleIds(modules);
  if (!retiredModules.length) return null;
  const error = new Error(
    `módulo(s) removido(s) permanentemente: ${retiredModules.join(', ')}`,
  );
  error.code = 'MODULE_RETIRED';
  error.statusCode = 410;
  error.retiredModules = retiredModules;
  return error;
}

export function assertNoRetiredModules(modules = []) {
  const error = createRetiredModulesError(modules);
  if (error) throw error;
  return modules;
}
