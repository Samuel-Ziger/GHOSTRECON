import { getRegistryEntry } from '../modules/module-registry.mjs';
import { moduleEnabled, normalizeModuleId } from '../modules/module-ids.mjs';
import { withProvenance } from '../modules/finding-provenance.js';

/**
 * Executa um módulo registado se estiver activo em `s.modules`.
 * @returns {boolean} true se o módulo existe no registry e foi despachado
 */
export async function dispatchRegistryModule(s, moduleId) {
  const id = normalizeModuleId(moduleId);
  const entry = getRegistryEntry(id);
  if (!entry?.run) return false;

  const { pipe, log, addFinding, modules } = s;

  if (!moduleEnabled(modules, id)) {
    pipe(id, 'skip');
    return true;
  }

  pipe(id, 'active');
  try {
    const result = await entry.run(s);
    const rows = Array.isArray(result?.findings) ? result.findings : [];
    for (const f of rows) {
      addFinding(withProvenance(f, id), null);
    }
    if (result?.logOk) {
      log(result.logOk, result.logLevel || 'info');
    }
  } catch (e) {
    log(`${entry.manifest?.name || id}: ${e?.message || e}`, 'warn');
  }
  pipe(id, 'done');
  return true;
}
