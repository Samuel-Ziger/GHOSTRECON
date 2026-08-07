import { getRegistryEntry } from '../modules/module-registry.mjs';
import { moduleEnabled, normalizeModuleId } from '../modules/module-ids.mjs';
import { withProvenance } from '../modules/finding-provenance.js';

function isTimeoutError(error) {
  if (!error) return false;
  if (error?.code === 'PROCESS_TIMEOUT') return true;
  if (error?.name === 'TimeoutError') return true;
  const message = String(error?.message || '');
  return /timed.?out|timeout/i.test(message) && !/aborted|cancelled|canceled/i.test(message);
}

function isAbortLikeError(error, signal = null) {
  if (signal?.aborted && !isTimeoutError(signal.reason) && !isTimeoutError(error)) return true;
  if (!error) return false;
  if (isTimeoutError(error)) return false;
  if (error?.name === 'AbortError') return true;
  const code = String(error?.code || '');
  if (code === 'PROCESS_ABORTED' || code === 'PROCESS_UNTERMINATED' || code === 'ABORT_ERR') {
    return true;
  }
  return /aborted|cancelled|canceled|unterminated/i.test(String(error?.message || ''));
}

function emitTerminalOutcome(s, moduleId, status, extra = {}) {
  const emit = typeof s?.emit === 'function' ? s.emit : null;
  const pipe = typeof s?.pipe === 'function' ? s.pipe : null;
  const pipeState = status === 'skipped' ? 'skip' : status;
  pipe?.(moduleId, pipeState);
  emit?.({
    type: 'module_outcome',
    moduleId,
    status,
    source: 'registry',
    ...extra,
  });
}

/**
 * Executa um módulo registado se estiver activo em `s.modules`.
 * @returns {boolean} true se o módulo existe no registry e foi despachado
 */
export async function dispatchRegistryModule(s, moduleId) {
  const id = normalizeModuleId(moduleId);
  const entry = getRegistryEntry(id);
  if (!entry?.run) return false;

  const { log, addFinding, modules } = s;

  if (!moduleEnabled(modules, id)) {
    emitTerminalOutcome(s, id, 'skipped');
    return true;
  }

  s.pipe?.(id, 'active');
  try {
    const result = await entry.run(s);
    const rows = Array.isArray(result?.findings) ? result.findings : [];
    for (const f of rows) {
      addFinding(withProvenance(f, id), null);
    }
    if (result?.logOk) {
      log(result.logOk, result.logLevel || 'info');
    }
    emitTerminalOutcome(s, id, 'done');
  } catch (e) {
    if (isTimeoutError(e)) {
      emitTerminalOutcome(s, id, 'timeout', { error: e?.message || String(e) });
      throw e;
    }
    if (isAbortLikeError(e, s?.signal)) {
      emitTerminalOutcome(s, id, 'cancelled', { error: e?.message || String(e) });
      throw e;
    }
    const message = e?.message || String(e);
    log(`${entry.manifest?.name || id}: ${message}`, 'warn');
    emitTerminalOutcome(s, id, 'failed', { error: message });
    // Não emite `done` após falha — outcome real para o Auto/pipeline.
  }
  return true;
}
