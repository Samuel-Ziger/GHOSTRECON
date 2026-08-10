/**
 * Fail-closed da trilha durável do RAG.
 *
 * Por padrão o Auto trata falha de escrita RAG como observável (evento
 * `auto_rag` com `memory.error`) porém não fatal. Quando o operador exige que a
 * trilha durável de decisão/avaliação seja obrigatória
 * (`GHOSTRECON_AUTO_RAG_REQUIRED=1`), uma falha ao persistir a memória RAG deve:
 *   1. emitir `auto_persist_failed` com stage `rag_<stage>` (observável); e
 *   2. abortar o turno com `AUTO_RAG_PERSIST_FAILED` para que o terminal da
 *      sessão seja `failed` (nunca `completed`/`partial`).
 *
 * O default é conservador: sem a flag, nada muda.
 */

export function isDurableRagRequired(env = process.env) {
  return /^(1|true|yes|on)$/i.test(String(env.GHOSTRECON_AUTO_RAG_REQUIRED ?? '0').trim());
}

/**
 * Interpreta o resultado dos writers de RAG (`writeAutoDecisionMarkdown`,
 * `writeAutoRagNote`) já normalizado pelo `.catch` do orquestrador.
 *
 * Contrato de entrada:
 *   - `null`/`undefined`         → RAG desabilitado ou ausente;
 *   - `{ error }`                → escrita falhou (capturada pelo orquestrador);
 *   - `{ skipped, reason }`      → limite de capacidade; nada foi gravado;
 *   - `{ filePath|filename ... }`→ persistido com sucesso.
 */
export function evaluateRagPersist(result) {
  if (result && typeof result === 'object') {
    if (result.error) return { ok: false, reason: `rag_write_error: ${String(result.error).slice(0, 300)}` };
    if (result.skipped) return { ok: false, reason: `rag_skipped: ${result.reason || 'unknown'}` };
    if (result.filePath || result.filename) return { ok: true, reason: null };
    return { ok: false, reason: 'rag_unknown_result' };
  }
  return { ok: false, reason: 'rag_disabled_or_absent' };
}

/**
 * Aplica o fail-closed quando a trilha durável for obrigatória. Retorna o
 * próprio `result` quando não obrigatória ou quando a persistência foi OK.
 * Caso contrário emite `auto_persist_failed` e lança `AUTO_RAG_PERSIST_FAILED`.
 */
export function assertDurableRagPersist(result, {
  env = process.env,
  captureEmit = () => {},
  sessionId = '',
  requestRunId = '',
  stage = 'rag',
} = {}) {
  if (!isDurableRagRequired(env)) return result;
  const verdict = evaluateRagPersist(result);
  if (verdict.ok) return result;
  captureEmit({
    type: 'auto_persist_failed',
    stage: `rag_${stage}`,
    sessionId,
    requestRunId,
    error: verdict.reason,
  });
  const error = new Error(`trilha durável RAG obrigatória falhou (${stage}): ${verdict.reason}`);
  error.code = 'AUTO_RAG_PERSIST_FAILED';
  throw error;
}
