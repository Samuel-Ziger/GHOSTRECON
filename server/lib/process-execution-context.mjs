import { AsyncLocalStorage } from 'node:async_hooks';

const processExecutionStorage = new AsyncLocalStorage();

/**
 * Propaga controles de subprocesso pela cadeia assíncrona sem exigir que cada
 * módulo legado receba e repasse o AbortSignal manualmente.
 *
 * O contexto é ativado pela fronteira resiliente do Auto. O RUN manual não
 * entra neste contexto e, portanto, preserva o comportamento anterior.
 */
export function runWithProcessExecutionContext(context, callback) {
  const value =
    context && typeof context === 'object'
      ? Object.freeze({
          signal: context.signal ?? null,
          managedProcessGroup: context.managedProcessGroup === true,
          killGraceMs: context.killGraceMs,
          closeGraceMs: context.closeGraceMs,
        })
      : null;
  return processExecutionStorage.run(value, callback);
}

export function getProcessExecutionContext() {
  return processExecutionStorage.getStore() ?? null;
}
