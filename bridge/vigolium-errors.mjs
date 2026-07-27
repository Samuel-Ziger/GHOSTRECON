const FATAL_VIGOLIUM_CODES = new Set([
  'VIGOLIUM_BINARY_IDENTITY_MISMATCH',
  'PROCESS_ABORTED',
  'PROCESS_UNTERMINATED',
]);

/**
 * Falhas que invalidam a autorização ou comprovam cancelamento incompleto não
 * podem ser convertidas em `skip`/falha recuperável por adapters ou fases.
 */
export function isFatalVigoliumExecutionError(error, signal = null) {
  return signal?.aborted === true
    || error?.name === 'AbortError'
    || FATAL_VIGOLIUM_CODES.has(String(error?.code || ''));
}

export function rethrowFatalVigoliumExecutionError(
  error,
  signal = null,
  publicMessage = null,
) {
  if (!isFatalVigoliumExecutionError(error, signal)) return;
  if (publicMessage == null) throw error;

  const wrapped = new Error(String(publicMessage || 'Vigolium execution failed'), {
    cause: error,
  });
  wrapped.name = error?.name === 'AbortError' || signal?.aborted
    ? 'AbortError'
    : 'Error';
  wrapped.code = error?.code
    || (signal?.aborted ? 'PROCESS_ABORTED' : 'VIGOLIUM_EXECUTION_FATAL');
  wrapped.fatal = true;
  wrapped.recoverable = false;
  if (error?.unterminated === true || error?.code === 'PROCESS_UNTERMINATED') {
    wrapped.unterminated = true;
  }
  throw wrapped;
}
