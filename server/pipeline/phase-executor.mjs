import { runWithProcessExecutionContext } from '../lib/process-execution-context.mjs';

/**
 * Limites conservadores usados apenas quando a fronteira resiliente do pipeline
 * foi explicitamente ativada. O RUN manual continua no caminho fail-fast
 * legado por padrão.
 */
export const DEFAULT_PIPELINE_PHASE_TIMEOUTS_MS = Object.freeze({
  input: 60_000,
  fingerprint: 180_000,
  discovery: 300_000,
  probe: 600_000,
  content_discovery: 900_000,
  go_engine: 900_000,
  validation: 900_000,
  aggressive: 1_200_000,
  asset_discovery: 300_000,
  dynamic_modules: 300_000,
  go_agent: 900_000,
  finalize: 600_000,
});

export const DEFAULT_PHASE_SETTLE_GRACE_MS = 2_000;

export class PipelinePhaseTimeoutError extends Error {
  constructor(phase, timeoutMs) {
    super(`Fase ${phase} excedeu o timeout de ${timeoutMs}ms`);
    this.name = 'PipelinePhaseTimeoutError';
    this.code = 'PIPELINE_PHASE_TIMEOUT';
    this.phase = phase;
    this.timeoutMs = timeoutMs;
  }
}

export class PipelinePhaseUnsettledError extends Error {
  constructor(phase, timeoutMs, graceMs) {
    super(
      `Fase ${phase} excedeu ${timeoutMs}ms e não encerrou após ${graceMs}ms de graça`,
    );
    this.name = 'PipelinePhaseUnsettledError';
    this.code = 'PIPELINE_PHASE_UNSETTLED';
    this.phase = phase;
    this.timeoutMs = timeoutMs;
    this.graceMs = graceMs;
  }
}

function positiveInteger(value, fallback, { min = 1, max = 86_400_000 } = {}) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < min) return fallback;
  return Math.min(max, Math.floor(parsed));
}

function timeoutForPhase(phase, configured = {}) {
  const fallback = DEFAULT_PIPELINE_PHASE_TIMEOUTS_MS[phase] ?? 300_000;
  if (!configured || typeof configured !== 'object' || Array.isArray(configured)) return fallback;
  return positiveInteger(configured[phase] ?? configured.default, fallback);
}

function abortReason(signal, fallback = 'pipeline cancelado') {
  if (signal?.reason instanceof Error) return signal.reason;
  const error = new Error(signal?.reason ? String(signal.reason) : fallback);
  error.name = 'AbortError';
  error.code = 'PIPELINE_CANCELLED';
  return error;
}

function safeErrorMessage(error) {
  return String(error?.message || error || 'erro desconhecido')
    .replace(
      /(\b(?:authorization|cookie|set-cookie|api[-_]?key|token|secret|password)\b\s*[:=]\s*)[^\s,;&]+/gi,
      '$1[REDACTED]',
    )
    .replace(/\bBearer\s+[A-Za-z0-9._~+/=-]{8,}\b/gi, 'Bearer [REDACTED]')
    .slice(0, 800);
}

function isUnterminatedProcessError(error) {
  return error?.code === 'PROCESS_UNTERMINATED'
    || error?.code === 'FRAMESEVEN_PROCESS_UNTERMINATED';
}

function isFatalPhaseError(error) {
  return isUnterminatedProcessError(error)
    || error?.code === 'VIGOLIUM_BINARY_IDENTITY_MISMATCH'
    || error?.code === 'PROCESS_ABORTED'
    || error?.name === 'AbortError';
}

function isSettledPhaseTimeoutAbort(error, phase) {
  const cause = error?.cause;
  return error?.code === 'PROCESS_ABORTED'
    && error?.result?.terminationConfirmed === true
    && cause?.code === 'PIPELINE_PHASE_TIMEOUT'
    && cause?.phase === phase;
}

function safeEmit(state, event) {
  try {
    state.emit?.(event);
  } catch {
    // Telemetria de resiliência não deve substituir o resultado real da fase.
  }
}

function emitPhaseOutcome(state, outcome) {
  state.phaseOutcomes ??= [];
  state.phaseOutcomes.push(outcome);
  safeEmit(state, { type: 'phase_outcome', ...outcome });
}

function emitPhaseLog(state, message, level = 'warn') {
  try {
    state.log?.(message, level);
  } catch {
    safeEmit(state, { type: 'log', msg: message, level });
  }
}

function waitForSettlement(settledPromise, graceMs) {
  let timer = null;
  const grace = new Promise((resolve) => {
    timer = setTimeout(() => resolve(null), graceMs);
  });
  return Promise.race([settledPromise, grace]).finally(() => {
    if (timer) clearTimeout(timer);
  });
}

function phaseControllerFor(parentSignal) {
  const controller = new AbortController();
  const forwardAbort = () => {
    if (!controller.signal.aborted) controller.abort(abortReason(parentSignal));
  };
  if (parentSignal?.aborted) forwardAbort();
  else parentSignal?.addEventListener('abort', forwardAbort, { once: true });
  return {
    controller,
    cleanup() {
      parentSignal?.removeEventListener('abort', forwardAbort);
    },
  };
}

async function executeBoundedPhase(state, descriptor, options) {
  const phase = String(descriptor.name || 'unknown');
  const timeoutMs = timeoutForPhase(phase, options.phaseTimeouts);
  const graceMs = positiveInteger(
    options.phaseSettleGraceMs,
    DEFAULT_PHASE_SETTLE_GRACE_MS,
    { min: 10, max: 30_000 },
  );
  const parentSignal = state.signal || null;
  const previousSignal = state.signal;
  const previousThrowIfAborted = state.throwIfAborted;
  const { controller, cleanup } = phaseControllerFor(parentSignal);
  const startedAt = Date.now();
  let timeoutTimer = null;
  let parentAbortListener = null;
  let phaseSettled = false;

  state.signal = controller.signal;
  state.throwIfAborted = function throwIfPhaseAborted() {
    if (state.signal?.aborted) throw abortReason(state.signal);
  };

  safeEmit(state, {
    type: 'phase_started',
    phase,
    timeoutMs,
    recoverable: descriptor.recoverable !== false,
  });

  const runPhase = () => descriptor.run(state);
  const settledPromise = Promise.resolve()
    .then(() =>
      state.autoModeExecution === true
        ? runWithProcessExecutionContext(
            {
              signal: controller.signal,
              managedProcessGroup: true,
              killGraceMs: state.subprocessKillGraceMs,
              closeGraceMs: state.subprocessCloseGraceMs,
            },
            runPhase,
          )
        : runPhase(),
    )
    .then(
      (value) => {
        phaseSettled = true;
        return { kind: 'fulfilled', value };
      },
      (error) => {
        phaseSettled = true;
        return { kind: 'rejected', error };
      },
    );

  const timeoutPromise = new Promise((resolve) => {
    timeoutTimer = setTimeout(() => resolve({ kind: 'timeout' }), timeoutMs);
  });
  const parentAbortPromise = new Promise((resolve) => {
    if (!parentSignal) return;
    parentAbortListener = () => resolve({ kind: 'cancelled' });
    if (parentSignal.aborted) parentAbortListener();
    else parentSignal.addEventListener('abort', parentAbortListener, { once: true });
  });

  try {
    const first = await Promise.race([settledPromise, timeoutPromise, parentAbortPromise]);
    if (timeoutTimer) clearTimeout(timeoutTimer);
    if (parentAbortListener) parentSignal?.removeEventListener('abort', parentAbortListener);

    if (first.kind === 'fulfilled') {
      emitPhaseOutcome(state, {
        phase,
        status: 'done',
        durationMs: Date.now() - startedAt,
        timeoutMs,
        recoverable: true,
        settled: true,
        error: null,
      });
      return first.value;
    }

    if (first.kind === 'rejected') {
      if (parentSignal?.aborted) {
        const error = abortReason(parentSignal);
        emitPhaseOutcome(state, {
          phase,
          status: 'cancelled',
          durationMs: Date.now() - startedAt,
          timeoutMs,
          recoverable: false,
          settled: true,
          error: safeErrorMessage(error),
        });
        throw error;
      }

      // Um timeout comum pode ser recuperável somente após exit/close. Se o
      // subprocesso não confirmou término, seguir para a próxima fase criaria
      // concorrência com trabalho ainda ativo e viola o fail-closed.
      const canContinue = !isFatalPhaseError(first.error)
        && options.continueOnPhaseError === true
        && descriptor.recoverable !== false;
      const message = safeErrorMessage(first.error);
      emitPhaseOutcome(state, {
        phase,
        status: 'failed',
        durationMs: Date.now() - startedAt,
        timeoutMs,
        recoverable: canContinue,
        settled: true,
        error: message,
      });
      if (!canContinue) throw first.error;
      emitPhaseLog(state, `Fase ${phase} falhou (${message}); seguindo com segurança.`, 'warn');
      return undefined;
    }

    if (first.kind === 'cancelled') {
      const error = abortReason(parentSignal);
      if (!controller.signal.aborted) controller.abort(error);
      const settled = await waitForSettlement(settledPromise, graceMs);
      if (settled?.kind === 'rejected' && isFatalPhaseError(settled.error)) {
        emitPhaseOutcome(state, {
          phase,
          status: 'cancelled',
          durationMs: Date.now() - startedAt,
          timeoutMs,
          recoverable: false,
          settled: !isUnterminatedProcessError(settled.error),
          error: safeErrorMessage(settled.error),
        });
        throw settled.error;
      }
      emitPhaseOutcome(state, {
        phase,
        status: 'cancelled',
        durationMs: Date.now() - startedAt,
        timeoutMs,
        recoverable: false,
        settled: Boolean(settled),
        error: safeErrorMessage(error),
      });
      throw error;
    }

    const timeoutError = new PipelinePhaseTimeoutError(phase, timeoutMs);
    if (!controller.signal.aborted) controller.abort(timeoutError);
    safeEmit(state, { type: 'pipe', name: phase, state: 'timeout' });
    safeEmit(state, {
      type: 'module_outcome',
      moduleId: phase,
      phase,
      status: 'timeout',
      source: 'pipeline_phase',
    });
    const settled = await waitForSettlement(settledPromise, graceMs);
    if (!settled) {
      const error = new PipelinePhaseUnsettledError(phase, timeoutMs, graceMs);
      emitPhaseOutcome(state, {
        phase,
        status: 'timeout',
        durationMs: Date.now() - startedAt,
        timeoutMs,
        recoverable: false,
        settled: false,
        error: safeErrorMessage(error),
      });
      emitPhaseLog(
        state,
        `Fase ${phase} não encerrou após cancelamento; pipeline interrompido por segurança.`,
        'error',
      );
      throw error;
    }
    if (
      settled.kind === 'rejected'
      && isFatalPhaseError(settled.error)
      && !isSettledPhaseTimeoutAbort(settled.error, phase)
    ) {
      const unterminated = isUnterminatedProcessError(settled.error);
      emitPhaseOutcome(state, {
        phase,
        status: 'timeout',
        durationMs: Date.now() - startedAt,
        timeoutMs,
        recoverable: false,
        settled: !unterminated,
        error: safeErrorMessage(settled.error),
      });
      emitPhaseLog(
        state,
        unterminated
          ? `Fase ${phase} não confirmou o encerramento do subprocesso; `
            + 'pipeline interrompido por segurança.'
          : `Fase ${phase} produziu uma falha fatal durante o encerramento; `
            + 'pipeline interrompido por segurança.',
        'error',
      );
      throw settled.error;
    }

    const canContinue = options.continueOnPhaseError === true && descriptor.recoverable !== false;
    emitPhaseOutcome(state, {
      phase,
      status: 'timeout',
      durationMs: Date.now() - startedAt,
      timeoutMs,
      recoverable: canContinue,
      settled: true,
      error: safeErrorMessage(timeoutError),
    });
    if (!canContinue) throw timeoutError;
    emitPhaseLog(
      state,
      `Fase ${phase} expirou, encerrou de forma cooperativa e foi ignorada; seguindo.`,
      'warn',
    );
    return undefined;
  } finally {
    if (timeoutTimer) clearTimeout(timeoutTimer);
    if (parentAbortListener) parentSignal?.removeEventListener('abort', parentAbortListener);
    cleanup();
    if (phaseSettled) {
      state.signal = previousSignal;
      state.throwIfAborted = previousThrowIfAborted;
    }
  }
}

/**
 * Executa fases em ordem. Sem `enabled`, mantém o comportamento sequencial
 * fail-fast. Com a fronteira ativa, cada fase recebe um AbortSignal derivado.
 */
export async function runPipelinePhases(state, phases, {
  enabled = false,
  continueOnPhaseError = false,
  phaseTimeouts = null,
  phaseSettleGraceMs = DEFAULT_PHASE_SETTLE_GRACE_MS,
} = {}) {
  for (const descriptor of phases || []) {
    state.throwIfAborted?.();
    if (!enabled) {
      await descriptor.run(state);
      continue;
    }
    await executeBoundedPhase(state, descriptor, {
      continueOnPhaseError,
      phaseTimeouts,
      phaseSettleGraceMs,
    });
  }
}
