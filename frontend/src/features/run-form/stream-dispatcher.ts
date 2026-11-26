import { readNdjson } from '../../services/ndjson';
import type { ExecutionStore } from '../execution/store';
import type { Finding } from '../findings/model';
import type { PipelineNodeState } from '../pipeline/model';

export type ReconStreamEvent = Record<string, any> & { type?: unknown };

export type ReconStreamDisposition = void | {
  failed?: boolean;
  stop?: boolean;
};

export type ReconStreamTerminalResult = {
  ok: boolean;
  partial?: boolean;
  sawAutoSession?: boolean;
  status: string;
  terminalPhase: string | null;
};

export type ReconStreamConsumeOptions = {
  batchPreserveCount?: number;
  eventTarget?: EventTarget | null;
  executionStore?: ExecutionStore | null;
  isCancelRequested?: () => boolean;
  onEvent?: (
    event: ReconStreamEvent,
  ) => ReconStreamDisposition | Promise<ReconStreamDisposition>;
  onInvalidFrame?: (raw: string, error: Error) => void;
  onStreamError?: (error: unknown, detail: { cancelled: boolean }) => void;
  requireAutoTerminal?: boolean;
  signal?: AbortSignal;
  statsBaseline?: Record<string, unknown> | null;
};

const AUTO_TERMINAL_PHASES = new Set([
  'completed',
  'partial',
  'cancelled',
  'interrupted',
  'failed',
  'timed_out',
  'stalled',
  'budget_exceeded',
]);

const AUTO_FAILED_PHASES = new Set([
  'failed',
  'timed_out',
  'stalled',
  'budget_exceeded',
]);

function pipelineNodeState(value: unknown): PipelineNodeState {
  const normalized = String(value || 'active');
  return normalized === 'done'
    || normalized === 'failed'
    || normalized === 'timeout'
    || normalized === 'cancelled'
    || normalized === 'skipped'
    || normalized === 'active'
    ? normalized
    : 'active';
}

function dispatchBrowserEvent(target: EventTarget | null | undefined, event: ReconStreamEvent) {
  if (!target || typeof CustomEvent !== 'function') return;
  target.dispatchEvent(new CustomEvent('ghostrecon:ndjson-event', { detail: event }));
}

/**
 * Projeta os eventos de transporte no store compartilhado antes dos efeitos do
 * adapter legado. Assim Pipeline/Findings/telemetria têm uma única sequência
 * tipada, enquanto popups, MITRE e compatibilidade visual podem migrar aos
 * poucos pelo callback `onEvent`.
 */
export function dispatchReconEventToExecutionStore(
  store: ExecutionStore | null | undefined,
  event: ReconStreamEvent,
  options: Pick<ReconStreamConsumeOptions, 'batchPreserveCount' | 'statsBaseline'> = {},
) {
  if (!store) return;
  store.appendEvent(event);

  if (event.type === 'log') {
    store.appendLog(String(event.msg || ''), String(event.level || 'info'));
  } else if (event.type === 'error') {
    store.appendLog(String(event.message || 'Erro no servidor'), event.recoverable ? 'warn' : 'error');
  }

  if (event.type === 'progress') {
    store.pipeline({ type: 'progress', value: Number(event.pct) || 0 });
  } else if (event.type === 'pipe_detail' && event.name) {
    store.pipeline({
      type: 'detail',
      name: String(event.name),
      current: event.current,
      total: event.total,
      label: event.label,
    });
  } else if (event.type === 'pipe' && event.name) {
    store.pipeline({
      type: 'node',
      name: String(event.name),
      state: pipelineNodeState(event.state),
    });
  } else if (event.type === 'stats' && event.stats && typeof event.stats === 'object') {
    store.pipeline({
      type: 'stats',
      value: event.stats,
      baseline: options.statsBaseline || undefined,
    });
  } else if (event.type === 'finding' && event.finding) {
    store.addFinding(event.finding as Finding);
  } else if (event.type === 'findings_rescore' && Array.isArray(event.findings)) {
    const preserve = Math.max(0, Number(options.batchPreserveCount) || 0);
    const previous = preserve ? store.getState().findings.slice(0, preserve) : [];
    store.replaceFindings([...previous, ...(event.findings as Finding[])]);
  } else if (event.type === 'recon_coverage' && event.snapshot) {
    store.setCoverage(event.snapshot);
  } else if (event.type === 'done') {
    store.setLastPipelineBundle({
      correlation: event.correlation ?? null,
      reportTemplates: event.reportTemplates ?? [],
      runId: event.runId ?? null,
      storage: event.storage ?? null,
      intelMerge: event.intelMerge ?? null,
      reconCoverage: event.reconCoverage ?? store.getState().coverage ?? null,
    });
  }
}

export async function consumeReconNdjson(
  response: Pick<Response, 'body' | 'ok' | 'status'>,
  options: ReconStreamConsumeOptions = {},
): Promise<boolean | ReconStreamTerminalResult> {
  const requireAutoTerminal = options.requireAutoTerminal === true;
  if (!response.ok) {
    return requireAutoTerminal
      ? { ok: false, status: 'http_error', terminalPhase: null }
      : false;
  }

  let failed = false;
  let terminalPhase: string | null = null;
  let sawAutoSession = false;
  let interrupted = false;

  try {
    for await (const frame of readNdjson<ReconStreamEvent>(response, { signal: options.signal })) {
      if (!frame.ok) {
        options.onInvalidFrame?.(frame.raw, frame.error);
        if (requireAutoTerminal) failed = true;
        continue;
      }

      const event = frame.value;
      if (event.type === 'auto_session') {
        sawAutoSession = true;
        const phase = String(event.phase || '');
        if (AUTO_TERMINAL_PHASES.has(phase)) {
          terminalPhase = phase;
          if (AUTO_FAILED_PHASES.has(phase)) failed = true;
        }
      }

      dispatchReconEventToExecutionStore(options.executionStore, event, options);
      dispatchBrowserEvent(options.eventTarget, event);
      const disposition = await options.onEvent?.(event);
      if (disposition?.failed) failed = true;
      if (disposition?.stop) break;
    }
  } catch (error) {
    interrupted = true;
    const cancelled = Boolean(options.isCancelRequested?.() || options.signal?.aborted);
    options.onStreamError?.(error, { cancelled });
    if (!cancelled) failed = true;
  }

  if (!requireAutoTerminal) return !failed;

  let status = terminalPhase;
  if (failed && !terminalPhase) status = 'failed';
  else if (!status && options.isCancelRequested?.()) status = 'cancel_requested_unconfirmed';
  else if (!status && interrupted) status = 'interrupted_unconfirmed';
  else if (!status) status = sawAutoSession ? 'incomplete' : 'session_not_started';
  return {
    ok: status === 'completed',
    status,
    terminalPhase,
    sawAutoSession,
    partial: status === 'partial',
  };
}
