import {
  createContext,
  useContext,
  useSyncExternalStore,
  type ReactNode,
} from 'react';
import type { Finding } from '../findings/model';
import {
  createPipelineState,
  pipelineReducer,
  type PipelineAction,
  type PipelineState,
} from '../pipeline/model';

export type ExecutionState = {
  batchPosition: { index: number; total: number } | null;
  batchTargets: string[];
  cascade: {
    index: number;
    rootHost: string;
    subHost: string;
    total: number;
  } | null;
  coverage: unknown;
  filter: string;
  findings: Finding[];
  events: unknown[];
  lastPipelineBundle: unknown;
  logs: ExecutionLogEntry[];
  manualFingerprints: string[];
  pipeline: PipelineState;
  progressDetail: string;
  runStartedAt: number;
  search: string;
  target: string;
};

export type ExecutionLogEntry = {
  level: string;
  message: string;
  timestamp: number;
};

export type ExecutionStore = ReturnType<typeof createExecutionStore>;
export type ExecutionSelector<Value> = (state: ExecutionState) => Value;

export const executionSelectors = Object.freeze({
  batchPosition: (state: ExecutionState) => state.batchPosition,
  batchTargets: (state: ExecutionState) => state.batchTargets,
  cascade: (state: ExecutionState) => state.cascade,
  coverage: (state: ExecutionState) => state.coverage,
  filter: (state: ExecutionState) => state.filter,
  findings: (state: ExecutionState) => state.findings,
  events: (state: ExecutionState) => state.events,
  lastPipelineBundle: (state: ExecutionState) => state.lastPipelineBundle,
  logs: (state: ExecutionState) => state.logs,
  manualFingerprints: (state: ExecutionState) => state.manualFingerprints,
  pipeline: (state: ExecutionState) => state.pipeline,
  progressDetail: (state: ExecutionState) => state.progressDetail,
  runStartedAt: (state: ExecutionState) => state.runStartedAt,
  search: (state: ExecutionState) => state.search,
  stats: (state: ExecutionState) => state.pipeline.stats,
  target: (state: ExecutionState) => state.target,
});

const INITIAL_STATE: ExecutionState = {
  batchPosition: null,
  batchTargets: [],
  cascade: null,
  coverage: null,
  filter: 'all',
  findings: [],
  events: [],
  lastPipelineBundle: null,
  logs: [],
  manualFingerprints: [],
  pipeline: createPipelineState(),
  progressDetail: '',
  runStartedAt: 0,
  search: '',
  target: '',
};

function normalizedFindings(findings: Finding[]): Finding[] {
  return findings.map((finding, index) => ({ ...finding, __idx: finding.__idx ?? index }));
}

export function createExecutionStore(initial: Partial<ExecutionState> = {}) {
  let state: ExecutionState = {
    ...INITIAL_STATE,
    ...initial,
    batchPosition: initial.batchPosition ? { ...initial.batchPosition } : null,
    batchTargets: [...(initial.batchTargets || INITIAL_STATE.batchTargets)],
    cascade: initial.cascade ? { ...initial.cascade } : null,
    findings: normalizedFindings(initial.findings || INITIAL_STATE.findings),
    events: [...(initial.events || INITIAL_STATE.events)],
    logs: [...(initial.logs || INITIAL_STATE.logs)],
    manualFingerprints: [...(initial.manualFingerprints || INITIAL_STATE.manualFingerprints)],
    pipeline: initial.pipeline || createPipelineState(),
  };
  const listeners = new Set<() => void>();

  const update = (next: ExecutionState | ((current: ExecutionState) => ExecutionState)) => {
    const resolved = typeof next === 'function' ? next(state) : next;
    if (Object.is(resolved, state)) return state;
    state = resolved;
    for (const listener of listeners) listener();
    return state;
  };

  return Object.freeze({
    getState: () => state,
    subscribe(listener: () => void) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    pipeline(action: PipelineAction) {
      return update((current) => ({
        ...current,
        pipeline: pipelineReducer(current.pipeline, action),
      })).pipeline;
    },
    resetPipeline() {
      return update((current) => ({
        ...current,
        pipeline: createPipelineState(),
        progressDetail: '',
      })).pipeline;
    },
    resetRun(options: { target?: string; preserveFilter?: boolean } = {}) {
      return update((current) => ({
        ...current,
        coverage: null,
        batchPosition: null,
        batchTargets: [],
        cascade: null,
        filter: options.preserveFilter ? current.filter : 'all',
        findings: [],
        events: [],
        lastPipelineBundle: null,
        logs: [],
        manualFingerprints: [],
        pipeline: createPipelineState(),
        progressDetail: '',
        runStartedAt: 0,
        search: '',
        target: options.target === undefined ? current.target : String(options.target || ''),
      }));
    },
    addFinding(finding: Finding) {
      return update((current) => ({
        ...current,
        findings: [
          ...current.findings,
          { ...finding, __idx: finding.__idx ?? current.findings.length },
        ],
      })).findings;
    },
    replaceFindings(findings: Finding[]) {
      return update((current) => ({ ...current, findings: normalizedFindings(findings) })).findings;
    },
    appendEvent(event: unknown) {
      return update((current) => ({
        ...current,
        events: [...current.events, event].slice(-5000),
      })).events;
    },
    appendLog(message: string, level = 'info', timestamp = Date.now()) {
      const entry: ExecutionLogEntry = {
        level: String(level || 'info'),
        message: String(message || ''),
        timestamp: Number.isFinite(timestamp) ? timestamp : Date.now(),
      };
      return update((current) => ({
        ...current,
        logs: [...current.logs, entry].slice(-2000),
      })).logs;
    },
    dismissFingerprint(fingerprint: string) {
      const value = String(fingerprint || '').trim();
      if (!value) return state.findings;
      return update((current) => ({
        ...current,
        findings: current.findings.filter((finding) => finding.fingerprint !== value),
      })).findings;
    },
    setFilter(filter: string) {
      return update((current) => ({ ...current, filter: String(filter || 'all') })).filter;
    },
    setSearch(search: string) {
      return update((current) => ({ ...current, search: String(search || '') })).search;
    },
    setManualFingerprints(fingerprints: Iterable<string>) {
      const values = [...new Set([...fingerprints].map(String).filter(Boolean))];
      return update((current) => ({ ...current, manualFingerprints: values })).manualFingerprints;
    },
    setRunStartedAt(value: number) {
      const normalized = Number.isFinite(Number(value)) ? Number(value) : 0;
      return update((current) => ({ ...current, runStartedAt: normalized })).runStartedAt;
    },
    setProgressDetail(progressDetail: string) {
      return update((current) => ({ ...current, progressDetail: String(progressDetail || '') }))
        .progressDetail;
    },
    setTarget(target: string) {
      return update((current) => ({ ...current, target: String(target || '') })).target;
    },
    setBatchTargets(targets: string[]) {
      return update((current) => ({ ...current, batchTargets: [...targets] })).batchTargets;
    },
    setBatchPosition(position: ExecutionState['batchPosition']) {
      return update((current) => ({ ...current, batchPosition: position ? { ...position } : null }))
        .batchPosition;
    },
    setCascade(cascade: ExecutionState['cascade']) {
      return update((current) => ({ ...current, cascade: cascade ? { ...cascade } : null })).cascade;
    },
    setCoverage(coverage: unknown) {
      return update((current) => ({ ...current, coverage })).coverage;
    },
    setLastPipelineBundle(lastPipelineBundle: unknown) {
      return update((current) => ({ ...current, lastPipelineBundle })).lastPipelineBundle;
    },
  });
}

const ExecutionStoreContext = createContext<ExecutionStore | null>(null);

export function ExecutionStoreProvider({
  children,
  store,
}: {
  children: ReactNode;
  store: ExecutionStore;
}) {
  return (
    <ExecutionStoreContext.Provider value={store}>
      {children}
    </ExecutionStoreContext.Provider>
  );
}

export function useExecutionStore(): ExecutionStore {
  const store = useContext(ExecutionStoreContext);
  if (!store) throw new Error('ExecutionStoreProvider ausente');
  return store;
}

export function useExecutionState(): ExecutionState {
  const store = useExecutionStore();
  return useSyncExternalStore(store.subscribe, store.getState, store.getState);
}

export function useExecutionSelector<Value>(selector: ExecutionSelector<Value>): Value {
  const store = useExecutionStore();
  return useSyncExternalStore(
    store.subscribe,
    () => selector(store.getState()),
    () => selector(store.getState()),
  );
}

declare global {
  interface Window {
    __ghostreconExecutionStore?: ExecutionStore;
  }
}

export function installExecutionStore(windowRef: Window, store: ExecutionStore): () => void {
  windowRef.__ghostreconExecutionStore = store;
  document.body.dataset.ghostreconExecutionStore = '1';
  return () => {
    if (windowRef.__ghostreconExecutionStore === store) {
      delete windowRef.__ghostreconExecutionStore;
      delete document.body.dataset.ghostreconExecutionStore;
    }
  };
}
