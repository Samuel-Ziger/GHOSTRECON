export type PipelineNodeState = '' | 'active' | 'done' | 'failed' | 'timeout' | 'cancelled' | 'skipped';

export type PipelineNode = {
  state: PipelineNodeState;
  current?: number;
  total?: number;
  detail?: string;
  label?: string;
};

export type PipelineStats = {
  subs: number;
  endpoints: number;
  params: number;
  secrets: number;
  dorks: number;
  high: number;
};

export type PipelineState = {
  nodes: Record<string, PipelineNode>;
  progress: number;
  stats: PipelineStats;
  currentNode: string;
};

export type PipelineAction =
  | { type: 'reset' }
  | { type: 'node'; name: string; state: PipelineNodeState }
  | { type: 'detail'; name: string; current?: number; total?: number; text?: string; label?: string }
  | { type: 'progress'; value: number }
  | { type: 'stat'; name: keyof PipelineStats; value: number }
  | { type: 'stats'; value: Partial<PipelineStats>; baseline?: Partial<PipelineStats> };

export const PIPE_UI_ALIASES: Readonly<Record<string, string>> = Object.freeze({
  validate: 'input',
  go_engine: 'vigolium_dast',
  vigolium_engine: 'vigolium_dast',
});

export const EMPTY_STATS: PipelineStats = Object.freeze({
  subs: 0,
  endpoints: 0,
  params: 0,
  secrets: 0,
  dorks: 0,
  high: 0,
});

export function createPipelineState(): PipelineState {
  return { nodes: {}, progress: 0, stats: { ...EMPTY_STATS }, currentNode: '' };
}

export function normalizePipelineNode(name: string): string {
  return PIPE_UI_ALIASES[name] || name;
}

function clampProgress(value: number): number {
  if (!Number.isFinite(value)) return 0;
  return Math.min(100, Math.max(0, value));
}

export function pipelineReducer(state: PipelineState, action: PipelineAction): PipelineState {
  if (action.type === 'reset') return createPipelineState();
  if (action.type === 'progress') return { ...state, progress: clampProgress(action.value) };
  if (action.type === 'stat') {
    return { ...state, stats: { ...state.stats, [action.name]: Number(action.value) || 0 } };
  }
  if (action.type === 'stats') {
    const stats = { ...state.stats };
    for (const name of Object.keys(EMPTY_STATS) as Array<keyof PipelineStats>) {
      if (action.value[name] == null) continue;
      stats[name] = (Number(action.baseline?.[name]) || 0) + (Number(action.value[name]) || 0);
    }
    return { ...state, stats };
  }
  const name = normalizePipelineNode(action.name);
  const previous = state.nodes[name] || { state: '' };
  if (action.type === 'node') {
    return {
      ...state,
      currentNode: action.state === 'active' ? name : state.currentNode,
      nodes: { ...state.nodes, [name]: { ...previous, state: action.state } },
    };
  }
  const current = Number(action.current);
  const total = Number(action.total);
  const detail = Number.isFinite(current) && Number.isFinite(total) && total > 0
    ? `${current}/${total}`
    : String(action.text || action.label || '').slice(0, 100);
  return {
    ...state,
    currentNode: name,
    nodes: {
      ...state.nodes,
      [name]: {
        ...previous,
        current: Number.isFinite(current) ? current : undefined,
        total: Number.isFinite(total) ? total : undefined,
        detail,
        label: action.label,
      },
    },
  };
}

export function formatElapsed(milliseconds: number): string {
  const seconds = Math.max(0, Math.floor(milliseconds / 1000));
  return `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, '0')}`;
}
