import { create } from "zustand";

export type AgentName =
  | "flow_analyzer" | "trust_boundary_detector"
  | "hypothesis_generator" | "heatmap_classifier";

interface AIState {
  lastOutputs: Record<AgentName, unknown>;
  running: AgentName | null;
  setOutput: (a: AgentName, v: unknown) => void;
  setRunning: (a: AgentName | null) => void;
}

export const useAIStore = create<AIState>((set) => ({
  lastOutputs: {
    flow_analyzer: null,
    trust_boundary_detector: null,
    hypothesis_generator: null,
    heatmap_classifier: null,
  } as Record<AgentName, unknown>,
  running: null,
  setOutput: (a, v) => set((s) => ({ lastOutputs: { ...s.lastOutputs, [a]: v } })),
  setRunning: (running) => set({ running }),
}));
