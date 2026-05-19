import { create } from "zustand";
import type { GraphResponse, NodeLabel } from "@/lib/types";

interface GraphState {
  data: GraphResponse;
  labelFilter: NodeLabel[];
  hostFilter: string[];
  minHeat: number;
  selectedNodeId: string | null;
  loading: boolean;
  setData: (d: GraphResponse) => void;
  setLabelFilter: (ls: NodeLabel[]) => void;
  setHostFilter: (hs: string[]) => void;
  setMinHeat: (h: number) => void;
  selectNode: (id: string | null) => void;
  setLoading: (v: boolean) => void;
}

export const useGraphStore = create<GraphState>((set) => ({
  data: { nodes: [], edges: [], stats: {} },
  labelFilter: [],
  hostFilter: [],
  minHeat: 0,
  selectedNodeId: null,
  loading: false,
  setData: (data) => set({ data }),
  setLabelFilter: (labelFilter) => set({ labelFilter }),
  setHostFilter: (hostFilter) => set({ hostFilter }),
  setMinHeat: (minHeat) => set({ minHeat }),
  selectNode: (selectedNodeId) => set({ selectedNodeId }),
  setLoading: (loading) => set({ loading }),
}));
