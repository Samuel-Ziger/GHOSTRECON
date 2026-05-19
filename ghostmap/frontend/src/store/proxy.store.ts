import { create } from "zustand";
import type { HttpRequestItem } from "@/lib/types";

interface ProxyState {
  liveRequests: HttpRequestItem[];      // chega via WS
  selectedRequestId: string | null;
  filter: { method?: string; q?: string; only_xhr: boolean; only_graphql: boolean };
  push: (r: HttpRequestItem) => void;
  clear: () => void;
  select: (id: string | null) => void;
  setFilter: (f: Partial<ProxyState["filter"]>) => void;
}

const MAX = 2000;

export const useProxyStore = create<ProxyState>((set) => ({
  liveRequests: [],
  selectedRequestId: null,
  filter: { only_xhr: false, only_graphql: false },
  push: (r) =>
    set((s) => {
      const next = [r, ...s.liveRequests];
      if (next.length > MAX) next.length = MAX;
      return { liveRequests: next };
    }),
  clear: () => set({ liveRequests: [] }),
  select: (selectedRequestId) => set({ selectedRequestId }),
  setFilter: (f) => set((s) => ({ filter: { ...s.filter, ...f } })),
}));
