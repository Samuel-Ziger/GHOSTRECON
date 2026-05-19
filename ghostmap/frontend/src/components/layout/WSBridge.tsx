"use client";
// Conecta o WS global e despacha mensagens para os stores apropriados.
// Renderiza nada — efeito colateral apenas.

import { useEffect } from "react";
import { ghostws } from "@/lib/ws";
import { useProxyStore } from "@/store/proxy.store";
import { useGraphStore } from "@/store/graph.store";
import { useSessionStore } from "@/store/session.store";
import { api } from "@/lib/api";

export function WSBridge() {
  const pushReq = useProxyStore((s) => s.push);
  const setGraph = useGraphStore((s) => s.setData);
  const active = useSessionStore((s) => s.activeProject);

  useEffect(() => {
    ghostws.connect();
    const off = ghostws.on((m) => {
      if (m.type === "http_request") {
        const data = m.data as { project_id?: string };
        if (active?.id && data.project_id && data.project_id !== active.id) return;
        pushReq(m.data as never);
      } else if (m.type === "graph_update" && active?.id) {
        // refresh diferido: 300ms para batching
        clearTimeout((WSBridge as any)._t);
        (WSBridge as any)._t = setTimeout(async () => {
          try { setGraph(await api.fetchGraph(active.id)); }
          catch { /* ignore */ }
        }, 300);
      }
    });
    return () => { off(); ghostws.disconnect(); };
  }, [pushReq, setGraph, active?.id]);

  return null;
}
