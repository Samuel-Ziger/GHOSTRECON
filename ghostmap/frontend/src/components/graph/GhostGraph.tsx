"use client";
// Wrapper do ReactFlow com:
//  * GhostNode customizado
//  * layout dagre automatico
//  * minimap + controles
//  * filtros (labels, hosts, min_heat)
//  * busca semantica simples (substring de titulo)
//  * agrupamento visual por cor (label) + heatmap (border)
//
// Para escalar a 10k+ nodes adicionar clustering server-side e virtualizar.

import { useEffect, useMemo, useState, useCallback } from "react";
import ReactFlow, {
  Background, Controls, MiniMap,
  type Edge, type Node, useEdgesState, useNodesState,
} from "reactflow";
import { GhostNode } from "./GhostNode";
import { layoutDagre } from "./layout";
import { api } from "@/lib/api";
import { useGraphStore } from "@/store/graph.store";
import { useSessionStore } from "@/store/session.store";

const nodeTypes = { ghost: GhostNode };

function toRFNodes(data: ReturnType<typeof useGraphStore.getState>["data"]): Node[] {
  return data.nodes.map((n) => ({
    id: n.id,
    type: "ghost",
    position: { x: 0, y: 0 },
    data: { label: n.label, title: n.title, heat: n.heat, props: n.props },
  }));
}

function toRFEdges(data: ReturnType<typeof useGraphStore.getState>["data"]): Edge[] {
  return data.edges.map((e) => ({
    id: e.id, source: e.source, target: e.target,
    type: "smoothstep",
    label: e.type, labelStyle: { fill: "#7c8194", fontSize: 9 },
    style: { strokeWidth: 1.2 },
  }));
}

export function GhostGraph() {
  const active = useSessionStore((s) => s.activeProject);
  const { data, setData, loading, setLoading, minHeat } = useGraphStore();
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [query, setQuery] = useState("");

  // load inicial + quando projeto/heat muda
  useEffect(() => {
    if (!active?.id) return;
    setLoading(true);
    api.fetchGraph(active.id, { min_heat: minHeat })
       .then(setData)
       .finally(() => setLoading(false));
  }, [active?.id, minHeat, setData, setLoading]);

  // recalcula layout a cada mudanca de data
  useEffect(() => {
    const baseNodes = toRFNodes(data);
    const baseEdges = toRFEdges(data);
    const laid = layoutDagre(baseNodes, baseEdges, "LR");
    setNodes(laid.nodes); setEdges(laid.edges);
  }, [data, setNodes, setEdges]);

  // filtro de busca client-side
  const filteredNodes = useMemo(() => {
    if (!query.trim()) return nodes;
    const q = query.toLowerCase();
    return nodes.map((n) => ({
      ...n, hidden: !(n.data as any).title?.toString().toLowerCase().includes(q),
    }));
  }, [nodes, query]);

  const recompute = useCallback(async () => {
    if (!active?.id) return;
    await api.recomputeHeatmap(active.id);
    setData(await api.fetchGraph(active.id, { min_heat: minHeat }));
  }, [active?.id, minHeat, setData]);

  return (
    <div className="flex h-full w-full">
      <aside className="w-64 border-r border-border bg-panel p-3 space-y-3 text-sm">
        <div>
          <label className="text-mute text-xs">Busca</label>
          <input
            value={query} onChange={(e) => setQuery(e.target.value)}
            placeholder="endpoint, host, role..."
            className="w-full bg-bg border border-border rounded px-2 py-1 mt-1"
          />
        </div>
        <div>
          <label className="text-mute text-xs">Heat mínimo: {(minHeat * 100).toFixed(0)}%</label>
          <input
            type="range" min={0} max={1} step={0.05}
            value={minHeat}
            onChange={(e) => useGraphStore.getState().setMinHeat(parseFloat(e.target.value))}
            className="w-full accent-accent"
          />
        </div>
        <button
          onClick={recompute}
          className="w-full px-3 py-1.5 rounded bg-accent/15 border border-accent/30 hover:bg-accent/25"
        >
          Recalcular heatmap
        </button>
        <div className="pt-3 border-t border-border text-xs text-mute">
          <div>nodes: <span className="text-ink">{data.nodes.length}</span></div>
          <div>edges: <span className="text-ink">{data.edges.length}</span></div>
          {loading && <div className="text-accent2 animate-pulseSoft">carregando…</div>}
        </div>
      </aside>

      <div className="flex-1 min-w-0 min-h-0">
        <ReactFlow
          nodes={filteredNodes} edges={edges}
          onNodesChange={onNodesChange} onEdgesChange={onEdgesChange}
          nodeTypes={nodeTypes}
          fitView
          minZoom={0.05} maxZoom={3}
          proOptions={{ hideAttribution: true }}
        >
          <Background gap={24} size={1} color="#1a1e2e" />
          <MiniMap nodeStrokeColor={() => "#7c5cff"} nodeColor={() => "#0c0f1a"} maskColor="rgba(7,8,17,.7)" />
          <Controls position="bottom-right" showInteractive={false} />
        </ReactFlow>
      </div>
    </div>
  );
}
