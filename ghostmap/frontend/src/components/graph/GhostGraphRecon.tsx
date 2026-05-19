'use client';

import { useEffect, useMemo, useState } from 'react';
import ReactFlow, {
  Background,
  Controls,
  MiniMap,
  type Edge,
  type Node,
  useEdgesState,
  useNodesState
} from 'reactflow';
import { GhostNode } from './GhostNode';
import { layoutDagre } from './layout';
import {
  buildGraphFromHistory,
  type ReconGraphData
} from '@/lib/ghostrecon/history-to-graph';
import type { HistoryEntry } from '@/lib/ghostrecon/types';

const nodeTypes = { ghost: GhostNode };

function toRF(data: ReconGraphData): { nodes: Node[]; edges: Edge[] } {
  const nodes: Node[] = data.nodes.map((n) => ({
    id: n.id,
    type: 'ghost',
    position: { x: 0, y: 0 },
    data: { label: n.label, title: n.title, heat: n.heat, props: n.props }
  }));
  const edges: Edge[] = data.edges.map((e) => ({
    id: e.id,
    source: e.source,
    target: e.target,
    type: 'smoothstep',
    label: e.type,
    labelStyle: { fill: '#7c8194', fontSize: 9 },
    style: { strokeWidth: 1.2 }
  }));
  return { nodes, edges };
}

export function GhostGraphRecon({ entries }: { entries: HistoryEntry[] }) {
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [query, setQuery] = useState('');
  const [minHeat, setMinHeat] = useState(0);

  const graph = useMemo(() => buildGraphFromHistory(entries), [entries]);

  useEffect(() => {
    const ids = new Set(
      graph.nodes.filter((n) => n.heat >= minHeat).map((n) => n.id)
    );
    const filtered: ReconGraphData = {
      nodes: graph.nodes.filter((n) => n.heat >= minHeat),
      edges: graph.edges.filter((e) => ids.has(e.source) && ids.has(e.target))
    };
    const { nodes: baseNodes, edges: baseEdges } = toRF(filtered);
    const laid = layoutDagre(baseNodes, baseEdges, 'LR');
    setNodes(laid.nodes);
    setEdges(laid.edges);
  }, [graph, minHeat, setNodes, setEdges]);

  const filteredNodes = useMemo(() => {
    if (!query.trim()) return nodes;
    const q = query.toLowerCase();
    return nodes.map((n) => ({
      ...n,
      hidden: !(n.data as { title?: string }).title
        ?.toString()
        .toLowerCase()
        .includes(q)
    }));
  }, [nodes, query]);

  return (
    <div className="flex h-full w-full min-h-0">
      <aside className="w-56 shrink-0 border-r border-border bg-panel p-3 space-y-3 text-sm">
        <div>
          <label className="text-mute text-xs">Busca</label>
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="host, endpoint…"
            className="w-full bg-bg border border-border rounded px-2 py-1 mt-1 text-sm"
          />
        </div>
        <div>
          <label className="text-mute text-xs">
            Heat mínimo: {(minHeat * 100).toFixed(0)}%
          </label>
          <input
            type="range"
            min={0}
            max={1}
            step={0.05}
            value={minHeat}
            onChange={(e) => setMinHeat(parseFloat(e.target.value))}
            className="w-full accent-accent"
          />
        </div>
        <div className="pt-2 border-t border-border text-xs text-mute space-y-1">
          <div>
            requests: <span className="text-ink">{entries.length}</span>
          </div>
          <div>
            nodes: <span className="text-ink">{graph.nodes.length}</span>
          </div>
          <div>
            edges: <span className="text-ink">{graph.edges.length}</span>
          </div>
          <p className="text-[10px] leading-snug pt-1">
            Grafo derivado do HTTP History GHOSTRECON (host → endpoint).
          </p>
        </div>
      </aside>
      <div className="flex-1 min-w-0 min-h-0">
        <ReactFlow
          nodes={filteredNodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          nodeTypes={nodeTypes}
          fitView
          minZoom={0.05}
          maxZoom={3}
          proOptions={{ hideAttribution: true }}
        >
          <Background gap={24} size={1} color="#1a1e2e" />
          <MiniMap
            nodeStrokeColor={() => '#7c5cff'}
            nodeColor={() => '#0c0f1a'}
            maskColor="rgba(7,8,17,.7)"
          />
          <Controls position="bottom-right" showInteractive={false} />
        </ReactFlow>
      </div>
    </div>
  );
}
