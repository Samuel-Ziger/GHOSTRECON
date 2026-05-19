'use client';

import { useEffect, useMemo, useState, useCallback } from 'react';
import ReactFlow, { Background, Controls, MiniMap, useEdgesState, useNodesState } from 'reactflow';
import { GhostNode } from './GhostNode';
import { layoutDagre } from './layout';
import { useGraphStore } from '@/store/graph.store';
import { findingsToGraph, type ReconFinding } from '@/lib/ghostrecon/findings-to-graph';
import { mitreChannelName } from '@/lib/ghostrecon/constants';
import {
  REPORTE_PAYLOAD_KEY,
  REPORTE_PAYLOAD_SHARED_KEY
} from '@/lib/ghostrecon/constants';

const nodeTypes = { ghost: GhostNode };

function readFindingsFromStorage(): { target: string; findings: ReconFinding[] } {
  const keys = [REPORTE_PAYLOAD_KEY, REPORTE_PAYLOAD_SHARED_KEY];
  for (const k of keys) {
    try {
      const raw = sessionStorage.getItem(k) || localStorage.getItem(k);
      if (!raw) continue;
      const pack = JSON.parse(raw) as { target?: string; findings?: ReconFinding[] };
      if (Array.isArray(pack.findings)) {
        return { target: String(pack.target || ''), findings: pack.findings };
      }
    } catch {
      /* ignore */
    }
  }
  return { target: '', findings: [] };
}

interface Props {
  sessionId: string;
}

export function GhostGraphRecon({ sessionId }: Props) {
  const { data, setData, minHeat } = useGraphStore();
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [query, setQuery] = useState('');
  const [target, setTarget] = useState('');
  const [liveCount, setLiveCount] = useState(0);
  const [source, setSource] = useState<'storage' | 'live' | 'empty'>('empty');

  const applyFindings = useCallback(
    (t: string, list: ReconFinding[]) => {
      setTarget(t);
      setLiveCount(list.length);
      setData(findingsToGraph(list, t || undefined));
      setSource(list.length ? 'live' : 'empty');
    },
    [setData]
  );

  useEffect(() => {
    const stored = readFindingsFromStorage();
    if (stored.findings.length) {
      applyFindings(stored.target, stored.findings);
      setSource('storage');
    }
  }, [applyFindings]);

  useEffect(() => {
    if (!sessionId || typeof BroadcastChannel === 'undefined') return;
    const bc = new BroadcastChannel(mitreChannelName(sessionId));
    const onMsg = (ev: MessageEvent) => {
      const msg = ev.data;
      if (!msg || typeof msg !== 'object') return;
      if (msg.type === 'reporte_payload' && Array.isArray(msg.findings)) {
        applyFindings(String(msg.target || ''), msg.findings);
        return;
      }
      if (msg.kind === 'ghostrecon_mitre_live_state' && Array.isArray(msg.findings)) {
        applyFindings(String(msg.target || ''), msg.findings);
      }
    };
    bc.addEventListener('message', onMsg);
    return () => bc.close();
  }, [sessionId, applyFindings]);

  useEffect(() => {
    const baseNodes = data.nodes.map((n) => ({
      id: n.id,
      type: 'ghost' as const,
      position: { x: 0, y: 0 },
      data: { label: n.label, title: n.title, heat: n.heat, props: n.props },
      hidden: n.heat < minHeat
    }));
    const baseEdges = data.edges.map((e) => ({
      id: e.id,
      source: e.source,
      target: e.target,
      type: 'smoothstep',
      label: e.type,
      labelStyle: { fill: '#7c8194', fontSize: 9 },
      style: { strokeWidth: 1.2 }
    }));
    const laid = layoutDagre(baseNodes, baseEdges, 'LR');
    setNodes(laid.nodes);
    setEdges(laid.edges);
  }, [data, minHeat, setNodes, setEdges]);

  const filteredNodes = useMemo(() => {
    if (!query.trim()) return nodes;
    const q = query.toLowerCase();
    return nodes.map((n) => ({
      ...n,
      hidden:
        (n.data as { title?: string }).title?.toString().toLowerCase().includes(q) === false
    }));
  }, [nodes, query]);

  return (
    <div className="flex h-full w-full">
      <aside className="w-72 border-r border-border bg-panel p-3 space-y-3 text-sm shrink-0">
        <div>
          <p className="text-mute text-xs uppercase tracking-wider">GHOSTRECON</p>
          <p className="text-accent font-mono text-xs mt-1 truncate" title={target}>
            {target || 'sem alvo'}
          </p>
          <p className="text-mute text-[11px] mt-1">
            {liveCount} achados · fonte: {source === 'live' ? 'ao vivo' : source === 'storage' ? 'pacote' : '—'}
          </p>
        </div>
        <div>
          <label className="text-mute text-xs">Busca</label>
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="tipo, url, valor…"
            className="w-full bg-bg border border-border rounded px-2 py-1 mt-1"
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
            onChange={(e) => useGraphStore.getState().setMinHeat(parseFloat(e.target.value))}
            className="w-full accent-accent"
          />
        </div>
        <p className="text-mute text-[11px] leading-relaxed">
          Grafo derivado dos achados do recon. Com proxy/captura completa (stack Docker do GhostMap),
          use a página <strong className="text-ink">Grafo</strong> para o mapa HTTP real.
        </p>
      </aside>
      <div className="flex-1 min-w-0 h-full">
        {!data.nodes.length ? (
          <div className="flex items-center justify-center h-full text-mute text-sm p-8 text-center">
            Corre recon no GHOSTRECON ou importa JSON no mapa MITRE — os achados aparecem aqui em tempo real.
          </div>
        ) : (
          <ReactFlow
            nodes={filteredNodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            nodeTypes={nodeTypes}
            fitView
            className="bg-bg"
          >
            <Background gap={16} color="#1a2535" />
            <Controls />
            <MiniMap />
          </ReactFlow>
        )}
      </div>
    </div>
  );
}
