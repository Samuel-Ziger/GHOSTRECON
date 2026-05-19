import type { HistoryEntry } from './types';
import { hostOf, pathOf } from './history-utils';

export interface ReconGraphNode {
  id: string;
  label: string;
  title: string;
  heat: number;
  props: Record<string, unknown>;
}

export interface ReconGraphEdge {
  id: string;
  source: string;
  target: string;
  type: string;
}

export interface ReconGraphData {
  nodes: ReconGraphNode[];
  edges: ReconGraphEdge[];
}

function heatFromEntry(e: HistoryEntry): number {
  if (e.error) return 0.85;
  const s = Number(e.status ?? 0);
  if (s >= 500) return 0.9;
  if (s >= 400) return 0.7;
  if (s >= 300) return 0.35;
  return 0.15;
}

/** Constrói grafo host → endpoint a partir do histórico HTTP GHOSTRECON. */
export function buildGraphFromHistory(entries: HistoryEntry[]): ReconGraphData {
  const nodes: ReconGraphNode[] = [];
  const edges: ReconGraphEdge[] = [];
  const hostIds = new Map<string, string>();
  const pathIds = new Map<string, string>();

  for (const e of entries) {
    const host = hostOf(e.url) || 'unknown';
    const path = pathOf(e.url) || '/';
    const method = String(e.method || 'GET').toUpperCase();

    if (!hostIds.has(host)) {
      const id = `host:${host}`;
      hostIds.set(host, id);
      nodes.push({
        id,
        label: 'Host',
        title: host,
        heat: 0.2,
        props: { host }
      });
    }
    const hostId = hostIds.get(host)!;

    const pathKey = `${host}|${method}|${path}`;
    if (!pathIds.has(pathKey)) {
      const id = `ep:${pathIds.size}`;
      pathIds.set(pathKey, id);
      const heat = heatFromEntry(e);
      nodes.push({
        id,
        label: method === 'GET' ? 'Endpoint' : 'ApiOperation',
        title: `${method} ${path.length > 48 ? path.slice(0, 48) + '…' : path}`,
        heat,
        props: { method, path, status: e.status }
      });
      edges.push({
        id: `e:${hostId}->${id}`,
        source: hostId,
        target: id,
        type: 'navigates'
      });
    } else {
      const id = pathIds.get(pathKey)!;
      const n = nodes.find((x) => x.id === id);
      if (n) n.heat = Math.max(n.heat, heatFromEntry(e));
    }
  }

  return { nodes, edges };
}
