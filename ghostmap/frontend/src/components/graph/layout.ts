// Layout automatico com dagre — bom o suficiente para milhares de nodes.
// Para 10k+ nodes, trocar por elkjs/cose-bilkent (fora do escopo da v1).

import dagre from "dagre";
import type { Edge, Node } from "reactflow";

const NODE_W = 200, NODE_H = 56;

export function layoutDagre(nodes: Node[], edges: Edge[], dir: "LR" | "TB" = "LR") {
  const g = new dagre.graphlib.Graph();
  g.setDefaultEdgeLabel(() => ({}));
  g.setGraph({ rankdir: dir, nodesep: 30, ranksep: 60 });

  nodes.forEach((n) => g.setNode(n.id, { width: NODE_W, height: NODE_H }));
  edges.forEach((e) => g.setEdge(e.source, e.target));
  dagre.layout(g);

  return {
    nodes: nodes.map((n) => {
      const p = g.node(n.id);
      return p ? { ...n, position: { x: p.x - NODE_W / 2, y: p.y - NODE_H / 2 } } : n;
    }),
    edges,
  };
}
