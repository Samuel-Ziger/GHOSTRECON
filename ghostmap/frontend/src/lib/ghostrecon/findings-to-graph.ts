import type { GraphEdge, GraphNode, GraphResponse, NodeLabel } from '@/lib/types';

export interface ReconFinding {
  type?: string;
  prio?: string;
  priority?: string;
  value?: string;
  url?: string;
  meta?: string;
  fingerprint?: string;
  mitre?: Array<{ id?: string } | string>;
  owasp?: string;
}

function prioToHeat(prio?: string): number {
  const p = String(prio || '').toLowerCase();
  if (p === 'critical') return 1;
  if (p === 'high') return 0.85;
  if (p === 'medium') return 0.55;
  if (p === 'low') return 0.35;
  return 0.2;
}

function labelForType(type: string): NodeLabel {
  const t = type.toLowerCase();
  if (t.includes('endpoint') || t.includes('param') || t === 'js') return 'Endpoint';
  if (t.includes('graphql')) return 'GraphQLOperation';
  if (t.includes('jwt')) return 'JWT';
  if (t.includes('secret')) return 'Integration';
  return 'Page';
}

/** Projeta achados GHOSTRECON num grafo ReactFlow (modo offline, sem Neo4j). */
export function findingsToGraph(
  findings: ReconFinding[],
  target?: string
): GraphResponse {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  const hostId = target ? `host:${target}` : 'host:target';

  if (target) {
    nodes.push({
      id: hostId,
      label: 'Host',
      title: target,
      props: { source: 'ghostrecon' },
      heat: 1,
      cluster: 'scope'
    });
  }

  const typeIds = new Map<string, string>();

  findings.forEach((f, i) => {
    const type = String(f.type || 'finding').trim() || 'finding';
    let typeNodeId = typeIds.get(type);
    if (!typeNodeId) {
      typeNodeId = `type:${type}`;
      typeIds.set(type, typeNodeId);
      nodes.push({
        id: typeNodeId,
        label: 'Page',
        title: type,
        props: { kind: 'finding_type' },
        heat: 0.5,
        cluster: type
      });
      if (target) {
        edges.push({
          id: `e-host-${typeNodeId}`,
          source: hostId,
          target: typeNodeId,
          type: 'HAS_TYPE',
          props: {}
        });
      }
    }

    const fid = f.fingerprint || `f${i}`;
    const nodeId = `finding:${fid}`;
    const title = String(f.value || f.url || type).slice(0, 120);
    const heat = prioToHeat(f.prio || f.priority);

    nodes.push({
      id: nodeId,
      label: labelForType(type),
      title,
      props: {
        type,
        url: f.url,
        meta: f.meta,
        prio: f.prio || f.priority,
        fingerprint: f.fingerprint
      },
      heat,
      cluster: type
    });

    edges.push({
      id: `e-${typeNodeId}-${nodeId}`,
      source: typeNodeId,
      target: nodeId,
      type: 'FINDING',
      props: {}
    });

    const mitreList = Array.isArray(f.mitre) ? f.mitre : [];
    for (const m of mitreList) {
      const id = typeof m === 'string' ? m : m?.id;
      if (!id || !String(id).startsWith('T')) continue;
      const tid = `mitre:${id}`;
      if (!nodes.find((n) => n.id === tid)) {
        nodes.push({
          id: tid,
          label: 'Integration',
          title: String(id),
          props: { mitre: true },
          heat: 0.7,
          cluster: 'mitre'
        });
      }
      edges.push({
        id: `e-${nodeId}-${tid}`,
        source: nodeId,
        target: tid,
        type: 'MITRE',
        props: {}
      });
    }
  });

  return {
    nodes,
    edges,
    stats: {
      findings: findings.length,
      nodes: nodes.length,
      edges: edges.length
    }
  };
}
