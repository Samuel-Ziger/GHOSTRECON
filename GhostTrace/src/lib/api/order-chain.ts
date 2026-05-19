import type { AttackChainNode } from '@/lib/types';

/** Ordena nós seguindo nextNodeIds (cadeia linear). Nós órfãos vão ao final. */
export function orderAttackChain(nodes: AttackChainNode[]): AttackChainNode[] {
  if (nodes.length <= 1) return [...nodes];
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const referenced = new Set(nodes.flatMap((n) => n.nextNodeIds));
  const heads = nodes.filter((n) => !referenced.has(n.id));
  const ordered: AttackChainNode[] = [];
  const seen = new Set<string>();

  function walk(start: AttackChainNode) {
    let cur: AttackChainNode | undefined = start;
    while (cur && !seen.has(cur.id)) {
      seen.add(cur.id);
      ordered.push(cur);
      const nextId: string | undefined = cur.nextNodeIds[0];
      cur = nextId ? byId.get(nextId) : undefined;
    }
  }

  for (const h of heads) walk(h);
  for (const n of nodes) {
    if (!seen.has(n.id)) ordered.push(n);
  }
  return ordered;
}
