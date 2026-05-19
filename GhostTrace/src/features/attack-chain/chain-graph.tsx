'use client';

import { PRIVILEGE_COLOR, PRIVILEGE_LABEL } from '@/lib/utils/severity';
import type { AttackChainNode } from '@/lib/types';

interface Props {
  nodes: AttackChainNode[];
}

/**
 * Visual flow of the attack chain — each node a host, each line a hop.
 * Renders linearly (one column) which fits the LocBook reference report style.
 */
export function ChainGraph({ nodes }: Props) {
  return (
    <div className="relative">
      <ol className="space-y-2">
        {nodes.map((node, idx) => (
          <li key={node.id} className="relative">
            <div
              className="rounded-lg border bg-surface relative overflow-hidden"
              style={{
                borderColor: `${PRIVILEGE_COLOR[node.privilege]}55`,
                boxShadow: `0 0 0 1px ${PRIVILEGE_COLOR[node.privilege]}1A inset`
              }}
            >
              {/* header */}
              <div className="flex items-center justify-between px-4 py-3 border-b border-border bg-bg/30">
                <div className="flex items-center gap-3">
                  <span
                    className="w-2 h-2 rounded-full"
                    style={{
                      background: PRIVILEGE_COLOR[node.privilege],
                      boxShadow: `0 0 12px ${PRIVILEGE_COLOR[node.privilege]}`
                    }}
                  />
                  <span className="font-mono text-2xs uppercase tracking-wider text-fg-dim">
                    NODE {String(idx + 1).padStart(2, '0')}
                  </span>
                  <span className="text-sm font-medium text-fg">{node.host}</span>
                  {node.ip && (
                    <span className="text-2xs font-mono text-fg-muted">
                      [{node.ip}]
                    </span>
                  )}
                </div>
                <span
                  className="text-2xs font-mono font-medium px-2 py-0.5 rounded border"
                  style={{
                    color: PRIVILEGE_COLOR[node.privilege],
                    borderColor: `${PRIVILEGE_COLOR[node.privilege]}55`,
                    background: `${PRIVILEGE_COLOR[node.privilege]}10`
                  }}
                >
                  {PRIVILEGE_LABEL[node.privilege]}
                </span>
              </div>
              {/* steps */}
              <ol className="divide-y divide-border">
                {node.steps.map((step) => (
                  <li
                    key={step.order}
                    className="flex items-start gap-3 px-4 py-2.5 hover:bg-surface-2/60 transition-colors"
                  >
                    <span className="font-mono text-2xs text-fg-dim w-7 shrink-0">
                      ({String(step.order).padStart(2, '0')})
                    </span>
                    <p className="text-sm text-fg-muted flex-1">{step.action}</p>
                  </li>
                ))}
              </ol>
            </div>
            {/* connector arrow */}
            {idx < nodes.length - 1 && (
              <div className="flex justify-center py-2 text-fg-dim font-mono text-xl select-none">
                ↓
              </div>
            )}
          </li>
        ))}
      </ol>
    </div>
  );
}
