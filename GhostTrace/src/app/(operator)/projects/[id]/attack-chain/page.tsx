'use client';

import { use, useMemo } from 'react';
import { notFound } from 'next/navigation';
import { GitBranch } from 'lucide-react';
import { OperatorShell } from '@/components/layout/operator-shell';
import { Card, CardBody, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { ChainEditor } from '@/features/attack-chain/chain-editor';
import { computeSummary, useProject, useProjectAttackChain, useProjectVulnerabilities } from '@/lib/mock/store';
import { PRIVILEGE_LABEL } from '@/lib/utils/severity';
import { orderAttackChain } from '@/lib/api/order-chain';

export default function AttackChainPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const project = useProject(id);
  const chain = useProjectAttackChain(id);
  const vulns = useProjectVulnerabilities(id);
  const summary = useMemo(() => computeSummary(vulns), [vulns]);
  const ordered = useMemo(() => orderAttackChain(chain), [chain]);

  if (!project) return notFound();

  const rootCount = chain.filter((n) => n.privilege === 'root').length;
  const userCount = chain.filter((n) => n.privilege === 'user').length;
  const hopCount = Math.max(0, ordered.length - 1);

  return (
    <OperatorShell
      projectId={id}
      title="Attack chain"
      subtitle={`${chain.length} hosts · ${hopCount} hops`}
      breadcrumbs={[
        { label: 'Projetos', href: '/projects' },
        { label: project.codename || project.client, href: `/projects/${id}` },
        { label: 'Attack chain' }
      ]}
      statusProject={{ codename: project.codename, client: project.client, status: project.status }}
      statusCounts={summary.bySeverity}
      statusPivots={Math.max(0, chain.length - 2)}
      statusHost={ordered[ordered.length - 1]?.ip}
    >
      <div className="px-6 py-6 max-w-5xl mx-auto space-y-5">
        <div className="grid grid-cols-3 gap-3">
          <KpiCard label="HOPS" value={hopCount} />
          <KpiCard label={PRIVILEGE_LABEL.user} value={userCount} color="var(--sev-info)" />
          <KpiCard label={PRIVILEGE_LABEL.root} value={rootCount} color="var(--sev-critical)" />
        </div>

        <Card className="border-accent/20 bg-accent-soft/30">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-sm">
              <GitBranch size={12} /> Editor da cadeia
            </CardTitle>
            <Badge mono tone="accent">
              EDITÁVEL
            </Badge>
          </CardHeader>
          <CardBody className="pt-0">
            <ChainEditor projectId={id} nodes={chain} />
          </CardBody>
        </Card>
      </div>
    </OperatorShell>
  );
}

function KpiCard({ label, value, color }: { label: string; value: number; color?: string }) {
  return (
    <div
      className="rounded-lg border border-border bg-surface p-4 severity-bar"
      style={{ ['--bar-color' as string]: color || 'hsl(var(--accent))' }}
    >
      <div className="text-2xs uppercase tracking-wider text-fg-muted font-mono">{label}</div>
      <div
        className="mt-1 text-3xl font-mono font-medium"
        style={{ color: color || 'hsl(var(--accent))' }}
      >
        {String(value).padStart(2, '0')}
      </div>
    </div>
  );
}
