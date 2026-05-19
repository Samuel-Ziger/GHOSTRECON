'use client';

import { use, useMemo } from 'react';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { Plus, FileText, Bug, GitBranch, Activity } from 'lucide-react';
import { OperatorShell } from '@/components/layout/operator-shell';
import { Button } from '@/components/ui/button';
import { Card, CardHeader, CardTitle, CardBody } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { SeverityBadge } from '@/components/ui/severity-badge';
import { SummaryGrid } from '@/features/projects/summary-grid';
import {
  computeSummary,
  useProject,
  useProjectVulnerabilities,
  useProjectTimeline,
  useProjectAttackChain
} from '@/lib/mock/store';
import { fmtRange, fmtRelative, fmtTime, fmtDate } from '@/lib/utils/format';
import {
  EVENT_COLOR,
  EVENT_LABEL,
  PRIVILEGE_COLOR,
  PRIVILEGE_LABEL,
  SEVERITY_ORDER,
  STATUS_LABEL,
  compareBySeverity
} from '@/lib/utils/severity';

export default function ProjectDashboard({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const project = useProject(id);
  const vulns = useProjectVulnerabilities(id);
  const timeline = useProjectTimeline(id);
  const chain = useProjectAttackChain(id);

  const summary = useMemo(() => computeSummary(vulns), [vulns]);

  if (!project) return notFound();

  const recentEvents = [...timeline].reverse().slice(0, 6);
  const sortedVulns = [...vulns].sort((a, b) => compareBySeverity(a.severity, b.severity));

  const pivots = chain.filter((n) => n.host !== 'INTERNET').length - 1; // edge counts, internal pivots count
  const lastHost = chain[chain.length - 1]?.ip;

  return (
    <OperatorShell
      projectId={id}
      title={project.codename || project.client}
      subtitle={project.methodology.toUpperCase()}
      breadcrumbs={[
        { label: 'Projetos', href: '/projects' },
        { label: project.codename || project.client }
      ]}
      statusProject={{
        codename: project.codename,
        client: project.client,
        status: project.status
      }}
      statusCounts={summary.bySeverity}
      statusPivots={Math.max(0, pivots)}
      statusHost={lastHost}
      actions={
        <div className="flex items-center gap-2">
          <Link href={`/projects/${id}/vulnerabilities/new`}>
            <Button variant="secondary" size="md">
              <Plus size={14} /> Nova vuln
            </Button>
          </Link>
          <Link href={`/projects/${id}/report`}>
            <Button variant="primary" size="md">
              <FileText size={14} /> Gerar relatório
            </Button>
          </Link>
        </div>
      }
    >
      <div className="px-6 py-6 space-y-5 max-w-7xl mx-auto">
        {/* Header info row */}
        <div className="flex flex-wrap items-start justify-between gap-4 pb-2">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <Badge mono tone="accent">
                {project.methodology.toUpperCase()}
              </Badge>
              <Badge mono>{project.engagementType.replace('_', ' ').toUpperCase()}</Badge>
              <Badge mono>{project.status.toUpperCase()}</Badge>
            </div>
            <div className="text-xs font-mono text-fg-muted">
              {fmtRange(project.startDate, project.endDate)}
            </div>
            <div className="mt-1 text-xs font-mono text-fg-dim">
              {project.scope.join(' · ')}
            </div>
          </div>
        </div>

        <SummaryGrid
          bySeverity={summary.bySeverity}
          totalUnique={summary.totalUnique}
          zeroDay={summary.zeroDay}
          easilyExploitable={summary.easilyExploitable}
        />

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {/* Vulnerabilities by severity */}
          <Card className="lg:col-span-2">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Bug size={12} /> Vulnerabilidades por severidade
              </CardTitle>
              <Link
                href={`/projects/${id}/vulnerabilities`}
                className="text-xs text-fg-muted hover:text-fg"
              >
                ver todas →
              </Link>
            </CardHeader>
            <CardBody className="p-0">
              {SEVERITY_ORDER.map((sev) => {
                const list = sortedVulns.filter((v) => v.severity === sev);
                if (list.length === 0) return null;
                return (
                  <div key={sev}>
                    <div className="px-4 py-2 bg-surface-2 border-b border-border flex items-center justify-between">
                      <SeverityBadge severity={sev} size="sm" />
                      <span className="text-2xs font-mono text-fg-dim">
                        {list.length} finding{list.length === 1 ? '' : 's'}
                      </span>
                    </div>
                    <ul className="divide-y divide-border">
                      {list.map((v) => (
                        <li key={v.id}>
                          <Link
                            href={`/projects/${id}/vulnerabilities/${v.id}`}
                            className="flex items-center justify-between px-4 py-3 hover:bg-surface-2 transition-colors group"
                          >
                            <div className="flex items-center gap-3 min-w-0">
                              <span className="text-2xs font-mono text-fg-dim w-6">
                                #{String(v.number ?? '–').padStart(2, '0')}
                              </span>
                              <span className="text-sm text-fg truncate group-hover:text-accent">
                                {v.title}
                              </span>
                            </div>
                            <div className="flex items-center gap-2 shrink-0">
                              <Badge mono>{STATUS_LABEL[v.status]}</Badge>
                              {v.cvss && (
                                <span className="font-mono text-2xs text-fg-muted">
                                  CVSS {v.cvss.score.toFixed(1)}
                                </span>
                              )}
                            </div>
                          </Link>
                        </li>
                      ))}
                    </ul>
                  </div>
                );
              })}
              {sortedVulns.length === 0 && (
                <div className="p-6 text-center text-sm text-fg-muted">
                  Nenhuma vulnerabilidade registrada ainda.
                </div>
              )}
            </CardBody>
          </Card>

          {/* Recent activity */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Activity size={12} /> Atividade recente
              </CardTitle>
              <Link
                href={`/projects/${id}/timeline`}
                className="text-xs text-fg-muted hover:text-fg"
              >
                timeline →
              </Link>
            </CardHeader>
            <CardBody className="p-0">
              <ul className="divide-y divide-border">
                {recentEvents.map((evt) => (
                  <li key={evt.id} className="px-4 py-3">
                    <div className="flex items-start gap-3">
                      <span
                        className="mt-1 text-2xs font-mono font-medium uppercase tracking-wider shrink-0 w-14"
                        style={{ color: EVENT_COLOR[evt.type] }}
                      >
                        {EVENT_LABEL[evt.type]}
                      </span>
                      <div className="min-w-0 flex-1">
                        <p className="text-xs text-fg leading-snug">{evt.title}</p>
                        {evt.host && (
                          <p className="text-2xs text-fg-dim font-mono mt-0.5">
                            {evt.host}
                          </p>
                        )}
                      </div>
                      <span className="text-2xs font-mono text-fg-dim shrink-0">
                        {fmtTime(evt.ts)}
                      </span>
                    </div>
                  </li>
                ))}
              </ul>
            </CardBody>
          </Card>
        </div>

        {/* Attack chain quick view */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <GitBranch size={12} /> Cadeia de ataque
            </CardTitle>
            <Link
              href={`/projects/${id}/attack-chain`}
              className="text-xs text-fg-muted hover:text-fg"
            >
              ver completa →
            </Link>
          </CardHeader>
          <CardBody>
            <div className="flex flex-wrap items-center gap-3">
              {chain.map((node, i) => (
                <div key={node.id} className="flex items-center gap-3">
                  <div
                    className="rounded-md border px-3 py-2 bg-surface-2 min-w-[140px]"
                    style={{ borderColor: `${PRIVILEGE_COLOR[node.privilege]}55` }}
                  >
                    <div className="text-2xs font-mono uppercase text-fg-dim">{node.host}</div>
                    {node.ip && (
                      <div className="text-xs font-mono text-fg mt-0.5">{node.ip}</div>
                    )}
                    <div
                      className="mt-1 text-2xs font-mono"
                      style={{ color: PRIVILEGE_COLOR[node.privilege] }}
                    >
                      {PRIVILEGE_LABEL[node.privilege]}
                    </div>
                  </div>
                  {i < chain.length - 1 && (
                    <div className="font-mono text-fg-dim text-lg">→</div>
                  )}
                </div>
              ))}
            </div>
          </CardBody>
        </Card>

        {project.notes && (
          <Card>
            <CardHeader>
              <CardTitle>Notas do projeto</CardTitle>
            </CardHeader>
            <CardBody>
              <p className="text-sm text-fg-muted leading-relaxed">{project.notes}</p>
            </CardBody>
          </Card>
        )}
      </div>
    </OperatorShell>
  );
}
