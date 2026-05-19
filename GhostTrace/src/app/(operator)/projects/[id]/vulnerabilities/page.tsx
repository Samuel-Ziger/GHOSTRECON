'use client';

import { use, useMemo, useState } from 'react';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { Plus, Search, Bug } from 'lucide-react';
import { OperatorShell } from '@/components/layout/operator-shell';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { SeverityBadge } from '@/components/ui/severity-badge';
import { Empty } from '@/components/ui/empty';
import { FindingsInbox } from '@/features/ghostrecon/findings-inbox';
import {
  computeSummary,
  useGhostreconSession,
  useProject,
  useProjectVulnerabilities
} from '@/lib/mock/store';
import {
  SEVERITY_ORDER,
  STATUS_LABEL,
  compareBySeverity
} from '@/lib/utils/severity';
import type { Severity } from '@/lib/types';

export default function VulnsListPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const project = useProject(id);
  const vulns = useProjectVulnerabilities(id);
  const greconSession = useGhostreconSession(id);

  const [q, setQ] = useState('');
  const [filterSev, setFilterSev] = useState<Severity | 'all'>('all');

  const summary = useMemo(() => computeSummary(vulns), [vulns]);

  const filtered = useMemo(() => {
    let arr = [...vulns];
    if (filterSev !== 'all') arr = arr.filter((v) => v.severity === filterSev);
    if (q.trim()) {
      const needle = q.toLowerCase();
      arr = arr.filter(
        (v) =>
          v.title.toLowerCase().includes(needle) ||
          v.tags.some((t) => t.toLowerCase().includes(needle)) ||
          v.targets.some((t) => t.toLowerCase().includes(needle))
      );
    }
    return arr.sort((a, b) => compareBySeverity(a.severity, b.severity));
  }, [vulns, filterSev, q]);

  if (!project) return notFound();

  return (
    <OperatorShell
      projectId={id}
      title="Vulnerabilidades"
      subtitle={`${vulns.length} registro${vulns.length === 1 ? '' : 's'}`}
      breadcrumbs={[
        { label: 'Projetos', href: '/projects' },
        { label: project.codename || project.client, href: `/projects/${id}` },
        { label: 'Vulnerabilidades' }
      ]}
      statusProject={{ codename: project.codename, client: project.client, status: project.status }}
      statusCounts={summary.bySeverity}
      actions={
        <Link href={`/projects/${id}/vulnerabilities/new`}>
          <Button variant="primary" size="md">
            <Plus size={14} /> Nova
          </Button>
        </Link>
      }
    >
      <div className="flex min-h-0 flex-1 w-full">
        {greconSession && <FindingsInbox projectId={id} />}
        <div className="flex-1 min-w-0 px-6 py-6 max-w-6xl mx-auto space-y-4">
        {/* Filter bar */}
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative flex-1 min-w-[200px]">
            <Search
              size={14}
              className="absolute left-3 top-1/2 -translate-y-1/2 text-fg-dim"
            />
            <Input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Buscar título, tag ou alvo..."
              className="pl-9"
            />
          </div>
          <div className="flex items-center gap-1 p-1 bg-surface-2 border border-border rounded-md">
            <FilterBtn active={filterSev === 'all'} onClick={() => setFilterSev('all')}>
              TODAS · {vulns.length}
            </FilterBtn>
            {SEVERITY_ORDER.map((s) => (
              <FilterBtn key={s} active={filterSev === s} onClick={() => setFilterSev(s)}>
                <SeverityBadge severity={s} size="sm" />
                <span className="font-mono">{summary.bySeverity[s]}</span>
              </FilterBtn>
            ))}
          </div>
        </div>

        {filtered.length === 0 ? (
          <Empty
            icon={Bug}
            title={vulns.length === 0 ? 'Nenhuma vulnerabilidade registrada' : 'Nenhum resultado para o filtro'}
            description={vulns.length === 0 ? 'Comece registrando o primeiro finding para este engajamento.' : undefined}
            action={
              vulns.length === 0 ? (
                <Link href={`/projects/${id}/vulnerabilities/new`}>
                  <Button variant="primary" size="md">
                    <Plus size={14} /> Registrar primeira
                  </Button>
                </Link>
              ) : undefined
            }
          />
        ) : (
          <Card>
            <ul className="divide-y divide-border">
              {filtered.map((v) => (
                <li key={v.id}>
                  <Link
                    href={`/projects/${id}/vulnerabilities/${v.id}`}
                    className="block px-5 py-4 hover:bg-surface-2 transition-colors"
                  >
                    <div className="flex items-start gap-4">
                      <span className="font-mono text-2xs text-fg-dim w-8 mt-0.5">
                        #{String(v.number ?? '–').padStart(2, '0')}
                      </span>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <SeverityBadge severity={v.severity} size="sm" />
                          <Badge mono>{STATUS_LABEL[v.status]}</Badge>
                          {v.isEasilyExploitable && (
                            <Badge mono tone="accent">
                              EASILY-EXPLOIT
                            </Badge>
                          )}
                          {v.isZeroDay && (
                            <Badge
                              mono
                              className="!text-[var(--sev-critical)] !border-[var(--sev-critical)]/40 !bg-[var(--sev-critical)]/10"
                            >
                              0-DAY
                            </Badge>
                          )}
                        </div>
                        <h3 className="mt-1 text-sm text-fg font-medium">{v.title}</h3>
                        <div className="mt-1 flex flex-wrap items-center gap-2 text-2xs font-mono text-fg-muted">
                          <span>{v.targets.join(' · ')}</span>
                          {v.cwe.length > 0 && (
                            <>
                              <span className="text-fg-dim">·</span>
                              <span>{v.cwe.join(', ')}</span>
                            </>
                          )}
                        </div>
                      </div>
                      <div className="shrink-0 text-right">
                        {v.cvss && (
                          <div className="font-mono text-sm text-fg">
                            {v.cvss.score.toFixed(1)}
                          </div>
                        )}
                        <div className="text-2xs uppercase text-fg-dim font-mono">
                          CVSS v3.1
                        </div>
                      </div>
                    </div>
                  </Link>
                </li>
              ))}
            </ul>
          </Card>
        )}
        </div>
      </div>
    </OperatorShell>
  );
}

function FilterBtn({
  active,
  onClick,
  children
}: {
  active?: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      className={`flex items-center gap-1.5 px-2.5 h-7 text-2xs uppercase tracking-wider rounded transition-colors ${
        active
          ? 'bg-surface text-fg'
          : 'text-fg-muted hover:text-fg hover:bg-surface'
      }`}
    >
      {children}
    </button>
  );
}
