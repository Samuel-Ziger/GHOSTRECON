'use client';

import Link from 'next/link';
import { Calendar, Target, Activity } from 'lucide-react';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { SeverityBadge } from '@/components/ui/severity-badge';
import { fmtRange } from '@/lib/utils/format';
import { SEVERITY_ORDER } from '@/lib/utils/severity';
import type { Project, Vulnerability, Severity } from '@/lib/types';
import { computeSummary } from '@/lib/mock/store';

interface Props {
  project: Project;
  vulnerabilities: Vulnerability[];
}

export function ProjectCard({ project, vulnerabilities }: Props) {
  const summary = computeSummary(vulnerabilities);
  const topSeverity = SEVERITY_ORDER.find((s) => summary.bySeverity[s] > 0) as Severity | undefined;

  return (
    <Link
      href={`/projects/${project.id}`}
      className="group block transition-all duration-150 ease-snap"
    >
      <Card className="h-full hover:border-border-strong hover:bg-surface group-hover:shadow-panel relative overflow-hidden">
        {/* methodology accent strip */}
        <div
          className="absolute top-0 left-0 right-0 h-px"
          style={{
            background:
              'linear-gradient(90deg, transparent, hsl(var(--accent) / 0.5), transparent)'
          }}
        />
        <div className="p-5">
          <div className="flex items-start justify-between">
            <div className="min-w-0">
              <div className="flex items-center gap-2 mb-1">
                <Badge tone="accent" mono>
                  {project.methodology.toUpperCase()}
                </Badge>
                <Badge mono>{project.status.toUpperCase()}</Badge>
              </div>
              <h3 className="text-base font-medium text-fg truncate">
                {project.codename || project.client}
              </h3>
              <p className="text-xs text-fg-muted mt-0.5 truncate">
                {project.codename ? `${project.client}` : ''}
              </p>
            </div>
            {topSeverity && <SeverityBadge severity={topSeverity} size="sm" />}
          </div>

          <dl className="mt-4 space-y-1.5 text-xs">
            <div className="flex items-center gap-2 text-fg-muted">
              <Target size={12} className="shrink-0" />
              <span className="font-mono truncate">{project.scope.slice(0, 2).join(' · ')}</span>
              {project.scope.length > 2 && (
                <span className="text-fg-dim font-mono">+{project.scope.length - 2}</span>
              )}
            </div>
            <div className="flex items-center gap-2 text-fg-muted">
              <Calendar size={12} className="shrink-0" />
              <span className="font-mono">{fmtRange(project.startDate, project.endDate)}</span>
            </div>
            <div className="flex items-center gap-2 text-fg-muted">
              <Activity size={12} className="shrink-0" />
              <span className="font-mono">
                {summary.totalUnique} vulns · {summary.unfixed} pendentes
              </span>
            </div>
          </dl>

          {/* severity grid mini */}
          <div className="mt-4 grid grid-cols-5 gap-1">
            {SEVERITY_ORDER.map((s) => (
              <div
                key={s}
                className="text-center px-1 py-1.5 rounded border border-border bg-surface-2"
                style={{
                  borderColor:
                    summary.bySeverity[s] > 0
                      ? `var(--sev-${s === 'critical' ? 'critical' : s})`
                      : undefined,
                  opacity: summary.bySeverity[s] > 0 ? 1 : 0.4
                }}
              >
                <div
                  className="text-sm font-mono font-medium"
                  style={{ color: `var(--sev-${s})` }}
                >
                  {summary.bySeverity[s]}
                </div>
                <div className="text-[9px] uppercase tracking-wider text-fg-dim">{s[0]}</div>
              </div>
            ))}
          </div>
        </div>
      </Card>
    </Link>
  );
}
