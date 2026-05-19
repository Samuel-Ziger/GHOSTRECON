'use client';

import { use, useMemo, useState } from 'react';
import { notFound } from 'next/navigation';
import { Plus, Activity } from 'lucide-react';
import { OperatorShell } from '@/components/layout/operator-shell';
import { Card, CardBody } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Empty } from '@/components/ui/empty';
import { TimelineFeed } from '@/features/timeline/timeline-feed';
import { EventComposer } from '@/features/timeline/event-composer';
import { computeSummary, useProject, useProjectTimeline, useProjectVulnerabilities } from '@/lib/mock/store';
import { EVENT_LABEL } from '@/lib/utils/severity';
import type { TimelineEventType } from '@/lib/types';

const EVENT_TYPES: TimelineEventType[] = [
  'recon',
  'enumeration',
  'creds',
  'rce',
  'shell',
  'privesc',
  'pivot',
  'lateral',
  'exfil',
  'persistence',
  'note'
];

export default function TimelinePage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const project = useProject(id);
  const events = useProjectTimeline(id);
  const vulns = useProjectVulnerabilities(id);
  const summary = useMemo(() => computeSummary(vulns), [vulns]);
  const [composerOpen, setComposerOpen] = useState(false);

  if (!project) return notFound();

  // Group event-type counts
  const typeCounts = events.reduce((acc, e) => {
    acc[e.type] = (acc[e.type] || 0) + 1;
    return acc;
  }, {} as Record<TimelineEventType, number>);

  return (
    <OperatorShell
      projectId={id}
      title="Timeline ofensiva"
      subtitle={`${events.length} eventos`}
      breadcrumbs={[
        { label: 'Projetos', href: '/projects' },
        { label: project.codename || project.client, href: `/projects/${id}` },
        { label: 'Timeline' }
      ]}
      statusProject={{ codename: project.codename, client: project.client, status: project.status }}
      statusCounts={summary.bySeverity}
      actions={
        <Button variant="primary" size="md" onClick={() => setComposerOpen(true)}>
          <Plus size={14} /> Registrar evento
        </Button>
      }
    >
      <div className="px-6 py-6 max-w-5xl mx-auto space-y-5">
        {/* Type legend */}
        <div className="flex flex-wrap gap-1.5">
          {EVENT_TYPES.map((t) => (
            <span
              key={t}
              className="text-2xs font-mono uppercase tracking-wider px-2 py-1 border border-border rounded bg-surface-2 text-fg-muted flex items-center gap-1.5"
            >
              <span
                className="w-1.5 h-1.5 rounded-full"
                style={{ background: `var(--sev-${t === 'rce' || t === 'privesc' || t === 'exfil' ? 'critical' : t === 'shell' || t === 'pivot' || t === 'lateral' ? 'high' : t === 'creds' || t === 'persistence' ? 'medium' : 'info'})` }}
              />
              {EVENT_LABEL[t]}
              {typeCounts[t] !== undefined && (
                <span className="text-fg-dim">· {typeCounts[t]}</span>
              )}
            </span>
          ))}
        </div>

        <Card>
          <CardBody>
            {events.length === 0 ? (
              <Empty
                icon={Activity}
                title="Timeline vazia"
                description="Registre o primeiro evento operacional (recon, exploit, pivot, creds...)."
              />
            ) : (
              <TimelineFeed events={events} projectId={id} />
            )}
          </CardBody>
        </Card>
      </div>

      <EventComposer
        open={composerOpen}
        onClose={() => setComposerOpen(false)}
        projectId={id}
      />
    </OperatorShell>
  );
}
