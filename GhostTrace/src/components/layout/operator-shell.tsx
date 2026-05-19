'use client';

import { useState, type ReactNode } from 'react';
import { Sidebar } from './sidebar';
import { TopBar } from './topbar';
import { CommandPalette } from './command-palette';
import { StatusBar } from './status-bar';
import type { Severity } from '@/lib/types';

interface Props {
  children: ReactNode;
  projectId?: string;

  // topbar props
  title: string;
  subtitle?: string;
  breadcrumbs?: { label: string; href?: string }[];
  actions?: ReactNode;

  // status bar props
  statusProject?: { codename?: string; client: string; status: string };
  statusCounts?: Record<Severity, number>;
  statusPivots?: number;
  statusHost?: string;
}

export function OperatorShell({
  children,
  projectId,
  title,
  subtitle,
  breadcrumbs,
  actions,
  statusProject,
  statusCounts,
  statusPivots,
  statusHost
}: Props) {
  const [cmdOpen, setCmdOpen] = useState(false);

  return (
    <div className="flex min-h-screen">
      <Sidebar projectId={projectId} />
      <div className="flex-1 flex flex-col min-h-screen min-w-0">
        <TopBar
          title={title}
          subtitle={subtitle}
          breadcrumbs={breadcrumbs}
          actions={actions}
          onOpenCommand={() => setCmdOpen(true)}
        />
        <main className="flex-1 min-w-0 pb-7">{children}</main>
        <StatusBar
          project={statusProject}
          counts={statusCounts}
          pivots={statusPivots}
          hostActive={statusHost}
        />
      </div>
      <CommandPalette open={cmdOpen} onOpenChange={setCmdOpen} projectId={projectId} />
    </div>
  );
}
