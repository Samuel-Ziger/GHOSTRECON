'use client';

import { use, useMemo, useState, useCallback } from 'react';
import { notFound } from 'next/navigation';
import { FileText, Sparkles, FileDown } from 'lucide-react';
import { OperatorShell } from '@/components/layout/operator-shell';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { ReportPreview } from '@/features/reports/report-preview';
import { ReportWizard } from '@/features/reports/report-wizard';
import { buildReportShape, downloadReportJson } from '@/lib/report/shape';
import { exportProjectToDocx } from '@/features/reports/docx-exporter';
import {
  computeSummary,
  useProject,
  useProjectVulnerabilities,
  useProjectTimeline,
  useProjectAttackChain,
  useProjectCredentials,
  useStore
} from '@/lib/mock/store';

export default function ReportPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const project = useProject(id);
  const vulns = useProjectVulnerabilities(id);
  const timeline = useProjectTimeline(id);
  const chain = useProjectAttackChain(id);
  const creds = useProjectCredentials(id);
  const conclusion = useStore((s) => s.getReportConclusion(id));
  const activeProvider = useStore((s) => s.getActiveAIProvider());
  const summary = useMemo(() => computeSummary(vulns), [vulns]);
  const [wizardOpen, setWizardOpen] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [, setTick] = useState(0);

  const exportDocx = useCallback(async () => {
    if (!project) return;
    setExporting(true);
    try {
      await exportProjectToDocx({
        project,
        vulnerabilities: vulns,
        attackChain: chain,
        credentials: creds
      });
    } finally {
      setExporting(false);
    }
  }, [project, vulns, chain, creds]);

  const exportJson = useCallback(() => {
    if (!project) return;
    const shape = buildReportShape({
      project,
      vulnerabilities: vulns,
      timeline,
      attackChain: chain,
      credentials: creds,
      generator: activeProvider
        ? { provider: activeProvider.id, model: activeProvider.model }
        : { provider: 'none' },
      conclusion
    });
    downloadReportJson(shape);
  }, [project, vulns, timeline, chain, creds, activeProvider, conclusion]);

  if (!project) return notFound();

  return (
    <OperatorShell
      projectId={id}
      title="Relatório"
      subtitle="preview enterprise"
      breadcrumbs={[
        { label: 'Projetos', href: '/projects' },
        { label: project.codename || project.client, href: `/projects/${id}` },
        { label: 'Relatório' }
      ]}
      statusProject={{ codename: project.codename, client: project.client, status: project.status }}
      statusCounts={summary.bySeverity}
      actions={
        <div className="flex items-center gap-2">
          <Button variant="secondary" size="md" onClick={exportDocx} disabled={exporting}>
            <FileDown size={14} /> {exporting ? 'Exportando...' : 'Exportar DOCX'}
          </Button>
          <Button variant="ghost" size="md" onClick={exportJson}>
            JSON
          </Button>
          <Button variant="primary" size="md" onClick={() => setWizardOpen(true)}>
            <Sparkles size={14} /> Gerar com IA
          </Button>
        </div>
      }
    >
      <div className="px-6 py-6 max-w-6xl mx-auto">
        <div className="flex items-center justify-between mb-4 text-xs text-fg-muted">
          <div className="flex items-center gap-2">
            <FileText size={14} className="text-accent" />
            <span>
              Preview HTML — contrato <code className="font-mono">ReportShape</code> exportável em
              JSON até o backend DOCX.
            </span>
          </div>
          <Badge mono>
            {vulns.length} VULNS · {chain.length} HOPS
          </Badge>
        </div>

        <ReportPreview
          project={project}
          vulnerabilities={vulns}
          timeline={timeline}
          attackChain={chain}
          credentials={creds}
        />
      </div>

      <ReportWizard
        open={wizardOpen}
        onClose={() => setWizardOpen(false)}
        project={project}
        onComplete={() => setTick((t) => t + 1)}
        onExport={exportDocx}
      />
    </OperatorShell>
  );
}

