'use client';

import { use, useMemo, useRef } from 'react';
import { notFound } from 'next/navigation';
import { Image as ImageIcon, Upload } from 'lucide-react';
import { OperatorShell } from '@/components/layout/operator-shell';
import { Button } from '@/components/ui/button';
import { EvidenceGrid } from '@/features/evidence/evidence-grid';
import {
  computeSummary,
  useProject,
  useProjectVulnerabilities,
  useProjectEvidence
} from '@/lib/mock/store';

export default function EvidencePage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const project = useProject(id);
  const vulns = useProjectVulnerabilities(id);
  const evidence = useProjectEvidence(id);
  const summary = useMemo(() => computeSummary(vulns), [vulns]);
  const uploadRef = useRef<HTMLInputElement>(null);

  if (!project) return notFound();

  return (
    <OperatorShell
      projectId={id}
      title="Evidências"
      subtitle={`${evidence.length} anexo${evidence.length === 1 ? '' : 's'}`}
      breadcrumbs={[
        { label: 'Projetos', href: '/projects' },
        { label: project.codename || project.client, href: `/projects/${id}` },
        { label: 'Evidências' }
      ]}
      statusProject={{ codename: project.codename, client: project.client, status: project.status }}
      statusCounts={summary.bySeverity}
      actions={
        <Button variant="primary" size="md" onClick={() => uploadRef.current?.click()}>
          <Upload size={14} /> Enviar arquivo
        </Button>
      }
    >
      <div className="px-6 py-6 max-w-6xl mx-auto">
        <EvidenceGrid projectId={id} items={evidence} uploadRef={uploadRef} />
        {evidence.length > 0 && (
          <p className="mt-4 text-2xs text-fg-dim flex items-center gap-2">
            <ImageIcon size={12} />
            Arquivos persistidos em localStorage neste navegador (protótipo).
          </p>
        )}
      </div>
    </OperatorShell>
  );
}
