'use client';

import { use } from 'react';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ChevronLeft } from 'lucide-react';
import { OperatorShell } from '@/components/layout/operator-shell';
import { Button } from '@/components/ui/button';
import { VulnEditor } from '@/features/vulnerabilities/vuln-editor';
import { useProject } from '@/lib/mock/store';

export default function NewVulnPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const project = useProject(id);
  if (!project) return notFound();

  return (
    <OperatorShell
      projectId={id}
      title="Nova vulnerabilidade"
      breadcrumbs={[
        { label: 'Projetos', href: '/projects' },
        { label: project.codename || project.client, href: `/projects/${id}` },
        { label: 'Vulnerabilidades', href: `/projects/${id}/vulnerabilities` },
        { label: 'Nova' }
      ]}
      actions={
        <Link href={`/projects/${id}/vulnerabilities`}>
          <Button variant="ghost" size="md">
            <ChevronLeft size={14} /> Cancelar
          </Button>
        </Link>
      }
    >
      <VulnEditor projectId={id} />
    </OperatorShell>
  );
}
