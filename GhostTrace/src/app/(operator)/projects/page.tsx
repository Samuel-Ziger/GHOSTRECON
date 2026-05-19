'use client';

import Link from 'next/link';
import { Plus, FolderKanban } from 'lucide-react';
import { OperatorShell } from '@/components/layout/operator-shell';
import { Button } from '@/components/ui/button';
import { Empty } from '@/components/ui/empty';
import { ProjectCard } from '@/features/projects/project-card';
import { useStore } from '@/lib/mock/store';

export default function ProjectsPage() {
  const projects = useStore((s) => s.projects);
  const allVulns = useStore((s) => s.vulnerabilities);

  return (
    <OperatorShell
      title="Projetos"
      subtitle={`${projects.length} ativo${projects.length === 1 ? '' : 's'}`}
      actions={
        <Link href="/projects/new">
          <Button variant="primary" size="md">
            <Plus size={14} />
            Novo projeto
          </Button>
        </Link>
      }
    >
      <div className="px-6 py-6 max-w-7xl mx-auto">
        {projects.length === 0 ? (
          <Empty
            icon={FolderKanban}
            title="Nenhum engajamento ativo"
            description="Crie um projeto para começar a documentar a operação em tempo real."
            action={
              <Link href="/projects/new">
                <Button variant="primary" size="md">
                  <Plus size={14} />
                  Criar projeto
                </Button>
              </Link>
            }
          />
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {projects.map((p) => (
              <ProjectCard
                key={p.id}
                project={p}
                vulnerabilities={allVulns.filter((v) => v.projectId === p.id)}
              />
            ))}
          </div>
        )}
      </div>
    </OperatorShell>
  );
}
