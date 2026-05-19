'use client';

import { use, useMemo, useState } from 'react';
import { notFound } from 'next/navigation';
import { KeyRound, Eye, EyeOff, Copy } from 'lucide-react';
import { OperatorShell } from '@/components/layout/operator-shell';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Empty } from '@/components/ui/empty';
import { computeSummary, useProject, useProjectCredentials, useProjectVulnerabilities } from '@/lib/mock/store';

export default function CredentialsPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const project = useProject(id);
  const creds = useProjectCredentials(id);
  const vulns = useProjectVulnerabilities(id);
  const summary = useMemo(() => computeSummary(vulns), [vulns]);
  const [revealed, setRevealed] = useState<Set<string>>(new Set());

  if (!project) return notFound();

  function toggle(idCred: string) {
    setRevealed((prev) => {
      const next = new Set(prev);
      next.has(idCred) ? next.delete(idCred) : next.add(idCred);
      return next;
    });
  }

  return (
    <OperatorShell
      projectId={id}
      title="Credential vault"
      subtitle={`${creds.length} entradas`}
      breadcrumbs={[
        { label: 'Projetos', href: '/projects' },
        { label: project.codename || project.client, href: `/projects/${id}` },
        { label: 'Credenciais' }
      ]}
      statusProject={{ codename: project.codename, client: project.client, status: project.status }}
      statusCounts={summary.bySeverity}
    >
      <div className="px-6 py-6 max-w-6xl mx-auto">
        <div className="mb-4 p-3 rounded-md border border-[var(--sev-medium)]/30 bg-[var(--sev-medium)]/5 text-xs text-fg-muted flex items-start gap-3">
          <KeyRound size={14} className="text-[var(--sev-medium)] mt-0.5 shrink-0" />
          <div>
            <p className="font-medium text-fg">Conteúdo sensível.</p>
            <p>
              Todas as credenciais listadas devem ser <strong>rotacionadas</strong> imediatamente
              após o encerramento do engajamento. Esta lista será incluída no Apêndice E do
              relatório, marcada como confidencial.
            </p>
          </div>
        </div>

        {creds.length === 0 ? (
          <Empty
            icon={KeyRound}
            title="Vault vazio"
            description="Credenciais e artefatos coletados aparecerão aqui."
          />
        ) : (
          <Card>
            <table className="w-full text-sm">
              <thead className="text-2xs uppercase tracking-wider text-fg-dim border-b border-border">
                <tr>
                  <th className="px-4 py-3 text-left font-medium">Usuário</th>
                  <th className="px-4 py-3 text-left font-medium">Contexto</th>
                  <th className="px-4 py-3 text-left font-medium">Host</th>
                  <th className="px-4 py-3 text-left font-medium">Valor</th>
                  <th className="px-4 py-3 text-left font-medium">Origem</th>
                  <th className="px-4 py-3" />
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {creds.map((c) => (
                  <tr key={c.id} className="hover:bg-surface-2/60 transition-colors">
                    <td className="px-4 py-3 font-mono text-fg">{c.user}</td>
                    <td className="px-4 py-3 text-fg-muted">{c.context}</td>
                    <td className="px-4 py-3 font-mono text-2xs text-fg-dim">
                      {c.host ?? '—'}
                    </td>
                    <td className="px-4 py-3">
                      <code className="font-mono text-xs px-2 py-1 rounded bg-bg border border-border text-fg">
                        {revealed.has(c.id) ? c.value : '•'.repeat(Math.min(c.value.length, 24))}
                      </code>
                    </td>
                    <td className="px-4 py-3 text-2xs text-fg-muted font-mono">
                      {c.source ?? '—'}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <div className="flex items-center justify-end gap-1">
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => toggle(c.id)}
                          title={revealed.has(c.id) ? 'Ocultar' : 'Revelar'}
                        >
                          {revealed.has(c.id) ? <EyeOff size={13} /> : <Eye size={13} />}
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => navigator.clipboard.writeText(c.value)}
                          title="Copiar"
                        >
                          <Copy size={13} />
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>
        )}
      </div>
    </OperatorShell>
  );
}
