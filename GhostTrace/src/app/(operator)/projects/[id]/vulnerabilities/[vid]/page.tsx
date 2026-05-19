'use client';

import { use } from 'react';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ChevronLeft, Edit, ExternalLink } from 'lucide-react';
import { OperatorShell } from '@/components/layout/operator-shell';
import { Card, CardHeader, CardTitle, CardBody } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { SeverityBadge } from '@/components/ui/severity-badge';
import { useProject, useVulnerability } from '@/lib/mock/store';
import { STATUS_LABEL } from '@/lib/utils/severity';
import { fmtRelative } from '@/lib/utils/format';

export default function VulnDetailPage({
  params
}: {
  params: Promise<{ id: string; vid: string }>;
}) {
  const { id, vid } = use(params);
  const project = useProject(id);
  const vuln = useVulnerability(vid);
  if (!project || !vuln) return notFound();

  return (
    <OperatorShell
      projectId={id}
      title={vuln.title}
      breadcrumbs={[
        { label: 'Projetos', href: '/projects' },
        { label: project.codename || project.client, href: `/projects/${id}` },
        { label: 'Vulnerabilidades', href: `/projects/${id}/vulnerabilities` },
        { label: `#${vuln.number ?? '?'}` }
      ]}
      actions={
        <div className="flex items-center gap-2">
          <Link href={`/projects/${id}/vulnerabilities`}>
            <Button variant="ghost" size="md">
              <ChevronLeft size={14} /> Voltar
            </Button>
          </Link>
          <Button variant="primary" size="md">
            <Edit size={14} /> Editar
          </Button>
        </div>
      }
    >
      <div className="px-6 py-6 max-w-5xl mx-auto space-y-5">
        {/* Header card */}
        <Card>
          <CardBody className="space-y-3">
            <div className="flex items-center gap-2 flex-wrap">
              <SeverityBadge severity={vuln.severity} />
              <Badge mono>{STATUS_LABEL[vuln.status]}</Badge>
              {vuln.isEasilyExploitable && (
                <Badge mono tone="accent">
                  EASILY-EXPLOIT
                </Badge>
              )}
              {vuln.isZeroDay && (
                <Badge mono className="!text-[var(--sev-critical)] !border-[var(--sev-critical)]/40 !bg-[var(--sev-critical)]/10">
                  0-DAY
                </Badge>
              )}
              {vuln.tags.map((t) => (
                <Badge key={t} mono>
                  {t}
                </Badge>
              ))}
            </div>
            <h1 className="text-xl font-medium text-fg">{vuln.title}</h1>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 pt-2 border-t border-border text-xs">
              <Meta label="CVSS Score">
                <span className="text-base font-mono text-fg">
                  {vuln.cvss?.score.toFixed(1) ?? '—'}
                </span>
              </Meta>
              <Meta label="CWE">
                <span className="font-mono text-fg">{vuln.cwe.join(', ') || '—'}</span>
              </Meta>
              <Meta label="Ativos">
                <span className="font-mono text-fg">{vuln.targets.length}</span>
              </Meta>
              <Meta label="Atualizado">
                <span className="text-fg-muted">{fmtRelative(vuln.updatedAt)}</span>
              </Meta>
            </div>
            {vuln.cvss?.vector && (
              <div className="text-2xs font-mono text-fg-dim border-t border-border pt-3">
                {vuln.cvss.vector}
              </div>
            )}
          </CardBody>
        </Card>

        <ContentSection title="Descrição" html={vuln.description} />
        <ContentSection title="Cenário de ataque" html={vuln.attackScenario} />
        <ContentSection title="Recomendação" html={vuln.recommendation} />

        {/* Targets */}
        <Card>
          <CardHeader>
            <CardTitle>Ativos afetados</CardTitle>
          </CardHeader>
          <CardBody>
            <ul className="space-y-1">
              {vuln.targets.map((t) => (
                <li
                  key={t}
                  className="font-mono text-sm text-fg-muted flex items-center gap-2"
                >
                  <span className="text-fg-dim">▸</span>
                  {t}
                </li>
              ))}
            </ul>
          </CardBody>
        </Card>

        {/* Steps */}
        {vuln.steps.length > 0 && (
          <Card>
            <CardHeader>
              <CardTitle>Passos de reprodução</CardTitle>
            </CardHeader>
            <CardBody className="space-y-3">
              {vuln.steps.map((s) => (
                <div key={s.id} className="flex gap-3">
                  <div className="shrink-0 w-7 h-7 rounded font-mono text-xs flex items-center justify-center bg-surface-3 text-fg-muted border border-border">
                    {s.order}
                  </div>
                  <div className="flex-1 space-y-1.5 min-w-0">
                    <p className="text-sm text-fg leading-snug">{s.text}</p>
                    {s.command && (
                      <pre className="text-xs font-mono bg-bg border border-border rounded p-2.5 overflow-x-auto text-fg">
                        {s.command}
                      </pre>
                    )}
                  </div>
                </div>
              ))}
            </CardBody>
          </Card>
        )}

        {/* POCs */}
        {vuln.pocs.length > 0 && (
          <Card>
            <CardHeader>
              <CardTitle>Proof of concept</CardTitle>
            </CardHeader>
            <CardBody className="space-y-4">
              {vuln.pocs.map((p) => (
                <div key={p.id} className="space-y-2">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium text-fg">{p.title}</span>
                    {p.code?.lang && <Badge mono>{p.code.lang.toUpperCase()}</Badge>}
                  </div>
                  {p.description && (
                    <p className="text-sm text-fg-muted">{p.description}</p>
                  )}
                  {p.code?.content && (
                    <pre className="text-xs font-mono bg-bg border border-border rounded p-3 overflow-x-auto text-fg whitespace-pre">
                      {p.code.content}
                    </pre>
                  )}
                </div>
              ))}
            </CardBody>
          </Card>
        )}

        {(vuln.remediationNotes || vuln.additionalNotes) && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {vuln.remediationNotes && (
              <ContentSection title="Notas de remediação" html={vuln.remediationNotes} />
            )}
            {vuln.additionalNotes && (
              <ContentSection title="Notas adicionais" html={vuln.additionalNotes} />
            )}
          </div>
        )}
      </div>
    </OperatorShell>
  );
}

function Meta({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="text-2xs uppercase tracking-wider text-fg-dim">{label}</div>
      <div className="mt-0.5">{children}</div>
    </div>
  );
}

function ContentSection({ title, html }: { title: string; html: string }) {
  if (!html || html.trim() === '<p></p>') return null;
  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
      </CardHeader>
      <CardBody>
        <div
          className="text-sm text-fg-muted leading-relaxed prose-styles"
          dangerouslySetInnerHTML={{ __html: html }}
        />
      </CardBody>
    </Card>
  );
}
