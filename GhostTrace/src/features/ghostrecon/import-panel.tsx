'use client';

import { useCallback, useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { ArrowRight, Loader2, Radar } from 'lucide-react';
import { OperatorShell } from '@/components/layout/operator-shell';
import { Button } from '@/components/ui/button';
import { Card, CardBody, CardHeader, CardTitle } from '@/components/ui/card';
import { loadGhostreconHandoff } from '@/lib/ghostrecon/handoff';
import { buildImportBundle } from '@/lib/ghostrecon/import';
import type { GhostreconHandoffPayload } from '@/lib/ghostrecon/types';
import { useStore } from '@/lib/mock/store';

export function GhostreconImportPanel() {
  const router = useRouter();
  const upsertProject = useStore((s) => s.upsertProject);
  const upsertVuln = useStore((s) => s.upsertVulnerability);
  const setSession = useStore((s) => s.setGhostreconSession);
  const addTimeline = useStore((s) => s.addTimelineEvent);

  const [pack, setPack] = useState<GhostreconHandoffPayload | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [preview, setPreview] = useState<{
    target: string;
    findings: number;
    validated: number;
  } | null>(null);
  const [importing, setImporting] = useState(false);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      setError('');
      try {
        const data = await loadGhostreconHandoff();
        if (cancelled) return;
        if (!data) {
          setPack(null);
          setPreview(null);
          return;
        }
        setPack(data);
        const bundle = await buildImportBundle(data);
        if (cancelled) return;
        setPreview({
          target: bundle.target,
          findings: bundle.findings.length,
          validated: bundle.validatedFingerprints.length
        });
      } catch (e) {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const runImport = useCallback(async () => {
    if (!pack) return;
    setImporting(true);
    setError('');
    try {
      const bundle = await buildImportBundle(pack);
      const { projectInput, vulnerabilities, timeline, findings, validatedFingerprints, target } =
        bundle;

      const project = upsertProject({
        client: projectInput.client,
        codename: projectInput.codename,
        engagementType: projectInput.engagementType,
        scope: projectInput.scope,
        methodology: projectInput.methodology,
        startDate: projectInput.startDate,
        status: 'active',
        notes: projectInput.notes,
        ghostrecon: projectInput.ghostrecon
      });

      const fpToVulnId: Record<string, string> = {};
      for (const v of vulnerabilities) {
        const fp = v.ghostreconFingerprint || '';
        const saved = upsertVuln({ ...v, projectId: project.id });
        if (fp) fpToVulnId[fp] = saved.id;
      }
      for (const evt of timeline) {
        const oldVid = evt.vulnerabilityId;
        const fp =
          vulnerabilities.find((x) => x.id === oldVid)?.ghostreconFingerprint || '';
        addTimeline({
          ...evt,
          projectId: project.id,
          vulnerabilityId: fp ? fpToVulnId[fp] : undefined
        });
      }

      setSession(project.id, {
        target,
        importedAt: new Date().toISOString(),
        findings,
        validatedFingerprints,
        linkedVulnIds: fpToVulnId
      });

      router.push(`/projects/${project.id}/vulnerabilities`);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setImporting(false);
    }
  }, [pack, upsertProject, upsertVuln, setSession, addTimeline, router]);

  return (
    <OperatorShell
      title="Importar do GHOSTRECON"
      subtitle="Pacote do Reporte · validações manuais · achados do recon"
      breadcrumbs={[
        { label: 'Projetos', href: '/projects' },
        { label: 'Importar GHOSTRECON' }
      ]}
    >
      <div className="px-6 py-8 max-w-2xl mx-auto">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Radar size={18} className="text-accent" />
              GhostTrace · área de anotação
            </CardTitle>
          </CardHeader>
          <CardBody className="space-y-4">
            {loading && (
              <p className="flex items-center gap-2 text-sm text-fg-muted">
                <Loader2 size={16} className="animate-spin" /> A carregar pacote…
              </p>
            )}
            {!loading && !pack && (
              <div className="space-y-3 text-sm text-fg-muted">
                <p>Nenhum pacote na sessão.</p>
                <ol className="list-decimal list-inside space-y-1 text-fg-dim">
                  <li>Corre recon no GHOSTRECON e abre o Reporte.</li>
                  <li>Valida achados na checklist.</li>
                  <li>
                    Clica <strong className="text-fg">ANOTAÇÃO</strong> — abre esta área com os dados.
                  </li>
                </ol>
                <Button variant="secondary" onClick={() => router.push('/projects')}>
                  Ver projetos existentes
                </Button>
              </div>
            )}
            {!loading && pack && preview && (
              <div className="space-y-4">
                <dl className="grid grid-cols-2 gap-3 font-mono text-sm">
                  <div>
                    <dt className="text-2xs uppercase text-fg-dim">Alvo</dt>
                    <dd className="text-accent">{preview.target || '—'}</dd>
                  </div>
                  <div>
                    <dt className="text-2xs uppercase text-fg-dim">Achados</dt>
                    <dd>{preview.findings}</dd>
                  </div>
                  <div>
                    <dt className="text-2xs uppercase text-fg-dim">Validados no Reporte</dt>
                    <dd>{preview.validated}</dd>
                  </div>
                </dl>
                <p className="text-xs text-fg-muted">
                  Será criado um projeto GhostTrace com vulnerabilidades para cada achado validado.
                  Os restantes ficam na bandeja «Achados GHOSTRECON» para documentar com o editor
                  TipTap, timeline e relatório DOCX.
                </p>
                <Button variant="primary" disabled={importing} onClick={() => void runImport()}>
                  {importing ? (
                    <>
                      <Loader2 size={14} className="animate-spin" /> A importar…
                    </>
                  ) : (
                    <>
                      Criar projeto e abrir workspace <ArrowRight size={14} />
                    </>
                  )}
                </Button>
              </div>
            )}
            {error && <p className="text-sm text-sev-critical">{error}</p>}
          </CardBody>
        </Card>
      </div>
    </OperatorShell>
  );
}
