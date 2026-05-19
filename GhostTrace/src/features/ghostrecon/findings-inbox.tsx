'use client';

import { useMemo } from 'react';
import { useRouter } from 'next/navigation';
import { Check, Plus, ShieldAlert } from 'lucide-react';
import { SeverityBadge } from '@/components/ui/severity-badge';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils/cn';
import { useGhostreconSession, useStore } from '@/lib/mock/store';
import { prioToSeverity } from '@/lib/ghostrecon/normalize';
import type { GhostreconFinding } from '@/lib/ghostrecon/types';

interface Props {
  projectId: string;
  className?: string;
}

export function FindingsInbox({ projectId, className }: Props) {
  const router = useRouter();
  const session = useGhostreconSession(projectId);
  const importFinding = useStore((s) => s.importFindingAsVuln);
  const vulns = useStore((s) => s.vulnerabilities.filter((v) => v.projectId === projectId));

  const linked = useMemo(() => {
    const m = new Set<string>();
    for (const v of vulns) {
      if (v.ghostreconFingerprint) m.add(v.ghostreconFingerprint.toLowerCase());
    }
    return m;
  }, [vulns]);

  if (!session?.findings?.length) return null;

  const validated = new Set(session.validatedFingerprints.map((x) => x.toLowerCase()));

  function onAdd(f: GhostreconFinding, force?: boolean) {
    const fp = String(f.fingerprint || '').toLowerCase();
    if (linked.has(fp)) {
      const vid =
        session?.linkedVulnIds[fp] || vulns.find((v) => v.ghostreconFingerprint === fp)?.id;
      if (vid) router.push(`/projects/${projectId}/vulnerabilities/${vid}`);
      return;
    }
    if (!validated.has(fp) && !force) {
      if (!window.confirm('Achado ainda não validado no Reporte. Documentar mesmo assim?')) return;
    }
    const v = importFinding(projectId, f, { allowUnvalidated: force || !validated.has(fp) });
    if (v) router.push(`/projects/${projectId}/vulnerabilities/${v.id}`);
  }

  return (
    <aside
      className={cn(
        'w-[272px] shrink-0 border-r border-border bg-surface flex flex-col max-h-[calc(100vh-7rem)]',
        className
      )}
    >
      <div className="px-3 py-2.5 border-b border-border">
        <p className="font-mono text-2xs uppercase tracking-wider text-fg-dim">GHOSTRECON</p>
        <p className="font-mono text-xs text-accent truncate mt-0.5" title={session.target}>
          {session.target || 'sem alvo'}
        </p>
        <p className="text-2xs text-fg-muted mt-1">
          {session.findings.length} achados · {validated.size} validados
        </p>
      </div>
      <ul className="flex-1 overflow-y-auto py-1">
        {session.findings.map((f, i) => (
          <FindingRow
            key={f.fingerprint || i}
            finding={f}
            isValidated={validated.has(String(f.fingerprint || '').toLowerCase())}
            inReport={linked.has(String(f.fingerprint || '').toLowerCase())}
            onAdd={(force) => onAdd(f, force)}
          />
        ))}
      </ul>
    </aside>
  );
}

function FindingRow({
  finding,
  isValidated,
  inReport,
  onAdd
}: {
  finding: GhostreconFinding;
  isValidated: boolean;
  inReport: boolean;
  onAdd: (force?: boolean) => void;
}) {
  const sev = prioToSeverity(finding.prio || finding.priority);
  return (
    <li
      className={cn(
        'group flex gap-2 px-3 py-2 border-b border-border/60 cursor-pointer transition-colors',
        isValidated && 'border-l-2 border-l-accent',
        inReport && 'bg-accent-soft/30'
      )}
      onClick={() => onAdd()}
    >
      <SeverityBadge severity={sev} className="shrink-0 mt-0.5" />
      <div className="min-w-0 flex-1">
        <p className="font-mono text-2xs uppercase text-fg-dim truncate">{finding.type}</p>
        <p className="text-xs text-fg leading-snug line-clamp-2">{finding.value}</p>
      </div>
      <span className="shrink-0 text-fg-dim self-center">
        {inReport ? (
          <Check size={14} className="text-accent" />
        ) : isValidated ? (
          <ShieldAlert size={14} className="text-sev-medium" />
        ) : (
          <Button
            variant="ghost"
            size="sm"
            className="opacity-0 group-hover:opacity-100 h-6 w-6 p-0"
            onClick={(e) => {
              e.stopPropagation();
              onAdd(true);
            }}
            title="Adicionar ao relatório"
          >
            <Plus size={12} />
          </Button>
        )}
      </span>
    </li>
  );
}
