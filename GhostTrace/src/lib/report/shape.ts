import type {
  AttackChainNode,
  Credential,
  EnhanceableField,
  Project,
  ReportShape,
  TimelineEvent,
  Vulnerability,
  AIProviderId
} from '@/lib/types';
import { computeSummary } from '@/lib/mock/store';

export interface BuildReportOptions {
  project: Project;
  vulnerabilities: Vulnerability[];
  timeline: TimelineEvent[];
  attackChain: AttackChainNode[];
  credentials: Credential[];
  generator?: { provider: AIProviderId | 'none'; model?: string };
  conclusion?: ReportShape['conclusion'];
}

/** Monta o JSON canônico consumido pelo preview HTML e futuro renderizador DOCX. */
export function buildReportShape(opts: BuildReportOptions): ReportShape {
  const summary = computeSummary(opts.vulnerabilities);
  return {
    project: opts.project,
    generatedAt: new Date().toISOString(),
    generator: opts.generator ?? { provider: 'none' },
    summary,
    vulnerabilities: opts.vulnerabilities,
    timeline: opts.timeline,
    attackChain: opts.attackChain,
    credentials: opts.credentials,
    conclusion: opts.conclusion
  };
}

export function applyFieldEnhancements(
  vulns: Vulnerability[],
  updates: { id: string; fields: Partial<Pick<Vulnerability, EnhanceableField>> }[]
): Vulnerability[] {
  const map = new Map(updates.map((u) => [u.id, u.fields]));
  return vulns.map((v) => {
    const patch = map.get(v.id);
    return patch ? { ...v, ...patch, updatedAt: new Date().toISOString() } : v;
  });
}

/** Exporta o shape como JSON para download (substituto do DOCX até o backend). */
export function downloadReportJson(shape: ReportShape, filename?: string): void {
  const blob = new Blob([JSON.stringify(shape, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download =
    filename ??
    `ghosttrace-${shape.project.codename ?? shape.project.client}-${shape.generatedAt.slice(0, 10)}.json`;
  a.click();
  URL.revokeObjectURL(url);
}
