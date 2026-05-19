import { nanoid } from 'nanoid';
import type { Project, Severity, TimelineEvent, Vulnerability } from '@/lib/types';
import { SEV_TEMPLATES } from './templates';
import { normalizeTarget, prioToSeverity } from './normalize';
import type { GhostreconFinding, GhostreconHandoffPayload } from './types';
import { normalizeHandoffPayload } from './normalize';

function cvssToScore(vector: string): number | undefined {
  const known: Record<string, number> = {
    'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N': 9.6,
    'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N': 8.8,
    'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N': 6.5,
    'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N': 6.5,
    'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N': 6.5
  };
  return known[String(vector || '')];
}

export function findingToVulnerability(
  f: GhostreconFinding,
  projectId: string,
  opts?: { forceValidated?: boolean }
): Vulnerability {
  const type = String(f.type || '');
  const tpl = SEV_TEMPLATES[type] || {};
  const severity: Severity = prioToSeverity(f.prio || f.priority);
  const cvssVector = f.cvss || tpl.cvss || '';
  const cvssScore = cvssVector ? cvssToScore(cvssVector) : undefined;
  const tags = tpl.tags
    ? tpl.tags.split(',').map((t) => t.trim())
    : [f.owasp, f.mitre].filter(Boolean).map(String);
  const ts = new Date().toISOString();
  const fp = String(f.fingerprint || '').toLowerCase();

  return {
    id: `vuln_${nanoid(8)}`,
    projectId,
    title: tpl.title || String(f.value || '').trim() || type || 'Achado GHOSTRECON',
    severity,
    status: 'unfixed',
    cvss: cvssVector
      ? { vector: cvssVector, score: cvssScore ?? (severity === 'critical' ? 9 : 6) }
      : undefined,
    cwe: [],
    tags,
    targets: f.url ? [String(f.url)] : [],
    description: tpl.desc || String(f.meta || ''),
    attackScenario: tpl.scenario || '',
    recommendation: tpl.rec || '',
    additionalNotes: opts?.forceValidated ? 'Importado do Reporte GHOSTRECON (validado).' : '',
    steps: [],
    pocs: f.url
      ? [
          {
            id: `poc_${nanoid(6)}`,
            title: 'URL / contexto',
            description: String(f.url),
            screenshots: []
          }
        ]
      : [],
    ghostreconFingerprint: fp || undefined,
    createdAt: ts,
    updatedAt: ts
  };
}

export async function buildImportBundle(pack: GhostreconHandoffPayload): Promise<{
  target: string;
  findings: GhostreconFinding[];
  validatedFingerprints: string[];
  projectInput: Partial<Project> &
    Pick<Project, 'client' | 'methodology' | 'scope' | 'engagementType' | 'startDate'>;
  vulnerabilities: Vulnerability[];
  timeline: TimelineEvent[];
}> {
  const { target, findings, validatedFingerprints } = await normalizeHandoffPayload(pack);
  const validated = new Set(validatedFingerprints);
  const ts = new Date().toISOString();
  const today = ts.slice(0, 10);

  const projectInput = {
    client: target || 'Alvo GHOSTRECON',
    codename: normalizeTarget(target) || undefined,
    engagementType: 'bug_bounty' as const,
    scope: target ? [target] : [],
    methodology: 'blackbox' as const,
    startDate: today,
    status: 'active' as const,
    notes: `Projeto importado do GHOSTRECON em ${ts}. ${findings.length} achados no pacote.`,
    ghostrecon: target
      ? { target, importedAt: ts, findingsCount: findings.length }
      : undefined
  };

  const draftProjectId = `_draft_${nanoid(6)}`;
  const vulnerabilities: Vulnerability[] = [];
  const timeline: TimelineEvent[] = [];

  for (const f of findings) {
    const fp = String(f.fingerprint || '').toLowerCase();
    if (!validated.has(fp)) continue;
    const vuln = findingToVulnerability(f, draftProjectId, { forceValidated: true });
    vulnerabilities.push(vuln);
    timeline.push({
      id: `evt_${nanoid(8)}`,
      projectId: draftProjectId,
      ts,
      type: 'recon',
      host: target || undefined,
      title: `Validado: ${vuln.title.slice(0, 80)}`,
      details: [f.type, f.value, f.url].filter(Boolean).join(' · '),
      vulnerabilityId: vuln.id
    });
  }

  return {
    target,
    findings,
    validatedFingerprints,
    projectInput,
    vulnerabilities,
    timeline
  };
}
