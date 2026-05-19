import { NextResponse } from 'next/server';
import { createAIAdapter } from '@/lib/ai';
import type { AIProviderId, EnhanceableField, Vulnerability } from '@/lib/types';

export const runtime = 'nodejs';

type Body = {
  projectId: string;
  providerId: AIProviderId | 'none';
  apiKey?: string;
  model?: string;
  fields: EnhanceableField[];
  executiveSummary: boolean;
  project: import('@/lib/types').Project;
  vulnerabilities: Vulnerability[];
};

export async function POST(req: Request) {
  try {
    const body = (await req.json()) as Body;
    const { project, vulnerabilities, fields, executiveSummary, providerId } = body;

    if (!project || !vulnerabilities) {
      return NextResponse.json({ error: 'project e vulnerabilities são obrigatórios' }, { status: 400 });
    }

    let enhanced = 0;
    const updated: Vulnerability[] = [];

    if (providerId !== 'none' && body.apiKey?.trim() && fields.length > 0) {
      const adapter = createAIAdapter({
        id: providerId,
        apiKey: body.apiKey,
        model: body.model
      });

      for (const vuln of vulnerabilities) {
        const patch: Partial<Vulnerability> = {};
        for (const field of fields) {
          const current = vuln[field];
          if (typeof current !== 'string') continue;
          try {
            patch[field] = await adapter.enhanceField({
              field,
              input: current,
              vuln: {
                title: vuln.title,
                severity: vuln.severity,
                cwe: vuln.cwe,
                tags: vuln.tags,
                targets: vuln.targets
              }
            });
            enhanced += 1;
          } catch {
            /* mantém original se um campo falhar */
          }
        }
        updated.push(
          Object.keys(patch).length
            ? { ...vuln, ...patch, updatedAt: new Date().toISOString() }
            : vuln
        );
      }
    } else {
      updated.push(...vulnerabilities);
    }

    let execSummary: string | undefined;
    if (executiveSummary && providerId !== 'none' && body.apiKey?.trim()) {
      const adapter = createAIAdapter({
        id: providerId,
        apiKey: body.apiKey,
        model: body.model
      });
      execSummary = await adapter.generateExecutiveSummary(project, updated);
    }

    return NextResponse.json({
      enhanced,
      executiveSummary: execSummary,
      vulnerabilities: updated,
      conclusion: execSummary
        ? {
            priorityActions: ['Revisar findings críticos e altos listados no sumário executivo.'],
            midTermActions: ['Executar reteste após remediação conforme plano de ação.']
          }
        : undefined
    });
  } catch (e) {
    const message = e instanceof Error ? e.message : 'Erro interno';
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
