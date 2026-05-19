import { NextResponse } from 'next/server';
import { createAIAdapter } from '@/lib/ai';
import type { AIProviderId, EnhanceableField } from '@/lib/types';

export const runtime = 'nodejs';

type Body = {
  providerId: AIProviderId;
  apiKey: string;
  model?: string;
  field: EnhanceableField;
  input: string;
  vuln: {
    title: string;
    severity: string;
    cwe: string[];
    tags: string[];
    targets: string[];
  };
};

export async function POST(req: Request) {
  try {
    const body = (await req.json()) as Body;
    if (!body.providerId || !body.apiKey?.trim()) {
      return NextResponse.json({ error: 'providerId e apiKey são obrigatórios' }, { status: 400 });
    }
    const adapter = createAIAdapter({
      id: body.providerId,
      apiKey: body.apiKey,
      model: body.model
    });
    const result = await adapter.enhanceField({
      field: body.field,
      input: body.input,
      vuln: body.vuln as Body['vuln'] & { severity: import('@/lib/types').Severity }
    });
    return NextResponse.json({ result });
  } catch (e) {
    const message = e instanceof Error ? e.message : 'Erro interno';
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
