import type { AIProviderId } from '@/lib/types';
import type { AIAdapter, AdapterCredentials, EnhanceFieldInput } from './adapter';
import { createAnthropicAdapter } from './providers/anthropic';
import { createGeminiAdapter } from './providers/gemini';
import { createOpenRouterAdapter } from './providers/openrouter';

export type { AIAdapter, EnhanceFieldInput, ClassifyResult } from './adapter';

export function createAIAdapter(creds: AdapterCredentials): AIAdapter {
  if (!creds.apiKey?.trim()) {
    throw new Error('API key ausente para o provider selecionado.');
  }
  switch (creds.id) {
    case 'anthropic':
      return createAnthropicAdapter(creds);
    case 'gemini':
      return createGeminiAdapter(creds);
    case 'openrouter':
      return createOpenRouterAdapter(creds);
    default:
      throw new Error(`Provider desconhecido: ${creds.id as AIProviderId}`);
  }
}

export async function enhanceFieldViaApi(body: {
  providerId: AIProviderId;
  apiKey: string;
  model?: string;
  field: EnhanceFieldInput['field'];
  input: string;
  vuln: EnhanceFieldInput['vuln'];
}): Promise<string> {
  const res = await fetch('/api/ai/enhance', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  const data = (await res.json()) as { result?: string; error?: string };
  if (!res.ok) throw new Error(data.error ?? 'Falha ao aprimorar campo');
  return data.result ?? '';
}

export async function generateReportViaApi(body: {
  projectId: string;
  providerId: AIProviderId | 'none';
  apiKey?: string;
  model?: string;
  fields: EnhanceFieldInput['field'][];
  executiveSummary: boolean;
  project: import('@/lib/types').Project;
  vulnerabilities: import('@/lib/types').Vulnerability[];
}): Promise<{
  enhanced: number;
  executiveSummary?: string;
  conclusion?: import('@/lib/types').ReportShape['conclusion'];
  vulnerabilities: import('@/lib/types').Vulnerability[];
}> {
  const res = await fetch('/api/ai/report', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  const data = (await res.json()) as {
    enhanced?: number;
    executiveSummary?: string;
    conclusion?: import('@/lib/types').ReportShape['conclusion'];
    vulnerabilities?: import('@/lib/types').Vulnerability[];
    error?: string;
  };
  if (!res.ok) throw new Error(data.error ?? 'Falha ao gerar relatório');
  return {
    enhanced: data.enhanced ?? 0,
    executiveSummary: data.executiveSummary,
    conclusion: data.conclusion,
    vulnerabilities: data.vulnerabilities ?? []
  };
}
