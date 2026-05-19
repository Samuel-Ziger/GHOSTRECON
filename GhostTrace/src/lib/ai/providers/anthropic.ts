import type { AIAdapter, AdapterCredentials, EnhanceFieldInput } from '../adapter';
import type { Project, Vulnerability } from '@/lib/types';
import {
  SYSTEM_OFFENSIVE,
  buildEnhanceUserPrompt,
  buildExecutiveSummaryPrompt
} from '../prompts';
import { postJson } from './http';

type MessagesResponse = {
  content: { type: string; text?: string }[];
};

export function createAnthropicAdapter(creds: AdapterCredentials): AIAdapter {
  const model = creds.model ?? 'claude-sonnet-4-20250514';
  const apiKey = creds.apiKey!;

  async function complete(user: string, maxTokens = 2048): Promise<string> {
    const data = await postJson<MessagesResponse>(
      'https://api.anthropic.com/v1/messages',
      {
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01'
      },
      {
        model,
        max_tokens: maxTokens,
        system: SYSTEM_OFFENSIVE,
        messages: [{ role: 'user', content: user }]
      }
    );
    const block = data.content.find((c) => c.type === 'text');
    return block?.text?.trim() ?? '';
  }

  return {
    id: 'anthropic',
    enhanceField: (opts: EnhanceFieldInput) =>
      complete(buildEnhanceUserPrompt(opts.field, opts.input, opts.vuln)),
    generateExecutiveSummary: (project: Project, vulns: Vulnerability[]) =>
      complete(buildExecutiveSummaryPrompt(project, vulns.map((v) => v.title)), 1500),
    classifySeverity: async (input: string) => {
      const raw = await complete(
        `Classifique a severidade do finding abaixo. Responda APENAS JSON: {"severity":"critical|high|medium|low|info","rationale":"..."}\n\n${input}`,
        256
      );
      try {
        const parsed = JSON.parse(raw.replace(/```json?\s*|\s*```/g, '')) as {
          severity: string;
          rationale: string;
        };
        return {
          severity: parsed.severity as EnhanceFieldInput['vuln']['severity'],
          rationale: parsed.rationale
        };
      } catch {
        return { severity: 'medium', rationale: raw };
      }
    }
  };
}
