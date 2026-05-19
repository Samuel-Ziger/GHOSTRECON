import type { AIAdapter, AdapterCredentials, EnhanceFieldInput } from '../adapter';
import type { Project, Vulnerability } from '@/lib/types';
import {
  SYSTEM_OFFENSIVE,
  buildEnhanceUserPrompt,
  buildExecutiveSummaryPrompt
} from '../prompts';
import { postJson } from './http';

type ChatResponse = {
  choices?: { message?: { content?: string } }[];
};

export function createOpenRouterAdapter(creds: AdapterCredentials): AIAdapter {
  const model = creds.model ?? 'anthropic/claude-3.5-sonnet';
  const apiKey = creds.apiKey!;

  async function complete(user: string, maxTokens = 2048): Promise<string> {
    const data = await postJson<ChatResponse>(
      'https://openrouter.ai/api/v1/chat/completions',
      {
        Authorization: `Bearer ${apiKey}`,
        'HTTP-Referer': 'https://ghosttrace.local',
        'X-Title': 'GhostTrace'
      },
      {
        model,
        max_tokens: maxTokens,
        temperature: 0.3,
        messages: [
          { role: 'system', content: SYSTEM_OFFENSIVE },
          { role: 'user', content: user }
        ]
      }
    );
    return data.choices?.[0]?.message?.content?.trim() ?? '';
  }

  return {
    id: 'openrouter',
    enhanceField: (opts: EnhanceFieldInput) =>
      complete(buildEnhanceUserPrompt(opts.field, opts.input, opts.vuln)),
    generateExecutiveSummary: (project: Project, vulns: Vulnerability[]) =>
      complete(buildExecutiveSummaryPrompt(project, vulns.map((v) => v.title)), 1500),
    classifySeverity: async (input: string) => {
      const raw = await complete(
        `Classifique a severidade. JSON apenas: {"severity":"critical|high|medium|low|info","rationale":"..."}\n\n${input}`,
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
