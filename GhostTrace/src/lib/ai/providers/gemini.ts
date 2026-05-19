import type { AIAdapter, AdapterCredentials, EnhanceFieldInput } from '../adapter';
import type { Project, Vulnerability } from '@/lib/types';
import {
  SYSTEM_OFFENSIVE,
  buildEnhanceUserPrompt,
  buildExecutiveSummaryPrompt
} from '../prompts';
import { postJson } from './http';

type GeminiResponse = {
  candidates?: { content?: { parts?: { text?: string }[] } }[];
};

export function createGeminiAdapter(creds: AdapterCredentials): AIAdapter {
  const model = creds.model ?? 'gemini-2.0-flash';
  const apiKey = creds.apiKey!;

  async function complete(user: string): Promise<string> {
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent?key=${encodeURIComponent(apiKey)}`;
    const data = await postJson<GeminiResponse>(url, {}, {
      systemInstruction: { parts: [{ text: SYSTEM_OFFENSIVE }] },
      contents: [{ role: 'user', parts: [{ text: user }] }],
      generationConfig: { temperature: 0.3, maxOutputTokens: 2048 }
    });
    return data.candidates?.[0]?.content?.parts?.[0]?.text?.trim() ?? '';
  }

  return {
    id: 'gemini',
    enhanceField: (opts: EnhanceFieldInput) =>
      complete(buildEnhanceUserPrompt(opts.field, opts.input, opts.vuln)),
    generateExecutiveSummary: (project: Project, vulns: Vulnerability[]) =>
      complete(buildExecutiveSummaryPrompt(project, vulns.map((v) => v.title))),
    classifySeverity: async (input: string) => {
      const raw = await complete(
        `Classifique a severidade. JSON apenas: {"severity":"critical|high|medium|low|info","rationale":"..."}\n\n${input}`
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
