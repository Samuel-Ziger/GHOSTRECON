import type { AIProviderConfig } from '@/lib/types';

export const DEFAULT_AI_PROVIDERS: AIProviderConfig[] = [
  {
    id: 'anthropic',
    label: 'Anthropic Claude',
    enabled: false,
    model: 'claude-sonnet-4-20250514'
  },
  {
    id: 'gemini',
    label: 'Google Gemini',
    enabled: false,
    model: 'gemini-2.0-flash'
  },
  {
    id: 'openrouter',
    label: 'OpenRouter (multi-model)',
    enabled: false,
    model: 'anthropic/claude-3.5-sonnet'
  }
];
