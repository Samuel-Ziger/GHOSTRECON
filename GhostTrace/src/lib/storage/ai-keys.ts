import type { AIProviderConfig, AIProviderId } from '@/lib/types';

const STORAGE_KEY = 'ghosttrace:ai-keys';

type StoredKeys = Partial<
  Record<AIProviderId, { apiKey?: string; model?: string; enabled?: boolean }>
>;

export function loadAIKeysFromStorage(): StoredKeys {
  if (typeof window === 'undefined') return {};
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? (JSON.parse(raw) as StoredKeys) : {};
  } catch {
    return {};
  }
}

export function saveAIKeysToStorage(providers: AIProviderConfig[]): void {
  if (typeof window === 'undefined') return;
  const payload: StoredKeys = {};
  for (const p of providers) {
    payload[p.id] = {
      apiKey: p.apiKey,
      model: p.model,
      enabled: p.enabled
    };
  }
  localStorage.setItem(STORAGE_KEY, JSON.stringify(payload));
}

export function mergeProvidersWithStored(
  defaults: AIProviderConfig[]
): AIProviderConfig[] {
  const stored = loadAIKeysFromStorage();
  return defaults.map((p) => {
    const s = stored[p.id];
    if (!s) return p;
    return {
      ...p,
      apiKey: s.apiKey ?? p.apiKey,
      model: s.model ?? p.model,
      enabled: s.enabled ?? p.enabled
    };
  });
}
