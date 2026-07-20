import { decideWithOpenAiCompatible } from './openai-compatible.mjs';

export function decideWithOpenRouter(opts = {}) {
  const env = opts.env || process.env;
  const referer = String(env.GHOSTRECON_OPENROUTER_HTTP_REFERER || '').trim();
  const title = String(env.GHOSTRECON_OPENROUTER_APP_TITLE || 'GHOSTRECON Auto Mode').trim();
  return decideWithOpenAiCompatible({
    ...opts,
    provider: 'openrouter',
    baseUrl: env.GHOSTRECON_OPENROUTER_BASE_URL || 'https://openrouter.ai/api/v1',
    apiKey: env.OPENROUTER_API_KEY || '',
    model: opts.model || env.GHOSTRECON_OPENROUTER_AUTO_MODEL || env.GHOSTRECON_OPENROUTER_MODEL || 'openrouter/auto',
    timeoutMs: Number(env.GHOSTRECON_AUTO_AGENT_TIMEOUT_MS || 180_000),
    extraHeaders: {
      ...(referer ? { 'HTTP-Referer': referer } : {}),
      ...(title ? { 'X-OpenRouter-Title': title } : {}),
    },
  });
}
