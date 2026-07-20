import { decideWithOpenAiCompatible } from './openai-compatible.mjs';

export function decideWithLocalModel(opts = {}) {
  const env = opts.env || process.env;
  const configured = String(env.GHOSTRECON_LMSTUDIO_BASE_URL || '').replace(/\/+$/, '');
  const ollama = String(env.OLLAMA_HOST || env.GHOSTRECON_OLLAMA_URL || 'http://127.0.0.1:11434').replace(/\/+$/, '');
  const baseUrl = configured || `${ollama}/v1`;
  return decideWithOpenAiCompatible({
    ...opts,
    provider: 'local_model',
    baseUrl,
    apiKey: env.GHOSTRECON_LOCAL_MODEL_API_KEY || '',
    model: opts.model || env.GHOSTRECON_LOCAL_MODEL || env.GHOSTRECON_LMSTUDIO_MODEL || 'local-model',
    timeoutMs: Number(env.GHOSTRECON_AUTO_AGENT_TIMEOUT_MS || 180_000),
    maxContextChars: Math.min(Number(opts.maxContextChars || 120_000), Number(env.GHOSTRECON_LOCAL_MAX_CONTEXT_CHARS || 48_000)),
  });
}
