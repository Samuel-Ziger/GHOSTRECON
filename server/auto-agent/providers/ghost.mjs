import { decideWithOpenAiCompatible } from './openai-compatible.mjs';

export function decideWithGhost(opts = {}) {
  const env = opts.env || process.env;
  const root = String(env.GHOSTRECON_SKYNET_URL || env.GHOSTRECON_GHOST_BASE_URL || 'http://127.0.0.1:8000').replace(/\/+$/, '');
  return decideWithOpenAiCompatible({
    ...opts,
    provider: 'skynet',
    baseUrl: `${root}/v1`,
    model: opts.model || env.GHOSTRECON_GHOST_MODEL || 'ghost',
    apiKey: env.GHOSTRECON_GHOST_API_KEY || '',
    timeoutMs: Number(env.GHOSTRECON_AUTO_AGENT_TIMEOUT_MS || 180_000),
  });
}
