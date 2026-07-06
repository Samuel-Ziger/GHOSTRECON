import { execFile as execFileCb } from 'node:child_process';
import { promisify } from 'node:util';

const execFileDefault = promisify(execFileCb);

export const OPENROUTER_AUTO_MODELS = Object.freeze([
  'anthropic/claude-3.7-sonnet',
  'openai/gpt-4.1',
  'google/gemini-2.5-pro',
  'x-ai/grok-4',
  'deepseek/deepseek-r1',
  'z-ai/glm-4.5',
  'qwen/qwen3-coder',
  'meta-llama/llama-4-maverick',
]);

function envFlag(env, key) {
  return /^(1|true|yes|on)$/i.test(String(env?.[key] || '').trim());
}

function isWindows(platform = process.platform) {
  return /^win/i.test(String(platform || ''));
}

async function commandAvailable(command, { execFileImpl = execFileDefault, platform = process.platform } = {}) {
  const bin = isWindows(platform) ? 'where' : 'which';
  try {
    await execFileImpl(bin, [command], { timeout: 2500, windowsHide: true });
    return true;
  } catch {
    return false;
  }
}

async function httpReachable(url, { fetchImpl = globalThis.fetch, timeoutMs = 2500 } = {}) {
  if (typeof fetchImpl !== 'function' || !url) return false;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetchImpl(url, { method: 'GET', signal: controller.signal, headers: { accept: 'application/json' } });
    return Boolean(res?.ok || (res?.status >= 200 && res?.status < 500));
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}

function provider(id, fields = {}) {
  return {
    id,
    selected: false,
    installed: false,
    configured: false,
    reachable: false,
    roleHint: 'unavailable',
    ...fields,
  };
}

export function normalizeCommanderSelection(input) {
  const raw = Array.isArray(input) ? input : String(input || '').split(',');
  return [...new Set(raw.map((x) => String(x).trim().toLowerCase()).filter(Boolean))];
}

export async function detectAutoProviders({
  selected = [],
  env = process.env,
  fetchImpl = globalThis.fetch,
  execFileImpl = execFileDefault,
  platform = process.platform,
} = {}) {
  const selectedSet = new Set(normalizeCommanderSelection(selected));
  const skynetUrl = String(env.GHOSTRECON_SKYNET_URL || env.GHOSTRECON_GHOST_BASE_URL || 'http://127.0.0.1:8000').replace(/\/+$/, '');
  const lmstudioUrl = String(env.GHOSTRECON_LMSTUDIO_BASE_URL || '').replace(/\/+$/, '');
  const ollamaUrl = String(env.OLLAMA_HOST || env.GHOSTRECON_OLLAMA_URL || 'http://127.0.0.1:11434').replace(/\/+$/, '');

  const [
    codexInstalled,
    claudeInstalled,
    cursorInstalled,
    cursorAgentInstalled,
    skynetReachable,
    lmstudioReachable,
    ollamaReachable,
  ] = await Promise.all([
    commandAvailable('codex', { execFileImpl, platform }),
    commandAvailable('claude', { execFileImpl, platform }),
    commandAvailable('cursor', { execFileImpl, platform }),
    commandAvailable('agent', { execFileImpl, platform }),
    httpReachable(`${skynetUrl}/health`, { fetchImpl }),
    lmstudioUrl ? httpReachable(`${lmstudioUrl}/models`, { fetchImpl }) : false,
    httpReachable(`${ollamaUrl}/api/tags`, { fetchImpl }),
  ]);

  const out = [
    provider('codex', {
      selected: selectedSet.has('codex'),
      installed: codexInstalled,
      configured: codexInstalled,
      reachable: codexInstalled,
      roleHint: 'module_forge_integrator',
      command: 'codex',
    }),
    provider('claude_code', {
      selected: selectedSet.has('claude') || selectedSet.has('claude_code'),
      installed: claudeInstalled,
      configured: claudeInstalled,
      reachable: claudeInstalled,
      roleHint: 'deep_planner_module_author',
      command: 'claude',
    }),
    provider('cursor', {
      selected: selectedSet.has('cursor'),
      installed: cursorInstalled,
      configured: cursorInstalled,
      reachable: cursorInstalled,
      roleHint: cursorAgentInstalled ? 'ide_agent_human_in_loop' : 'ide_human_in_loop',
      command: 'cursor',
      agentInstalled: cursorAgentInstalled,
    }),
    provider('skynet', {
      selected: selectedSet.has('skynet'),
      installed: true,
      configured: Boolean(skynetUrl),
      reachable: skynetReachable,
      roleHint: 'local_private_commander',
      baseUrl: skynetUrl,
    }),
    provider('local_model', {
      selected: selectedSet.has('local') || selectedSet.has('local_model') || selectedSet.has('glm'),
      installed: lmstudioReachable || ollamaReachable,
      configured: Boolean(lmstudioUrl || ollamaUrl),
      reachable: lmstudioReachable || ollamaReachable,
      roleHint: 'offline_fallback_planner',
      lmstudioUrl: lmstudioUrl || null,
      ollamaUrl,
    }),
    provider('openrouter', {
      selected: selectedSet.has('openrouter'),
      installed: true,
      configured: Boolean(String(env.OPENROUTER_API_KEY || '').trim()),
      reachable: Boolean(String(env.OPENROUTER_API_KEY || '').trim()),
      roleHint: 'cloud_planner_reviewer',
      defaultModel: env.GHOSTRECON_OPENROUTER_AUTO_MODEL || env.GHOSTRECON_OPENROUTER_MODEL || OPENROUTER_AUTO_MODELS[0],
      models: [...OPENROUTER_AUTO_MODELS],
    }),
  ];

  const selectedConfigured = out.filter((p) => p.selected && (p.configured || p.installed || envFlag(env, 'GHOSTRECON_AUTO_ALLOW_UNCONFIGURED')));
  const available = out.filter((p) => p.configured || p.installed || p.reachable);
  const commanders = selectedConfigured.length ? selectedConfigured : available.filter((p) => ['skynet', 'codex', 'openrouter', 'local_model'].includes(p.id)).slice(0, 2);

  return {
    ok: commanders.length > 0,
    selected: [...selectedSet],
    providers: out,
    commanders: commanders.map((p) => p.id),
  };
}
