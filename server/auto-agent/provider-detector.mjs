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

async function commandAvailable(command, {
  execFileImpl = execFileDefault,
  platform = process.platform,
  signal = null,
} = {}) {
  throwIfAborted(signal);
  const bin = isWindows(platform) ? 'where' : 'which';
  try {
    await execFileImpl(bin, [command], { timeout: 2500, windowsHide: true, signal });
    return true;
  } catch (error) {
    if (signal?.aborted) throw signal.reason || error;
    return false;
  }
}

async function commandSucceeds(command, args, {
  execFileImpl = execFileDefault,
  timeoutMs = 5000,
  signal = null,
} = {}) {
  throwIfAborted(signal);
  try {
    await execFileImpl(command, args, { timeout: timeoutMs, windowsHide: true, signal });
    return true;
  } catch (error) {
    if (signal?.aborted) throw signal.reason || error;
    return false;
  }
}

function throwIfAborted(signal) {
  if (signal?.aborted) {
    throw signal.reason || new Error('detecção de providers cancelada');
  }
}

function combineSignals(parentSignal, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new Error('provider_probe_timeout')), timeoutMs);
  const onParentAbort = () => {
    controller.abort(parentSignal?.reason || new Error('detecção de providers cancelada'));
  };
  if (parentSignal) {
    if (parentSignal.aborted) onParentAbort();
    else parentSignal.addEventListener('abort', onParentAbort, { once: true });
  }
  return {
    signal: controller.signal,
    cleanup() {
      clearTimeout(timer);
      parentSignal?.removeEventListener?.('abort', onParentAbort);
    },
  };
}

async function httpReachable(url, {
  fetchImpl = globalThis.fetch,
  timeoutMs = 2500,
  headers = {},
  signal = null,
} = {}) {
  if (typeof fetchImpl !== 'function' || !url) return false;
  throwIfAborted(signal);
  const probe = combineSignals(signal, timeoutMs);
  try {
    const res = await fetchImpl(url, {
      method: 'GET',
      signal: probe.signal,
      headers: { accept: 'application/json', ...headers },
    });
    return Boolean(res?.ok || (res?.status >= 200 && res?.status < 500));
  } catch (error) {
    if (signal?.aborted) throw signal.reason || error;
    return false;
  } finally {
    probe.cleanup();
  }
}

function provider(id, fields = {}) {
  const out = {
    id,
    selected: false,
    installed: false,
    configured: false,
    authenticated: false,
    reachable: false,
    roleHint: 'unavailable',
    dataPlane: 'local',
    ...fields,
  };
  out.usable = fields.usable ?? Boolean(out.selected && out.configured && out.authenticated && out.reachable);
  out.reason = out.usable ? null : fields.reason || (
    !out.selected ? 'not_selected'
      : !out.installed ? 'not_installed'
        : !out.configured ? 'not_configured'
          : !out.authenticated ? 'not_authenticated'
            : !out.reachable ? 'not_reachable'
              : 'not_usable'
  );
  return out;
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
  signal = null,
} = {}) {
  throwIfAborted(signal);
  const selectedSet = new Set(normalizeCommanderSelection(selected));
  const skynetUrl = String(env.GHOSTRECON_SKYNET_URL || env.GHOSTRECON_GHOST_BASE_URL || 'http://127.0.0.1:8000').replace(/\/+$/, '');
  const lmstudioUrl = String(env.GHOSTRECON_LMSTUDIO_BASE_URL || '').replace(/\/+$/, '');
  const ollamaUrl = String(env.OLLAMA_HOST || env.GHOSTRECON_OLLAMA_URL || 'http://127.0.0.1:11434').replace(/\/+$/, '');
  const openrouterKey = String(env.OPENROUTER_API_KEY || '').trim();
  const cursorExecEnabled = envFlag(env, 'GHOSTRECON_CURSOR_PROVIDER_EXEC');
  const probe = { fetchImpl, signal };

  const [
    codexInstalled,
    claudeInstalled,
    cursorInstalled,
    cursorAgentInstalled,
    skynetReachable,
    skynetModelsReachable,
    lmstudioReachable,
    ollamaReachable,
    openrouterReachable,
  ] = await Promise.all([
    commandAvailable('codex', { execFileImpl, platform, signal }),
    commandAvailable('claude', { execFileImpl, platform, signal }),
    commandAvailable('cursor', { execFileImpl, platform, signal }),
    commandAvailable('agent', { execFileImpl, platform, signal }),
    httpReachable(`${skynetUrl}/health`, probe),
    httpReachable(`${skynetUrl}/v1/models`, probe),
    lmstudioUrl ? httpReachable(`${lmstudioUrl}/models`, probe) : false,
    httpReachable(`${ollamaUrl}/api/tags`, probe),
    openrouterKey ? httpReachable('https://openrouter.ai/api/v1/models', {
      ...probe,
      headers: { Authorization: `Bearer ${openrouterKey}` },
    }) : false,
  ]);

  throwIfAborted(signal);
  const [codexAuthenticated, claudeAuthenticated, cursorAuthenticated] = await Promise.all([
    codexInstalled && selectedSet.has('codex')
      ? commandSucceeds('codex', ['login', 'status'], { execFileImpl, signal })
      : false,
    claudeInstalled && (selectedSet.has('claude') || selectedSet.has('claude_code'))
      ? commandSucceeds('claude', ['auth', 'status'], { execFileImpl, signal })
      : false,
    cursorAgentInstalled && selectedSet.has('cursor') && cursorExecEnabled
      ? commandSucceeds(String(env.GHOSTRECON_CURSOR_AGENT_COMMAND || 'agent'), ['status'], { execFileImpl, signal })
      : false,
  ]);

  const out = [
    provider('codex', {
      selected: selectedSet.has('codex'),
      installed: codexInstalled,
      configured: codexInstalled,
      authenticated: codexAuthenticated,
      reachable: codexAuthenticated,
      roleHint: 'module_forge_integrator',
      command: 'codex',
    }),
    provider('claude_code', {
      selected: selectedSet.has('claude') || selectedSet.has('claude_code'),
      installed: claudeInstalled,
      configured: claudeInstalled,
      authenticated: claudeAuthenticated,
      reachable: claudeAuthenticated,
      roleHint: 'deep_planner_module_author',
      command: 'claude',
    }),
    provider('cursor', {
      selected: selectedSet.has('cursor'),
      installed: cursorInstalled,
      configured: cursorInstalled,
      authenticated: cursorAuthenticated,
      reachable: cursorAgentInstalled && cursorAuthenticated,
      usable: selectedSet.has('cursor') && cursorExecEnabled && cursorAuthenticated,
      reason: !cursorExecEnabled ? 'handoff_only' : cursorAuthenticated ? null : 'not_authenticated',
      roleHint: cursorAgentInstalled ? 'ide_agent_human_in_loop' : 'ide_human_in_loop',
      command: 'cursor',
      agentInstalled: cursorAgentInstalled,
    }),
    provider('skynet', {
      selected: selectedSet.has('skynet'),
      installed: true,
      configured: Boolean(skynetUrl),
      authenticated: skynetReachable && skynetModelsReachable,
      reachable: skynetReachable && skynetModelsReachable,
      roleHint: 'local_private_commander',
      baseUrl: skynetUrl,
    }),
    provider('local_model', {
      selected: selectedSet.has('local') || selectedSet.has('local_model') || selectedSet.has('glm'),
      installed: lmstudioReachable || ollamaReachable,
      configured: Boolean(lmstudioUrl || ollamaUrl),
      authenticated: lmstudioReachable || ollamaReachable,
      reachable: lmstudioReachable || ollamaReachable,
      roleHint: 'offline_fallback_planner',
      lmstudioUrl: lmstudioUrl || null,
      ollamaUrl,
      defaultModel: env.GHOSTRECON_LOCAL_MODEL || env.GHOSTRECON_LMSTUDIO_MODEL || 'local-model',
    }),
    provider('openrouter', {
      selected: selectedSet.has('openrouter'),
      installed: true,
      configured: Boolean(openrouterKey),
      authenticated: openrouterReachable,
      reachable: openrouterReachable,
      roleHint: 'cloud_planner_reviewer',
      dataPlane: 'cloud',
      defaultModel: env.GHOSTRECON_OPENROUTER_AUTO_MODEL || env.GHOSTRECON_OPENROUTER_MODEL || OPENROUTER_AUTO_MODELS[0],
      models: [...OPENROUTER_AUTO_MODELS],
    }),
  ];

  const allowUnconfigured = envFlag(env, 'GHOSTRECON_AUTO_ALLOW_UNCONFIGURED');
  const commanders = out.filter((p) => p.selected && (p.usable || allowUnconfigured));

  return {
    ok: commanders.length > 0,
    selected: [...selectedSet],
    providers: out,
    commanders: commanders.map((p) => p.id),
  };
}
