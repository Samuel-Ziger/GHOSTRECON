import { execFile as execFileCb } from 'node:child_process';
import { promisify } from 'node:util';
import { writeAutoRagNote } from '../rag-memory.mjs';
import { normalizeAndValidateAgentDecision, parseAgentDecisionText } from '../decision-contract.mjs';
import { availableCatalogIds, availableEvidenceRefs, buildAgentPrompt } from './shared.mjs';

const execFileDefault = promisify(execFileCb);

function slug(value, fallback = 'cursor-task') {
  const s = String(value || '')
    .toLowerCase()
    .replace(/https?:\/\//g, '')
    .replace(/[^a-z0-9._-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 80);
  return s || fallback;
}

function envFlag(env, key) {
  return /^(1|true|yes|on)$/i.test(String(env?.[key] || '').trim());
}

async function commandAvailable(command, { execFileImpl = execFileDefault, platform = process.platform } = {}) {
  const bin = /^win/i.test(String(platform || '')) ? 'where' : 'which';
  try {
    await execFileImpl(bin, [command], { timeout: 2500, windowsHide: true });
    return true;
  } catch {
    return false;
  }
}

export async function resolveCursorProviderState({
  env = process.env,
  execFileImpl = execFileDefault,
  platform = process.platform,
} = {}) {
  const command = String(env.GHOSTRECON_CURSOR_COMMAND || 'cursor').trim() || 'cursor';
  const agentCommand = String(env.GHOSTRECON_CURSOR_AGENT_COMMAND || 'agent').trim() || 'agent';
  const [cursorInstalled, agentInstalled] = await Promise.all([
    commandAvailable(command, { execFileImpl, platform }),
    commandAvailable(agentCommand, { execFileImpl, platform }),
  ]);
  const execEnabled = envFlag(env, 'GHOSTRECON_CURSOR_PROVIDER_EXEC');
  return {
    id: 'cursor',
    mode: execEnabled ? 'exec' : 'handoff',
    installed: cursorInstalled,
    agentInstalled,
    command,
    agentCommand,
    execEnabled,
  };
}

export async function createCursorHandoff({
  root,
  env = process.env,
  requestRunId = '',
  target = '',
  plan = null,
  providers = null,
  ragContext = null,
  cursorState = null,
  execFileImpl = execFileDefault,
  platform = process.platform,
} = {}) {
  const state = cursorState || await resolveCursorProviderState({ env, execFileImpl, platform });
  const modules = Array.isArray(plan?.modules) ? plan.modules : [];
  const roles = plan?.commanders?.roles || {};
  const body = [
    '## Mission',
    '',
    `Target: \`${target || plan?.target || 'unknown'}\``,
    `Request run: \`${requestRunId || 'unknown'}\``,
    '',
    '## Expected Cursor Role',
    '',
    '- Read this task before editing.',
    '- Act as workspace implementer/reviewer when selected by Auto Mode.',
    '- Prefer small modules, tests, and local-only behavior.',
    '- Do not run intrusive network actions without explicit operator confirmation.',
    '',
    '## Commander Roles',
    '',
    Object.keys(roles).length
      ? Object.entries(roles).map(([k, v]) => `- ${k}: ${v}`).join('\n')
      : '- none',
    '',
    '## Planned Modules',
    '',
    modules.length ? modules.map((m) => `- ${m}`).join('\n') : '- none',
    '',
    '## Recent RAG Context',
    '',
    Array.isArray(ragContext?.items) && ragContext.items.length
      ? ragContext.items.map((item) => `- ${item.name}: ${item.title}`).join('\n')
      : '- none',
    '',
    '## Plan JSON',
    '',
    `\`\`\`json\n${JSON.stringify(plan || null, null, 2)}\n\`\`\``,
    '',
    '## Providers JSON',
    '',
    `\`\`\`json\n${JSON.stringify(providers || null, null, 2)}\n\`\`\``,
  ].join('\n');
  const note = await writeAutoRagNote({
    root,
    env,
    kind: 'cursor-task',
    title: `Cursor handoff - ${slug(target || requestRunId)}`,
    body,
    target,
    tags: ['cursor', 'handoff', 'task'],
    metadata: {
      requestRunId,
      cursor: state,
      modules,
    },
  });
  return {
    ok: Boolean(note),
    state,
    task: note,
  };
}

function cursorArgs(env, root, prompt) {
  const configured = String(env.GHOSTRECON_CURSOR_AGENT_ARGS_JSON || '').trim();
  if (configured) {
    const args = JSON.parse(configured);
    if (!Array.isArray(args)) throw new Error('GHOSTRECON_CURSOR_AGENT_ARGS_JSON deve ser array');
    return args.map((arg) => String(arg).replaceAll('{cwd}', root).replaceAll('{prompt}', prompt));
  }
  return ['-p', '--output-format', 'json', '--mode', 'ask', '--workspace', root, prompt];
}

export async function decideWithCursor({
  target, mode, catalog, ragContext, root, role = 'planner', iteration = 1,
  peerDecisions = [], observationBundle = null, env = process.env,
  execFileImpl = execFileDefault, signal, maxContextChars = 120_000,
  allowIntrusive = false, autonomyLevel = 'observation',
} = {}) {
  if (!envFlag(env, 'GHOSTRECON_CURSOR_PROVIDER_EXEC')) throw new Error('Cursor Agent exec desabilitado');
  const prompt = buildAgentPrompt({
    target, mode, catalog, ragContext, role, iteration, peerDecisions,
    observationBundle, maxContextChars, allowIntrusive, autonomyLevel,
  });
  const command = String(env.GHOSTRECON_CURSOR_AGENT_COMMAND || 'agent');
  const startedAt = Date.now();
  let result;
  try {
    result = await execFileImpl(command, cursorArgs(env, root, prompt), {
      cwd: root, timeout: Number(env.GHOSTRECON_AUTO_AGENT_TIMEOUT_MS || 180_000),
      maxBuffer: 8 * 1024 * 1024, windowsHide: true, signal,
    });
  } catch (error) {
    const code = error?.code == null ? '' : ` (exit ${error.code})`;
    throw Object.assign(new Error(`Cursor Agent falhou${code}`), {
      code: error?.code,
    });
  }
  const raw = String(result?.stdout || '').trim();
  let output = raw;
  try {
    const envelope = JSON.parse(raw);
    output = envelope.result || envelope.message || envelope.content || envelope;
  } catch { /* parser comum tratará texto/JSON fenced */ }
  const parsed = typeof output === 'object' ? output : parseAgentDecisionText(output);
  const validated = normalizeAndValidateAgentDecision(parsed, {
    repairEnvelope: true,
    repairOptions: { objective: `authorized_recon:${target || 'target'}` },
    catalogModuleIds: availableCatalogIds(catalog, { allowIntrusive, autonomyLevel }),
    availableEvidenceRefs: availableEvidenceRefs({ ragContext, observationBundle }),
  });
  if (!validated.ok) throw new Error(`decisão Cursor rejeitada: ${validated.errors.join('; ')}`);
  return {
    ok: true, provider: 'cursor', role, iteration, latencyMs: Date.now() - startedAt,
    decision: validated.decision, transport: { command, mode: 'ask', realtime: true },
  };
}
