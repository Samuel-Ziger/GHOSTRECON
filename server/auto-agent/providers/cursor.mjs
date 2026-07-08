import { execFile as execFileCb } from 'node:child_process';
import { promisify } from 'node:util';
import { writeAutoRagNote } from '../rag-memory.mjs';

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
