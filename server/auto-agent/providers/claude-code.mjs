import { execFile as execFileCb } from 'node:child_process';
import { promisify } from 'node:util';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseAgentDecisionText, validateAgentDecision } from '../decision-contract.mjs';
import { availableCatalogIds, availableEvidenceRefs, buildAgentPrompt } from './shared.mjs';

const execFileDefault = promisify(execFileCb);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCHEMA_PATH = path.join(__dirname, '..', 'schemas', 'decision.schema.json');

export function claudeChildEnv(env) {
  const allowed = ['PATH', 'HOME', 'USER', 'LOGNAME', 'SHELL', 'LANG', 'LC_ALL', 'TERM', 'TMPDIR', 'TEMP', 'TMP', 'XDG_CONFIG_HOME', 'XDG_CACHE_HOME'];
  const out = {};
  for (const key of allowed) if (env[key] != null) out[key] = env[key];
  if (/^(1|true|yes)$/i.test(String(env.GHOSTRECON_CLAUDE_INHERIT_API_KEY || '')) && env.ANTHROPIC_API_KEY) {
    out.ANTHROPIC_API_KEY = env.ANTHROPIC_API_KEY;
  }
  return out;
}

function unwrapClaudeJson(stdout) {
  const parsed = JSON.parse(String(stdout || '').trim());
  if (parsed?.structured_output) return parsed.structured_output;
  if (typeof parsed?.result === 'string') return parseAgentDecisionText(parsed.result);
  if (parsed?.result && typeof parsed.result === 'object') return parsed.result;
  return parsed;
}

export async function decideWithClaudeCode({
  target, mode, catalog, ragContext, root, role = 'planner', iteration = 1,
  peerDecisions = [], observationBundle = null, env = process.env, execFileImpl = execFileDefault,
  signal, maxContextChars = 120_000, allowIntrusive = false,
} = {}) {
  const schema = JSON.parse(await fs.readFile(SCHEMA_PATH, 'utf8'));
  const timeoutMs = Math.max(30_000, Math.min(900_000, Number(env.GHOSTRECON_CLAUDE_TIMEOUT_MS || 240_000)));
  const prompt = buildAgentPrompt({ target, mode, catalog, ragContext, role, iteration, peerDecisions, observationBundle, maxContextChars, allowIntrusive });
  const args = [
    '--print',
    '--output-format', 'json',
    '--json-schema', JSON.stringify(schema),
    '--permission-mode', 'plan',
    '--tools', '',
    '--disable-slash-commands',
    '--no-session-persistence',
    '--setting-sources', 'user',
    prompt,
  ];
  const startedAt = Date.now();
  const result = await execFileImpl(String(env.GHOSTRECON_CLAUDE_COMMAND || 'claude'), args, {
    cwd: root,
    env: claudeChildEnv(env),
    timeout: timeoutMs,
    maxBuffer: 8 * 1024 * 1024,
    windowsHide: true,
    signal,
  });
  const parsed = unwrapClaudeJson(result?.stdout || '');
  const validated = validateAgentDecision(parsed, {
    catalogModuleIds: availableCatalogIds(catalog, { allowIntrusive }),
    availableEvidenceRefs: availableEvidenceRefs({ ragContext, observationBundle }),
  });
  if (!validated.ok) throw new Error(`decisão Claude Code rejeitada: ${validated.errors.join('; ')}`);
  return {
    ok: true,
    provider: 'claude_code',
    model: env.GHOSTRECON_CLAUDE_CODE_MODEL || null,
    role,
    iteration,
    latencyMs: Date.now() - startedAt,
    decision: validated.decision,
    usage: parsed?.usage || null,
    transport: { command: 'claude --print', permissionMode: 'plan', tools: [] },
  };
}
