import fs from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { requireScope } from '../modules/auth.js';
import { createHackbotClient } from '../integrations/hackbot/client.mjs';
import { getArtexClient } from '../integrations/artex/client.mjs';
import {
  HACKBOT_AGENTS,
  HACKBOT_MODEL_CATALOG,
  hackbotRuntimePaths,
  publicHackbotBindings,
  readHackbotBindings,
  writeHackbotBindings,
} from '../integrations/hackbot/config.mjs';
import { listCodexMcpCatalog, validateCodexMcpSelection } from '../integrations/mcp/catalog.mjs';

const MAX_HACKBOT_MESSAGE_CHARS = 64_000;

function csrfOk(req, res, validateCsrfToken) {
  if (typeof validateCsrfToken === 'function' && !validateCsrfToken(req)) {
    res.status(403).json({ ok: false, error: 'CSRF' });
    return false;
  }
  return true;
}

function publicError(error) {
  return String(error?.message || error || 'HackBot indisponível')
    .replace(/\bsk-[A-Za-z0-9_-]{12,}\b/g, '[REDACTED]')
    .replace(/(bearer\s+)[A-Za-z0-9._~+/-]{12,}/ig, '$1[REDACTED]')
    .slice(0, 1_500);
}

function principalId(principal) {
  return String(principal?.sub || '').trim();
}

function canAccess(row, principal) {
  const owner = principalId(principal);
  return Boolean(row && owner && (row.owner === owner || principal?.role === 'admin'));
}

async function readIndex(root) {
  const file = hackbotRuntimePaths(root).conversations;
  try {
    const parsed = JSON.parse(await fs.readFile(file, 'utf8'));
    return Array.isArray(parsed?.conversations) ? parsed : { version: 1, conversations: [] };
  } catch (error) {
    if (error?.code === 'ENOENT' || error instanceof SyntaxError) return { version: 1, conversations: [] };
    throw error;
  }
}

async function writeIndex(root, index) {
  const paths = hackbotRuntimePaths(root);
  await fs.mkdir(paths.dir, { recursive: true, mode: 0o700 });
  const file = paths.conversations;
  const temporary = `${file}.${process.pid}.tmp`;
  await fs.writeFile(temporary, `${JSON.stringify(index, null, 2)}\n`, { mode: 0o600 });
  await fs.rename(temporary, file);
  await fs.chmod(file, 0o600).catch(() => {});
}

function publicConversation(row) {
  return {
    id: row.id,
    title: row.title,
    agent: row.agent,
    created_at: row.created_at,
    updated_at: row.updated_at,
    last_status: row.last_status || 'idle',
  };
}

function findConversation(index, id) {
  return index.conversations.find((row) => row.id === String(id || '').trim().toLowerCase());
}

export function registerHackbotRoutes(app, {
  ROOT, validateCsrfToken, client = createHackbotClient(), artexClient = getArtexClient({ root: ROOT }),
}) {
  app.get('/api/hackbot/status', requireScope('ai.run'), async (_req, res) => {
    const config = publicHackbotBindings(await readHackbotBindings(ROOT));
    try {
      const runtime = await client.status();
      res.json({ ok: true, online: true, runtime, config, agents: HACKBOT_AGENTS });
    } catch (error) {
      res.json({ ok: true, online: false, error: publicError(error), config, agents: HACKBOT_AGENTS });
    }
  });

  app.get('/api/hackbot/models', requireScope('ai.run'), async (_req, res) => {
    let profiles = [];
    let artexOnline = false;
    try {
      const [listed, plan] = await Promise.all([
        artexClient.listProfiles(),
        artexClient.chatGptPlanStatus().catch(() => ({ connected: false })),
      ]);
      profiles = (listed?.profiles || []).map((profile) => ({
        id: `artex-profile-${profile.id}`,
        label: `GhostIA · ${profile.name} · ${profile.model}`,
        model: String(profile.model || ''),
        base_url: null,
        api_key_env: 'ARTEX_INTERNAL_SESSION',
        source: 'artex',
        profile_id: Number(profile.id),
        provider: String(profile.format || 'openai'),
        format: String(profile.format || 'openai'),
        kind: 'ghostia-profile',
        status: profile.format === 'chatgpt-plan'
          ? (plan?.connected ? 'ready' : 'chatgpt-plan-disconnected')
          : (profile.api_key_hint ? 'ready' : 'credential-missing'),
        recommended_for: HACKBOT_AGENTS.map((agent) => agent.name),
      }));
      artexOnline = true;
    } catch {
      // Static/direct presets remain useful while GhostIA is restarting.
    }
    const mcpServers = await listCodexMcpCatalog({ root: ROOT }).catch(() => []);
    res.json({ ok: true, models: [...profiles, ...HACKBOT_MODEL_CATALOG], mcp_servers: mcpServers, artex_online: artexOnline });
  });

  app.get('/api/hackbot/agents', requireScope('ai.run'), async (_req, res) => {
    const config = publicHackbotBindings(await readHackbotBindings(ROOT));
    res.json({
      ok: true,
      agents: HACKBOT_AGENTS.map((agent) => ({ ...agent, binding: config.bindings[agent.name] })),
      orchestrator_optional: true,
      direct_specialists: HACKBOT_AGENTS.filter((agent) => agent.name !== 'orchestrator').map((agent) => agent.name),
    });
  });

  app.post('/api/hackbot/config', requireScope('ai.manage'), async (req, res) => {
    if (!csrfOk(req, res, validateCsrfToken)) return;
    try {
      for (const row of Object.values(req.body?.bindings || {})) {
        if (row?.source === 'codex-cli') {
          await validateCodexMcpSelection({ root: ROOT, selected: row.mcp_servers });
        }
      }
      const config = await writeHackbotBindings(ROOT, req.body || {});
      res.json({ ok: true, config: publicHackbotBindings(config) });
    } catch (error) {
      res.status(400).json({ ok: false, error: publicError(error) });
    }
  });

  app.get('/api/hackbot/conversations', requireScope('ai.run'), async (req, res) => {
    const index = await readIndex(ROOT);
    const rows = index.conversations
      .filter((row) => canAccess(row, req.principal))
      .sort((a, b) => String(b.updated_at).localeCompare(String(a.updated_at)))
      .map(publicConversation);
    res.json({ ok: true, conversations: rows });
  });

  app.post('/api/hackbot/conversations', requireScope('ai.run'), async (req, res) => {
    if (!csrfOk(req, res, validateCsrfToken)) return;
    const owner = principalId(req.principal);
    if (!owner) return res.status(403).json({ ok: false, error: 'principal sem identidade estável' });
    const agent = String(req.body?.agent || 'orchestrator').trim();
    if (!HACKBOT_AGENTS.some((item) => item.name === agent)) {
      return res.status(400).json({ ok: false, error: 'agente HackBot inválido' });
    }
    const now = new Date().toISOString();
    const row = {
      id: randomUUID(),
      owner,
      title: String(req.body?.title || 'Nova conversa HackBot').trim().slice(0, 160) || 'Nova conversa HackBot',
      agent,
      created_at: now,
      updated_at: now,
      last_status: 'idle',
    };
    const index = await readIndex(ROOT);
    index.conversations.push(row);
    await writeIndex(ROOT, index);
    return res.status(201).json({ ok: true, conversation: publicConversation(row) });
  });

  app.get('/api/hackbot/conversations/:id/messages', requireScope('ai.run'), async (req, res) => {
    const index = await readIndex(ROOT);
    const row = findConversation(index, req.params.id);
    if (!canAccess(row, req.principal)) {
      return res.status(404).json({ ok: false, error: 'conversa HackBot não encontrada' });
    }
    try {
      const result = await client.session(row.id);
      return res.json({ ok: true, session: result.session, conversation: publicConversation(row) });
    } catch (error) {
      if (Number(error?.status) === 404) {
        return res.json({ ok: true, session: { id: row.id, title: row.title, entries: [] }, conversation: publicConversation(row) });
      }
      return res.status(502).json({ ok: false, error: publicError(error) });
    }
  });

  app.post('/api/hackbot/conversations/:id/messages', requireScope('ai.run'), async (req, res) => {
    if (!csrfOk(req, res, validateCsrfToken)) return;
    const index = await readIndex(ROOT);
    const row = findConversation(index, req.params.id);
    if (!canAccess(row, req.principal)) {
      return res.status(404).json({ ok: false, error: 'conversa HackBot não encontrada' });
    }
    // `message` is the current React contract. Accept the old aliases as well
    // so a cached frontend bundle cannot create a conversation and then lose
    // its first request at this boundary.
    const prompt = String(req.body?.message ?? req.body?.prompt ?? req.body?.content ?? '').trim();
    if (!prompt) {
      return res.status(400).json({ ok: false, error: 'mensagem HackBot vazia ou ausente' });
    }
    if (prompt.length > MAX_HACKBOT_MESSAGE_CHARS) {
      return res.status(413).json({
        ok: false,
        error: `mensagem HackBot excede ${MAX_HACKBOT_MESSAGE_CHARS.toLocaleString('pt-BR')} caracteres`,
      });
    }
    const requestedAgent = String(req.body?.agent || row.agent || 'orchestrator').trim();
    if (!HACKBOT_AGENTS.some((item) => item.name === requestedAgent)) {
      return res.status(400).json({ ok: false, error: 'agente HackBot inválido' });
    }
    row.agent = requestedAgent;
    row.last_status = 'running';
    row.updated_at = new Date().toISOString();
    await writeIndex(ROOT, index);
    try {
      const result = await client.run({
        session_id: row.id,
        prompt,
        agent: requestedAgent,
        document_path: req.body?.document_path || null,
        sarif_path: req.body?.sarif_path || null,
        document_desc: String(req.body?.document_desc || '').slice(0, 500),
      });
      row.title = row.title === 'Nova conversa HackBot' ? prompt.split(/\r?\n/, 1)[0].slice(0, 80) : row.title;
      row.last_status = 'completed';
      row.updated_at = new Date().toISOString();
      await writeIndex(ROOT, index);
      return res.json({ ok: true, ...result, conversation: publicConversation(row) });
    } catch (error) {
      row.last_status = 'failed';
      row.updated_at = new Date().toISOString();
      await writeIndex(ROOT, index);
      const status = [400, 401, 402, 403, 408, 409, 422, 429, 502, 503, 504].includes(Number(error?.status))
        ? Number(error.status)
        : 502;
      return res.status(status).json({ ok: false, error: publicError(error), conversation: publicConversation(row) });
    }
  });

  app.delete('/api/hackbot/conversations/:id', requireScope('ai.run'), async (req, res) => {
    if (!csrfOk(req, res, validateCsrfToken)) return;
    const index = await readIndex(ROOT);
    const row = findConversation(index, req.params.id);
    if (!canAccess(row, req.principal)) {
      return res.status(404).json({ ok: false, error: 'conversa HackBot não encontrada' });
    }
    try { await client.deleteSession(row.id); } catch (error) {
      if (Number(error?.status) !== 404 && Number(error?.status) !== 503) {
        return res.status(502).json({ ok: false, error: publicError(error) });
      }
    }
    index.conversations = index.conversations.filter((item) => item.id !== row.id);
    await writeIndex(ROOT, index);
    return res.json({ ok: true, deleted: row.id });
  });
}
