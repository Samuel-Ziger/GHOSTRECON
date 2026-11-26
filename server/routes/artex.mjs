import fs from 'node:fs/promises';
import path from 'node:path';
import { requireScope } from '../modules/auth.js';
import { getArtexClient } from '../integrations/artex/client.mjs';
import {
  ARTEX_PROMPT_VERSION,
  GHOSTIA_PRIVATE_PENTEST_PROMPT,
} from '../integrations/artex/context.mjs';

function csrfOk(req, res, validateCsrfToken) {
  if (validateCsrfToken(req)) return true;
  res.status(403).json({ ok: false, error: 'CSRF token inválido ou ausente' });
  return false;
}

async function ensureGhostreconMcp(client, root) {
  const body = await client.listMcp();
  const servers = Array.isArray(body?.servers) ? body.servers : [];
  const current = servers.find((item) => String(item?.name || '').toLowerCase() === 'ghostrecon');
  const definition = {
    ...(current?.id ? { id: Number(current.id) } : {}),
    name: 'GHOSTRECON',
    transport: 'stdio',
    command: process.execPath,
    args: [path.join(root, 'mcp', 'ghostrecon-mcp.mjs')],
    env: {
      GHOSTRECON_URL: process.env.GHOSTRECON_API_URL || `http://127.0.0.1:${Number(process.env.PORT || 3847)}`,
      GHOSTRECON_AUTO_AUTH_FROM_SERVER: '1',
      GHOSTRECON_MCP_AUTOSTART: '0',
    },
    url: '',
    enabled: true,
    insecure: false,
  };
  const saved = await client.saveMcp(definition);
  const id = Number(saved?.id || current?.id);
  if (!id) throw new Error('Artex não devolveu o ID do MCP GHOSTRECON');
  if (current?.id) await client.refreshMcp(id);
  return { id, tools: current?.tools || [] };
}

async function ensureGhostIaAgent(client, mcpId) {
  const agentsBody = await client.listAgents();
  const agents = Array.isArray(agentsBody?.agents) ? agentsBody.agents : [];
  let agent = agents.find((item) => item?.key === 'ghostia');
  if (!agent) {
    agent = await client.createAgent({
      key: 'ghostia',
      name: 'GhostIA',
      description: 'Artex integrado ao GHOSTRECON para pentests privados autorizados.',
    });
  }
  const detail = await client.getAgent('ghostia');
  const prompt = `[prompt-version:${ARTEX_PROMPT_VERSION}]\n${GHOSTIA_PRIVATE_PENTEST_PROMPT}`;
  if (String(detail?.prompt || '') !== prompt) await client.saveAgentPrompt('ghostia', prompt);
  await client.saveAgentConfig('ghostia', {
    max_turns: 80,
    run_seconds: 3_600,
    web_search: true,
    interactive_shell: true,
  });
  const visibility = detail?.visibility || await client.getAgentVisibility('ghostia');
  const mcp = [...new Set([...(Array.isArray(visibility?.mcp) ? visibility.mcp : []).map(Number), mcpId])];
  await client.setAgentVisibility('ghostia', {
    mcp,
    skill: Array.isArray(visibility?.skill) ? visibility.skill : [],
  });
  return { key: 'ghostia', id: agent?.id || detail?.agent?.id || null };
}

async function ensureIntegration(client, root) {
  const mcp = await ensureGhostreconMcp(client, root);
  const agent = await ensureGhostIaAgent(client, mcp.id);
  return { mcp, agent };
}

function conversationId(raw) {
  const id = String(raw || '').trim();
  return /^\d{1,20}$/.test(id) ? id : '';
}

async function writeConversationOwner(root, id, principal) {
  const safeId = conversationId(id);
  const owner = String(principal?.sub || '').trim();
  if (!safeId || !owner) throw new Error('conversa GhostIA sem identidade de proprietário');
  const dir = path.join(root, '.runtime', 'artex', 'conversations');
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  await fs.writeFile(path.join(dir, `${safeId}.json`), `${JSON.stringify({
    id: safeId,
    owner,
    createdAt: new Date().toISOString(),
  }, null, 2)}\n`, { mode: 0o600 });
}

async function readConversationOwner(root, id) {
  const safeId = conversationId(id);
  if (!safeId) return null;
  try {
    const value = JSON.parse(await fs.readFile(path.join(root, '.runtime', 'artex', 'conversations', `${safeId}.json`), 'utf8'));
    return value?.id === safeId ? value : null;
  } catch {
    return null;
  }
}

async function removeConversationOwner(root, id) {
  const safeId = conversationId(id);
  if (!safeId) return;
  await fs.unlink(path.join(root, '.runtime', 'artex', 'conversations', `${safeId}.json`)).catch((error) => {
    if (error?.code !== 'ENOENT') throw error;
  });
}

export async function canAccessArtexConversation(root, id, principal) {
  if (!conversationId(id)) return false;
  if (principal?.role === 'admin') return true;
  const link = await readConversationOwner(root, id);
  return Boolean(link?.owner && link.owner === String(principal?.sub || '').trim());
}

function publicStatusError(error) {
  const message = error?.cause?.code === 'ECONNREFUSED'
    ? 'backend Artex offline'
    : String(error?.message || error || 'Artex indisponível');
  return message.replace(/Bearer\s+\S+/gi, 'Bearer [REDACTED]').slice(0, 500);
}

export function registerArtexRoutes(app, { ROOT, validateCsrfToken }) {
  const client = getArtexClient({ root: ROOT });

  app.get('/api/artex/status', requireScope('ai.run'), async (req, res) => {
    try {
      const [health, profiles, chatgpt, mcp, conversations] = await Promise.all([
        client.health(),
        client.listProfiles(),
        client.chatGptPlanStatus(),
        client.listMcp(),
        client.listConversations(),
      ]);
      const ghostMcp = (mcp?.servers || []).find((item) => String(item?.name || '').toLowerCase() === 'ghostrecon') || null;
      const allConversations = Array.isArray(conversations?.conversations) ? conversations.conversations : [];
      const visibleConversations = req.principal?.role === 'admin'
        ? allConversations
        : (await Promise.all(allConversations.map(async (item) => (
          await canAccessArtexConversation(ROOT, item?.id, req.principal) ? item : null
        )))).filter(Boolean);
      res.json({
        ok: true,
        online: true,
        health,
        baseUrl: client.baseUrl,
        profiles: profiles?.profiles || [],
        chatgptPlan: chatgpt,
        ghostreconMcp: ghostMcp,
        conversations: visibleConversations,
        promptVersion: ARTEX_PROMPT_VERSION,
        canManage: req.principal?.role === 'admin',
      });
    } catch (error) {
      res.status(503).json({ ok: false, online: false, baseUrl: client.baseUrl, error: publicStatusError(error) });
    }
  });

  app.post('/api/artex/integration/ensure', requireScope('ai.manage'), async (req, res) => {
    if (!csrfOk(req, res, validateCsrfToken)) return;
    try {
      res.json({ ok: true, ...(await ensureIntegration(client, ROOT)) });
    } catch (error) {
      res.status(502).json({ ok: false, error: publicStatusError(error) });
    }
  });

  app.post('/api/artex/llm/profiles', requireScope('ai.manage'), async (req, res) => {
    if (!csrfOk(req, res, validateCsrfToken)) return;
    try { res.json({ ok: true, result: await client.saveProfile(req.body || {}) }); }
    catch (error) { res.status(502).json({ ok: false, error: publicStatusError(error) }); }
  });

  app.post('/api/artex/llm/profiles/active', requireScope('ai.manage'), async (req, res) => {
    if (!csrfOk(req, res, validateCsrfToken)) return;
    try { res.json({ ok: true, result: await client.activateProfile(req.body?.id) }); }
    catch (error) { res.status(502).json({ ok: false, error: publicStatusError(error) }); }
  });

  app.delete('/api/artex/llm/profiles/:id', requireScope('ai.manage'), async (req, res) => {
    if (!csrfOk(req, res, validateCsrfToken)) return;
    const profileId = Number(req.params.id);
    if (!Number.isSafeInteger(profileId) || profileId <= 0) {
      return res.status(400).json({ ok: false, error: 'perfil LLM inválido' });
    }
    try {
      return res.json({ ok: true, result: await client.deleteProfile(profileId) });
    } catch (error) {
      const status = [404, 409].includes(Number(error?.status)) ? Number(error.status) : 502;
      return res.status(status).json({ ok: false, error: publicStatusError(error) });
    }
  });

  app.post('/api/artex/llm/models', requireScope('ai.manage'), async (req, res) => {
    if (!csrfOk(req, res, validateCsrfToken)) return;
    const profileId = Number(req.body?.profile_id || 0);
    const body = {
      provider: String(req.body?.provider || ''),
      base_url: String(req.body?.base_url || ''),
      api_key: String(req.body?.api_key || ''),
      proxy: String(req.body?.proxy || ''),
      ...(Number.isSafeInteger(profileId) && profileId > 0 ? { profile_id: profileId } : {}),
    };
    try {
      const result = await client.listModels(body);
      if (result?.ok === false) {
        return res.status(502).json({ ok: false, error: publicStatusError(new Error(String(result.error || 'não foi possível listar os modelos'))) });
      }
      return res.json({ ok: true, result });
    } catch (error) {
      return res.status(502).json({ ok: false, error: publicStatusError(error) });
    }
  });

  app.post('/api/artex/llm/profiles/:id/test', requireScope('ai.manage'), async (req, res) => {
    if (!csrfOk(req, res, validateCsrfToken)) return;
    const profileId = Number(req.params.id);
    if (!Number.isSafeInteger(profileId) || profileId <= 0) {
      return res.status(400).json({ ok: false, error: 'perfil LLM inválido' });
    }
    try {
      const listed = await client.listProfiles();
      const profile = (listed?.profiles || []).find((item) => Number(item?.id) === profileId);
      if (!profile) return res.status(404).json({ ok: false, error: 'perfil LLM não encontrado' });
      const result = await client.testProfile({
        profile_id: profileId,
        provider: String(profile.format || ''),
        model: String(profile.model || ''),
        base_url: String(profile.base_url || ''),
        reasoning_effort: String(profile.reasoning_effort || ''),
        streaming: profile.streaming !== false,
      });
      if (result?.ok === false) {
        return res.status(502).json({ ok: false, error: publicStatusError(new Error(String(result.error || 'provider recusou o teste'))) });
      }
      return res.json({ ok: true, result });
    } catch (error) {
      return res.status(502).json({ ok: false, error: publicStatusError(error) });
    }
  });

  app.post('/api/artex/chatgpt-plan/connect', requireScope('ai.manage'), async (req, res) => {
    if (!csrfOk(req, res, validateCsrfToken)) return;
    try { res.json({ ok: true, ...(await client.chatGptPlanConnect()) }); }
    catch (error) { res.status(502).json({ ok: false, error: publicStatusError(error) }); }
  });

  app.get('/api/artex/chatgpt-plan/models', requireScope('ai.run'), async (_req, res) => {
    try { res.json({ ok: true, ...(await client.chatGptPlanModels()) }); }
    catch (error) { res.status(502).json({ ok: false, error: publicStatusError(error) }); }
  });

  app.post('/api/artex/conversations', requireScope('ai.run'), async (req, res) => {
    if (!csrfOk(req, res, validateCsrfToken)) return;
    try {
      await ensureIntegration(client, ROOT);
      const body = { agent_key: 'ghostia', title: String(req.body?.title || 'GhostIA').slice(0, 160) };
      if (req.body?.llm_profile_id) body.llm_profile_id = Number(req.body.llm_profile_id);
      const conversation = await client.createConversation(body);
      await writeConversationOwner(ROOT, conversation?.id, req.principal);
      res.json({ ok: true, conversation });
    } catch (error) { res.status(502).json({ ok: false, error: publicStatusError(error) }); }
  });

  app.get('/api/artex/conversations/:id/messages', requireScope('ai.run'), async (req, res) => {
    if (!(await canAccessArtexConversation(ROOT, req.params.id, req.principal))) {
      return res.status(404).json({ ok: false, error: 'conversa GhostIA não encontrada para este operador' });
    }
    try { res.json({ ok: true, ...(await client.conversationMessages(req.params.id, req.query.since)) }); }
    catch (error) { res.status(502).json({ ok: false, error: publicStatusError(error) }); }
  });

  app.delete('/api/artex/conversations/:id', requireScope('ai.run'), async (req, res) => {
    if (!csrfOk(req, res, validateCsrfToken)) return;
    if (!(await canAccessArtexConversation(ROOT, req.params.id, req.principal))) {
      return res.status(404).json({ ok: false, error: 'conversa GhostIA não encontrada para este operador' });
    }
    try {
      const result = await client.deleteConversation(req.params.id);
      await removeConversationOwner(ROOT, req.params.id);
      return res.json({ ok: true, result });
    } catch (error) {
      return res.status(502).json({ ok: false, error: publicStatusError(error) });
    }
  });

  app.get('/api/artex/conversations/:id/messages/:seq', requireScope('ai.run'), async (req, res) => {
    if (!(await canAccessArtexConversation(ROOT, req.params.id, req.principal))) {
      return res.status(404).json({ ok: false, error: 'conversa GhostIA não encontrada para este operador' });
    }
    const seq = Number(req.params.seq);
    if (!Number.isSafeInteger(seq) || seq <= 0) {
      return res.status(400).json({ ok: false, error: 'mensagem GhostIA inválida' });
    }
    try { return res.json({ ok: true, ...(await client.conversationMessageDetail(req.params.id, seq)) }); }
    catch (error) { return res.status(502).json({ ok: false, error: publicStatusError(error) }); }
  });

  app.post('/api/artex/conversations/:id/messages', requireScope('ai.run'), async (req, res) => {
    if (!csrfOk(req, res, validateCsrfToken)) return;
    if (!(await canAccessArtexConversation(ROOT, req.params.id, req.principal))) {
      return res.status(404).json({ ok: false, error: 'conversa GhostIA não encontrada para este operador' });
    }
    const message = String(req.body?.message || '').trim();
    if (!message) return res.status(400).json({ ok: false, error: 'mensagem vazia' });
    try { res.json({ ok: true, result: await client.sendConversationMessage(req.params.id, message) }); }
    catch (error) { res.status(502).json({ ok: false, error: publicStatusError(error) }); }
  });

  app.post('/api/artex/conversations/:id/stop', requireScope('ai.run'), async (req, res) => {
    if (!csrfOk(req, res, validateCsrfToken)) return;
    if (!(await canAccessArtexConversation(ROOT, req.params.id, req.principal))) {
      return res.status(404).json({ ok: false, error: 'conversa GhostIA não encontrada para este operador' });
    }
    try { res.json({ ok: true, result: await client.stopConversation(req.params.id) }); }
    catch (error) { res.status(502).json({ ok: false, error: publicStatusError(error) }); }
  });

}
