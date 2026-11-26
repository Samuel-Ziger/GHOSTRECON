import fs from 'node:fs/promises';
import path from 'node:path';
import { requireScope } from '../modules/auth.js';
import { attachRunToEngagement, getEngagement, preRunChecklist } from '../modules/engagement.mjs';
import { parseReconTarget } from '../modules/recon-target.js';
import { getArtexClient } from '../integrations/artex/client.mjs';
import { getNeuroSploitManager, NEUROSPLOIT_MODES } from '../integrations/neurosploit/manager.mjs';
import { syncNeuroSploitFindingsToCortex } from '../integrations/neurosploit/cortex.mjs';
import {
  resolveNeuroSploitProfile,
  validateNeuroSploitProfileReady,
} from '../integrations/neurosploit/profile.mjs';
import { listCodexMcpCatalog, normalizeMcpSelection } from '../integrations/mcp/catalog.mjs';

const NETWORK_MODES = new Set(['run', 'greybox', 'host', 'aitest']);
const PATH_MODES = new Set(['whitebox', 'greybox', 'mobile', 'skills']);
const ARTIFACT_EXTENSIONS = new Set([
  '.json', '.jsonl', '.md', '.txt', '.html', '.pdf', '.png', '.jpg', '.jpeg',
  '.svg', '.sarif', '.mmd', '.cypher', '.http', '.yaml', '.yml', '.spdx',
]);

function csrfOk(req, res, validateCsrfToken) {
  if (typeof validateCsrfToken === 'function' && validateCsrfToken(req)) return true;
  res.status(403).json({ ok: false, error: 'CSRF token inválido ou ausente' });
  return false;
}

function publicError(error) {
  return String(error?.message || error || 'NeuroSploit indisponível')
    .replace(/\bsk-(?:proj-)?[A-Za-z0-9_-]{12,}\b/g, '[REDACTED]')
    .replace(/(bearer\s+)[A-Za-z0-9._~+/-]{12,}/ig, '$1[REDACTED]')
    .slice(0, 2_000);
}

function principalId(principal) { return String(principal?.sub || '').trim(); }

function isRemoteRepository(value) {
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && ['github.com', 'gitlab.com'].includes(url.hostname.toLowerCase());
  } catch { return false; }
}

function allowedLocalRoots(root) {
  const configured = String(process.env.GHOSTRECON_NEUROSPLOIT_ALLOWED_ROOTS || '')
    .split(path.delimiter).map((item) => item.trim()).filter(Boolean);
  return (configured.length ? configured : [root]).map((item) => path.resolve(item));
}

async function validateRepositoryPath(root, raw, { allowRemote = true } = {}) {
  const value = String(raw || '').trim();
  if (!value) throw new Error('repositório/artefato obrigatório para este modo');
  if (isRemoteRepository(value)) {
    if (!allowRemote) throw new Error('este modo exige um artefato local dentro das raízes permitidas');
    return value;
  }
  const resolved = path.resolve(value);
  const allowed = allowedLocalRoots(root).some((base) => resolved === base || resolved.startsWith(`${base}${path.sep}`));
  if (!allowed) throw new Error('caminho local fora das raízes permitidas do NeuroSploit');
  const stat = await fs.stat(resolved).catch(() => null);
  if (!stat) throw new Error('repositório/artefato local não encontrado');
  return resolved;
}

async function normalizeStart(root, body) {
  const mode = String(body?.mode || 'run').trim().toLowerCase();
  if (!NEUROSPLOIT_MODES.includes(mode)) throw new Error('modo NeuroSploit inválido');
  let target = String(body?.target || '').trim();
  let scopeHost = '';
  if (NETWORK_MODES.has(mode)) {
    const parsed = parseReconTarget(target);
    if (!parsed.ok) throw new Error(parsed.message || 'alvo NeuroSploit inválido');
    scopeHost = parsed.hostname;
    target = parsed.explicitUrl ? parsed.targetUrl : parsed.target;
  }
  let repository = String(body?.repository || '').trim();
  if (PATH_MODES.has(mode)) {
    repository = await validateRepositoryPath(root, repository || (mode !== 'greybox' ? target : ''), {
      allowRemote: mode !== 'mobile',
    });
  }
  if (mode === 'container') {
    if (!target || target.length > 500 || /[\r\n\0]/.test(target)) throw new Error('imagem de container inválida');
  }
  return {
    mode, target, repository, scopeHost,
    profileId: Number(body?.profileId),
    engagementId: String(body?.engagementId || '').trim(),
    authorizationConfirmed: body?.authorizationConfirmed === true,
    authorizationReference: String(body?.authorizationReference || '').trim(),
    environment: String(body?.environment || 'production').trim().toLowerCase(),
    policy: String(body?.policy || 'web').trim().toLowerCase(),
    votes: body?.votes,
    chainDepth: body?.chainDepth,
    recon: body?.recon,
    maxAgents: body?.maxAgents,
    quick: body?.quick === true,
    focus: String(body?.focus || '').trim().slice(0, 2_000),
    objective: String(body?.objective || '').trim().slice(0, 2_000),
    outOfScope: String(body?.outOfScope || '').trim().slice(0, 2_000),
    agents: Array.isArray(body?.agents) ? body.agents.slice(0, 64) : [],
    codexCli: body?.codexCli === true,
    mcpServers: normalizeMcpSelection(body?.mcpServers),
  };
}

async function validateAuthorization(input) {
  if (!NETWORK_MODES.has(input.mode)) return { engagement: null, checklist: { ok: true, errors: [], warnings: [] } };
  if (!input.authorizationConfirmed || input.authorizationReference.length < 3) {
    throw new Error('confirmação e referência de autorização são obrigatórias');
  }
  if (!input.engagementId) throw new Error('engagement formal obrigatório para execução NeuroSploit de rede');
  const engagement = await getEngagement(input.engagementId);
  const checklist = preRunChecklist({
    engagement,
    target: input.scopeHost,
    modules: [`neurosploit_${input.mode}`],
    intrusiveModules: [`neurosploit_${input.mode}`],
    requireFormalAuthorization: true,
  });
  if (!checklist.ok) throw new Error(checklist.errors.join(' '));
  return { engagement, checklist };
}

async function listArtifacts(root, relative = '', depth = 0) {
  if (depth > 4) return [];
  const dir = path.join(root, relative);
  const entries = await fs.readdir(dir, { withFileTypes: true }).catch(() => []);
  const rows = [];
  for (const entry of entries.slice(0, 500)) {
    const next = relative ? `${relative}/${entry.name}` : entry.name;
    if (entry.isDirectory()) rows.push(...await listArtifacts(root, next, depth + 1));
    else if (entry.isFile() && ARTIFACT_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) {
      const stat = await fs.stat(path.join(root, next)).catch(() => null);
      rows.push({ path: next, size: Number(stat?.size || 0) });
    }
  }
  return rows.slice(0, 1_000);
}

export function registerNeuroSploitRoutes(app, {
  ROOT,
  validateCsrfToken,
  artexClient = getArtexClient({ root: ROOT }),
  manager = null,
} = {}) {
  const runtime = manager || getNeuroSploitManager({
    root: ROOT,
    onTerminal: async (job) => {
      const cortex = await syncNeuroSploitFindingsToCortex({ job, findings: job.findings });
      if (job.engagementId && job.runId) {
        await attachRunToEngagement(job.engagementId, {
          runId: `neurosploit:${job.runId}`,
          target: job.target,
          by: job.owner,
        });
      }
      return cortex;
    },
  });

  app.get('/api/neurosploit/status', requireScope('ai.run'), async (req, res) => {
    try {
      const [status, profilesBody, plan] = await Promise.all([
        runtime.status(),
        artexClient.listProfiles(),
        artexClient.chatGptPlanStatus().catch(() => ({ connected: false })),
      ]);
      const profiles = (profilesBody?.profiles || []).map((profile) => ({
        id: Number(profile.id),
        name: String(profile.name || `Perfil #${profile.id}`),
        model: String(profile.model || ''),
        format: String(profile.format || 'openai'),
        ready: profile.format === 'chatgpt-plan' ? plan?.connected === true : Boolean(profile.api_key_hint),
        credentialSource: profile.format === 'chatgpt-plan' ? 'codex-plan' : 'ghostia-vault',
      }));
      const mcpServers = await listCodexMcpCatalog({ root: ROOT }).catch(() => []);
      res.json({
        ok: true,
        ...status,
        jobs: status.jobs.filter((job) => runtime.owns(job, req.principal)),
        profiles,
        mcpServers,
        artexOnline: true,
      });
    } catch (error) {
      const status = await runtime.status().catch(() => ({}));
      res.json({
        ok: true,
        ...status,
        jobs: (status.jobs || []).filter((job) => runtime.owns(job, req.principal)),
        profiles: [],
        artexOnline: false,
        error: publicError(error),
      });
    }
  });

  app.get('/api/neurosploit/jobs', requireScope('ai.run'), async (req, res) => {
    const status = await runtime.status();
    res.json({ ok: true, jobs: status.jobs.filter((job) => runtime.owns(job, req.principal)) });
  });

  app.post('/api/neurosploit/jobs',
    requireScope('ai.run'),
    requireScope('recon.run', { intrusiveCheck: (req) => NETWORK_MODES.has(String(req.body?.mode || 'run')) }),
    async (req, res) => {
      if (!csrfOk(req, res, validateCsrfToken)) return;
      try {
        const input = await normalizeStart(ROOT, req.body || {});
        const { checklist } = await validateAuthorization(input);
        if (!Number.isSafeInteger(input.profileId) || input.profileId <= 0) throw new Error('perfil GhostIA/Artex obrigatório');
        const profile = await resolveNeuroSploitProfile(artexClient, input.profileId);
        if (input.codexCli && String(profile.format || '') !== 'chatgpt-plan') {
          throw new Error('Codex CLI exige um perfil ChatGPT Plan');
        }
        if (input.mcpServers.length && !input.codexCli) {
          throw new Error('selecione Codex CLI para usar Mind ou outros MCPs');
        }
        const artexToken = input.codexCli ? '' : await artexClient.login();
        const owner = principalId(req.principal);
        if (!owner) throw new Error('principal sem identidade estável');
        const job = await runtime.start(input, {
          owner,
          profile,
          artexToken,
          artexBaseUrl: artexClient.baseUrl,
          scopeHost: input.scopeHost,
        });
        res.status(202).json({ ok: true, job, checklist });
      } catch (error) {
        res.status(400).json({ ok: false, error: publicError(error) });
      }
    });

  app.get('/api/neurosploit/jobs/:id', requireScope('ai.run'), async (req, res) => {
    const job = await runtime.snapshot(req.params.id, { includeFeed: true });
    if (!runtime.owns(job, req.principal)) return res.status(404).json({ ok: false, error: 'engagement NeuroSploit não encontrado' });
    return res.json({ ok: true, job });
  });

  app.post('/api/neurosploit/jobs/:id/:action(pause|continue|stop)', requireScope('ai.run'), async (req, res) => {
    if (!csrfOk(req, res, validateCsrfToken)) return;
    const current = await runtime.snapshot(req.params.id, { includeFeed: false });
    if (!runtime.owns(current, req.principal)) return res.status(404).json({ ok: false, error: 'engagement NeuroSploit não encontrado' });
    try {
      const job = await runtime.control(req.params.id, req.params.action);
      return res.json({ ok: true, job });
    } catch (error) {
      return res.status(409).json({ ok: false, error: publicError(error) });
    }
  });

  app.post('/api/neurosploit/jobs/:id/resume', requireScope('ai.run'), requireScope('recon.run', {
    intrusiveCheck: () => true,
  }), async (req, res) => {
    if (!csrfOk(req, res, validateCsrfToken)) return;
    const current = await runtime.snapshot(req.params.id, { includeFeed: false });
    if (!runtime.owns(current, req.principal)) return res.status(404).json({ ok: false, error: 'engagement NeuroSploit não encontrado' });
    try {
      const profilesBody = await artexClient.listProfiles();
      const profile = (profilesBody?.profiles || []).find((item) => Number(item.id) === Number(current.profileId));
      if (!profile) throw new Error('perfil GhostIA/Artex original não encontrado');
      await validateNeuroSploitProfileReady(artexClient, profile);
      const parsed = parseReconTarget(current.target);
      const artexToken = current.codexCli ? '' : await artexClient.login();
      const job = await runtime.resume(req.params.id, {
        profile,
        artexToken,
        artexBaseUrl: artexClient.baseUrl,
        scopeHost: parsed.ok ? parsed.hostname : '',
      });
      return res.json({ ok: true, job });
    } catch (error) {
      return res.status(409).json({ ok: false, error: publicError(error) });
    }
  });

  app.get('/api/neurosploit/jobs/:id/artifacts', requireScope('ai.run'), async (req, res) => {
    const job = await runtime.snapshot(req.params.id, { includeFeed: false });
    if (!runtime.owns(job, req.principal)) return res.status(404).json({ ok: false, error: 'engagement NeuroSploit não encontrado' });
    const dir = runtime.runDir(runtime.job(req.params.id));
    return res.json({ ok: true, artifacts: dir ? await listArtifacts(dir) : [] });
  });

  app.get('/api/neurosploit/jobs/:id/artifacts/*', requireScope('ai.run'), async (req, res) => {
    const job = await runtime.snapshot(req.params.id, { includeFeed: false });
    if (!runtime.owns(job, req.principal)) return res.status(404).json({ ok: false, error: 'engagement NeuroSploit não encontrado' });
    const relative = String(req.params[0] || '');
    if (!ARTIFACT_EXTENSIONS.has(path.extname(relative).toLowerCase())) return res.status(403).json({ ok: false, error: 'tipo de artefato não permitido' });
    const artifact = await runtime.artifact(req.params.id, relative);
    if (!artifact) return res.status(404).json({ ok: false, error: 'artefato não encontrado' });
    res.setHeader('Content-Disposition', `attachment; filename="${artifact.name.replace(/"/g, '')}"`);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    return res.sendFile(artifact.full);
  });

  return runtime;
}

export { normalizeStart, validateAuthorization };
