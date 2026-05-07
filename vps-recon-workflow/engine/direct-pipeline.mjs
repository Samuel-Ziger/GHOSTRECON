/**
 * Invoca runPipeline do GHOSTRECON em processo (sem HTTP).
 * O servidor real vive em GHOSTRECON_REPO_ROOT/server (por defeito: pasta pai deste pacote).
 */
import { randomBytes } from 'node:crypto';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import { ghostreconRootPath } from '../lib/ghostrecon-root.mjs';

process.env.GHOSTRECON_NO_HTTP_LISTEN = process.env.GHOSTRECON_NO_HTTP_LISTEN ?? '1';

function srvUrl(...parts) {
  const root = ghostreconRootPath();
  return pathToFileURL(path.join(root, 'server', ...parts)).href;
}

/** @typedef {Awaited<ReturnType<typeof loadDepsStatic>>['deps']} PipelineDeps */

let depsCache = /** @type {PipelineDeps | null} */ (null);
let indexPromise = /** @type {Promise<{ runPipeline: Function, reconHttpContext: { run: Function } }>|null} */ (null);

async function loadDepsStatic() {
  if (depsCache) return { deps: depsCache };

  const [
    { parseReconTarget },
    { getEngagement, preRunChecklist },
    { gateModules, applyWatermarkHeaders },
    { createIdentityController, normalizeIdentityOptions },
    { normalizeOpenrouterOnlyFlag },
  ] = await Promise.all([
    import(srvUrl('modules', 'recon-target.js')),
    import(srvUrl('modules', 'engagement.mjs')),
    import(srvUrl('modules', 'opsec.mjs')),
    import(srvUrl('modules', 'identity-controller.mjs')),
    import(srvUrl('modules', 'ai-dual-report.js')),
  ]);

  depsCache = {
    parseReconTarget,
    getEngagement,
    preRunChecklist,
    gateModules,
    applyWatermarkHeaders,
    createIdentityController,
    normalizeIdentityOptions,
    normalizeOpenrouterOnlyFlag,
  };
  return { deps: depsCache };
}

function loadPipelineIndex() {
  if (!indexPromise) {
    indexPromise = import(srvUrl('load-env.js'))
      .catch(() => ({}))
      .then(() => import(srvUrl('index.js')));
  }
  return indexPromise;
}

/**
 * Executa recon completo — espelho mínimo do POST /api/recon/stream (sem pré-validação Tor).
 */
export async function executeReconDirect(opts) {
  await loadDepsStatic();
  const d = depsCache;

  const {
    modules,
    kaliMode = false,
    profile = 'standard',
    projectName = '',
    playbook = null,
    engagementId = null,
    operator = null,
    autoAiReports = false,
    outOfScope = null,
    confirmActive = false,
  } = opts;

  const parsed = d.parseReconTarget(opts.domain);
  if (!parsed.ok) throw new Error(parsed.message || 'Alvo inválido');
  const domain = parsed.target;
  const exactMatch = Boolean(opts.exactMatch);

  const rawOpsec = String(opts.opsecProfile || process.env.GHOSTRECON_OPSEC_PROFILE || 'standard')
    .trim()
    .toLowerCase();
  const allowedOpsec = new Set(['passive', 'stealth', 'standard', 'aggressive']);
  const opsecProfile = allowedOpsec.has(rawOpsec) ? rawOpsec : 'standard';

  const engagementIdRaw = engagementId != null ? String(engagementId).trim() : '';
  let engagement = null;
  if (engagementIdRaw) {
    engagement = await d.getEngagement(engagementIdRaw);
    if (!engagement) throw new Error(`engagement "${engagementIdRaw}" não encontrado`);
  }

  const playbookNameForCheck = playbook != null ? String(playbook).trim() : '';

  const checklist = d.preRunChecklist({
    engagement,
    target: domain,
    modules,
    playbook: playbookNameForCheck || null,
  });
  if (!checklist.ok) {
    throw new Error(`Pré-checklist falhou: ${(checklist.errors || []).join('; ') || JSON.stringify(checklist)}`);
  }

  const gate = d.gateModules({
    modules,
    profile: opsecProfile,
    confirm:
      Boolean(confirmActive) || String(process.env.GHOSTRECON_CONFIRM_ACTIVE || '').trim() === '1',
    engagement,
  });
  if (!gate.ok) {
    throw new Error(
      `${gate.reason || 'OPSEC bloqueado'} — perfil=${gate.profile} blocked=${(gate.blocked || []).join(', ') || '—'}`,
    );
  }

  const idx = await loadPipelineIndex();
  const { runPipeline, reconHttpContext } = idx;

  const requestRunId = `emb-${Date.now().toString(36)}-${randomBytes(4).toString('hex')}`;

  const events = [];
  const emit = (obj) => {
    events.push(obj);
  };

  const identityOpts = d.normalizeIdentityOptions(modules, null);
  identityOpts.runId = requestRunId;
  identityOpts.target = domain;
  const identityCtrl = d.createIdentityController({ ...identityOpts, modules });

  const headers = {};
  if (engagementIdRaw) {
    d.applyWatermarkHeaders(headers, {
      engagementId: engagementIdRaw,
      operator: operator != null ? String(operator).trim() || undefined : undefined,
    });
  }
  const auth = engagementIdRaw || Object.keys(headers).length ? { headers, cookie: '' } : null;

  await reconHttpContext.run({ requestRunId, target: domain, emit }, async () => {
    await runPipeline({
      domain,
      exactMatch,
      modules,
      emit,
      kaliMode,
      auth,
      profile: String(profile).trim().toLowerCase(),
      outOfScope,
      projectName,
      autoAiReports: Boolean(autoAiReports),
      aiProviderMode: 'auto',
      aiUseOpenrouter: true,
      aiOpenrouterOnly: d.normalizeOpenrouterOnlyFlag(false),
      aiPrimaryCloud: null,
      shannonPrecheck: true,
      shannonSkipDepsVerify: false,
      shannonGithubRepos: null,
      pentestgptUrl: null,
      bountyContext: null,
      engagementId: engagementIdRaw || null,
      engagementOperator: operator != null ? String(operator).trim() || null : null,
      identityCtrl,
      navegation: null,
    });
  });

  const doneEvt = [...events].reverse().find((e) => e && typeof e === 'object' && e.type === 'done');
  return {
    findings: Array.isArray(doneEvt?.findings) ? doneEvt.findings : [],
    runId: doneEvt?.runId ?? null,
    stats: doneEvt?.stats ?? null,
    errors: events
      .filter((e) => e && typeof e === 'object' && e.type === 'error')
      .map((e) => e.message || JSON.stringify(e)),
  };
}
