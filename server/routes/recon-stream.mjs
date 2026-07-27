import { createHash, randomBytes } from 'node:crypto';
import { parseReconTarget } from '../modules/recon-target.js';
import {
  computeEngagementAuthorizationBinding,
  getEngagement,
  preRunChecklist,
} from '../modules/engagement.mjs';
import {
  createEngagementScopePolicy,
  parseOutOfScopeClientInput,
} from '../modules/scope.js';
import {
  gateModules,
  applyWatermarkHeaders,
  expandIntrusiveRunModules,
  isIntrusive,
} from '../modules/opsec.mjs';
import { createIdentityController, normalizeIdentityOptions } from '../modules/identity-controller.mjs';
import { getShannonCapabilities } from '../modules/shannon-capabilities.js';
import { quickValidateTor, isNavigatorModeActive } from '../modules/navegation.js';
import {
  requireScope,
  reconBodyIsIntrusive,
  audit as auditAuth,
} from '../modules/auth.js';
import { newnym as torNewnym } from '../modules/tor-control.js';
import {
  beginTorStrictScope,
  refuseToRun as torRefuseToRun,
} from '../modules/tor-strict.js';
import { normalizeOpenrouterOnlyFlag } from '../modules/ai-dual-report.js';
import { reconHttpContext } from '../lib/http-history.mjs';
import { runIntegratedFrameSeven } from '../integrations/frameseven-runner.mjs';
import {
  inspectFrameSevenBinaryIdentity,
  resolveFrameSevenBinary,
} from '../integrations/frameseven-adapter.mjs';
import {
  FRAMESEVEN_OFFENSIVE_TOOLS_ARG_V1,
  FRAMESEVEN_OFFENSIVE_TOOLS_V1,
} from '../integrations/frameseven-policy.mjs';
import { resolveVigoliumBinary } from '../../bridge/vigolium-config.mjs';
import { inspectVigoliumBinaryIdentity } from '../../bridge/vigolium-binary-integrity.mjs';
import {
  buildManualReconPlan,
  createManualReconApprovalStore,
} from '../modules/manual-recon-approval.mjs';

function normalizeManualModules(body = {}) {
  let modules = Array.isArray(body.modules) ? body.modules.map(String) : [];
  const navigatorActive = isNavigatorModeActive({
    navigatorMode: body.navigatorMode === true,
    navegation: body.navegation && typeof body.navegation === 'object' ? body.navegation : null,
  });
  const fullPreset = body.fullPreset === true || String(body.playbook || '').trim() === 'full-recon';
  if (!navigatorActive || fullPreset) {
    modules = modules.filter((moduleId) => moduleId !== 'navegation');
  }
  return [...new Set(modules.map((moduleId) => String(moduleId).trim()).filter(Boolean))];
}

function normalizedVigoliumAgent(value) {
  const agent = String(value || '').trim().toLowerCase();
  return ['none', 'audit', 'swarm', 'autopilot'].includes(agent) ? agent : 'none';
}

function normalizedExecutionEngine(value) {
  const engine = String(value || '').trim().toLowerCase();
  return ['node', 'go', 'both'].includes(engine) ? engine : 'node';
}

function opaqueBinding(value) {
  const normalized = String(value || '').trim();
  return normalized
    ? createHash('sha256').update(normalized, 'utf8').digest('hex')
    : null;
}

export function registerReconStreamRoutes(app, deps) {
  const {
    runPipeline,
    validateCsrfToken,
    allowReconRequest,
    ROOT,
    httpHistory,
    getEngagementImpl = getEngagement,
    getShannonCapabilitiesImpl = getShannonCapabilities,
    quickValidateTorImpl = quickValidateTor,
    torNewnymImpl = torNewnym,
    runIntegratedFrameSevenImpl = runIntegratedFrameSeven,
    inspectFrameSevenBinaryIdentityImpl = inspectFrameSevenBinaryIdentity,
    resolveFrameSevenBinaryImpl = resolveFrameSevenBinary,
    inspectVigoliumBinaryIdentityImpl = inspectVigoliumBinaryIdentity,
    resolveVigoliumBinaryImpl = resolveVigoliumBinary,
    auditAuthImpl = auditAuth,
    env = process.env,
  } = deps;
  const {
    normalizeHeadersForHistory,
    recordReconHttpHistory,
    safeJsonBodyForHistory,
  } = httpHistory;
  const manualApprovalStore = deps.manualApprovalStore
    || createManualReconApprovalStore({
      ttlMs: Number(env.GHOSTRECON_MANUAL_APPROVAL_TTL_MS || 120_000),
    });
  const buildResolvedManualPlan = ({
    body,
    target,
    modules,
    expandedModules,
    intrusiveModules,
    engagementId,
    engagementBinding,
    opsecProfile,
    frameSevenIdentity,
    vigoliumIdentity,
  }) => {
    const includeFrameSeven = body.includeFrameSeven === true;
    const vigoliumAgent = normalizedVigoliumAgent(body.vigoliumAgent);
    const vigoliumRequested = expandedModules.some((moduleId) => (
      String(moduleId || '').replace(/-/g, '_').startsWith('vigolium_')
    ));
    const tor = body.tor && typeof body.tor === 'object' ? body.tor : {};
    const torStrict = tor.strict === true
      || String(env.GHOSTRECON_TOR_STRICT || '').trim() === '1';
    const torRequired = tor.required === true
      || torStrict
      || String(env.GHOSTRECON_TOR_REQUIRED || '').trim() === '1';
    const identity = body.identity && typeof body.identity === 'object' ? body.identity : {};
    return buildManualReconPlan({
      target,
      engagementId,
      engagementBinding,
      selectedModules: modules,
      expandedModules,
      intrusiveModules,
      execution: {
        exactMatch: body.exactMatch === true,
        kaliMode: body.kaliMode === true,
        profile: body.profile,
        opsecProfile,
        engine: normalizedExecutionEngine(body.engine),
        playbook: body.playbook,
        fullPreset: body.fullPreset === true,
        navigatorMode: body.navigatorMode === true,
        torRequired,
        torStrict,
        identityEnabled: identity.enabled === true,
        identityBehavior: identity.behavior === true,
        identityRotation: identity.rotation,
        proxyCount: Array.isArray(identity.proxyPool) ? identity.proxyPool.length : 0,
        outOfScope: parseOutOfScopeClientInput(body.outOfScope),
      },
      frameSeven: {
        enabled: includeFrameSeven,
        authenticated: includeFrameSeven && body.frameSevenAuth === true,
        profile: includeFrameSeven ? 'offensive_v1' : null,
        tools: includeFrameSeven ? FRAMESEVEN_OFFENSIVE_TOOLS_V1 : [],
        timeoutMs: 30_000,
        toolTimeoutMs: 300_000,
        concurrency: 10,
        rate: 100,
        identity: frameSevenIdentity,
      },
      vigolium: {
        enabled: vigoliumRequested,
        agent: vigoliumAgent,
        strategy: body.vigoliumStrategy,
        useCodex: body.vigoliumUseCodex === true,
        modules: body.vigoliumModules,
        moduleTags: Array.isArray(body.vigoliumModuleTags)
          ? body.vigoliumModuleTags
          : body.vigoliumModuleTag
            ? [body.vigoliumModuleTag]
            : [],
        auditMode: body.vigoliumAuditMode,
        only: body.vigoliumOnly,
        reportOnly: body.vigoliumReportOnly,
        htmlReport: body.vigoliumHtmlReport === true,
        sourceBinding: opaqueBinding(body.vigoliumSource),
        identity: vigoliumIdentity,
      },
    });
  };

  const prepareManualApprovalPlan = async (body = {}, principal = null, signal = null) => {
    const throwIfAborted = () => {
      if (signal?.aborted) {
        throw signal.reason || Object.assign(new Error('preflight manual cancelado'), {
          name: 'AbortError',
          code: 'PROCESS_ABORTED',
        });
      }
    };
    const fail = (code, message, details = null) => {
      const error = new Error(message);
      error.code = code;
      if (details) Object.assign(error, details);
      return error;
    };

    throwIfAborted();
    const parsed = parseReconTarget(body.domain);
    if (!parsed.ok) {
      throw fail('MANUAL_RECON_TARGET_INVALID', parsed.message || 'alvo inválido');
    }
    const target = parsed.target;
    const includeFrameSeven = body.includeFrameSeven === true;
    if (body.frameSevenAuth === true && !includeFrameSeven) {
      throw fail(
        'MANUAL_RECON_FRAMESEVEN_AUTH_INVALID',
        'FrameSeven autenticado exige includeFrameSeven=true',
      );
    }
    const modules = normalizeManualModules(body);
    const engine = normalizedExecutionEngine(body.engine);
    const vigoliumAgent = normalizedVigoliumAgent(body.vigoliumAgent);
    const expandedModules = expandIntrusiveRunModules({
      modules: includeFrameSeven ? [...modules, 'frameseven_active'] : modules,
      engine,
      vigoliumAgent,
    });
    const intrusiveModules = expandedModules.filter((moduleId) => isIntrusive(moduleId));
    const vigoliumRequested = expandedModules.some((moduleId) => (
      String(moduleId || '').replace(/-/g, '_').startsWith('vigolium_')
    ));
    const requestedVigoliumInputFile = String(
      body.vigoliumInputFile || env.GHOSTRECON_VIGOLIUM_INPUT_FILE || '',
    ).trim();
    const requestedVigoliumInputType = String(
      body.vigoliumInputType || env.GHOSTRECON_VIGOLIUM_INPUT_TYPE || '',
    ).trim();
    if (vigoliumRequested && (requestedVigoliumInputFile || requestedVigoliumInputType)) {
      throw fail(
        'VIGOLIUM_INPUT_SCOPE_UNSEALED',
        'Vigolium -T está desativado no RUN até todos os alvos do arquivo serem validados e selados',
      );
    }

    const engagementId = String(body.engagementId || '').trim();
    let engagement = null;
    if (engagementId) {
      engagement = await getEngagementImpl(engagementId, { signal });
      throwIfAborted();
      if (!engagement) {
        throw fail('MANUAL_RECON_ENGAGEMENT_NOT_FOUND', 'engagement informado não foi encontrado');
      }
    }
    const engagementBinding = computeEngagementAuthorizationBinding(
      engagement,
      engagementId,
    );
    const checklist = preRunChecklist({
      engagement,
      target,
      modules: expandedModules,
      playbook: String(body.playbook || '').trim() || null,
      requireFormalAuthorization: intrusiveModules.length > 0,
      intrusiveModules,
    });
    if (!checklist.ok) {
      throw fail(
        'MANUAL_RECON_PREFLIGHT_BLOCKED',
        'Pré-checklist de engagement/escopo bloqueou o plano',
        { checklist },
      );
    }
    const opsecProfile = ['passive', 'stealth', 'standard', 'aggressive'].includes(
      String(body.opsecProfile || env.GHOSTRECON_OPSEC_PROFILE || 'standard')
        .trim()
        .toLowerCase(),
    )
      ? String(body.opsecProfile || env.GHOSTRECON_OPSEC_PROFILE || 'standard').trim().toLowerCase()
      : 'standard';
    const opsecGate = gateModules({
      modules: expandedModules,
      profile: opsecProfile,
      // A decisão humana ocorre no endpoint separado. Aqui apenas validamos se
      // o perfil/ROE admite que o plano seja apresentado para aprovação.
      confirm: true,
      engagement,
    });
    if (!opsecGate.ok) {
      throw fail('MANUAL_RECON_OPSEC_BLOCKED', opsecGate.reason || 'OPSEC bloqueou o plano');
    }

    let frameSevenIdentity = null;
    if (includeFrameSeven) {
      throwIfAborted();
      const binary = resolveFrameSevenBinaryImpl(ROOT, env);
      frameSevenIdentity = await inspectFrameSevenBinaryIdentityImpl(binary);
      throwIfAborted();
    }
    let vigoliumIdentity = null;
    if (vigoliumRequested) {
      throwIfAborted();
      const resolved = await resolveVigoliumBinaryImpl(ROOT, {
        preferPath: body.vigoliumPreferPath === true || body.kaliMode === true,
      });
      const binary = resolved?.binary || resolved?.bin;
      if (!binary) {
        throw fail('MANUAL_RECON_VIGOLIUM_UNAVAILABLE', 'binário Vigolium indisponível');
      }
      vigoliumIdentity = await inspectVigoliumBinaryIdentityImpl(binary);
      throwIfAborted();
    }

    const plan = buildResolvedManualPlan({
      body,
      target,
      modules,
      expandedModules,
      intrusiveModules,
      engagementId,
      engagementBinding,
      opsecProfile,
      frameSevenIdentity,
      vigoliumIdentity,
    });
    return {
      plan,
      checklist,
      engagement,
      engagementBinding,
      frameSevenIdentity,
      vigoliumIdentity,
      ownerSub: String(principal?.sub || '').trim(),
    };
  };

  const intrusiveRequestCheck = (req) => (
    req.body?.includeFrameSeven === true || reconBodyIsIntrusive(req.body)
  );

  app.post('/api/recon/preflight', requireScope('recon.run', {
    intrusiveCheck: intrusiveRequestCheck,
  }), async (req, res) => {
    if (!validateCsrfToken(req)) {
      res.status(403).json({ ok: false, code: 'CSRF_INVALID', error: 'CSRF token inválido/ausente' });
      return;
    }
    try {
      const prepared = await prepareManualApprovalPlan(req.body, req.principal);
      let approval = null;
      if (prepared.plan.requiresHumanApproval) {
        approval = manualApprovalStore.issue({
          plan: prepared.plan,
          ownerSub: prepared.ownerSub,
        });
      }
      auditAuthImpl(req, req.principal, 'allow', {
        action: 'recon.manual_plan.issue',
        target: prepared.plan.target,
        planHash: prepared.plan.hash,
        engagementId: prepared.plan.engagement.id,
        intrusive: prepared.plan.requiresHumanApproval,
      });
      res.json({
        ok: true,
        requiresApproval: prepared.plan.requiresHumanApproval,
        plan: prepared.plan,
        approval,
      });
    } catch (error) {
      auditAuthImpl(req, req.principal, 'deny', {
        action: 'recon.manual_plan.issue',
        reason: error?.code || 'preflight_failed',
      });
      res.status(400).json({
        ok: false,
        code: error?.code || 'MANUAL_RECON_PREFLIGHT_FAILED',
        error: error?.message || 'preflight manual falhou',
        ...(error?.checklist ? { checklist: error.checklist } : {}),
      });
    }
  });

  app.post('/api/recon/approval', requireScope('recon.intrusive'), async (req, res) => {
    if (!validateCsrfToken(req)) {
      res.status(403).json({ ok: false, code: 'CSRF_INVALID', error: 'CSRF token inválido/ausente' });
      return;
    }
    try {
      const approval = manualApprovalStore.decide({
        approvalId: req.body?.approvalId,
        ownerSub: String(req.principal?.sub || '').trim(),
        planHash: req.body?.planHash,
        approved: req.body?.approved === true,
      });
      auditAuthImpl(req, req.principal, approval.status === 'approved' ? 'allow' : 'deny', {
        action: 'recon.manual_plan.decision',
        target: approval.target,
        planHash: approval.planHash,
        approved: approval.status === 'approved',
      });
      res.json({ ok: true, approval });
    } catch (error) {
      auditAuthImpl(req, req.principal, 'deny', {
        action: 'recon.manual_plan.decision',
        reason: error?.code || 'approval_failed',
      });
      res.status(400).json({
        ok: false,
        code: error?.code || 'MANUAL_RECON_APPROVAL_FAILED',
        error: error?.message || 'aprovação manual falhou',
      });
    }
  });

  app.post('/api/recon/stream', requireScope('recon.run', {
    // O runner manual do FrameSeven usa o perfil ofensivo explícito. Portanto,
    // mesmo sem auth-browser, ele permanece intrusivo e exige recon.intrusive.
    intrusiveCheck: intrusiveRequestCheck,
  }), async (req, res) => {
  res.setHeader('Content-Type', 'application/x-ndjson; charset=utf-8');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('X-Accel-Buffering', 'no');

  const controller = new AbortController();
  const abortFromClient = (source) => {
    if (controller.signal.aborted) return;
    const error = new Error(`recon manual cancelado: cliente desconectado (${source})`);
    error.name = 'AbortError';
    error.code = 'CLIENT_DISCONNECTED';
    controller.abort(error);
  };
  const onRequestAborted = () => {
    abortFromClient('request_aborted');
    cleanupAbortListeners();
  };
  const onResponseClose = () => {
    if (!res.writableEnded) abortFromClient('response_close');
    cleanupAbortListeners();
  };
  let abortListenersCleaned = false;
  const cleanupAbortListeners = () => {
    if (abortListenersCleaned) return;
    abortListenersCleaned = true;
    req.removeListener('aborted', onRequestAborted);
    res.removeListener('close', onResponseClose);
    res.removeListener('finish', cleanupAbortListeners);
  };
  req.once('aborted', onRequestAborted);
  res.once('close', onResponseClose);
  res.once('finish', cleanupAbortListeners);
  const endResponse = () => {
    if (!res.destroyed && !res.writableEnded) res.end();
    cleanupAbortListeners();
  };

  const send = (obj) => {
    if (res.destroyed || res.writableEnded) return false;
    return res.write(`${JSON.stringify(obj)}\n`);
  };
  const throwIfCancelled = () => {
    if (controller.signal.aborted) {
      throw controller.signal.reason || Object.assign(new Error('recon manual cancelado'), {
        name: 'AbortError',
      });
    }
  };

  if (!validateCsrfToken(req)) {
    send({ type: 'error', message: 'CSRF token inválido/ausente' });
    endResponse();
    return;
  }

  if (!allowReconRequest(req)) {
    send({ type: 'error', message: 'Rate limit — aguarde antes de novo recon' });
    endResponse();
    return;
  }

  const domainRaw = req.body?.domain;
  let modules = normalizeManualModules(req.body);
  const exactMatch = Boolean(req.body?.exactMatch);
  const kaliMode = Boolean(req.body?.kaliMode);
  const profile = String(req.body?.profile || 'standard')
    .trim()
    .toLowerCase();
  const includeFrameSeven = req.body?.includeFrameSeven === true;
  if (req.body?.frameSevenAuth === true && !includeFrameSeven) {
    send({ type: 'error', message: 'FrameSeven autenticado exige includeFrameSeven=true' });
    endResponse();
    return;
  }
  const auth =
    req.body?.auth && typeof req.body.auth === 'object'
      ? {
          headers: req.body.auth.headers && typeof req.body.auth.headers === 'object' ? req.body.auth.headers : {},
          cookie: req.body.auth.cookie ? String(req.body.auth.cookie) : '',
        }
      : null;

  const parsed = parseReconTarget(domainRaw);
  if (!parsed.ok) {
    send({ type: 'error', message: parsed.message || 'Alvo inválido' });
    endResponse();
    return;
  }

  const domain = parsed.target;

  const engagementIdRaw = req.body?.engagementId != null ? String(req.body.engagementId).trim() : '';
  const operatorRaw = req.body?.operator != null ? String(req.body.operator).trim() : '';
  const rawOpsec = String(req.body?.opsecProfile || process.env.GHOSTRECON_OPSEC_PROFILE || 'standard')
    .trim()
    .toLowerCase();
  const allowedOpsec = new Set(['passive', 'stealth', 'standard', 'aggressive']);
  const opsecProfile = allowedOpsec.has(rawOpsec) ? rawOpsec : 'standard';
  const confirmActive = Boolean(req.body?.confirmActive);
  const playbookNameForCheck =
    req.body?.playbook != null ? String(req.body.playbook).trim() : '';
  const navigatorMode = Boolean(req.body?.navigatorMode === true);
  const navegationBody =
    req.body?.navegation && typeof req.body.navegation === 'object' ? req.body.navegation : null;
  const navigatorActive = isNavigatorModeActive({ navigatorMode, navegation: navegationBody });
  const isFullPresetRun =
    req.body?.fullPreset === true || playbookNameForCheck === 'full-recon';

  if (!navigatorActive || isFullPresetRun) {
    modules = modules.filter((m) => m !== 'navegation');
  }
  const modulesForOpsecGate = expandIntrusiveRunModules({
    modules: includeFrameSeven ? [...modules, 'frameseven_active'] : modules,
    engine: req.body?.engine,
    vigoliumAgent: req.body?.vigoliumAgent,
  });
  const intrusiveModulesForRun = modulesForOpsecGate.filter((moduleId) => isIntrusive(moduleId));
  const requiresFormalAuthorization = intrusiveModulesForRun.length > 0;
  let manualApprovalGranted = !requiresFormalAuthorization;
  let manualReconPlan = null;
  const vigoliumRequested = modulesForOpsecGate.some((moduleId) => (
    String(moduleId || '').replace(/-/g, '_').startsWith('vigolium_')
  ));
  const requestedVigoliumInputFile = String(
    req.body?.vigoliumInputFile || env.GHOSTRECON_VIGOLIUM_INPUT_FILE || '',
  ).trim();
  const requestedVigoliumInputType = String(
    req.body?.vigoliumInputType || env.GHOSTRECON_VIGOLIUM_INPUT_TYPE || '',
  ).trim();
  if (vigoliumRequested && (requestedVigoliumInputFile || requestedVigoliumInputType)) {
    auditAuthImpl(req, req.principal, 'deny', {
      action: 'recon.stream.vigolium_input_file',
      target: domain,
      reason: 'unsealed_multi_target_input',
    });
    send({
      type: 'error',
      code: 'VIGOLIUM_INPUT_SCOPE_UNSEALED',
      message:
        'Vigolium -T está desativado no RUN: arquivos arbitrários podem declarar alvos fora do escopo; use o alvo validado do recon',
    });
    endResponse();
    return;
  }

  let engagement = null;
  if (engagementIdRaw) {
    try {
      engagement = await getEngagementImpl(engagementIdRaw, { signal: controller.signal });
    } catch (e) {
      send({ type: 'error', message: `engagement: ${e?.message || e}` });
      endResponse();
      return;
    }
    if (!engagement) {
      send({ type: 'error', message: `engagement "${engagementIdRaw}" não encontrado` });
      endResponse();
      return;
    }
  }
  const engagementAuthorizationBinding = computeEngagementAuthorizationBinding(
    engagement,
    engagementIdRaw,
  );

  const checklist = preRunChecklist({
    engagement,
    target: domain,
    modules: modulesForOpsecGate,
    playbook: playbookNameForCheck || null,
    requireFormalAuthorization: requiresFormalAuthorization,
    intrusiveModules: intrusiveModulesForRun,
  });
  if (!checklist.ok) {
    send({
      type: 'error',
      message: 'Pré-checklist (engagement / escopo) falhou — ver campo checklist',
      checklist,
    });
    endResponse();
    return;
  }
  for (const w of checklist.warnings || []) {
    send({ type: 'log', msg: `[engagement] ${w}`, level: 'warn' });
  }

  let expectedFrameSevenBinaryIdentity = null;
  if (includeFrameSeven) {
    try {
      throwIfCancelled();
      const frameSevenBinary = resolveFrameSevenBinaryImpl(ROOT, env);
      expectedFrameSevenBinaryIdentity = await inspectFrameSevenBinaryIdentityImpl(frameSevenBinary);
      throwIfCancelled();
    } catch (e) {
      send({
        type: 'error',
        message: controller.signal.aborted
          ? 'FrameSeven: preparação cancelada'
          : 'FrameSeven: binário indisponível ou identidade não pôde ser validada',
      });
      endResponse();
      return;
    }
  }

  let gate;
  try {
    gate = gateModules({
      modules: modulesForOpsecGate,
      profile: opsecProfile,
      // A aprovação real será consumida depois que as identidades de todos os
      // motores forem seladas. Aqui validamos apenas perfil e ROE.
      confirm: true,
      engagement,
    });
  } catch (e) {
    send({ type: 'error', message: `OPSEC: ${e?.message || e}` });
    endResponse();
    return;
  }
  if (!gate.ok) {
    send({
      type: 'error',
      message: gate.reason || 'Módulos bloqueados por perfil OPSEC',
      opsec: { blocked: gate.blocked, needsConfirm: gate.needsConfirm, profile: gate.profile },
    });
    endResponse();
    return;
  }

  const revalidateEngagementForExecution = async (stage) => {
    throwIfCancelled();
    const currentEngagement = engagementIdRaw
      ? await getEngagementImpl(engagementIdRaw, { signal: controller.signal })
      : null;
    throwIfCancelled();
    if (engagementIdRaw && !currentEngagement) {
      const error = new Error(`engagement "${engagementIdRaw}" removido antes da execução`);
      error.code = 'ENGAGEMENT_INVALIDATED';
      throw error;
    }
    const currentBinding = computeEngagementAuthorizationBinding(
      currentEngagement,
      engagementIdRaw,
    );
    if (currentBinding !== engagementAuthorizationBinding) {
      const error = new Error(
        'autorização do engagement mudou após o pré-checklist; inicie um novo RUN',
      );
      error.code = 'ENGAGEMENT_CHANGED';
      throw error;
    }
    const currentChecklist = preRunChecklist({
      engagement: currentEngagement,
      target: domain,
      modules: modulesForOpsecGate,
      playbook: playbookNameForCheck || null,
      requireFormalAuthorization: requiresFormalAuthorization,
      intrusiveModules: intrusiveModulesForRun,
    });
    if (!currentChecklist.ok) {
      const error = new Error(
        `engagement inválido em ${stage}: ${currentChecklist.errors.join('; ')}`,
      );
      error.code = 'ENGAGEMENT_INVALIDATED';
      error.checklist = currentChecklist;
      throw error;
    }
    const currentGate = gateModules({
      modules: modulesForOpsecGate,
      profile: opsecProfile,
      confirm: manualApprovalGranted,
      engagement: currentEngagement,
    });
    if (!currentGate.ok) {
      const error = new Error(currentGate.reason || `OPSEC bloqueou o RUN em ${stage}`);
      error.code = 'ENGAGEMENT_INVALIDATED';
      error.opsec = currentGate;
      throw error;
    }
    engagement = currentEngagement;
    send({
      type: 'preflight_revalidated',
      stage,
      engagementId: engagementIdRaw || null,
      bindingMatches: true,
    });
    return currentEngagement
      ? createEngagementScopePolicy({
          rootDomain: domain,
          engagement: currentEngagement,
          engagementId: engagementIdRaw,
          authorizationBinding: currentBinding,
        })
      : null;
  };

  let authForPipeline = auth;
  if (engagementIdRaw) {
    const baseHeaders = { ...(auth?.headers && typeof auth.headers === 'object' ? auth.headers : {}) };
    authForPipeline = {
      headers: applyWatermarkHeaders(baseHeaders, {
        engagementId: engagementIdRaw,
        operator: operatorRaw || undefined,
      }),
      cookie: auth?.cookie ? String(auth.cookie) : '',
    };
  }

  const shannonPrecheck = req.body?.shannonPrecheck !== false;
  const shannonSkipDepsVerify = Boolean(req.body?.shannonSkipDepsVerify);

  const extraPathRaw = typeof req.body?.extraPath === 'string' ? req.body.extraPath : '';
  if (extraPathRaw.trim()) {
    // PATH é estado global do processo. Alterá-lo por requisição permite que
    // dois recons concorrentes selecionem binários um do outro. Falhe fechado:
    // ferramentas adicionais devem ser configuradas no ambiente antes do boot,
    // onde a identidade escolhida pode ser selada e revalidada.
    send({
      type: 'error',
      code: 'REQUEST_PATH_OVERRIDE_DISABLED',
      message: 'extraPath por requisição está desativado; configure PATH antes de iniciar o GHOSTRECON',
    });
    endResponse();
    return;
  }
  let expectedVigoliumBinaryIdentity = null;
  if (vigoliumRequested) {
    try {
      throwIfCancelled();
      const resolvedVigolium = await resolveVigoliumBinaryImpl(ROOT, {
        preferPath: req.body?.vigoliumPreferPath === true || kaliMode,
      });
      const vigoliumBinary = resolvedVigolium?.binary || resolvedVigolium?.bin;
      if (!vigoliumBinary) throw new Error('binário Vigolium indisponível');
      expectedVigoliumBinaryIdentity = await inspectVigoliumBinaryIdentityImpl(vigoliumBinary);
      throwIfCancelled();
    } catch (error) {
      send({
        type: 'error',
        message: controller.signal.aborted
          ? 'Vigolium: preparação cancelada'
          : `Vigolium: identidade do binário não pôde ser selada (${error?.message || error})`,
      });
      endResponse();
      return;
    }
  }

  manualReconPlan = buildResolvedManualPlan({
    body: req.body,
    target: domain,
    modules,
    expandedModules: modulesForOpsecGate,
    intrusiveModules: intrusiveModulesForRun,
    engagementId: engagementIdRaw,
    engagementBinding: engagementAuthorizationBinding,
    opsecProfile,
    frameSevenIdentity: expectedFrameSevenBinaryIdentity,
    vigoliumIdentity: expectedVigoliumBinaryIdentity,
  });
  send({
    type: 'manual_effective_plan',
    plan: manualReconPlan,
  });
  if (requiresFormalAuthorization) {
    const providedApproval = req.body?.manualApproval
      && typeof req.body.manualApproval === 'object'
      ? req.body.manualApproval
      : null;
    if (!confirmActive || !providedApproval?.approvalId) {
      auditAuthImpl(req, req.principal, 'deny', {
        action: 'recon.manual_plan.consume',
        target: domain,
        planHash: manualReconPlan.hash,
        reason: 'plan_bound_approval_required',
      });
      send({
        type: 'error',
        code: 'MANUAL_RECON_APPROVAL_REQUIRED',
        message:
          'Plano intrusivo exige Confirmar ativo e aprovação vinculada ao hash emitido por /api/recon/preflight',
        planHash: manualReconPlan.hash,
      });
      endResponse();
      return;
    }
    try {
      const clientHashMismatch = Boolean(
        providedApproval.planHash
        && String(providedApproval.planHash) !== manualReconPlan.hash,
      );
      manualApprovalStore.consume({
        approvalId: providedApproval.approvalId,
        ownerSub: String(req.principal?.sub || '').trim(),
        // O hash vem do plano recomputado no servidor. O ID opaco referencia
        // o registro aprovado; o cliente não consegue substituir esse binding.
        planHash: manualReconPlan.hash,
        target: manualReconPlan.target,
        engagementBinding: manualReconPlan.engagement.authorizationBinding,
      });
      if (clientHashMismatch) {
        const mismatch = new Error('plano mudou depois da confirmação');
        mismatch.code = 'MANUAL_RECON_APPROVAL_PLAN_MISMATCH';
        throw mismatch;
      }
      manualApprovalGranted = true;
      auditAuthImpl(req, req.principal, 'allow', {
        action: 'recon.manual_plan.consume',
        target: domain,
        planHash: manualReconPlan.hash,
        engagementId: engagementIdRaw || null,
      });
      send({
        type: 'manual_approval_consumed',
        planHash: manualReconPlan.hash,
        approvalId: providedApproval.approvalId,
      });
    } catch (error) {
      auditAuthImpl(req, req.principal, 'deny', {
        action: 'recon.manual_plan.consume',
        target: domain,
        planHash: manualReconPlan.hash,
        reason: error?.code || 'approval_invalid',
      });
      send({
        type: 'error',
        code: error?.code || 'MANUAL_RECON_APPROVAL_INVALID',
        message: error?.message || 'aprovação manual inválida',
        planHash: manualReconPlan.hash,
      });
      endResponse();
      return;
    }
  }

  if (modules.includes('shannon_whitebox') && shannonPrecheck && !shannonSkipDepsVerify) {
    try {
      const sc = await getShannonCapabilitiesImpl({
        ghostRoot: ROOT,
        signal: controller.signal,
      });
      throwIfCancelled();
      if (!sc.ok) {
        send({
          type: 'error',
          message: `Shannon: dependências incompletas — ${sc.message}`,
        });
        endResponse();
        return;
      }
    } catch (e) {
      send({ type: 'error', message: `Shannon: falha ao verificar dependências — ${e?.message || e}` });
      endResponse();
      return;
    }
  }

  // ── Tor enforcement ────────────────────────────────────────────────────
  // Body shape:
  //   tor: {
  //     required: true,            // aborta o run se o tunnel não validar
  //     strict: true,              // exige tor-strict prereqs (proxychains, DNS lockdown…)
  //     newnymBeforeRun: true,     // sinaliza NEWNYM antes do pipeline iniciar
  //     perTargetCircuit: true,    // injeta isolation user/pass no SOCKS5 (IsolateSOCKSAuth)
  //     dnsLeakHost: 'check.tor…' // host usado para o DNS leak test (opt)
  //   }
  // Default: se GHOSTRECON_TOR_REQUIRED=1 ou GHOSTRECON_TOR_STRICT=1, força.
  const torOpts = req.body?.tor && typeof req.body.tor === 'object' ? req.body.tor : {};
  const torStrictWanted =
    torOpts.strict === true ||
    String(process.env.GHOSTRECON_TOR_STRICT || '').trim() === '1';
  const torRequired =
    torOpts.required === true ||
    torStrictWanted ||
    String(process.env.GHOSTRECON_TOR_REQUIRED || '').trim() === '1';
  let cleanupTorStrictScope = null;

  // STRICT prereq check — se faltar algo (proxychains, DNS lockdown, SOCKS,
  // ControlPort, conf), abortamos antes do pipeline para evitar leaks parciais.
  if (torStrictWanted) {
    cleanupTorStrictScope = beginTorStrictScope();
    const refusal = torRefuseToRun();
    if (refusal) {
      if (cleanupTorStrictScope) cleanupTorStrictScope();
      auditAuthImpl(req, req.principal, 'deny', {
        action: 'recon.stream.tor_strict_prereqs',
        target: domain,
        reason: 'strict_prereqs_failed',
        missing: refusal.missing,
      });
      send({
        type: 'error',
        message: 'tor.strict: pré-requisitos em falta — ver `missing`',
        missing: refusal.missing,
        checks: refusal.checks,
      });
      endResponse();
      return;
    }
  }
  let torValidation = null;
  if (torRequired) {
    send({ type: 'log', msg: '[tor] enforcement activo — a validar tunnel antes do recon', level: 'info' });
    try {
      torValidation = await quickValidateTorImpl({
        timeoutMs: 12_000,
        signal: controller.signal,
      });
      throwIfCancelled();
    } catch (e) {
      torValidation = { validated: false, error: e?.message || String(e) };
    }
    if (!torValidation.validated) {
      if (cleanupTorStrictScope) cleanupTorStrictScope();
      auditAuthImpl(req, req.principal, 'deny', {
        action: 'recon.stream.tor_required',
        target: domain,
        reason: 'tor_validation_failed',
        torValidation,
      });
      send({
        type: 'error',
        message: 'Tor enforcement: tunnel não validado — ver detalhes em torValidation',
        torValidation,
      });
      endResponse();
      return;
    }
    send({
      type: 'log',
      msg: `[tor] OK — exitIp=${torValidation.tor?.ip} bootstrap=${torValidation.control?.bootstrap?.tag} (${torValidation.durationMs}ms)`,
      level: 'info',
    });
    if (torOpts.newnymBeforeRun === true) {
      try {
        await torNewnymImpl({ timeoutMs: 5_000, signal: controller.signal });
        throwIfCancelled();
        send({ type: 'log', msg: '[tor] NEWNYM sinalizado', level: 'info' });
      } catch (e) {
        send({ type: 'log', msg: `[tor] NEWNYM falhou: ${e?.message || e}`, level: 'warn' });
      }
    }
  }

  const identityOpts = normalizeIdentityOptions(modules, req.body?.identity);
  // ID temporário para telemetria do tor-strict (correlacionável com runId
  // depois que saveRun emitir um). Emitimos no stream para o cliente saber.
  const requestRunId = `req-${Date.now().toString(36)}-${randomBytes(4).toString('hex')}`;
  identityOpts.runId = requestRunId;
  identityOpts.target = domain;
  // Quando torRequired + perTargetCircuit, propagamos para identity-controller
  // ativar IsolateSOCKSAuth com user/pass únicos (circuit dedicado por target).
  if (torRequired && torOpts.perTargetCircuit !== false) {
    identityOpts.isolate = true;
    identityOpts.isolationKey = `${domain}-${Date.now().toString(36)}`;
  }
  const identityCtrl = createIdentityController({ ...identityOpts, modules });
  send({ type: 'meta', requestRunId, torStrict: torStrictWanted, torRequired });
  recordReconHttpHistory({
    requestRunId,
    target: domain,
    source: 'browser',
    method: 'POST',
    url: '/api/recon/stream',
    requestHeaders: normalizeHeadersForHistory(req.headers),
    requestBody: safeJsonBodyForHistory(req.body),
    status: 200,
    statusText: 'stream',
    ok: true,
    durationMs: 0,
    emit: send,
  });

  // Auditoria operacional do início do pipeline (após CSRF/rate-limit/escopo).
  auditAuthImpl(req, req.principal, 'allow', {
    action: 'recon.stream.start',
    target: domain,
    modules,
    expandedModules: modulesForOpsecGate,
    planHash: manualReconPlan?.hash || null,
    kaliMode,
    opsecProfile,
    profile,
    intrusive: requiresFormalAuthorization || reconBodyIsIntrusive(req.body),
    engagementId: engagementIdRaw || null,
    tor: torRequired
      ? {
          required: true,
          exitIp: torValidation?.tor?.ip || null,
          bootstrap: torValidation?.control?.bootstrap?.tag || null,
          perTargetCircuit: torOpts.perTargetCircuit !== false,
          newnymBefore: Boolean(torOpts.newnymBeforeRun),
        }
      : { required: false },
  });

  try {
    throwIfCancelled();
    await revalidateEngagementForExecution('before_integrated_execution');
    await reconHttpContext.run({ requestRunId, target: domain, emit: send }, async () => {
      const runSelectedPipeline = (
        capturedAuth = null,
        integratedEmit = null,
        { signal: stageSignal } = {},
      ) => revalidateEngagementForExecution('immediately_before_pipeline').then((scopePolicy) => runPipeline({
        domain,
        exactMatch,
        modules,
        emit: integratedEmit || send,
        kaliMode,
        auth: capturedAuth || authForPipeline,
        profile,
        outOfScope: req.body?.outOfScope,
        projectName: req.body?.projectName,
        autoAiReports: Boolean(req.body?.autoAiReports),
        aiProviderMode: String(req.body?.aiProviderMode || 'auto'),
        aiUseOpenrouter: req.body?.aiUseOpenrouter !== false,
        aiOpenrouterOnly: normalizeOpenrouterOnlyFlag(req.body?.aiOpenrouterOnly),
        aiPrimaryCloud:
          typeof req.body?.aiPrimaryCloud === 'string'
            ? req.body.aiPrimaryCloud
            : typeof req.body?.aiPrimaryReport === 'string'
              ? req.body.aiPrimaryReport
              : null,
        shannonPrecheck,
        shannonSkipDepsVerify,
        shannonGithubRepos: req.body?.shannonGithubRepos,
        pentestgptUrl: req.body?.pentestgptUrl != null ? String(req.body.pentestgptUrl) : null,
        bountyContext:
          req.body?.bountyContext && typeof req.body.bountyContext === 'object' ? req.body.bountyContext : null,
        engagementId: engagementIdRaw || null,
        engagementOperator: operatorRaw || null,
        scopePolicy,
        identityCtrl,
        navegation: navegationBody,
        navigatorMode: navigatorActive,
        engine: ['node', 'go', 'both'].includes(String(req.body?.engine || '').trim().toLowerCase())
          ? String(req.body.engine).trim().toLowerCase()
          : 'node',
        vigoliumStrategy:
          req.body?.vigoliumStrategy != null
            ? String(req.body.vigoliumStrategy).trim().toLowerCase()
            : req.body?.strategy != null
              ? String(req.body.strategy).trim().toLowerCase()
              : null,
        vigoliumModules: Array.isArray(req.body?.vigoliumModules)
          ? req.body.vigoliumModules.map(String)
          : null,
        vigoliumModuleTags: Array.isArray(req.body?.vigoliumModuleTags)
          ? req.body.vigoliumModuleTags.map(String)
          : null,
        vigoliumModuleTag: req.body?.vigoliumModuleTag != null ? String(req.body.vigoliumModuleTag).trim() : null,
        vigoliumAgent: ['none', 'audit', 'swarm', 'autopilot'].includes(
          String(req.body?.vigoliumAgent || '').trim().toLowerCase(),
        )
          ? String(req.body.vigoliumAgent).trim().toLowerCase()
          : 'none',
        vigoliumSource: req.body?.vigoliumSource != null ? String(req.body.vigoliumSource).trim() : null,
        vigoliumAuthFiles: Array.isArray(req.body?.vigoliumAuthFiles)
          ? req.body.vigoliumAuthFiles.map(String)
          : null,
        vigoliumAuthFile: req.body?.vigoliumAuthFile != null ? String(req.body.vigoliumAuthFile).trim() : null,
        vigoliumAuditMode:
          req.body?.vigoliumAuditMode != null ? String(req.body.vigoliumAuditMode).trim().toLowerCase() : null,
        // `-T` permanece fechado até existir um contrato que enumere, valide e
        // sele cada alvo contido no arquivo antes dos gates.
        vigoliumInputFile: null,
        vigoliumInputType: null,
        vigoliumOnly:
          req.body?.vigoliumOnly != null ? String(req.body.vigoliumOnly).trim() : null,
        vigoliumAuthEntries: Array.isArray(req.body?.vigoliumAuthEntries)
          ? req.body.vigoliumAuthEntries.map(String)
          : null,
        vigoliumAuth:
          req.body?.vigoliumAuth != null ? String(req.body.vigoliumAuth).trim() : null,
        vigoliumHtmlReport: req.body?.vigoliumHtmlReport === true,
        vigoliumReportOnly:
          req.body?.vigoliumReportOnly != null ? String(req.body.vigoliumReportOnly).trim() : null,
        vigoliumPreferPath: req.body?.vigoliumPreferPath === true,
        vigoliumUseCodex: req.body?.vigoliumUseCodex === true,
        vigoliumExpectedIdentity: expectedVigoliumBinaryIdentity,
        signal: stageSignal || controller.signal,
        requestRunId,
      }));
      if (includeFrameSeven) {
        await runIntegratedFrameSevenImpl({
          root: ROOT,
          target: /^https?:\/\//i.test(domain) ? domain : `https://${domain}`,
          authBrowser: req.body?.frameSevenAuth === true,
          tools: FRAMESEVEN_OFFENSIVE_TOOLS_ARG_V1,
          offensiveApproved: manualApprovalGranted === true,
          requestId: requestRunId,
          signal: controller.signal,
          emit: send,
          ownerSub: String(req.principal?.sub || '').trim() || null,
          engagementId: engagementIdRaw || null,
          expectedBinaryIdentity: expectedFrameSevenBinaryIdentity,
          env,
          beforeFrameSevenScan: () => revalidateEngagementForExecution(
            'immediately_before_frameseven',
          ),
          pipeline: runSelectedPipeline,
        });
      } else {
        await runSelectedPipeline();
      }
    });
  } catch (e) {
    send({ type: 'error', message: e?.message || String(e) });
  } finally {
    if (cleanupTorStrictScope) cleanupTorStrictScope();
    cleanupAbortListeners();
  }
  endResponse();
  });
}
