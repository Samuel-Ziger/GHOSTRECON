import { createHmac, randomBytes } from 'node:crypto';
import path from 'node:path';
import { parseReconTarget } from '../modules/recon-target.js';
import { normalizeModuleId } from '../modules/module-ids.mjs';
import {
  computeEngagementAuthorizationBinding,
  getEngagement,
  preRunChecklist,
} from '../modules/engagement.mjs';
import {
  createEngagementScopePolicy,
  mergeOutOfScopeLists,
  parseOutOfScopeEnv,
  parseOutOfScopeClientInput,
} from '../modules/scope.js';
import {
  gateModules,
  applyWatermarkHeaders,
  expandIntrusiveRunModules,
  isIntrusive,
} from '../modules/opsec.mjs';
import {
  createIdentityController,
  resolveEffectiveIdentityConfig,
} from '../modules/identity-controller.mjs';
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
import { resolveReconProfile } from '../modules/runtime-profile.js';
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
import {
  buildVigoliumChildEnv,
  resolveVigoliumBinary,
  resolveVigoliumEffectiveConfig,
} from '../../bridge/vigolium-config.mjs';
import {
  inspectVigoliumAuthFileIdentities,
} from '../../bridge/vigolium-auth-transport.mjs';
import { inspectVigoliumBinaryIdentity } from '../../bridge/vigolium-binary-integrity.mjs';
import {
  inspectVigoliumSourceIdentity,
  resolveVigoliumSourceAllowedRoots,
} from '../../bridge/vigolium-source-integrity.mjs';
import {
  buildManualReconPrivateContext,
  buildManualReconPlan,
  createManualReconApprovalStore,
  summarizeManualReconAuthentication,
} from '../modules/manual-recon-approval.mjs';

function normalizeManualModules(body = {}) {
  let modules = Array.isArray(body.modules)
    ? body.modules.map(normalizeModuleId).filter(Boolean)
    : [];
  const navigatorActive = isNavigatorModeActive({
    navigatorMode: body.navigatorMode === true,
    navegation: body.navegation && typeof body.navegation === 'object' ? body.navegation : null,
  });
  const fullPreset = body.fullPreset === true || String(body.playbook || '').trim() === 'full-recon';
  if (!navigatorActive || fullPreset) {
    modules = modules.filter((moduleId) => moduleId !== 'navegation');
  }
  return [...new Set(modules)];
}

function opaqueBinding(value, bindingKey) {
  const normalized = String(value || '').trim();
  return normalized
    ? createHmac('sha256', bindingKey).update(normalized, 'utf8').digest('hex')
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
    inspectVigoliumAuthFileIdentitiesImpl = inspectVigoliumAuthFileIdentities,
    inspectVigoliumSourceIdentityImpl = inspectVigoliumSourceIdentity,
    resolveVigoliumSourceAllowedRootsImpl = resolveVigoliumSourceAllowedRoots,
    resolveVigoliumBinaryImpl = resolveVigoliumBinary,
    auditAuthImpl = auditAuth,
    env = process.env,
    manualPlanBindingKey = randomBytes(32),
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
  const privatePlanBindingKey = Buffer.from(manualPlanBindingKey);
  if (privatePlanBindingKey.length < 16) {
    throw new Error('manualPlanBindingKey precisa de pelo menos 16 bytes');
  }
  const bindPrivateValue = (value) => opaqueBinding(value, privatePlanBindingKey);
  const vigoliumAuthAllowedRoots = Object.freeze([
    path.resolve(
      String(env.GHOSTRECON_VIGOLIUM_AUTH_ROOT || '').trim()
        || path.join(ROOT, '.runtime', 'vigolium-sessions'),
    ),
  ]);
  const vigoliumSourceAllowedRoots = resolveVigoliumSourceAllowedRootsImpl(ROOT, env);
  const resolveManualRuntimeConfig = (body = {}, modules = []) => {
    const identity = resolveEffectiveIdentityConfig({
      modules,
      identityBody: body.identity,
      env,
    });
    const vigolium = resolveVigoliumEffectiveConfig({
      modules,
      engine: body.engine,
      kaliMode: body.kaliMode === true,
      strategy: body.strategy,
      vigoliumStrategy: body.vigoliumStrategy,
      vigoliumModules: body.vigoliumModules,
      vigoliumModuleTags: body.vigoliumModuleTags,
      vigoliumModuleTag: body.vigoliumModuleTag,
      vigoliumAgent: body.vigoliumAgent,
      vigoliumSource: body.vigoliumSource,
      vigoliumAuthFiles: body.vigoliumAuthFiles,
      vigoliumAuthFile: body.vigoliumAuthFile,
      vigoliumAuthEntries: body.vigoliumAuthEntries,
      vigoliumAuth: body.vigoliumAuth,
      vigoliumInputFile: body.vigoliumInputFile,
      vigoliumInputType: body.vigoliumInputType,
      vigoliumOnly: body.vigoliumOnly,
      vigoliumHtmlReport: body.vigoliumHtmlReport,
      vigoliumReportOnly: body.vigoliumReportOnly,
      vigoliumPreferPath: body.vigoliumPreferPath,
      vigoliumUseCodex: body.vigoliumUseCodex,
      vigoliumVpsProfile: body.vigoliumVpsProfile,
      vigoliumSkipExternalHarvest: body.vigoliumSkipExternalHarvest,
      vigoliumAuditMode: body.vigoliumAuditMode,
    }, { env });
    const vigoliumChildEnv = Object.freeze({
      ...buildVigoliumChildEnv(vigolium, env),
    });
    const torBody = body.tor && typeof body.tor === 'object' ? body.tor : {};
    const torStrict = torBody.strict === true
      || String(env.GHOSTRECON_TOR_STRICT || '').trim() === '1';
    const torRequired = torBody.required === true
      || torStrict
      || String(env.GHOSTRECON_TOR_REQUIRED || '').trim() === '1';
    const tor = Object.freeze({
      required: torRequired,
      strict: torStrict,
      newnymBeforeRun: torRequired && torBody.newnymBeforeRun === true,
      perTargetCircuit: torRequired && torBody.perTargetCircuit !== false,
      dnsLeakHost: String(torBody.dnsLeakHost || '').trim() || null,
    });
    const outOfScope = Object.freeze(mergeOutOfScopeLists(
      parseOutOfScopeEnv(env.GHOSTRECON_OUT_OF_SCOPE),
      parseOutOfScopeClientInput(body.outOfScope),
    ));
    return Object.freeze({
      identity,
      vigolium,
      vigoliumChildEnv,
      tor,
      executionProfile: resolveReconProfile(body.profile).name,
      outOfScope,
    });
  };
  const buildApprovalPrivateContext = (
    body,
    runtimeConfig,
    {
      vigoliumBinaryPath = null,
      vigoliumBinarySource = null,
      vigoliumAuthFileIdentities = [],
      vigoliumSourceIdentity = null,
    } = {},
  ) => buildManualReconPrivateContext({
    request: buildManualReconPrivateContext(body),
    effective: {
      identity: runtimeConfig.identity,
      tor: runtimeConfig.tor,
      vigolium: {
        ...runtimeConfig.vigolium,
        childEnv: runtimeConfig.vigoliumChildEnv,
        binaryPath: vigoliumBinaryPath,
        binarySource: vigoliumBinarySource,
        authFileIdentities: vigoliumAuthFileIdentities,
        sourceIdentity: vigoliumSourceIdentity,
        sourceAllowedRoots: vigoliumSourceAllowedRoots,
      },
    },
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
    runtimeConfig,
    frameSevenIdentity,
    vigoliumIdentity,
    vigoliumBinaryPath = null,
    vigoliumBinarySource = null,
    vigoliumAuthFileIdentities = [],
    vigoliumSourceIdentity = null,
  }) => {
    const includeFrameSeven = body.includeFrameSeven === true;
    const {
      identity,
      vigolium,
      vigoliumChildEnv,
      tor,
    } = runtimeConfig;
    const vigoliumAgent = vigolium.vigoliumAgentMode;
    const vigoliumRequested = expandedModules.some((moduleId) => (
      String(moduleId || '').replace(/-/g, '_').startsWith('vigolium_')
    ));
    const proxyPool = [...identity.proxyPool];
    const navegation = body.navegation && typeof body.navegation === 'object'
      ? body.navegation
      : {};
    const fullPreset = body.fullPreset === true
      || String(body.playbook || '').trim() === 'full-recon';
    const navigatorActive = !fullPreset && isNavigatorModeActive({
      navigatorMode: body.navigatorMode === true,
      navegation,
    });
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
        profile: runtimeConfig.executionProfile,
        opsecProfile,
        engine: vigolium.engineMode,
        playbook: body.playbook,
        fullPreset,
        navigatorMode: navigatorActive,
        navigatorExec: navigatorActive && navegation.exec === true,
        navigatorUserMode: navigatorActive && navegation.userMode === true,
        torRequired: tor.required,
        torStrict: tor.strict,
        torNewnymBeforeRun: tor.newnymBeforeRun,
        torPerTargetCircuit: tor.perTargetCircuit,
        torDnsLeakHostBinding: bindPrivateValue(tor.dnsLeakHost),
        identityEnabled: identity.enabled,
        identityBehavior: identity.behavior,
        identityRotation: identity.rotation,
        identityIsolate: identity.isolate || tor.perTargetCircuit,
        proxyCount: proxyPool.length,
        proxyPoolBinding: proxyPool.length
          ? bindPrivateValue(JSON.stringify(proxyPool))
          : null,
        outOfScope: runtimeConfig.outOfScope,
      },
      authentication: summarizeManualReconAuthentication({
        auth: body.auth,
        vigoliumAuthEntries: vigolium.vigoliumAuthEntries,
        vigoliumAuthFiles: vigolium.vigoliumAuthFiles,
      }, {
        vigoliumEnabled: vigoliumRequested,
      }),
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
        strategy: vigolium.vigoliumStrategy,
        useCodex: vigolium.vigoliumUseCodex,
        modules: vigolium.vigoliumModules,
        moduleTags: vigolium.vigoliumModuleTags,
        auditMode: vigolium.vigoliumAuditMode,
        only: vigolium.vigoliumOnly,
        reportOnly: vigolium.vigoliumReportOnly,
        htmlReport: vigolium.vigoliumHtmlReport,
        preferPath: vigolium.vigoliumPreferPath,
        vpsProfile: vigolium.vigoliumVpsProfile,
        skipExternalHarvest: vigolium.vigoliumSkipExternalHarvest,
        scanTimeoutMs: vigolium.vigoliumTimeoutMs,
        agentTimeoutMs: vigolium.vigoliumAgentTimeoutMs,
        binarySource: vigoliumBinarySource,
        binaryPathBinding: bindPrivateValue(vigoliumBinaryPath),
        sourceMode: body.vigoliumSource
          ? 'request'
          : env.GHOSTRECON_VIGOLIUM_SOURCE
            ? 'environment'
            : 'none',
        sourceBinding: bindPrivateValue(vigolium.vigoliumSource),
        sourceIdentity: vigoliumSourceIdentity,
        childEnvBinding: bindPrivateValue(JSON.stringify(vigoliumChildEnv)),
        authMaterialBinding: bindPrivateValue(JSON.stringify({
          entries: vigolium.vigoliumAuthEntries,
          files: vigolium.vigoliumAuthFiles,
          identities: vigoliumAuthFileIdentities,
        })),
        authFileIdentityCount: vigoliumAuthFileIdentities.length,
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
    const runtimeConfig = resolveManualRuntimeConfig(body, modules);
    const engine = runtimeConfig.vigolium.engineMode;
    const vigoliumAgent = runtimeConfig.vigolium.vigoliumAgentMode;
    const expandedModules = expandIntrusiveRunModules({
      modules: includeFrameSeven ? [...modules, 'frameseven_active'] : modules,
      engine,
      vigoliumAgent,
      includeManualImplicit: true,
      includeManualIntrusive: body.confirmActive === true,
      kaliMode: body.kaliMode === true,
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
    let vigoliumBinaryPath = null;
    let vigoliumBinarySource = null;
    let vigoliumAuthFileIdentities = [];
    let vigoliumSourceIdentity = null;
    if (vigoliumRequested) {
      throwIfAborted();
      const resolved = await resolveVigoliumBinaryImpl(ROOT, {
        preferPath: runtimeConfig.vigolium.vigoliumPreferPath,
        env,
      });
      const binary = resolved?.binary || resolved?.bin;
      if (!binary) {
        throw fail('MANUAL_RECON_VIGOLIUM_UNAVAILABLE', 'binário Vigolium indisponível');
      }
      vigoliumBinaryPath = binary;
      vigoliumBinarySource = resolved?.source || null;
      vigoliumIdentity = await inspectVigoliumBinaryIdentityImpl(binary);
      throwIfAborted();
      if (runtimeConfig.vigolium.vigoliumAuthFiles.length) {
        vigoliumAuthFileIdentities = await inspectVigoliumAuthFileIdentitiesImpl(
          runtimeConfig.vigolium.vigoliumAuthFiles,
          {
            allowedRoots: vigoliumAuthAllowedRoots,
            signal,
          },
        );
        throwIfAborted();
      }
      if (
        runtimeConfig.vigolium.vigoliumSource
        && runtimeConfig.vigolium.vigoliumAgentMode !== 'none'
      ) {
        vigoliumSourceIdentity = await inspectVigoliumSourceIdentityImpl(
          runtimeConfig.vigolium.vigoliumSource,
          {
            allowedRoots: vigoliumSourceAllowedRoots,
            signal,
            timeoutMs: runtimeConfig.vigolium.vigoliumAgentTimeoutMs,
            env,
          },
        );
        throwIfAborted();
      }
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
      runtimeConfig,
      frameSevenIdentity,
      vigoliumIdentity,
      vigoliumBinaryPath,
      vigoliumBinarySource,
      vigoliumAuthFileIdentities,
      vigoliumSourceIdentity,
    });
    const privateContext = buildApprovalPrivateContext(body, runtimeConfig, {
      vigoliumBinaryPath,
      vigoliumBinarySource,
      vigoliumAuthFileIdentities,
      vigoliumSourceIdentity,
    });
    return {
      plan,
      checklist,
      engagement,
      engagementBinding,
      frameSevenIdentity,
      vigoliumIdentity,
      vigoliumBinaryPath,
      vigoliumBinarySource,
      vigoliumAuthFileIdentities,
      vigoliumAuthAllowedRoots,
      vigoliumSourceIdentity,
      vigoliumSourceAllowedRoots,
      runtimeConfig,
      privateContext,
      ownerSub: String(principal?.sub || '').trim(),
    };
  };

  const intrusiveRequestCheck = (req) => {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const modules = normalizeManualModules(body);
    const runtimeConfig = resolveManualRuntimeConfig(body, modules);
    const expanded = expandIntrusiveRunModules({
      modules: body.includeFrameSeven === true
        ? [...modules, 'frameseven_active']
        : modules,
      engine: runtimeConfig.vigolium.engineMode,
      vigoliumAgent: runtimeConfig.vigolium.vigoliumAgentMode,
      includeManualImplicit: true,
      includeManualIntrusive: body.confirmActive === true,
      kaliMode: body.kaliMode === true,
    });
    return expanded.some((moduleId) => isIntrusive(moduleId));
  };

  app.post('/api/recon/preflight', requireScope('recon.run', {
    intrusiveCheck: intrusiveRequestCheck,
  }), async (req, res) => {
    if (!validateCsrfToken(req)) {
      res.status(403).json({ ok: false, code: 'CSRF_INVALID', error: 'CSRF token inválido/ausente' });
      return;
    }
    const preflightController = new AbortController();
    const abortPreflight = (source = 'request_aborted') => {
      if (preflightController.signal.aborted) return;
      const error = Object.assign(new Error(
        `preflight manual cancelado: cliente desconectado (${source})`,
      ), {
        name: 'AbortError',
        code: 'CLIENT_DISCONNECTED',
      });
      preflightController.abort(error);
    };
    const onRequestAborted = () => abortPreflight('request_aborted');
    const onResponseClose = () => {
      if (!res.writableEnded) abortPreflight('response_close');
    };
    req.once?.('aborted', onRequestAborted);
    res.once?.('close', onResponseClose);
    try {
      const prepared = await prepareManualApprovalPlan(
        req.body,
        req.principal,
        preflightController.signal,
      );
      if (preflightController.signal.aborted) {
        throw preflightController.signal.reason;
      }
      let approval = null;
      if (prepared.plan.requiresHumanApproval) {
        approval = manualApprovalStore.issue({
          plan: prepared.plan,
          ownerSub: prepared.ownerSub,
          privateContext: prepared.privateContext,
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
    } finally {
      req.removeListener?.('aborted', onRequestAborted);
      res.removeListener?.('close', onResponseClose);
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
  const rawOpsec = String(req.body?.opsecProfile || env.GHOSTRECON_OPSEC_PROFILE || 'standard')
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
  const isFullPresetRun =
    req.body?.fullPreset === true || playbookNameForCheck === 'full-recon';
  const navigatorActive = !isFullPresetRun
    && isNavigatorModeActive({ navigatorMode, navegation: navegationBody });

  if (!navigatorActive || isFullPresetRun) {
    modules = modules.filter((m) => m !== 'navegation');
  }
  const runtimeConfig = resolveManualRuntimeConfig(req.body, modules);
  const profile = runtimeConfig.executionProfile;
  const modulesForOpsecGate = expandIntrusiveRunModules({
    modules: includeFrameSeven ? [...modules, 'frameseven_active'] : modules,
    engine: runtimeConfig.vigolium.engineMode,
    vigoliumAgent: runtimeConfig.vigolium.vigoliumAgentMode,
    includeManualImplicit: true,
    includeManualIntrusive: confirmActive,
    kaliMode,
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
  let expectedVigoliumBinaryPath = null;
  let expectedVigoliumBinarySource = null;
  let expectedVigoliumAuthFileIdentities = [];
  let expectedVigoliumSourceIdentity = null;
  if (vigoliumRequested) {
    try {
      throwIfCancelled();
      const resolvedVigolium = await resolveVigoliumBinaryImpl(ROOT, {
        preferPath: runtimeConfig.vigolium.vigoliumPreferPath,
        env,
      });
      const vigoliumBinary = resolvedVigolium?.binary || resolvedVigolium?.bin;
      if (!vigoliumBinary) throw new Error('binário Vigolium indisponível');
      expectedVigoliumBinaryPath = vigoliumBinary;
      expectedVigoliumBinarySource = resolvedVigolium?.source || null;
      expectedVigoliumBinaryIdentity = await inspectVigoliumBinaryIdentityImpl(vigoliumBinary);
      throwIfCancelled();
      if (runtimeConfig.vigolium.vigoliumAuthFiles.length) {
        expectedVigoliumAuthFileIdentities = await inspectVigoliumAuthFileIdentitiesImpl(
          runtimeConfig.vigolium.vigoliumAuthFiles,
          {
            allowedRoots: vigoliumAuthAllowedRoots,
            signal: controller.signal,
          },
        );
        throwIfCancelled();
      }
      if (
        runtimeConfig.vigolium.vigoliumSource
        && runtimeConfig.vigolium.vigoliumAgentMode !== 'none'
      ) {
        expectedVigoliumSourceIdentity = await inspectVigoliumSourceIdentityImpl(
          runtimeConfig.vigolium.vigoliumSource,
          {
            allowedRoots: vigoliumSourceAllowedRoots,
            signal: controller.signal,
            timeoutMs: runtimeConfig.vigolium.vigoliumAgentTimeoutMs,
            env,
          },
        );
        throwIfCancelled();
      }
    } catch (error) {
      send({
        type: 'error',
        code: error?.code || 'VIGOLIUM_PREPARATION_FAILED',
        message: controller.signal.aborted
          ? 'Vigolium: preparação cancelada'
          : `Vigolium: identidade efetiva não pôde ser selada (${error?.message || error})`,
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
    runtimeConfig,
    frameSevenIdentity: expectedFrameSevenBinaryIdentity,
    vigoliumIdentity: expectedVigoliumBinaryIdentity,
    vigoliumBinaryPath: expectedVigoliumBinaryPath,
    vigoliumBinarySource: expectedVigoliumBinarySource,
    vigoliumAuthFileIdentities: expectedVigoliumAuthFileIdentities,
    vigoliumSourceIdentity: expectedVigoliumSourceIdentity,
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
        privateContext: buildApprovalPrivateContext(req.body, runtimeConfig, {
          vigoliumBinaryPath: expectedVigoliumBinaryPath,
          vigoliumBinarySource: expectedVigoliumBinarySource,
          vigoliumAuthFileIdentities: expectedVigoliumAuthFileIdentities,
          vigoliumSourceIdentity: expectedVigoliumSourceIdentity,
        }),
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
  const torOpts = runtimeConfig.tor;
  const torStrictWanted = torOpts.strict;
  const torRequired = torOpts.required;
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
    if (torOpts.newnymBeforeRun) {
      try {
        await torNewnymImpl({ timeoutMs: 5_000, signal: controller.signal });
        throwIfCancelled();
        send({ type: 'log', msg: '[tor] NEWNYM sinalizado', level: 'info' });
      } catch (e) {
        send({ type: 'log', msg: `[tor] NEWNYM falhou: ${e?.message || e}`, level: 'warn' });
      }
    }
  }

  const identityOpts = {
    ...runtimeConfig.identity,
    proxyPool: [...runtimeConfig.identity.proxyPool],
    modules: [...runtimeConfig.identity.modules],
  };
  // ID temporário para telemetria do tor-strict (correlacionável com runId
  // depois que saveRun emitir um). Emitimos no stream para o cliente saber.
  const requestRunId = `req-${Date.now().toString(36)}-${randomBytes(4).toString('hex')}`;
  identityOpts.runId = requestRunId;
  identityOpts.target = domain;
  // Quando torRequired + perTargetCircuit, propagamos para identity-controller
  // ativar IsolateSOCKSAuth com user/pass únicos (circuit dedicado por target).
  if (torOpts.perTargetCircuit) {
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
          perTargetCircuit: torOpts.perTargetCircuit,
          newnymBefore: torOpts.newnymBeforeRun,
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
        outOfScope: runtimeConfig.outOfScope,
        outOfScopeFrozen: true,
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
        engine: runtimeConfig.vigolium.engineMode,
        vigoliumStrategy: runtimeConfig.vigolium.vigoliumStrategy,
        vigoliumModules: [...runtimeConfig.vigolium.vigoliumModules],
        vigoliumModuleTags: [...runtimeConfig.vigolium.vigoliumModuleTags],
        vigoliumModuleTag: null,
        vigoliumAgent: runtimeConfig.vigolium.vigoliumAgentMode,
        vigoliumSource: runtimeConfig.vigolium.vigoliumSource,
        vigoliumAuthFiles: [...runtimeConfig.vigolium.vigoliumAuthFiles],
        vigoliumAuthFile: null,
        vigoliumAuditMode: runtimeConfig.vigolium.vigoliumAuditMode,
        // `-T` permanece fechado até existir um contrato que enumere, valide e
        // sele cada alvo contido no arquivo antes dos gates.
        vigoliumInputFile: null,
        vigoliumInputType: null,
        vigoliumOnly: runtimeConfig.vigolium.vigoliumOnly,
        vigoliumAuthEntries: [...runtimeConfig.vigolium.vigoliumAuthEntries],
        vigoliumAuth: null,
        vigoliumHtmlReport: runtimeConfig.vigolium.vigoliumHtmlReport,
        vigoliumReportOnly: runtimeConfig.vigolium.vigoliumReportOnly,
        vigoliumPreferPath: runtimeConfig.vigolium.vigoliumPreferPath,
        vigoliumUseCodex: runtimeConfig.vigolium.vigoliumUseCodex,
        vigoliumExpectedIdentity: expectedVigoliumBinaryIdentity,
        vigoliumExpectedSourceIdentity: expectedVigoliumSourceIdentity,
        vigoliumRuntimeConfig: Object.freeze({
          ...runtimeConfig.vigolium,
          vigoliumChildEnv: runtimeConfig.vigoliumChildEnv,
          vigoliumBinaryPath: expectedVigoliumBinaryPath,
          vigoliumBinarySource: expectedVigoliumBinarySource,
          vigoliumExpectedIdentity: expectedVigoliumBinaryIdentity,
          vigoliumExpectedSourceIdentity: expectedVigoliumSourceIdentity
            ? Object.freeze({ ...expectedVigoliumSourceIdentity })
            : null,
          vigoliumSourceAllowedRoots,
          vigoliumExpectedAuthFileIdentities: Object.freeze(
            expectedVigoliumAuthFileIdentities.map((identity) => Object.freeze({ ...identity })),
          ),
          vigoliumAuthAllowedRoots,
        }),
        signal: stageSignal || controller.signal,
        requestRunId,
        manualEffectiveCapabilities: modulesForOpsecGate,
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
