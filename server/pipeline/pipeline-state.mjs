import {
  hostInReconScope,
  parseOutOfScopeEnv,
  parseOutOfScopeClientInput,
  mergeOutOfScopeLists,
  urlInReconScope,
  validateEngagementScopePolicy,
} from '../modules/scope.js';
import { resolveReconProfile } from '../modules/runtime-profile.js';
import { targetIsIp } from '../modules/recon-target.js';
import { createPipelineContext } from './finding-context.mjs';
import {
  resolveEngineMode,
  resolveVigoliumStrategy,
  resolveVigoliumAgentMode,
  resolveVigoliumSource,
  resolveVigoliumAuthFiles,
  resolveVigoliumModuleTags,
  resolveVigoliumAuthEntries,
  resolveVigoliumInputFile,
  resolveVigoliumInputType,
  resolveVigoliumOnly,
  resolveVigoliumReportOnly,
  shouldPreferVigoliumPath,
  shouldUseVigoliumCodex,
  shouldWriteVigoliumHtmlReport,
} from '../../bridge/vigolium-config.mjs';

function normalizeCapabilityId(value) {
  return String(value || '').trim().toLowerCase().replace(/-/g, '_');
}

/**
 * O RUN manual preserva o comportamento legado. No Auto, uma ação implícita
 * só pode ocorrer quando a capacidade correspondente estiver no plano
 * efetivo/congelado.
 */
export function pipelineCapabilityAllowed(state, capabilityId) {
  if (state?.autoModeExecution !== true) return true;
  const normalized = normalizeCapabilityId(capabilityId);
  if (!normalized) return false;
  if (state.autoCapabilityIds instanceof Set) {
    return state.autoCapabilityIds.has(normalized);
  }
  return (Array.isArray(state?.modules) ? state.modules : [])
    .map(normalizeCapabilityId)
    .includes(normalized);
}

/** Estado mutável partilhado entre fases do pipeline. */
export function createPipelineState(ctx) {
  const {
    domain,
    exactMatch,
    modules,
    emit,
    kaliMode = false,
    auth = null,
    profile = 'standard',
    outOfScope: outOfScopeClientRaw = null,
    projectName: projectNameRaw = '',
    autoAiReports = false,
    aiProviderMode = 'auto',
    aiUseOpenrouter = true,
    aiOpenrouterOnly = false,
    aiPrimaryCloud = null,
    shannonPrecheck = true,
    shannonSkipDepsVerify = false,
    shannonGithubRepos = null,
    pentestgptUrl: pentestgptUrlOverride = null,
    bountyContext: bountyContextBody = null,
    engagementId: engagementIdRaw = null,
    engagementOperator: engagementOperatorRaw = null,
    scopePolicy: scopePolicyRaw = null,
    identityCtrl = null,
    navegation = null,
    navigatorMode = false,
    engine = null,
    vigoliumStrategy = null,
    vigoliumModules = null,
    vigoliumModuleTags = null,
    vigoliumModuleTag = null,
    vigoliumAgent = null,
    vigoliumSource = null,
    vigoliumAuthFiles = null,
    vigoliumAuthFile = null,
    vigoliumAuditMode = null,
    vigoliumInputFile = null,
    vigoliumInputType = null,
    vigoliumOnly = null,
    vigoliumAuthEntries = null,
    vigoliumAuth = null,
    vigoliumHtmlReport = false,
    vigoliumReportOnly = null,
    vigoliumPreferPath = false,
    vigoliumUseCodex = false,
    vigoliumExpectedIdentity = null,
    signal = null,
    requestRunId = null,
    autoModeExecution = false,
    captureTokenFindings = false,
    tokenCaptureOptions = null,
    forgeSandboxRunner = null,
    forgeCanaryId = null,
  } = ctx;

  const apexHostIsIp = targetIsIp(domain);

  let bountyCtx =
    bountyContextBody && typeof bountyContextBody === 'object' ? bountyContextBody : null;
  if (!bountyCtx && process.env.GHOSTRECON_BOUNTY_CONTEXT?.trim()) {
    try {
      bountyCtx = JSON.parse(process.env.GHOSTRECON_BOUNTY_CONTEXT);
    } catch {
      bountyCtx = { note: String(process.env.GHOSTRECON_BOUNTY_CONTEXT).slice(0, 400) };
    }
  }

  const runtimeProfile = resolveReconProfile(profile);
  const autoCapabilityIds = new Set(
    (Array.isArray(modules) ? modules : []).map(normalizeCapabilityId).filter(Boolean),
  );
  const domainStr = exactMatch ? `"${domain}"` : domain;
  const pctx = createPipelineContext({
    domain,
    emit,
    captureTokenFindings: captureTokenFindings === true,
    tokenCaptureOptions,
  });

  const outOfScopeFromEnv = parseOutOfScopeEnv(process.env.GHOSTRECON_OUT_OF_SCOPE);
  let outOfScopeList = [...outOfScopeFromEnv];
  if (outOfScopeClientRaw != null && outOfScopeClientRaw !== '') {
    const fromUi = parseOutOfScopeClientInput(outOfScopeClientRaw);
    outOfScopeList = mergeOutOfScopeLists(outOfScopeFromEnv, fromUi);
  }
  const scopePolicy = validateEngagementScopePolicy(scopePolicyRaw, {
    rootDomain: domain,
    engagementId: engagementIdRaw,
  });
  if (scopePolicy) {
    outOfScopeList = mergeOutOfScopeLists(outOfScopeList, scopePolicy.exclusions);
    if (!hostInReconScope(domain, domain, outOfScopeList, scopePolicy)) {
      throw new Error('scope policy formal não autoriza o alvo raiz do pipeline');
    }
  }

  return {
    domain,
    exactMatch,
    modules,
    emit,
    kaliMode,
    auth,
    profile,
    outOfScopeClientRaw,
    projectNameRaw,
    autoAiReports,
    aiProviderMode,
    aiUseOpenrouter,
    aiOpenrouterOnly,
    aiPrimaryCloud,
    shannonPrecheck,
    shannonSkipDepsVerify,
    shannonGithubRepos,
    pentestgptUrlOverride,
    bountyContextBody,
    engagementIdRaw,
    engagementOperatorRaw,
    scopePolicy,
    identityCtrl,
    navegation,
    navigatorMode,
    apexHostIsIp,
    bountyCtx,
    runtimeProfile,
    domainStr,
    outOfScopeFromEnv,
    outOfScopeList,
    reconCoverageSnapshot: null,
    pipelineAiOut: null,
    subdomainsAlive: [],
    probedHosts: new Set(),
    seenEp: new Set(),
    vtHostnames: [],
    tlsSanHosts: [],
    dnsAForHost: new Map(),
    lovableContext: null,
    firebaseContext: null,
    originByHost: null,
    probeResults: null,
    paramRows: [],
    paramUrlsForKali: [],
    interesting: [],
    urlCorpus: [],
    githubClonedItems: [],
    engineMode: resolveEngineMode({ engine, modules }),
    vigoliumStrategy: resolveVigoliumStrategy({ vigoliumStrategy, strategy: vigoliumStrategy }),
    vigoliumModules: Array.isArray(vigoliumModules) ? vigoliumModules : [],
    vigoliumModuleTags: resolveVigoliumModuleTags({ vigoliumModuleTags, vigoliumModuleTag }),
    vigoliumAgentMode: resolveVigoliumAgentMode({ vigoliumAgent, modules }),
    vigoliumSource: resolveVigoliumSource({ vigoliumSource }),
    vigoliumAuthFiles: resolveVigoliumAuthFiles({ vigoliumAuthFiles, vigoliumAuthFile }),
    vigoliumAuthEntries: resolveVigoliumAuthEntries({ vigoliumAuthEntries, vigoliumAuth }),
    vigoliumInputFile: resolveVigoliumInputFile({ vigoliumInputFile }),
    vigoliumInputType: resolveVigoliumInputType({ vigoliumInputType }),
    vigoliumOnly: resolveVigoliumOnly({ vigoliumOnly }),
    vigoliumHtmlReport: shouldWriteVigoliumHtmlReport({ vigoliumHtmlReport }),
    vigoliumReportOnly: resolveVigoliumReportOnly({ vigoliumReportOnly }),
    vigoliumPreferPath: shouldPreferVigoliumPath({ vigoliumPreferPath, kaliMode }),
    vigoliumUseCodex: shouldUseVigoliumCodex({ vigoliumUseCodex }),
    vigoliumExpectedIdentity: vigoliumExpectedIdentity
      && typeof vigoliumExpectedIdentity === 'object'
      ? Object.freeze({ ...vigoliumExpectedIdentity })
      : null,
    vigoliumAuditMode: vigoliumAuditMode || null,
    signal,
    requestRunId,
    autoModeExecution: autoModeExecution === true,
    autoCapabilityIds,
    // Dependências de execução Forge são injetadas pela rota/orquestrador e
    // nunca serializadas em checkpoints ou eventos.
    forgeSandboxRunner,
    forgeCanaryId: forgeCanaryId ? String(forgeCanaryId) : null,
    allowsPipelineCapability(capabilityId) {
      return pipelineCapabilityAllowed(this, capabilityId);
    },
    hostInScope(hostname) {
      return hostInReconScope(hostname, domain, outOfScopeList, scopePolicy);
    },
    urlInScope(url) {
      return urlInReconScope(url, domain, outOfScopeList, scopePolicy);
    },
    throwIfAborted() {
      if (signal?.aborted) throw signal.reason || new Error('pipeline cancelado');
    },
    ...pctx,
  };
}
