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
import {
  MANUAL_IMPLICIT_CAPABILITIES,
  MANUAL_INTRUSIVE_IMPLICIT_CAPABILITIES,
} from '../modules/opsec.mjs';
import { createPipelineContext } from './finding-context.mjs';
import {
  assertVigoliumRuntimeConfig,
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

const MANUAL_IMPLICIT_CAPABILITY_IDS = new Set(
  MANUAL_IMPLICIT_CAPABILITIES.map(normalizeCapabilityId),
);
const MANUAL_INTRUSIVE_IMPLICIT_CAPABILITY_IDS = new Set(
  MANUAL_INTRUSIVE_IMPLICIT_CAPABILITIES.map(normalizeCapabilityId),
);
const MANUAL_SAFE_IMPLICIT_CAPABILITY_IDS = new Set(
  [...MANUAL_IMPLICIT_CAPABILITY_IDS]
    .filter((capabilityId) => !MANUAL_INTRUSIVE_IMPLICIT_CAPABILITY_IDS.has(capabilityId)),
);

/**
 * Uma ação implícita só pode ocorrer quando pertencer ao contrato central do
 * RUN manual ou estiver no plano efetivo/congelado do Auto. Isso preserva as
 * fases legadas conhecidas sem deixar novas capacidades escaparem dos gates.
 */
export function pipelineCapabilityAllowed(state, capabilityId) {
  const normalized = normalizeCapabilityId(capabilityId);
  if (!normalized) return false;
  if (state?.autoModeExecution !== true) {
    if (state?.manualCapabilityIds instanceof Set) {
      return state.manualCapabilityIds.has(normalized);
    }
    return MANUAL_SAFE_IMPLICIT_CAPABILITY_IDS.has(normalized);
  }
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
    outOfScopeFrozen = false,
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
    vigoliumExpectedSourceIdentity = null,
    vigoliumRuntimeConfig = null,
    signal = null,
    requestRunId = null,
    autoModeExecution = false,
    manualEffectiveCapabilities = null,
    captureTokenFindings = false,
    tokenCaptureOptions = null,
    forgeSandboxRunner = null,
    forgeCanaryId = null,
  } = ctx;

  const apexHostIsIp = targetIsIp(domain);
  const frozenVigoliumCandidate = vigoliumRuntimeConfig
    && typeof vigoliumRuntimeConfig === 'object'
    && vigoliumRuntimeConfig.vigoliumRuntimeConfigFrozen === true
    ? vigoliumRuntimeConfig
    : null;
  const frozenVigolium = frozenVigoliumCandidate
    ? assertVigoliumRuntimeConfig(frozenVigoliumCandidate)
    : null;
  const resolvedVigoliumExpectedIdentity = frozenVigolium?.vigoliumExpectedIdentity
    || vigoliumExpectedIdentity;
  const resolvedVigoliumExpectedSourceIdentity =
    frozenVigolium?.vigoliumExpectedSourceIdentity
    || vigoliumExpectedSourceIdentity;

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
  const manualCapabilityIds = new Set(
    (Array.isArray(manualEffectiveCapabilities)
      ? manualEffectiveCapabilities
      : [...MANUAL_SAFE_IMPLICIT_CAPABILITY_IDS])
      .map(normalizeCapabilityId)
      .filter(Boolean),
  );
  const domainStr = exactMatch ? `"${domain}"` : domain;
  const pctx = createPipelineContext({
    domain,
    emit,
    captureTokenFindings: captureTokenFindings === true,
    tokenCaptureOptions,
  });

  const outOfScopeFromEnv = outOfScopeFrozen
    ? []
    : parseOutOfScopeEnv(process.env.GHOSTRECON_OUT_OF_SCOPE);
  let outOfScopeList = outOfScopeFrozen
    ? parseOutOfScopeClientInput(outOfScopeClientRaw)
    : [...outOfScopeFromEnv];
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
    engineMode: frozenVigolium
      ? frozenVigolium.engineMode
      : resolveEngineMode({ engine, modules }),
    vigoliumStrategy: frozenVigolium
      ? frozenVigolium.vigoliumStrategy
      : resolveVigoliumStrategy({ vigoliumStrategy, strategy: vigoliumStrategy }),
    vigoliumModules: frozenVigolium
      ? [...frozenVigolium.vigoliumModules]
      : Array.isArray(vigoliumModules) ? vigoliumModules : [],
    vigoliumModuleTags: frozenVigolium
      ? [...frozenVigolium.vigoliumModuleTags]
      : resolveVigoliumModuleTags({ vigoliumModuleTags, vigoliumModuleTag }),
    vigoliumAgentMode: frozenVigolium
      ? frozenVigolium.vigoliumAgentMode
      : resolveVigoliumAgentMode({ vigoliumAgent, modules }),
    vigoliumSource: frozenVigolium
      ? frozenVigolium.vigoliumSource
      : resolveVigoliumSource({ vigoliumSource }),
    vigoliumAuthFiles: frozenVigolium
      ? [...frozenVigolium.vigoliumAuthFiles]
      : resolveVigoliumAuthFiles({ vigoliumAuthFiles, vigoliumAuthFile }),
    vigoliumAuthEntries: frozenVigolium
      ? [...frozenVigolium.vigoliumAuthEntries]
      : resolveVigoliumAuthEntries({ vigoliumAuthEntries, vigoliumAuth }),
    vigoliumInputFile: frozenVigolium
      ? frozenVigolium.vigoliumInputFile
      : resolveVigoliumInputFile({ vigoliumInputFile }),
    vigoliumInputType: frozenVigolium
      ? frozenVigolium.vigoliumInputType
      : resolveVigoliumInputType({ vigoliumInputType }),
    vigoliumOnly: frozenVigolium
      ? frozenVigolium.vigoliumOnly
      : resolveVigoliumOnly({ vigoliumOnly }),
    vigoliumHtmlReport: frozenVigolium
      ? frozenVigolium.vigoliumHtmlReport
      : shouldWriteVigoliumHtmlReport({ vigoliumHtmlReport }),
    vigoliumReportOnly: frozenVigolium
      ? frozenVigolium.vigoliumReportOnly
      : resolveVigoliumReportOnly({ vigoliumReportOnly }),
    vigoliumPreferPath: frozenVigolium
      ? frozenVigolium.vigoliumPreferPath
      : shouldPreferVigoliumPath({ vigoliumPreferPath, kaliMode }),
    vigoliumUseCodex: frozenVigolium
      ? frozenVigolium.vigoliumUseCodex
      : shouldUseVigoliumCodex({ vigoliumUseCodex }),
    vigoliumVpsProfile: frozenVigolium
      ? frozenVigolium.vigoliumVpsProfile
      : undefined,
    vigoliumSkipExternalHarvest: frozenVigolium
      ? frozenVigolium.vigoliumSkipExternalHarvest
      : undefined,
    vigoliumAuditMode: frozenVigolium
      ? frozenVigolium.vigoliumAuditMode
      : vigoliumAuditMode || null,
    vigoliumTimeoutMs: frozenVigolium ? frozenVigolium.vigoliumTimeoutMs : null,
    vigoliumAgentTimeoutMs: frozenVigolium
      ? frozenVigolium.vigoliumAgentTimeoutMs
      : null,
    vigoliumChildEnv: frozenVigolium?.vigoliumChildEnv
      ? Object.freeze({ ...frozenVigolium.vigoliumChildEnv })
      : null,
    vigoliumBinaryPath: frozenVigolium?.vigoliumBinaryPath || null,
    vigoliumBinarySource: frozenVigolium?.vigoliumBinarySource || null,
    vigoliumRuntimeConfigFrozen: Boolean(frozenVigolium),
    vigoliumRuntimeConfigVersion: frozenVigolium
      ? frozenVigolium.vigoliumRuntimeConfigVersion
      : null,
    vigoliumExpectedIdentity: resolvedVigoliumExpectedIdentity
      && typeof resolvedVigoliumExpectedIdentity === 'object'
      ? Object.freeze({ ...resolvedVigoliumExpectedIdentity })
      : null,
    vigoliumExpectedSourceIdentity: resolvedVigoliumExpectedSourceIdentity
      && typeof resolvedVigoliumExpectedSourceIdentity === 'object'
      ? Object.freeze({ ...resolvedVigoliumExpectedSourceIdentity })
      : null,
    vigoliumSourceAllowedRoots: frozenVigolium
      && Array.isArray(frozenVigolium.vigoliumSourceAllowedRoots)
      ? Object.freeze(frozenVigolium.vigoliumSourceAllowedRoots.map(String))
      : Object.freeze([]),
    vigoliumExpectedAuthFileIdentities: frozenVigolium
      && Array.isArray(frozenVigolium.vigoliumExpectedAuthFileIdentities)
      ? Object.freeze(
          frozenVigolium.vigoliumExpectedAuthFileIdentities
            .map((identity) => Object.freeze({ ...identity })),
        )
      : Object.freeze([]),
    vigoliumAuthAllowedRoots: frozenVigolium
      && Array.isArray(frozenVigolium.vigoliumAuthAllowedRoots)
      ? Object.freeze(frozenVigolium.vigoliumAuthAllowedRoots.map(String))
      : Object.freeze([]),
    signal,
    requestRunId,
    autoModeExecution: autoModeExecution === true,
    autoCapabilityIds,
    manualCapabilityIds,
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
