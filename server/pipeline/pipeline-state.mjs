import { createHash } from 'node:crypto';
import {
  hostInReconScope,
  parseOutOfScopeEnv,
  parseOutOfScopeClientInput,
  mergeOutOfScopeLists,
  dnsResolvedAddressesEligibleForProbe,
  urlInReconScope,
  validateEngagementScopePolicy,
} from '../modules/scope.js';
import { resolveReconProfile } from '../modules/runtime-profile.js';
import { parseReconTarget, targetIsIp } from '../modules/recon-target.js';
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
    targetUrl: targetUrlRaw = null,
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
    githubManualRepos = null,
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
    fetchImpl: injectedFetchImpl = null,
    jwtClaimAuthzConfig = null,
    authzObjectMatrixConfig = null,
    sqliTargetedConfig = null,
    cloudObjectProxyAuthzConfig = null,
    financialIntegrityConfig = null,
    sensitivePaymentObservations = null,
    apiResponseObservations = null,
    knownObjectKeys = null,
    objectKeyDiscoveryBudget = null,
    artifactPaths = null,
    artifactRoot = null,
    sensitiveEvidenceVault = null,
  } = ctx;

  const parsedTarget = parseReconTarget(targetUrlRaw || domain);
  if (!parsedTarget.ok || parsedTarget.target !== String(domain || '').trim().toLowerCase()) {
    throw new Error('targetUrl não corresponde ao hostname canónico do pipeline');
  }
  const targetUrl = parsedTarget.targetUrl;
  const targetOrigin = parsedTarget.origin;
  const targetPathname = parsedTarget.pathname || '/';
  const targetBasePath = parsedTarget.basePath || targetPathname;
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
  const sensitiveEvidenceIndex = new Map();
  const storeSensitiveEvidence = async ({ value, kind = 'sensitive_evidence' } = {}) => {
    const bytes = Buffer.from(value || '');
    if (!bytes.length) throw new Error('sensitive_evidence_empty');
    try {
      if (sensitiveEvidenceVault && typeof sensitiveEvidenceVault.put === 'function') {
        const stored = await sensitiveEvidenceVault.put(bytes, { kind });
        sensitiveEvidenceIndex.set(stored.secretRef, { vault: true, stored });
        return { secretRef: stored.secretRef, fingerprint: stored.fingerprint };
      }
      const fingerprint = createHash('sha256').update(bytes).digest('hex');
      const secretRef = `memory:sha256:${fingerprint}`;
      const previous = sensitiveEvidenceIndex.get(secretRef)?.value;
      if (Buffer.isBuffer(previous)) previous.fill(0);
      sensitiveEvidenceIndex.set(secretRef, { vault: false, value: Buffer.from(bytes), kind: String(kind) });
      return { secretRef, fingerprint };
    } finally {
      bytes.fill(0);
    }
  };
  const resolveSensitiveEvidence = async (secretRef) => {
    const entry = sensitiveEvidenceIndex.get(String(secretRef || ''));
    if (!entry) return null;
    if (entry.vault) return sensitiveEvidenceVault.get(entry.stored);
    return Buffer.from(entry.value);
  };
  const disposeSensitiveEvidence = () => {
    for (const entry of sensitiveEvidenceIndex.values()) {
      if (Buffer.isBuffer(entry?.value)) entry.value.fill(0);
    }
    sensitiveEvidenceIndex.clear();
  };

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
    targetUrl,
    targetOrigin,
    targetPathname,
    targetBasePath,
    targetExplicitUrl: parsedTarget.explicitUrl === true,
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
    githubManualRepos,
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
    fetchImpl: typeof injectedFetchImpl === 'function'
      ? injectedFetchImpl
      : typeof identityCtrl?.fetchWithPolicy === 'function'
        ? identityCtrl.fetchWithPolicy
        : globalThis.fetch,
    requestRunId,
    autoModeExecution: autoModeExecution === true,
    autoCapabilityIds,
    manualCapabilityIds,
    // Dependências de execução Forge são injetadas pela rota/orquestrador e
    // nunca serializadas em checkpoints ou eventos.
    forgeSandboxRunner,
    forgeCanaryId: forgeCanaryId ? String(forgeCanaryId) : null,
    jwtClaimAuthzConfig: jwtClaimAuthzConfig && typeof jwtClaimAuthzConfig === 'object'
      ? jwtClaimAuthzConfig : null,
    authzObjectMatrixConfig: authzObjectMatrixConfig && typeof authzObjectMatrixConfig === 'object'
      ? authzObjectMatrixConfig : null,
    sqliTargetedConfig: sqliTargetedConfig && typeof sqliTargetedConfig === 'object'
      ? sqliTargetedConfig : null,
    cloudObjectProxyAuthzConfig: cloudObjectProxyAuthzConfig && typeof cloudObjectProxyAuthzConfig === 'object'
      ? cloudObjectProxyAuthzConfig : null,
    financialIntegrityConfig: financialIntegrityConfig && typeof financialIntegrityConfig === 'object'
      ? financialIntegrityConfig : null,
    sensitivePaymentObservations: Array.isArray(sensitivePaymentObservations)
      ? [...sensitivePaymentObservations] : [],
    apiResponseObservations: Array.isArray(apiResponseObservations) ? [...apiResponseObservations] : [],
    knownObjectKeys: Array.isArray(knownObjectKeys) ? [...knownObjectKeys] : [],
    objectKeyDiscoveryBudget,
    artifactPaths: Array.isArray(artifactPaths) ? [...artifactPaths] : [],
    artifactRoot: typeof artifactRoot === 'string' ? artifactRoot : null,
    storeSensitiveEvidence,
    resolveSensitiveEvidence,
    disposeSensitiveEvidence,
    latestJwtSecretRef: null,
    allowsPipelineCapability(capabilityId) {
      return pipelineCapabilityAllowed(this, capabilityId);
    },
    hostInScope(hostname) {
      return hostInReconScope(hostname, domain, outOfScopeList, scopePolicy);
    },
    resolvedAddressInScope(hostname, address) {
      if (!hostInReconScope(hostname, domain, outOfScopeList, scopePolicy)) return false;
      return dnsResolvedAddressesEligibleForProbe(
        [address],
        domain,
        outOfScopeList,
        scopePolicy,
      ).eligible;
    },
    urlInScope(url) {
      if (!urlInReconScope(url, domain, outOfScopeList, scopePolicy)) return false;
      if (!targetOrigin) return true;
      try {
        const candidate = new URL(url);
        // Uma URL explicitamente fornecida sela scheme+porta para o host raiz.
        // Subdomínios descobertos continuam sujeitos à política de hostname.
        if (candidate.hostname.toLowerCase() === String(domain).toLowerCase()) {
          return candidate.origin.toLowerCase() === targetOrigin.toLowerCase();
        }
        return true;
      } catch {
        return false;
      }
    },
    throwIfAborted() {
      if (signal?.aborted) throw signal.reason || new Error('pipeline cancelado');
    },
    ...pctx,
  };
}
