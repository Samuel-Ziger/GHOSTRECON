import {
  parseOutOfScopeEnv,
  parseOutOfScopeClientInput,
  mergeOutOfScopeLists,
} from '../modules/scope.js';
import { resolveReconProfile } from '../modules/runtime-profile.js';
import { targetIsIp } from '../modules/recon-target.js';
import { createPipelineContext } from './finding-context.mjs';
import { resolveEngineMode, resolveVigoliumStrategy, resolveVigoliumAgentMode, resolveVigoliumSource } from '../../bridge/vigolium-config.mjs';

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
    identityCtrl = null,
    navegation = null,
    navigatorMode = false,
    engine = null,
    vigoliumStrategy = null,
    vigoliumModules = null,
    vigoliumAgent = null,
    vigoliumSource = null,
    vigoliumAuditMode = null,
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
  const domainStr = exactMatch ? `"${domain}"` : domain;
  const pctx = createPipelineContext({ domain, emit });

  const outOfScopeFromEnv = parseOutOfScopeEnv(process.env.GHOSTRECON_OUT_OF_SCOPE);
  let outOfScopeList = [...outOfScopeFromEnv];
  if (modules.includes('out_of_scope') && outOfScopeClientRaw != null && outOfScopeClientRaw !== '') {
    const fromUi = parseOutOfScopeClientInput(outOfScopeClientRaw);
    outOfScopeList = mergeOutOfScopeLists(outOfScopeFromEnv, fromUi);
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
    vigoliumAgentMode: resolveVigoliumAgentMode({ vigoliumAgent, modules }),
    vigoliumSource: resolveVigoliumSource({ vigoliumSource }),
    vigoliumAuditMode: vigoliumAuditMode || null,
    ...pctx,
  };
}
