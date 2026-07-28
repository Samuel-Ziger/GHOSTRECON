import { createHash } from 'node:crypto';
import { normalizeModuleId } from '../modules/module-ids.mjs';
import { expandIntrusiveRunModules, isIntrusive } from '../modules/opsec.mjs';
import {
  FRAMESEVEN_OFFENSIVE_TOOLS_ARG_V1,
  FRAMESEVEN_RECON_TOOLS_ARG_V1,
} from '../integrations/frameseven-policy.mjs';
import { autoCapabilityPhase } from './pipeline-capabilities.mjs';

export const AUTO_AUTONOMY_POLICIES = Object.freeze({
  observation: Object.freeze({
    allowedClasses: Object.freeze(['passive', 'deep_passive', 'hexstrike_intel']),
    requirePlanApproval: false,
    allowIntrusive: false,
    opsecProfile: 'passive',
  }),
  assisted: Object.freeze({
    allowedClasses: Object.freeze(['passive', 'deep_passive', 'active', 'hexstrike_intel']),
    requirePlanApproval: true,
    allowIntrusive: false,
    opsecProfile: 'standard',
  }),
  authorized: Object.freeze({
    allowedClasses: Object.freeze(['passive', 'deep_passive', 'active', 'intrusive', 'hexstrike_intel']),
    requirePlanApproval: true,
    allowIntrusive: true,
    opsecProfile: 'standard',
  }),
  authorized_opsec: Object.freeze({
    allowedClasses: Object.freeze(['passive', 'deep_passive', 'active', 'intrusive', 'hexstrike_intel']),
    requirePlanApproval: true,
    allowIntrusive: true,
    opsecProfile: 'aggressive',
  }),
});

const FRAMESEVEN_IDS = new Set([
  'frameseven_recon',
  'frameseven_active',
  'frameseven_authenticated',
]);

const VIGOLIUM_AGENT_BY_MODULE = Object.freeze({
  vigolium_audit: 'audit',
  vigolium_swarm: 'swarm',
  vigolium_autopilot: 'autopilot',
});

const EXTERNAL_ENGINE_PREFIXES = Object.freeze(['frameseven_', 'vigolium_']);
const AUTO_HTTP_PROBE_CAPABILITY = 'http_probe';
const MAX_AUTO_PHASE_TIMEOUT_MS = 60 * 60_000;

const OPSEC_RANK = Object.freeze({
  passive: 0,
  stealth: 1,
  standard: 2,
  aggressive: 3,
});

const AUTO_ACTIONS = new Set([
  'run_modules',
  'continue_with_context',
  'finish',
  'ask_operator',
  'forge_module',
  'abstain',
]);

function uniqueIds(values) {
  return [...new Set((values || []).map(normalizeModuleId).filter(Boolean))];
}

function moduleClass(item) {
  const declared = String(item?.class || item?.manifest?.class || '').trim().toLowerCase();
  if (declared === 'destructive' || item?.manifest?.destructive === true) return 'destructive';
  if (declared === 'intrusive' || item?.manifest?.intrusive === true || isIntrusive(item?.id)) {
    return 'intrusive';
  }
  if (['passive', 'deep_passive', 'active', 'hexstrike_intel'].includes(declared)) {
    return declared;
  }
  return 'unknown';
}

function deepFreeze(value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function stablePlanHash(value) {
  return createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

function boundedOpsecProfile(requested, policyProfile) {
  const candidate = String(requested || '').trim().toLowerCase();
  if (!(candidate in OPSEC_RANK)) return policyProfile;
  return OPSEC_RANK[candidate] <= OPSEC_RANK[policyProfile] ? candidate : policyProfile;
}

function boundedPositiveInteger(value, fallback, min, max) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < min) return fallback;
  return Math.min(max, Math.floor(parsed));
}

function isExternalEngineCapability(id) {
  return EXTERNAL_ENGINE_PREFIXES.some((prefix) => String(id || '').startsWith(prefix));
}

function capabilityNeedsHttpProbe(id, item) {
  if (!id || id === AUTO_HTTP_PROBE_CAPABILITY || isExternalEngineCapability(id)) return false;
  return ['active', 'intrusive'].includes(moduleClass(item));
}

export function phaseTimeoutsFromModuleLimits(moduleLimits = []) {
  const totals = new Map();
  for (const limit of moduleLimits || []) {
    const phase = String(limit?.phase || '').trim();
    if (!phase || phase === 'frameseven') continue;
    const timeoutMs = boundedPositiveInteger(limit?.timeoutMs, 90_000, 100, 3_600_000);
    totals.set(
      phase,
      Math.min(MAX_AUTO_PHASE_TIMEOUT_MS, (totals.get(phase) || 0) + timeoutMs),
    );
  }
  return Object.fromEntries([...totals.entries()].sort(([left], [right]) => left.localeCompare(right)));
}

export function buildEffectiveAutoPlan({
  plan,
  catalog,
  body = {},
  autonomyLevel = 'observation',
  frameSevenAvailable = false,
  forceFrameSevenRecon = false,
} = {}) {
  if (!Object.hasOwn(AUTO_AUTONOMY_POLICIES, autonomyLevel)) {
    throw new Error(`Autonomia AUTO desconhecida: ${autonomyLevel}`);
  }
  const policy = AUTO_AUTONOMY_POLICIES[autonomyLevel];
  const catalogItems = Array.isArray(catalog?.modules) ? catalog.modules : [];
  const byId = new Map(catalogItems.map((item) => [normalizeModuleId(item.id), item]));
  const action = String(
    plan?.action || plan?.agentDecision?.action || (plan?.modules?.length ? 'run_modules' : 'finish'),
  ).trim().toLowerCase();
  if (!AUTO_ACTIONS.has(action)) throw new Error(`Ação AUTO inválida no plano efetivo: ${action}`);
  const executes = ['run_modules', 'continue_with_context'].includes(action);
  const selected = executes ? uniqueIds(plan?.modules) : [];

  if (executes && forceFrameSevenRecon && frameSevenAvailable && !selected.some((id) => FRAMESEVEN_IDS.has(id))) {
    selected.push('frameseven_recon');
  }
  if (executes && body.frameSevenAuth === true) {
    for (let index = selected.length - 1; index >= 0; index -= 1) {
      if (FRAMESEVEN_IDS.has(selected[index])) selected.splice(index, 1);
    }
    selected.push('frameseven_authenticated');
  } else if (executes && selected.includes('frameseven_authenticated')) {
    throw new Error('FrameSeven autenticado exige frameSevenAuth=true');
  } else if (executes && selected.includes('frameseven_active')) {
    const reconIndex = selected.indexOf('frameseven_recon');
    if (reconIndex >= 0) selected.splice(reconIndex, 1);
  }

  const frameSevenSelected = selected.filter((id) => FRAMESEVEN_IDS.has(id));
  if (frameSevenSelected.length && body.includeFrameSeven !== true && forceFrameSevenRecon !== true) {
    throw new Error('FrameSeven exige opt-in includeFrameSeven=true');
  }
  if (body.frameSevenAuth === true && body.includeFrameSeven !== true) {
    throw new Error('frameSevenAuth exige includeFrameSeven=true');
  }
  if (selected.some((id) => id.startsWith('vigolium_')) && body.includeVigolium !== true) {
    throw new Error('Vigolium exige opt-in includeVigolium=true');
  }
  if (selected.includes('hexstrike_orchestrator') && body.includeHexstrike !== true) {
    throw new Error('HexStrike exige opt-in includeHexstrike=true');
  }

  const unknown = selected.filter((id) => !byId.has(id));
  if (unknown.length) throw new Error(`Plano AUTO contém módulos fora do catálogo: ${unknown.join(', ')}`);
  if (selected.some((id) => capabilityNeedsHttpProbe(id, byId.get(id)))
    && !selected.includes(AUTO_HTTP_PROBE_CAPABILITY)) {
    if (!byId.has(AUTO_HTTP_PROBE_CAPABILITY)) {
      throw new Error(`Catálogo AUTO não contém dependência obrigatória: ${AUTO_HTTP_PROBE_CAPABILITY}`);
    }
    selected.push(AUTO_HTTP_PROBE_CAPABILITY);
  }
  const unavailable = selected.filter((id) => byId.get(id)?.available === false);
  if (unavailable.length) throw new Error(`Plano AUTO contém módulos indisponíveis: ${unavailable.join(', ')}`);
  const disallowed = selected.filter((id) => !policy.allowedClasses.includes(moduleClass(byId.get(id))));
  if (disallowed.length) {
    throw new Error(`Autonomia ${autonomyLevel} não permite: ${disallowed.join(', ')}`);
  }

  const frameSevenActive = frameSevenSelected.some((id) => id !== 'frameseven_recon');
  const frameSevenIdentity = catalog?.engines?.frameseven?.identity || null;
  if (
    frameSevenSelected.length > 0
    && (
      frameSevenIdentity?.algorithm !== 'sha256'
      || !/^[a-f0-9]{64}$/i.test(String(frameSevenIdentity?.sha256 || ''))
      || !Number.isSafeInteger(Number(frameSevenIdentity?.size))
    )
  ) {
    throw new Error('FrameSeven exige identidade executável selada no catálogo aprovado');
  }
  const frameSeven = {
    enabled: frameSevenSelected.length > 0,
    available: frameSevenAvailable,
    // Selado pelo catálogo e coberto pelo hash do plano. O adapter somente
    // revalida esta identidade; ele não cria uma nova aprovação implícita.
    identity: frameSevenSelected.length > 0 ? frameSevenIdentity : null,
    authBrowser: frameSevenSelected.includes('frameseven_authenticated'),
    profile: frameSevenSelected.length > 0
      ? (frameSevenActive ? 'offensive_v1' : 'recon_v1')
      : null,
    offensive: frameSevenActive,
    tools: frameSevenSelected.length > 0
      ? (
          frameSevenActive
            ? FRAMESEVEN_OFFENSIVE_TOOLS_ARG_V1
            : FRAMESEVEN_RECON_TOOLS_ARG_V1
        )
      : null,
    moduleIds: frameSevenSelected,
    runTimeoutMs: null,
  };

  const pipelineModules = selected.filter((id) => !FRAMESEVEN_IDS.has(id));
  const vigoliumDast = pipelineModules.includes('vigolium_dast');
  const vigoliumAgentModules = pipelineModules.filter((id) => VIGOLIUM_AGENT_BY_MODULE[id]);
  if (vigoliumAgentModules.length > 1) {
    throw new Error(`Plano AUTO contém agentes Vigolium mutuamente exclusivos: ${vigoliumAgentModules.join(', ')}`);
  }
  const vigoliumAgentModule = vigoliumAgentModules[0] || null;
  const engine = vigoliumDast ? 'both' : 'node';
  const vigoliumAgent = vigoliumAgentModule ? VIGOLIUM_AGENT_BY_MODULE[vigoliumAgentModule] : 'none';
  const vigoliumEnabled = vigoliumDast || Boolean(vigoliumAgentModule);
  if (
    vigoliumEnabled
    && (
      String(body.vigoliumInputFile || '').trim()
      || String(body.vigoliumInputType || '').trim()
    )
  ) {
    throw new Error(
      'Vigolium -T não pode integrar o plano Auto sem enumeração e validação prévia de todos os alvos',
    );
  }
  const vigoliumIdentity = catalog?.engines?.vigolium?.identity || null;
  if (
    vigoliumEnabled
    && (
      vigoliumIdentity?.algorithm !== 'sha256'
      || !/^[a-f0-9]{64}$/i.test(String(vigoliumIdentity?.sha256 || ''))
      || !Number.isSafeInteger(Number(vigoliumIdentity?.size))
    )
  ) {
    throw new Error('Vigolium exige identidade executável selada no catálogo aprovado');
  }
  const expandedModules = uniqueIds([
    ...expandIntrusiveRunModules({ modules: pipelineModules, engine, vigoliumAgent }),
    ...frameSevenSelected,
  ]);
  const intrusiveModules = expandedModules.filter((id) => {
    const item = byId.get(id);
    return moduleClass(item) === 'intrusive' || item?.manifest?.intrusive === true || isIntrusive(id);
  });
  const requiresKali = pipelineModules.some((id) => byId.get(id)?.manifest?.requiresKali === true
    || byId.get(id)?.requiresKali === true
    || id.startsWith('kali_'));
  const moduleLimits = selected.map((id) => {
    const item = byId.get(id);
    const manifest = item?.manifest || {};
    return {
      id,
      source: String(item?.source || manifest.source || 'ghostrecon'),
      class: moduleClass(item),
      phase: FRAMESEVEN_IDS.has(id)
        ? 'frameseven'
        : autoCapabilityPhase(id, { ...manifest, source: item?.source || manifest.source }),
      timeoutMs: boundedPositiveInteger(
        manifest.timeoutMs ?? item?.timeoutMs,
        90_000,
        100,
        3_600_000,
      ),
      concurrency: boundedPositiveInteger(
        manifest.concurrency ?? item?.concurrency,
        1,
        1,
        50,
      ),
    };
  });
  const frameSevenTimeouts = moduleLimits
    .filter((limit) => limit.phase === 'frameseven')
    .map((limit) => limit.timeoutMs);
  frameSeven.runTimeoutMs = frameSevenTimeouts.length
    ? Math.max(...frameSevenTimeouts)
    : null;
  const phaseTimeoutsMs = phaseTimeoutsFromModuleLimits(moduleLimits);
  const outOfScope = Array.isArray(body.outOfScope)
    ? [...new Set(body.outOfScope.map((item) => String(item || '').trim()).filter(Boolean))].sort()
    : [];

  const effective = {
    schemaVersion: 1,
    kind: 'ghostrecon.auto.effective-plan',
    target: String(plan?.target || body.domain || body.target || '').trim(),
    action,
    autonomyLevel,
    mode: String(plan?.mode || body.mode || 'balanced'),
    // Deep mode affects the planner's explicit module selection. The legacy
    // pipeline "deep" profile also enables unselected archive/crawler tools,
    // so Auto keeps the runtime profile bounded to preserve the plan exactly.
    profile: plan?.mode === 'quick' ? 'quick' : 'standard',
    opsecProfile: boundedOpsecProfile(body.opsecProfile, policy.opsecProfile),
    selectedModules: selected,
    pipelineModules,
    expandedModules,
    intrusiveModules,
    moduleLimits,
    requiresHumanApproval: selected.length > 0
      && (policy.requirePlanApproval || intrusiveModules.length > 0),
    engines: {
      ghostrecon: { enabled: pipelineModules.length > 0 },
      vigolium: {
        enabled: vigoliumEnabled,
        identity: vigoliumEnabled ? vigoliumIdentity : null,
        engine,
        agent: vigoliumAgent,
        useCodex: body.vigoliumUseCodex === true && Boolean(vigoliumAgentModule),
        runtime: vigoliumEnabled && body.vigoliumRuntimePlan
          && typeof body.vigoliumRuntimePlan === 'object'
          ? { ...body.vigoliumRuntimePlan }
          : null,
        input: {
          mode: 'authorized_target',
          file: null,
          type: null,
          allowEnvironment: false,
        },
      },
      frameseven: frameSeven,
    },
    execution: {
      kaliMode: requiresKali,
      // This is the exact flag that will be forwarded after the corresponding
      // approval succeeds. The orchestrator never flips it after hashing.
      confirmActive: selected.length > 0
        && (policy.requirePlanApproval || intrusiveModules.length > 0),
      engagementId: body.engagementId ? String(body.engagementId).trim() : null,
      engagementAuthorizationBinding:
        typeof body.engagementAuthorizationBinding === 'string'
          ? body.engagementAuthorizationBinding
          : null,
      outOfScope,
      autoAiReports: body.autoAiReports === true,
      phaseTimeoutsMs,
      phaseSettleGraceMs: boundedPositiveInteger(
        body.phaseSettleGraceMs,
        2_000,
        100,
        30_000,
      ),
    },
    policy: {
      ...policy,
      allowedClasses: [...policy.allowedClasses],
    },
  };
  effective.hash = stablePlanHash(effective);
  return deepFreeze(effective);
}

export function effectivePlanApprovalDetails(effectivePlan) {
  const intrusive = (effectivePlan?.intrusiveModules?.length || 0) > 0;
  return {
    kind: intrusive ? 'intrusive_plan' : 'execution_plan',
    intrusive,
    requiredScope: intrusive ? 'recon.intrusive' : null,
    target: effectivePlan?.target,
    module: (effectivePlan?.expandedModules || []).join(', '),
    action: 'executar exatamente o plano efetivo exibido',
    risk: intrusive
      ? `intrusivo: ${effectivePlan.intrusiveModules.join(', ')}`
      : 'não intrusivo; execução assistida',
    planHash: effectivePlan?.hash,
    engagementAuthorizationBinding:
      effectivePlan?.execution?.engagementAuthorizationBinding || null,
    denialBehavior: intrusive
      ? 'nenhum módulo será executado; uma nova execução exigirá novo plano e nova aprovação'
      : 'nenhum módulo será executado',
    engines: effectivePlan?.engines,
    limits: {
      profile: effectivePlan?.profile,
      opsecProfile: effectivePlan?.opsecProfile,
      enforcement: 'deadlines por fase calculados e aplicados; concorrência abaixo permanece declarativa no pipeline legado',
      phaseTimeoutsMs: effectivePlan?.execution?.phaseTimeoutsMs || {},
      modules: effectivePlan?.moduleLimits || [],
    },
  };
}
