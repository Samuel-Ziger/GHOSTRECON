import { AUTO_BASE_MODULES, AUTO_DEEP_PASSIVE_MODULES, AUTO_HEXSTRIKE_MODULES } from './tool-catalog.mjs';
import { isCatalogModuleAllowed } from './providers/shared.mjs';
import { normalizeModuleId } from '../modules/module-ids.mjs';

function uniq(list) {
  return [...new Set((list || []).map((x) => String(x).trim()).filter(Boolean))];
}

function uniqModuleIds(list) {
  return [...new Set((list || []).map(normalizeModuleId).filter(Boolean))];
}

function normalizeMode(mode) {
  const m = String(mode || 'balanced').trim().toLowerCase();
  if (['quick', 'balanced', 'deep'].includes(m)) return m;
  return 'balanced';
}

function commanderRoles(providers = []) {
  const selected = (providers || []).filter((p) => p.selected);
  const active = selected.filter((p) => p.usable !== false && (p.reachable || p.configured || p.installed));
  const has = (id) => active.some((p) => p.id === id);
  const leader =
    has('skynet') ? 'skynet'
      : has('codex') ? 'codex'
        : has('claude_code') ? 'claude_code'
          : has('openrouter') ? 'openrouter'
            : active[0]?.id || 'ghostrecon';
  const implementer =
    has('codex') ? 'codex'
      : has('claude_code') ? 'claude_code'
        : has('cursor') ? 'cursor'
          : leader;
  const reviewer =
    has('openrouter') ? 'openrouter'
      : has('claude_code') && implementer !== 'claude_code' ? 'claude_code'
        : has('codex') && implementer !== 'codex' ? 'codex'
          : leader;
  return { leader, implementer, reviewer };
}

function shouldUseHexstrike({ requestedModules, catalog, mode }) {
  if (requestedModules.includes('hexstrike_orchestrator')) return true;
  if (mode === 'quick') return false;
  const hx = catalog?.hexstrike;
  return Boolean(hx?.installed);
}

function catalogModuleIndex(catalog) {
  return new Map((catalog?.modules || [])
    .filter((item) => item?.id)
    .map((item) => [normalizeModuleId(item.id), item]));
}

function selectAvailableModules(moduleIds, index, autonomyLevel) {
  return uniqModuleIds(moduleIds).filter((id) => {
    const item = index.get(id);
    return Boolean(item && isCatalogModuleAllowed(item, {
      autonomyLevel,
      allowIntrusive: ['authorized', 'authorized_opsec'].includes(autonomyLevel),
    }));
  });
}

function moduleRejectionReason(id, index, autonomyLevel) {
  const item = index.get(id);
  if (!item) return 'module_not_in_catalog';
  if (item.available === false) return 'module_unavailable';
  if (!isCatalogModuleAllowed(item, {
    autonomyLevel,
    allowIntrusive: ['authorized', 'authorized_opsec'].includes(autonomyLevel),
  })) return 'module_disallowed_by_autonomy';
  return 'module_rejected';
}

export function createAutoPlan({
  target,
  mode = 'balanced',
  requestedModules = [],
  providers = [],
  catalog = {},
  openrouterModel = null,
  includeHexstrike = false,
  includeDeepPassive = null,
  ragContext = null,
  agentDecision = null,
  autonomyLevel = 'observation',
} = {}) {
  const selectedMode = normalizeMode(mode);
  const requested = uniqModuleIds(requestedModules);
  const deep = includeDeepPassive == null ? selectedMode === 'deep' : Boolean(includeDeepPassive);
  const modules = [];
  const catalogIndex = catalogModuleIndex(catalog);
  const operatorModules = selectAvailableModules(requested, catalogIndex, autonomyLevel);
  const rejectedOperatorModules = requested
    .filter((id) => !operatorModules.includes(id))
    .map((id) => ({ id, reason: moduleRejectionReason(id, catalogIndex, autonomyLevel) }));
  const decidedModules = uniqModuleIds(agentDecision?.requestedModules);
  const agentModules = selectAvailableModules(decidedModules, catalogIndex, autonomyLevel);
  const agentAction = agentDecision?.action || null;
  const executesAgentDecision = ['run_modules', 'continue_with_context'].includes(agentAction);
  const operatorOverridesTerminal = ['finish', 'abstain'].includes(agentAction)
    && operatorModules.length > 0;
  let baselineModules = [];
  let selectionStrategy = 'deterministic_baseline';

  if (agentDecision && executesAgentDecision) {
    selectionStrategy = 'agent_and_operator_allowlisted';
    modules.push(...agentModules, ...operatorModules);
  } else if (agentDecision && operatorOverridesTerminal) {
    // Explicit, allowlisted operator intent has precedence over a terminal AI
    // opinion. This is recorded as an override rather than hidden fallback.
    selectionStrategy = `explicit_operator_override:${agentAction}`;
    modules.push(...operatorModules);
  } else if (agentDecision) {
    // finish/abstain/ask_operator/forge_module are control decisions. They must
    // not be silently converted into a deterministic scan.
    selectionStrategy = `control_action:${agentAction || 'invalid'}`;
  } else {
    baselineModules.push(...AUTO_BASE_MODULES);
    if (deep) baselineModules.push(...AUTO_DEEP_PASSIVE_MODULES);
    if (includeHexstrike && shouldUseHexstrike({ requestedModules: requested, catalog, mode: selectedMode })) {
      baselineModules.push(...AUTO_HEXSTRIKE_MODULES);
    }
    baselineModules = selectAvailableModules(baselineModules, catalogIndex, autonomyLevel);
    modules.push(...baselineModules, ...operatorModules);
  }

  const roles = commanderRoles(providers);
  const openrouter = (providers || []).find((p) => p.id === 'openrouter');
  const model = openrouterModel || openrouter?.defaultModel || null;
  const planAction = operatorOverridesTerminal
    ? 'run_modules'
    : agentAction || (modules.length ? 'run_modules' : 'finish');

  return {
    schemaVersion: 1,
    kind: 'ghostrecon.auto.plan',
    target: String(target || '').trim(),
    mode: selectedMode,
    action: planAction,
    objective: 'authorized_bug_bounty_recon',
    commanders: {
      selected: (providers || []).filter((p) => p.selected).map((p) => p.id),
      available: (providers || []).filter((p) => p.configured || p.reachable || p.installed).map((p) => p.id),
      roles,
      openrouterModel: model,
    },
    steps: [
      {
        id: 'observe',
        action: 'collect_capabilities',
        status: 'planned',
      },
      {
        id: 'plan',
        action: 'select_modules',
        status: 'planned',
        modules: uniq(modules),
      },
      {
        id: 'act',
        action: 'run_ghostrecon_pipeline',
        status: 'planned',
      },
      {
        id: 'evaluate',
        action: 'summarize_findings_and_detect_gaps',
        status: 'planned',
      },
    ],
    modules: uniq(modules),
    moduleSelection: {
      strategy: selectionStrategy,
      explicitOperatorOverride: operatorOverridesTerminal,
      baseline: uniq(baselineModules),
      operator: {
        requested,
        accepted: operatorModules,
        rejected: rejectedOperatorModules,
      },
      agent: {
        action: agentAction,
        requested: decidedModules,
        accepted: agentModules,
        rejected: decidedModules
          .filter((id) => !agentModules.includes(id))
          .map((id) => ({ id, reason: moduleRejectionReason(id, catalogIndex, autonomyLevel) })),
      },
    },
    agentDecision: agentDecision || null,
    policy: {
      intrusiveAllowed: ['authorized', 'authorized_opsec'].includes(autonomyLevel),
      moduleForge: 'pending_validation_and_operator_approval',
      hexstrikeTools: 'intelligence_only',
    },
    memory: {
      ragDir: ragContext?.dir || null,
      recentDecisionCount: Array.isArray(ragContext?.items) ? ragContext.items.length : 0,
      recentDecisions: Array.isArray(ragContext?.items)
        ? ragContext.items.slice(0, 6).map((x) => ({
          name: x.name,
          title: x.title,
          preview: String(x.preview || '').slice(0, 700),
        }))
        : [],
    },
  };
}

const MODULE_OK_STATUSES = new Set(['done', 'skipped', 'skip']);
/** Outcomes que degradam a sessão para partial (não elevam a failed sozinhos). */
const MODULE_PARTIAL_STATUSES = new Set([
  'failed', 'timeout', 'cancelled', 'partial', 'error', 'blocked',
]);
/** Outcomes fatais de motor — sessão failed mesmo sem error event. */
const MODULE_FATAL_STATUSES = new Set([
  'unterminated', 'fatal', 'process_unterminated',
]);

export function classifyModuleOutcomeStatus(status) {
  const normalized = String(status || '').trim().toLowerCase();
  if (!normalized || MODULE_OK_STATUSES.has(normalized)) return 'ok';
  if (MODULE_FATAL_STATUSES.has(normalized)) return 'fatal';
  if (MODULE_PARTIAL_STATUSES.has(normalized)) return 'partial';
  // Status desconhecido: fail-closed como partial (não inventa completed).
  return 'partial';
}

export function evaluateAutoRun({ events = [], plan = null, moduleOutcomes = null } = {}) {
  const findings = events.filter((e) => e?.type === 'finding').length;
  const errors = events.filter((e) => e?.type === 'error');
  const fatalErrors = errors.filter((e) => e?.recoverable !== true);
  const recoverableErrors = errors.filter((e) => e?.recoverable === true);
  const phaseFailures = events.filter((e) => e?.type === 'phase_outcome'
    && !['done', 'skipped'].includes(String(e?.status || '')));
  const outcomes = Array.isArray(moduleOutcomes)
    ? moduleOutcomes
    : events
      .filter((e) => e?.type === 'auto_module_outcome' || (e?.type === 'module_outcome' && e.source !== 'pipeline_phase'))
      .map((e) => ({ moduleId: e.moduleId, status: e.status, source: e.source }));
  const moduleFailures = outcomes.filter((row) => classifyModuleOutcomeStatus(row?.status) !== 'ok');
  const fatalModuleFailures = moduleFailures.filter(
    (row) => classifyModuleOutcomeStatus(row?.status) === 'fatal',
  );
  const warnings = events.filter((e) => e?.type === 'log' && e.level === 'warn');
  const highSignals = events.filter((e) => e?.type === 'finding' && ['high', 'critical'].includes(String(e.finding?.prio || e.prio || '').toLowerCase())).length;
  const hasFatal = fatalErrors.length > 0 || fatalModuleFailures.length > 0;
  const partial = !hasFatal && (
    recoverableErrors.length > 0 || phaseFailures.length > 0 || moduleFailures.length > 0
  );
  return {
    schemaVersion: 1,
    kind: 'ghostrecon.auto.evaluation',
    target: plan?.target || null,
    ok: !hasFatal,
    status: hasFatal ? 'failed' : partial ? 'partial' : 'completed',
    findings,
    highSignals,
    warnings: warnings.length + recoverableErrors.length,
    errors: [
      ...fatalErrors.map((e) => e.message || e.msg || 'erro'),
      ...fatalModuleFailures.map((row) => (
        `módulo ${row.moduleId || '?'}: ${row.status || 'fatal'}`
      )),
    ],
    recoverableErrors: recoverableErrors.map((e) => e.message || e.msg || 'erro recuperável'),
    phaseFailures: phaseFailures.map((e) => ({
      phase: e.phase || null,
      status: e.status || 'failed',
      recoverable: e.recoverable === true,
      error: e.error || null,
    })),
    moduleFailures: moduleFailures.map((row) => ({
      moduleId: row.moduleId || null,
      status: row.status || 'failed',
      source: row.source || null,
      class: classifyModuleOutcomeStatus(row?.status),
    })),
    next: hasFatal
      ? 'review_errors_before_next_iteration'
      : partial
        ? 'review_partial_results_and_recoverable_failures'
      : findings
        ? 'review_findings_and_consider_deep_or_module_forge'
        : 'consider_deep_mode_or_additional_context',
  };
}
