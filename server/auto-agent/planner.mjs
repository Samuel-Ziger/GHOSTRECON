import { AUTO_BASE_MODULES, AUTO_DEEP_PASSIVE_MODULES, AUTO_HEXSTRIKE_MODULES } from './tool-catalog.mjs';

function uniq(list) {
  return [...new Set((list || []).map((x) => String(x).trim()).filter(Boolean))];
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

export function createAutoPlan({
  target,
  mode = 'balanced',
  requestedModules = [],
  providers = [],
  catalog = {},
  openrouterModel = null,
  includeHexstrike = true,
  includeDeepPassive = null,
  ragContext = null,
  agentDecision = null,
  autonomyLevel = 'observation',
} = {}) {
  const selectedMode = normalizeMode(mode);
  const requested = uniq(requestedModules);
  const deep = includeDeepPassive == null ? selectedMode === 'deep' : Boolean(includeDeepPassive);
  const modules = [];

  const decidedModules = uniq(agentDecision?.requestedModules);
  if (agentDecision && decidedModules.length) {
    modules.push(...decidedModules);
    if (['authorized', 'authorized_opsec'].includes(autonomyLevel)) {
      modules.push(...(catalog.modules || []).filter((m) => m.available !== false && (m.class === 'intrusive' || m.manifest?.intrusive === true)).map((m) => m.id));
    }
  } else {
    modules.push(...AUTO_BASE_MODULES);
    if (deep) modules.push(...AUTO_DEEP_PASSIVE_MODULES);
    if (includeHexstrike && shouldUseHexstrike({ requestedModules: requested, catalog, mode: selectedMode })) {
      modules.push(...AUTO_HEXSTRIKE_MODULES);
    }
    modules.push(...requested.filter((m) => !/^kali_|sqlmap|vigolium_|cloud_bruteforce|cred_spray|race_/i.test(m)));
    if (['authorized', 'authorized_opsec'].includes(autonomyLevel)) {
      modules.push(...(catalog.modules || []).filter((m) => m.available !== false && (m.class === 'intrusive' || m.manifest?.intrusive === true)).map((m) => m.id));
    }
  }

  const roles = commanderRoles(providers);
  const openrouter = (providers || []).find((p) => p.id === 'openrouter');
  const model = openrouterModel || openrouter?.defaultModel || null;

  return {
    schemaVersion: 1,
    kind: 'ghostrecon.auto.plan',
    target: String(target || '').trim(),
    mode: selectedMode,
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
    agentDecision: agentDecision || null,
    policy: {
      intrusiveAllowed: ['authorized', 'authorized_opsec'].includes(autonomyLevel),
      moduleForge: 'disabled_in_phase_1',
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

export function evaluateAutoRun({ events = [], plan = null } = {}) {
  const findings = events.filter((e) => e?.type === 'finding').length;
  const errors = events.filter((e) => e?.type === 'error');
  const warnings = events.filter((e) => e?.type === 'log' && e.level === 'warn');
  const highSignals = events.filter((e) => e?.type === 'finding' && ['high', 'critical'].includes(String(e.finding?.prio || e.prio || '').toLowerCase())).length;
  return {
    schemaVersion: 1,
    kind: 'ghostrecon.auto.evaluation',
    target: plan?.target || null,
    ok: errors.length === 0,
    findings,
    highSignals,
    warnings: warnings.length,
    errors: errors.map((e) => e.message || e.msg || 'erro'),
    next: errors.length
      ? 'review_errors_before_next_iteration'
      : findings
        ? 'review_findings_and_consider_deep_or_module_forge'
        : 'consider_deep_mode_or_additional_context',
  };
}
