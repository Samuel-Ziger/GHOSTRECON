export const SUPPORT_MATRIX_SCHEMA_VERSION = 1;

const SUPPORT_LEVELS = new Set(['stable', 'beta', 'experimental', 'external']);
const OPERATIONAL_POLICIES = new Set(['enabled', 'opt_in', 'disabled']);

const DECLARED_COMPONENTS = Object.freeze([
  Object.freeze({
    id: 'core',
    name: 'Núcleo GHOSTRECON',
    level: 'stable',
    policy: 'enabled',
    scope: ['api', 'pipeline', 'ndjson', 'sqlite', 'cockpit', 'cli', 'mcp', 'passive_recon'],
  }),
  Object.freeze({
    id: 'auto_observation',
    name: 'Auto observation',
    level: 'beta',
    policy: 'opt_in',
    scope: ['passive', 'deep_passive', 'intelligence'],
  }),
  Object.freeze({
    id: 'auto_assisted',
    name: 'Auto assisted',
    level: 'beta',
    policy: 'opt_in',
    scope: ['supervised_active', 'exact_plan_approval'],
  }),
  Object.freeze({
    id: 'auto_authorized',
    name: 'Auto authorized/opsec',
    level: 'experimental',
    policy: 'disabled',
    scope: ['intrusive', 'engagement_required', 'exact_plan_approval'],
  }),
  Object.freeze({
    id: 'forge',
    name: 'Module Forge',
    level: 'experimental',
    policy: 'disabled',
    scope: ['non_intrusive_only', 'strong_sandbox_required'],
  }),
  Object.freeze({
    id: 'vigolium',
    name: 'Vigolium',
    level: 'external',
    policy: 'opt_in',
    scope: ['dast', 'sealed_binary_identity', 'native_expansion_pending'],
  }),
  Object.freeze({
    id: 'frameseven',
    name: 'FrameSeven',
    level: 'external',
    policy: 'opt_in',
    scope: ['recon_v1', 'offensive_v1_requires_approval', 'authenticated_opt_in'],
  }),
  Object.freeze({
    id: 'hexstrike',
    name: 'HexStrike intelligence',
    level: 'external',
    policy: 'opt_in',
    scope: ['intelligence', 'tool_plan_only'],
  }),
]);

function observedReadiness(id, observed = {}) {
  const value = observed[id];
  if (!value || typeof value !== 'object') {
    return { state: 'unknown', reason: 'not_checked' };
  }
  if (value.ok === true || value.installed === true || value.reachable === true) {
    return value.reachable === false
      ? { state: 'degraded', reason: 'installed_not_reachable' }
      : { state: 'available', reason: 'ready' };
  }
  return {
    state: 'unavailable',
    reason: String(value.message || value.reason || 'prerequisites_missing').slice(0, 200),
  };
}

export function buildSupportMatrix({ observed = {} } = {}) {
  const components = DECLARED_COMPONENTS.map((component) => {
    if (!SUPPORT_LEVELS.has(component.level) || !OPERATIONAL_POLICIES.has(component.policy)) {
      throw new Error(`matriz de suporte inválida: ${component.id}`);
    }
    const readiness = component.id === 'core'
      ? { state: 'available', reason: 'builtin' }
      : observedReadiness(component.id, observed);
    return {
      ...component,
      scope: [...component.scope],
      readiness,
    };
  });

  return {
    schemaVersion: SUPPORT_MATRIX_SCHEMA_VERSION,
    generatedAt: new Date().toISOString(),
    policyNotice: 'readiness não concede autorização nem altera RBAC, scope, engagement, OPSEC ou aprovação',
    components,
  };
}

export function listDeclaredSupportComponents() {
  return DECLARED_COMPONENTS.map((component) => ({ ...component, scope: [...component.scope] }));
}
