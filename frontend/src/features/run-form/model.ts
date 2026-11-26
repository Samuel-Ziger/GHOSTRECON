import type { ManualReconBody } from '../manual-recon/service';

export const BATCH_MAX_TARGETS = 25;
export const SUBDOMAIN_CASCADE_MAX_PER_ROOT = 50;

export type ReconProfile = 'quick' | 'standard' | 'deep';

export type TargetCollection =
  | { ok: true; targets: string[] }
  | {
      ok: false;
      reason: 'empty' | 'invalid' | 'batch_empty' | 'batch_invalid';
      targets: [];
    };

export type CascadeFinding = {
  type?: unknown;
  value?: unknown;
};

export type AiStreamOptions = {
  aiPrimaryCloud?: unknown;
  aiUseOpenrouter?: unknown;
};

export type RunFormProjectionOptions = {
  aiOptions?: AiStreamOptions | null;
  kaliAvailable?: boolean;
  pipelineAuth?: unknown;
  selectedModules?: readonly string[];
};

export type RunFormProjection = {
  aiOpenrouterOnly: boolean;
  aiPrimaryCloud: 'gemini' | 'openrouter';
  aiReportsEnabled: boolean;
  aiUseOpenrouter: boolean;
  anonMode: boolean;
  anonTor: boolean;
  authorizationBasis: string;
  batchDomains: string;
  batchMode: boolean;
  domain: string;
  engagementId: string;
  exactMatch: boolean;
  frameSevenAuth: boolean;
  fullPreset: boolean;
  identityBodyEnabled: boolean;
  identityProxyPool: string[];
  includeFrameSeven: boolean;
  kaliMode: boolean;
  lmStudioOnly: boolean;
  manualAuthorizationRequested: boolean;
  modules: string[];
  navigationExec: boolean;
  navigatorMode: boolean;
  operator: string;
  outOfScope: string;
  outOfScopeEnabled: boolean;
  pipelineAuth: unknown;
  playbook: string;
  profile: ReconProfile;
  projectName: string;
  subdomainCascade: boolean;
  vigolium: {
    auditMode: string;
    authEntries: string[];
    authFiles: string[];
    engine: string;
    htmlReport: boolean;
    inputFile: string;
    inputType: string;
    moduleTags: string[];
    only: string;
    preferPath: boolean;
    reportOnly: string;
    source: string;
    strategy: string;
    useCodex: boolean;
  };
};

export type FormRoot = Pick<ParentNode, 'querySelector' | 'querySelectorAll'> & {
  getElementById?: (id: string) => HTMLElement | null;
};

function control(root: FormRoot, id: string): HTMLElement | null {
  return root.getElementById?.(id) || root.querySelector(`[id="${id}"]`);
}

function value(root: FormRoot, id: string): string {
  const element = control(root, id) as HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement | null;
  return String(element?.value || '').trim();
}

function rawValue(root: FormRoot, id: string): string {
  const element = control(root, id) as HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement | null;
  return String(element?.value || '');
}

function checked(root: FormRoot, id: string): boolean {
  return Boolean((control(root, id) as HTMLInputElement | null)?.checked);
}

function csv(valueToSplit: string): string[] {
  return valueToSplit.split(',').map((item) => item.trim()).filter(Boolean);
}

function lines(valueToSplit: string, max = Number.POSITIVE_INFINITY): string[] {
  return valueToSplit
    .split(/\r?\n/)
    .map((item) => item.trim())
    .filter(Boolean)
    .slice(0, max);
}

export function normalizeTargetKey(raw: unknown): string {
  const source = String(raw || '').trim();
  if (!source) return '';
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(source)) return source;
  if (/^\[[0-9a-f:]+\]$/i.test(source)) {
    try {
      return new URL(`https://${source}/x`).hostname.replace(/^\[|\]$/g, '').toLowerCase();
    } catch {
      return '';
    }
  }
  if (/^[0-9a-f:]+$/i.test(source) && source.includes(':')) {
    try {
      return new URL(`https://[${source}]/x`).hostname.replace(/^\[|\]$/g, '').toLowerCase();
    } catch {
      return '';
    }
  }
  try {
    const candidate = /^[a-z][a-z0-9+.-]*:\/\//i.test(source) ? source : `https://${source}`;
    return new URL(candidate).hostname.replace(/^\[|\]$/g, '').toLowerCase();
  } catch {
    return '';
  }
}

export function parseBatchTargets(raw: unknown, maxEntries = BATCH_MAX_TARGETS): string[] {
  const parts: string[] = [];
  for (const line of String(raw || '').split(/\r?\n/)) {
    for (const chunk of line.split(/[,;\s]+/)) {
      const target = chunk.trim();
      if (target) parts.push(target);
    }
  }
  const seen = new Set<string>();
  const targets: string[] = [];
  for (const target of parts) {
    const key = normalizeTargetKey(target);
    if (!key || seen.has(key)) continue;
    seen.add(key);
    targets.push(target);
    if (targets.length >= maxEntries) break;
  }
  return targets;
}

export function collectRunTargets(input: {
  batchMode?: boolean;
  batchText?: unknown;
  maxTargets?: number;
  target?: unknown;
}): TargetCollection {
  const target = String(input.target || '').trim();
  const firstKey = normalizeTargetKey(target);
  if (!target) {
    return {
      ok: false,
      reason: input.batchMode ? 'batch_empty' : 'empty',
      targets: [],
    };
  }
  if (!firstKey) {
    return {
      ok: false,
      reason: input.batchMode ? 'batch_invalid' : 'invalid',
      targets: [],
    };
  }
  if (!input.batchMode) return { ok: true, targets: [target] };

  const maxTargets = Math.max(1, Math.min(BATCH_MAX_TARGETS, Number(input.maxTargets) || BATCH_MAX_TARGETS));
  const seen = new Set([firstKey]);
  const targets = [target];
  for (const candidate of parseBatchTargets(input.batchText, maxTargets - 1)) {
    const key = normalizeTargetKey(candidate);
    if (!key || seen.has(key)) continue;
    seen.add(key);
    targets.push(candidate);
    if (targets.length >= maxTargets) break;
  }
  return { ok: true, targets };
}

export function normalizeCascadeOutOfScopeToken(raw: unknown): string {
  const source = String(raw || '').trim();
  if (!source || source.startsWith('#')) return '';
  if (source.toLowerCase().startsWith('*.')) return source.toLowerCase();
  try {
    if (/^https?:\/\//i.test(source)) return new URL(source).hostname.toLowerCase();
  } catch {
    // A regra simples abaixo continua compatível com o controller anterior.
  }
  return source.split(/[/?#]/)[0].replace(/:\d+$/, '').trim().toLowerCase();
}

export function parseCascadeOutOfScopeRules(raw: unknown): string[] {
  const rules: string[] = [];
  const seen = new Set<string>();
  for (const line of String(raw || '').split(/\r?\n/)) {
    for (const part of line.split(',')) {
      const normalized = normalizeCascadeOutOfScopeToken(part);
      if (!normalized || seen.has(normalized)) continue;
      seen.add(normalized);
      rules.push(normalized);
    }
  }
  return rules;
}

export function cascadeHostnameInTree(host: unknown, root: unknown): boolean {
  const normalizedHost = String(host || '').toLowerCase().replace(/^\[|\]$/g, '');
  const normalizedRoot = String(root || '').toLowerCase();
  return normalizedHost === normalizedRoot || normalizedHost.endsWith(`.${normalizedRoot}`);
}

export function cascadeHostMatchesOutOfScope(host: unknown, rules: readonly string[]): boolean {
  const normalizedHost = String(host || '').toLowerCase().replace(/^\[|\]$/g, '');
  if (!normalizedHost || !rules.length) return false;
  return rules.some((rule) => {
    if (!rule) return false;
    const suffix = rule.startsWith('*.') ? rule.slice(2) : rule;
    return Boolean(suffix) && (
      normalizedHost === suffix || normalizedHost.endsWith(`.${suffix}`)
    );
  });
}

export function extractCascadeSubdomains(
  findings: readonly CascadeFinding[],
  rootHost: string,
  alreadySeen: ReadonlySet<string>,
  outOfScopeRules: readonly string[],
  maxEntries = SUBDOMAIN_CASCADE_MAX_PER_ROOT,
): string[] {
  const root = rootHost.toLowerCase();
  const local = new Set<string>();
  const subdomains: string[] = [];
  for (const finding of findings) {
    if (!finding || finding.type !== 'subdomain' || !finding.value) continue;
    const host = String(finding.value).trim().toLowerCase();
    if (host === root) continue;
    if (!cascadeHostnameInTree(host, root)) continue;
    if (cascadeHostMatchesOutOfScope(host, outOfScopeRules)) continue;
    if (alreadySeen.has(host) || local.has(host)) continue;
    local.add(host);
    subdomains.push(host);
    if (subdomains.length >= maxEntries) break;
  }
  return subdomains;
}

export function normalizeReconProfile(raw: unknown): ReconProfile {
  const profile = String(raw || '').trim().toLowerCase();
  return profile === 'quick' || profile === 'deep' ? profile : 'standard';
}

export function projectRunForm(
  root: FormRoot,
  options: RunFormProjectionOptions = {},
): RunFormProjection {
  const modules = options.selectedModules
    ? [...new Set(options.selectedModules.map(String).filter(Boolean))]
    : [...root.querySelectorAll<HTMLInputElement>('input.mod[type="checkbox"]:checked')]
        .map((element) => element.value)
        .filter(Boolean);
  const includeFrameSeven = checked(root, 'includeFrameSevenToggle');
  const aiReportsEnabled = checked(root, 'modAiReports');
  const primaryCloud = options.aiOptions?.aiPrimaryCloud === 'openrouter'
    ? 'openrouter'
    : 'gemini';

  return {
    aiOpenrouterOnly: primaryCloud === 'openrouter',
    aiPrimaryCloud: primaryCloud,
    aiReportsEnabled,
    aiUseOpenrouter: options.aiOptions?.aiUseOpenrouter !== false,
    anonMode: checked(root, 'anonModeToggle'),
    anonTor: checked(root, 'anonTorToggle'),
    authorizationBasis: value(root, 'manualAuthorizationBasisSelect') || 'explicit',
    batchDomains: rawValue(root, 'batchDomainsInput'),
    batchMode: checked(root, 'batchModeToggle'),
    domain: value(root, 'domainInput'),
    engagementId: value(root, 'engagementIdInput'),
    exactMatch: checked(root, 'exactMatch'),
    frameSevenAuth: includeFrameSeven && checked(root, 'frameSevenAuthToggle'),
    fullPreset: checked(root, 'fullPresetToggle'),
    identityBodyEnabled: checked(root, 'identityBodyEnabledToggle'),
    identityProxyPool: lines(rawValue(root, 'identityProxyPoolInput'), 32),
    includeFrameSeven,
    kaliMode: Boolean(options.kaliAvailable && checked(root, 'kaliModeToggle')),
    lmStudioOnly: checked(root, 'modAiLmStudioOnly'),
    manualAuthorizationRequested: checked(root, 'manualAuthorizationToggle'),
    modules,
    navigationExec: checked(root, 'navegationExecToggle'),
    navigatorMode: checked(root, 'navigatorModeToggle'),
    operator: value(root, 'engagementOperatorInput'),
    outOfScope: value(root, 'outOfScopeInput'),
    outOfScopeEnabled: modules.includes('out_of_scope'),
    pipelineAuth: options.pipelineAuth ?? null,
    playbook: value(root, 'playbookNameInput'),
    profile: normalizeReconProfile(value(root, 'reconProfileSelect')),
    projectName: value(root, 'projectNameInput'),
    subdomainCascade: checked(root, 'subdomainCascadeToggle'),
    vigolium: {
      auditMode: value(root, 'vigoliumAuditModeSelect').toLowerCase(),
      authEntries: lines(rawValue(root, 'vigoliumAuthEntriesInput')),
      authFiles: csv(rawValue(root, 'vigoliumAuthFileInput')),
      engine: value(root, 'vigoliumEngineSelect').toLowerCase(),
      htmlReport: checked(root, 'vigoliumHtmlReportToggle'),
      inputFile: value(root, 'vigoliumInputFileInput'),
      inputType: value(root, 'vigoliumInputTypeInput'),
      moduleTags: csv(rawValue(root, 'vigoliumModuleTagsInput')),
      only: value(root, 'vigoliumOnlyInput'),
      preferPath: checked(root, 'vigoliumPreferPathToggle'),
      reportOnly: value(root, 'vigoliumReportOnlyInput'),
      source: value(root, 'vigoliumSourceInput'),
      strategy: value(root, 'vigoliumStrategySelect').toLowerCase(),
      useCodex: checked(root, 'vigoliumUseCodexToggle'),
    },
  };
}

export function buildManualReconBody(
  projection: RunFormProjection,
  host: string,
): ManualReconBody {
  const modules = [...projection.modules];
  if (!projection.navigatorMode || projection.fullPreset) {
    const index = modules.indexOf('navegation');
    if (index >= 0) modules.splice(index, 1);
  } else if (!modules.includes('navegation')) {
    modules.push('navegation');
  }

  const body: ManualReconBody = {
    domain: host,
    exactMatch: projection.exactMatch,
    modules,
    kaliMode: projection.kaliMode,
    profile: projection.profile,
    opsecProfile: 'standard',
    auth: projection.pipelineAuth,
    includeFrameSeven: projection.includeFrameSeven,
    frameSevenAuth: projection.frameSevenAuth,
    autoAiReports: projection.aiReportsEnabled,
    aiProviderMode: projection.lmStudioOnly ? 'lmstudio_only' : 'auto',
  };

  if (projection.aiReportsEnabled) {
    body.aiUseOpenrouter = projection.aiUseOpenrouter;
    body.aiPrimaryCloud = projection.aiPrimaryCloud;
    body.aiOpenrouterOnly = projection.aiOpenrouterOnly;
  }
  if (projection.outOfScopeEnabled) body.outOfScope = projection.outOfScope;
  if (projection.projectName) body.projectName = projection.projectName;
  if (projection.engagementId && !projection.manualAuthorizationRequested) {
    body.engagementId = projection.engagementId;
  }
  if (projection.operator) body.operator = projection.operator;
  if (projection.playbook) body.playbook = projection.playbook;
  if (projection.fullPreset) body.fullPreset = true;
  if (projection.navigatorMode && !projection.fullPreset) {
    body.navigatorMode = true;
    body.navegation = { exec: projection.navigationExec, userMode: true };
  }

  const vigolium = projection.vigolium;
  if (['node', 'go', 'both'].includes(vigolium.engine)) body.engine = vigolium.engine;
  if (['lite', 'balanced', 'deep'].includes(vigolium.strategy)) {
    body.vigoliumStrategy = vigolium.strategy;
  }
  if (vigolium.preferPath) body.vigoliumPreferPath = true;
  if (vigolium.useCodex) body.vigoliumUseCodex = true;
  if (vigolium.source) body.vigoliumSource = vigolium.source;
  if (vigolium.authFiles.length) body.vigoliumAuthFiles = vigolium.authFiles;
  if (vigolium.authEntries.length) body.vigoliumAuthEntries = vigolium.authEntries;
  if (vigolium.inputFile) body.vigoliumInputFile = vigolium.inputFile;
  if (vigolium.inputType) body.vigoliumInputType = vigolium.inputType;
  if (vigolium.only) body.vigoliumOnly = vigolium.only;
  if (vigolium.htmlReport) body.vigoliumHtmlReport = true;
  if (vigolium.reportOnly) body.vigoliumReportOnly = vigolium.reportOnly;
  if (vigolium.moduleTags.length) body.vigoliumModuleTags = vigolium.moduleTags;
  if (['lite', 'balanced', 'deep'].includes(vigolium.auditMode)) {
    body.vigoliumAuditMode = vigolium.auditMode;
  }
  if (modules.includes('vigolium_autopilot')) body.vigoliumAgent = 'autopilot';
  else if (modules.includes('vigolium_swarm')) body.vigoliumAgent = 'swarm';
  else if (modules.includes('vigolium_audit')) body.vigoliumAgent = 'audit';

  const anonTor = projection.anonMode && projection.anonTor;
  if (anonTor) {
    body.tor = {
      required: true,
      strict: true,
      newnymBeforeRun: true,
      perTargetCircuit: true,
    };
  }

  const identityModule = projection.modules.includes('identity_rotation');
  const fixedProxy = projection.identityProxyPool[0] || '';
  const proxyPool = fixedProxy
    ? [fixedProxy]
    : anonTor
      ? ['socks5h://127.0.0.1:9050']
      : [];
  if (identityModule || projection.identityBodyEnabled || projection.identityProxyPool.length || anonTor) {
    body.identity = {
      enabled: identityModule
        || projection.identityBodyEnabled
        || projection.identityProxyPool.length > 0
        || anonTor,
      behavior: true,
      rotation: 'fixed',
      proxyPool,
    };
  }

  return body;
}
