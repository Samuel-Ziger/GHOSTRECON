import { createHash, randomBytes } from 'node:crypto';
import { buildAutoToolCatalog } from './tool-catalog.mjs';
import { createAutoPlan, evaluateAutoRun } from './planner.mjs';
import { writeAutoDecisionMarkdown } from './rag-memory.mjs';
import { assertDurableRagPersist } from './rag-persist-guard.mjs';
import { buildAutoObservationBundle } from './observation-builder.mjs';
import { gateModules } from '../modules/opsec.mjs';
import { assertNoRetiredModules } from '../modules/retired-modules.mjs';
import {
  assertAutoResumeSnapshotCompatible,
  claimAutoResumeCheckpoint,
  computeAutoReadyPlanHash,
  computeAutoResumePolicyHash,
  createAutoCheckpoint,
  autoEngineTimeouts,
  autoSessionLimits,
  createAutoSession,
  readAutoSessionSnapshot,
  writeAutoSessionSnapshot,
} from './session-store.mjs';
import { registerActiveAutoSession, unregisterActiveAutoSession } from './active-sessions.mjs';
import { persistAutoRunReport } from './auto-run-report.mjs';
import { runFrameSeven } from '../integrations/frameseven-adapter.mjs';
import { readAndMergeFrameSevenReport } from '../integrations/frameseven-report.mjs';
import { publicFrameSevenReportUrl } from '../integrations/frameseven-runner.mjs';
import {
  buildEffectiveAutoPlan,
  effectivePlanApprovalDetails,
} from './effective-plan.mjs';
import { autoCapabilityPhase } from './pipeline-capabilities.mjs';
import {
  computeEngagementAuthorizationBinding,
  getEngagement,
  preRunChecklist,
} from '../modules/engagement.mjs';
import {
  createEngagementScopePolicy,
  mergeOutOfScopeLists,
  parseOutOfScopeClientInput,
} from '../modules/scope.js';
import { loadAutoRedactionPolicy, redactAutoValue } from './redaction.mjs';
import { _authStateForTests } from '../modules/auth.js';
import { isFatalVigoliumExecutionError } from '../../bridge/vigolium-errors.mjs';
import { normalizeMcpSelection } from '../integrations/mcp/catalog.mjs';
import {
  buildVigoliumChildEnv,
  resolveVigoliumEffectiveConfig,
} from '../../bridge/vigolium-config.mjs';
import {
  applyVigoliumExpansionToRuntime,
  expandVigoliumEffectiveModules,
} from '../../bridge/vigolium-plan-expand.mjs';
import {
  inspectVigoliumSourceIdentity,
  resolveVigoliumSourceAllowedRoots,
} from '../../bridge/vigolium-source-integrity.mjs';
import {
  assertEngineScopeEnforcementAvailable,
  scopePolicyEnvBindings,
  sealEngineScopePolicy,
  writeSealedScopePolicyFile,
} from '../modules/engine-scope-policy.mjs';

const AUTO_PROMPT_VERSION = 'auto-deterministic-v1';
const AUTO_BOUNTY_CONTEXT_MAX_CHARS = 16_000;
const RETIRED_AUTO_AI_FIELDS = Object.freeze([
  'commander',
  'commanders',
  'providers',
  'openrouterModel',
  'model',
  'cloudEvidenceConsent',
]);

export function normalizeAutoBugBountyContext(value, env = process.env) {
  if (value == null || value === '') return null;
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('bountyContext do Auto precisa ser um objeto JSON');
  }
  const safe = redactAutoValue(value, {
    env,
    maxDepth: 6,
    maxArrayItems: 100,
    maxObjectKeys: 100,
  });
  const serialized = JSON.stringify(safe);
  if (serialized.length > AUTO_BOUNTY_CONTEXT_MAX_CHARS) {
    throw new Error(`bountyContext do Auto excede ${AUTO_BOUNTY_CONTEXT_MAX_CHARS} caracteres`);
  }
  return safe;
}

export function normalizeAutoNeuroSploitConfig(value) {
  const source = value && typeof value === 'object' && !Array.isArray(value) ? value : {};
  const forbidden = ['apiKey', 'api_key', 'token', 'authorization', 'password', 'secret'];
  if (forbidden.some((key) => Object.prototype.hasOwnProperty.call(source, key))) {
    throw new Error('credenciais não podem ser enviadas na configuração NeuroSploit do Auto');
  }
  const profileId = Number(source.profileId || 0);
  const mcpServers = normalizeMcpSelection(source.mcpServers);
  if (mcpServers.length && source.codexCli !== true) {
    throw new Error('Mind e outros MCPs do NeuroSploit Auto exigem Codex CLI');
  }
  return Object.freeze({
    profileId: Number.isSafeInteger(profileId) && profileId > 0 ? profileId : null,
    environment: ['lab', 'development', 'staging', 'production'].includes(String(source.environment || '').toLowerCase())
      ? String(source.environment).toLowerCase()
      : 'production',
    votes: boundedNumber(source.votes, 2, 1, 5),
    recon: boundedNumber(source.recon, 1, 1, 4),
    chainDepth: boundedNumber(source.chainDepth, 2, 0, 6),
    maxAgents: boundedNumber(source.maxAgents, 0, 0, 64),
    quick: source.quick === true,
    timeoutMs: boundedNumber(source.timeoutMs, 90 * 60_000, 60_000, 2 * 60 * 60_000),
    focus: String(source.focus || '').replace(/[\r\n\0]+/g, ' ').trim().slice(0, 2_000),
    objective: String(source.objective || '').replace(/[\r\n\0]+/g, ' ').trim().slice(0, 2_000),
    outOfScope: String(source.outOfScope || '').replace(/[\r\n\0]+/g, ' ').trim().slice(0, 2_000),
    codexCli: source.codexCli === true,
    mcpServers,
  });
}

function stableCatalogValue(value) {
  if (Array.isArray(value)) return value.map(stableCatalogValue);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, stableCatalogValue(value[key])]),
  );
}

function bindAutoRuntimeValue(value) {
  return createHash('sha256')
    .update(JSON.stringify(stableCatalogValue(value)))
    .digest('hex');
}

function hasAutoVigoliumAuthMaterial(body = {}, env = {}) {
  const bodyValues = [
    body.vigoliumAuth,
    body.vigoliumAuthFile,
    ...(Array.isArray(body.vigoliumAuthEntries) ? body.vigoliumAuthEntries : []),
    ...(Array.isArray(body.vigoliumAuthFiles) ? body.vigoliumAuthFiles : []),
  ];
  const envValues = [
    env.GHOSTRECON_VIGOLIUM_AUTH,
    env.GHOSTRECON_VIGOLIUM_AUTHS,
    env.GHOSTRECON_VIGOLIUM_AUTH_FILE,
    env.GHOSTRECON_VIGOLIUM_AUTH_FILES,
  ];
  return [...bodyValues, ...envValues].some((value) => String(value ?? '').trim());
}

function autoVigoliumRuntimeContext(body, effectivePlan, useCodex) {
  const agentMode = effectivePlan?.engines?.vigolium?.agent || 'none';
  return {
    ...body,
    modules: [...(effectivePlan?.pipelineModules || [])],
    engine: effectivePlan?.engines?.vigolium?.engine || 'node',
    vigoliumAgent: agentMode,
    vigoliumUseCodex: useCodex === true,
    // Auth pré-carregada não integra o Auto. No fluxo autenticado, o contexto
    // nasce no browser somente depois da aprovação humana específica.
    vigoliumAuth: null,
    vigoliumAuthFile: null,
    vigoliumAuthEntries: [],
    vigoliumAuthFiles: [],
    // `-T` permanece proibido porque pode expandir o alvo.
    vigoliumInputFile: null,
    vigoliumInputType: null,
    // Uma fonte configurada não participa de DAST puro. Evite que um valor de
    // ambiente não utilizado contamine ou amplie esse plano.
    ...(agentMode === 'none'
      ? {
          vigoliumRuntimeConfigFrozen: true,
          vigoliumSource: null,
        }
      : {}),
  };
}

/**
 * Resolve uma única vez a configuração executável do Vigolium usada pelo Auto.
 * O plano público recebe somente valores não sensíveis e bindings; o snapshot
 * privado completo é entregue ao pipeline sem voltar a consultar `process.env`.
 */
export async function resolveAutoVigoliumRuntimeSnapshot({
  body = {},
  effectivePlan,
  catalog,
  env = {},
  useCodex = false,
  sourceIdentity = null,
  sourceAllowedRoots = [],
  listVigoliumModulesImpl = null,
  ghostRoot = null,
  sealedScopePolicy = null,
} = {}) {
  if (!effectivePlan?.engines?.vigolium?.enabled) {
    return Object.freeze({ runtime: null, publicPlan: null });
  }
  const resolved = resolveVigoliumEffectiveConfig(
    autoVigoliumRuntimeContext(body, effectivePlan, useCodex),
    { env },
  );
  const dastSelected = effectivePlan?.engines?.vigolium?.engine === 'both'
    || effectivePlan?.engines?.vigolium?.engine === 'go'
    || (effectivePlan?.pipelineModules || []).includes('vigolium_dast');
  let expansion = Object.freeze({
    schemaVersion: 1,
    moduleIds: Object.freeze([]),
    modules: Object.freeze([]),
    catalogHash: null,
    catalogCount: 0,
  });
  let expandedResolved = resolved;
  if (dastSelected) {
    expansion = await expandVigoliumEffectiveModules({
      modules: resolved.vigoliumModules,
      moduleTags: resolved.vigoliumModuleTags,
      only: resolved.vigoliumOnly,
      root: ghostRoot || process.cwd(),
      forAuto: true,
      ...(typeof listVigoliumModulesImpl === 'function'
        ? { listModulesImpl: listVigoliumModulesImpl }
        : {}),
    });
    expandedResolved = applyVigoliumExpansionToRuntime(resolved, expansion);
  }
  if (sealedScopePolicy) {
    assertEngineScopeEnforcementAvailable({
      engine: 'vigolium',
      sealedPolicy: sealedScopePolicy,
      env,
      engineDeclaresSupport: catalog?.engines?.vigolium?.supportsSealedScopePolicy === true,
    });
  }
  const scopeEnv = scopePolicyEnvBindings(sealedScopePolicy);
  const childEnv = Object.freeze({
    ...buildVigoliumChildEnv(expandedResolved, env),
    ...scopeEnv,
  });
  const binaryPath = String(catalog?.engines?.vigolium?.binary || '').trim() || null;
  const binarySource = String(catalog?.engines?.vigolium?.source || '').trim() || null;
  if (!binaryPath || !effectivePlan.engines.vigolium.identity) {
    throw new Error('Vigolium exige binário e identidade selados antes do plano efetivo');
  }
  const runtime = Object.freeze({
    ...expandedResolved,
    vigoliumChildEnv: childEnv,
    vigoliumBinaryPath: binaryPath,
    vigoliumBinarySource: binarySource,
    vigoliumExpectedIdentity: effectivePlan.engines.vigolium.identity,
    vigoliumExpectedSourceIdentity: sourceIdentity,
    vigoliumSourceAllowedRoots: Object.freeze([...(sourceAllowedRoots || [])]),
    vigoliumSealedScopePolicyHash: sealedScopePolicy?.policyHash || null,
    // Auth pré-carregada é proibida no Auto. Mantenha o contrato completo no
    // snapshot para que o pipeline não precise inferir defaults nem consultar
    // o ambiente depois da aprovação.
    vigoliumExpectedAuthFileIdentities: Object.freeze([]),
    vigoliumAuthAllowedRoots: Object.freeze([]),
  });
  const publicPlan = Object.freeze({
    strategy: runtime.vigoliumStrategy,
    modules: [...runtime.vigoliumModules],
    resolvedModules: expansion.modules,
    catalogHash: expansion.catalogHash,
    catalogCount: expansion.catalogCount,
    moduleTags: [...runtime.vigoliumModuleTags],
    auditMode: runtime.vigoliumAuditMode,
    only: runtime.vigoliumOnly,
    reportOnly: runtime.vigoliumReportOnly,
    htmlReport: runtime.vigoliumHtmlReport,
    preferPath: runtime.vigoliumPreferPath,
    vpsProfile: runtime.vigoliumVpsProfile,
    skipExternalHarvest: runtime.vigoliumSkipExternalHarvest,
    scanTimeoutMs: runtime.vigoliumTimeoutMs,
    agentTimeoutMs: runtime.vigoliumAgentTimeoutMs,
    scopePolicyHash: sealedScopePolicy?.policyHash || null,
    binarySource,
    binaryPathBinding: bindAutoRuntimeValue(binaryPath),
    sourceMode: runtime.vigoliumSource ? 'configured_local' : 'none',
    sourceBinding: runtime.vigoliumSource
      ? bindAutoRuntimeValue(runtime.vigoliumSource)
      : null,
    sourceIdentity: sourceIdentity
      ? Object.freeze({
          version: sourceIdentity.version,
          kind: sourceIdentity.kind,
          objectFormat: sourceIdentity.objectFormat,
          commit: sourceIdentity.commit,
          tree: sourceIdentity.tree,
          trackedEntries: sourceIdentity.trackedEntries,
        })
      : null,
    childEnvBinding: bindAutoRuntimeValue(childEnv),
    runtimeBinding: bindAutoRuntimeValue({
      ...runtime,
      vigoliumExpectedIdentity: effectivePlan.engines.vigolium.identity,
    }),
  });
  return Object.freeze({ runtime, publicPlan, expansion });
}

export function computeAutoCatalogHash(catalog = {}) {
  const rows = (Array.isArray(catalog?.modules) ? catalog.modules : [])
    .map((module) => {
      const manifest = module?.manifest || {};
      return {
        id: String(module?.id || ''),
        source: String(module?.source || manifest.source || ''),
        class: String(module?.class || manifest.class || ''),
        available: module?.available !== false,
        intrusive: module?.intrusive === true || manifest.intrusive === true,
        destructive: module?.destructive === true || manifest.destructive === true,
        requiresAuth: module?.requiresAuth === true || manifest.requiresAuth === true,
        requiresKali: module?.requiresKali === true || manifest.requiresKali === true,
        timeoutMs: Number(manifest.timeoutMs ?? module?.timeoutMs ?? 0) || 0,
        concurrency: Number(manifest.concurrency ?? module?.concurrency ?? 0) || 0,
        phase: String(manifest.phase || ''),
        forgeId: module?.forgeId || manifest?.forgeId || null,
        runtimeIntegrity: module?.runtimeIntegrity || manifest?.runtimeIntegrity || null,
        engineIdentity: module?.engineIdentity || manifest?.engineIdentity || null,
      };
    })
    .sort((left, right) => left.id.localeCompare(right.id));
  const engines = Object.fromEntries(
    Object.entries(catalog?.engines || {})
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([id, engine]) => [id, {
        available: engine?.available === true,
        identity: engine?.identity || null,
        runtimeBinding: engine?.runtimeBinding || null,
      }]),
  );
  return createHash('sha256')
    .update(JSON.stringify(stableCatalogValue({ modules: rows, engines })))
    .digest('hex');
}

/**
 * Vincula o plano AUTO somente aos campos do engagement que concedem ou
 * restringem autorização. Notas e histórico de runs não invalidam uma
 * aprovação; status, ROE, janela, origem, escopo ou exclusões invalidam.
 */
export function computeAutoEngagementAuthorizationBinding(
  engagement,
  requestedEngagementId = null,
) {
  return computeEngagementAuthorizationBinding(engagement, requestedEngagementId);
}

function sendSafe(emit, obj) {
  try { emit(obj); } catch { /* ignore */ }
}

const LOCAL_ARTIFACT_KEYS = new Set([
  'baseDir',
  'binary',
  'dir',
  'filePath',
  'outputDir',
  'path',
  'pendingDir',
  'revisionDir',
]);

function isAbsoluteLocalPath(value) {
  return typeof value === 'string'
    && (/^(?:\/|[A-Za-z]:[\\/])/.test(value) || /^\\\\[^\\]/.test(value));
}

function redactRootFromString(value, root = null) {
  const text = String(value);
  const localRoot = String(root || '').replace(/[\\/]+$/, '');
  if (!localRoot || !text.includes(localRoot)) return text;
  return text.split(localRoot).join('[LOCAL_ROOT]');
}

/**
 * Eventos NDJSON são uma fronteira pública. Redija segredos em profundidade e
 * remova caminhos absolutos de artefatos sem apagar URLs/paths relativos que
 * façam parte de findings.
 */
export function publicAutoEvent(event, { root = null } = {}) {
  const redacted = redactAutoValue(event, {
    preserveSensitiveKeys: new Set(['session', 'sessionId']),
  });
  const sanitize = (value) => {
    if (Array.isArray(value)) return value.map(sanitize);
    if (typeof value === 'string') return redactRootFromString(value, root);
    if (!value || typeof value !== 'object') return value;
    const safe = {};
    for (const [key, item] of Object.entries(value)) {
      if (LOCAL_ARTIFACT_KEYS.has(key) && isAbsoluteLocalPath(item)) continue;
      safe[key] = sanitize(item);
    }
    return safe;
  };
  return sanitize(redacted);
}

function boundedNumber(value, fallback, min, max) {
  const parsed = Number(value);
  return Math.max(min, Math.min(max, Number.isFinite(parsed) ? parsed : fallback));
}

export async function runWithDeadline({
  name,
  timeoutMs,
  parentSignal,
  settleGraceMs = 5_000,
  work,
}) {
  const controller = new AbortController();
  const combinedSignal = parentSignal
    ? AbortSignal.any([parentSignal, controller.signal])
    : controller.signal;
  const timeoutError = new Error(`${name}_timeout`);
  timeoutError.code = 'AUTO_DEADLINE_TIMEOUT';
  let timer = null;
  let graceTimer = null;
  let parentAbortListener = null;
  const workPromise = Promise.resolve()
    .then(() => work(combinedSignal))
    .then(
      (value) => ({ status: 'fulfilled', value }),
      (error) => ({ status: 'rejected', error }),
    );
  const timeout = new Promise((resolve) => {
    timer = setTimeout(() => {
      controller.abort(timeoutError);
      resolve({ status: 'timeout' });
    }, timeoutMs);
    timer.unref?.();
  });
  const cancelled = new Promise((resolve) => {
    if (!parentSignal) return;
    parentAbortListener = () => resolve({ status: 'cancelled' });
    if (parentSignal.aborted) parentAbortListener();
    else parentSignal.addEventListener('abort', parentAbortListener, { once: true });
  });
  try {
    const first = await Promise.race([workPromise, timeout, cancelled]);
    if (first.status === 'fulfilled') return first.value;
    if (first.status === 'rejected') throw first.error;

    // Não avance para outro motor enquanto o trabalho vencido ainda estiver
    // executando. Se não assentar após o abort, falhe fechado: continuar criaria
    // sobreposição e subprocessos órfãos.
    const settled = await Promise.race([
      workPromise,
      new Promise((resolve) => {
        graceTimer = setTimeout(() => resolve(null), Math.max(100, settleGraceMs));
        graceTimer.unref?.();
      }),
    ]);
    if (!settled) {
      const error = new Error(`${name}_timeout_unsettled`);
      error.code = 'AUTO_DEADLINE_UNSETTLED';
      error.cause = first.status === 'cancelled'
        ? parentSignal?.reason || new Error(`${name}_cancelled`)
        : timeoutError;
      throw error;
    }
    if (first.status === 'cancelled') {
      throw parentSignal?.reason || new Error(`${name}_cancelled`);
    }
    throw timeoutError;
  } finally {
    clearTimeout(timer);
    clearTimeout(graceTimer);
    if (parentAbortListener) {
      parentSignal?.removeEventListener('abort', parentAbortListener);
    }
  }
}

export function terminalStatus(error, session) {
  if (!session?.signal?.aborted) return { status: 'failed', cause: 'failed' };
  const reason = String(session.signal.reason?.message || session.signal.reason || error?.message || '');
  if (/stall/i.test(reason)) return { status: 'stalled', cause: reason };
  if (/timeout|timed.out/i.test(reason)) return { status: 'timed_out', cause: reason };
  if (/budget|custo/i.test(reason)) return { status: 'budget_exceeded', cause: reason };
  if (/client|stream|disconnect/i.test(reason)) return { status: 'cancelled', cause: 'client_disconnected' };
  return { status: 'cancelled', cause: reason || 'operator_cancelled' };
}

export function sessionTerminalFromEvaluation(evaluation) {
  const status = String(evaluation?.status || 'completed');
  if (status === 'failed') return 'failed';
  if (status === 'partial') return 'partial';
  if (status === 'completed') return 'completed';
  // Status de avaliação desconhecido: fail-closed (não promove a completed).
  return 'failed';
}

function assertPersistentPrincipalBinding(env = process.env) {
  if (/^(0|false|no|off)$/i.test(String(env.GHOSTRECON_AUTO_REQUIRE_PERSISTENT_BINDING || '0'))) {
    return;
  }
  const binding = _authStateForTests()?.principalBinding;
  if (binding?.persistent === true) return;
  const error = new Error(
    'binding persistente do principal obrigatório (AUTH_PRINCIPAL_BINDING_SECRET ou AUTH_JWT_SECRET HS256 >=32)',
  );
  error.code = 'AUTO_PRINCIPAL_BINDING_REQUIRED';
  throw error;
}

async function persistTerminalSession({
  ROOT,
  env,
  session,
  finalSession,
  captureEmit,
  sessionId,
  requestRunId,
  preferredPhase,
  evaluation = null,
  moduleOutcomes = [],
  plan = null,
  events = [],
}) {
  let phase = String(finalSession?.status || preferredPhase || 'failed');
  finalSession.runId = String(finalSession.requestRunId || requestRunId || '').trim() || null;
  try {
    await writeAutoSessionSnapshot(ROOT, finalSession, env);
  } catch (snapshotError) {
    captureEmit({
      type: 'auto_persist_failed',
      stage: 'terminal_snapshot',
      sessionId,
      requestRunId,
      error: snapshotError?.message || String(snapshotError),
    });
    if (['completed', 'partial'].includes(phase)) {
      phase = 'failed';
      finalSession.status = 'failed';
      finalSession.error = finalSession.error
        || `persist_failed: ${snapshotError?.message || snapshotError}`;
      finalSession.terminationCause = 'persist_failed';
    }
    // Persistência terminal obrigatória: não reportar sucesso sem snapshot.
    if (['completed', 'partial'].includes(String(preferredPhase || ''))) {
      throw Object.assign(
        new Error(finalSession.error || 'falha ao persistir snapshot terminal'),
        { code: 'AUTO_TERMINAL_PERSIST_FAILED', cause: snapshotError },
      );
    }
  }
  try {
    const report = await persistAutoRunReport({
      root: ROOT,
      session: finalSession,
      evaluation,
      moduleOutcomes,
      plan,
      events,
      env,
    });
    if (report) {
      finalSession.reportUrl = report.reportUrl;
      finalSession.reportPath = report.jsonPath;
      captureEmit({
        type: 'auto_report_ready',
        sessionId,
        requestRunId,
        runId: report.runId,
        reportUrl: report.reportUrl,
      });
    }
  } catch (reportError) {
    captureEmit({
      type: 'auto_persist_failed',
      stage: 'terminal_report',
      sessionId,
      requestRunId,
      error: reportError?.message || String(reportError),
    });
  }
  captureEmit({ type: 'auto_session', phase, session: finalSession });
  return { phase, finalSession };
}

export function assertNoRetiredAutoAiFields(body = {}) {
  const retired = RETIRED_AUTO_AI_FIELDS.filter((field) => (
    Object.prototype.hasOwnProperty.call(body || {}, field)
  ));
  if (!retired.length) return;
  const error = new Error(
    `AI Council removido; campos aposentados: ${retired.join(', ')}`,
  );
  error.code = 'AUTO_AI_COUNCIL_RETIRED';
  error.status = 410;
  error.fields = retired;
  throw error;
}

export function normalizeAutoRequest(body = {}, env = process.env) {
  assertNoRetiredAutoAiFields(body);
  assertNoRetiredModules(body.modules);
  return {
    target: body.domain || body.target || '',
    mode: body.autoMode || body.mode || 'balanced',
    modules: Array.isArray(body.modules) ? body.modules.map(String) : [],
    includeHexstrike: body.includeHexstrike === true,
    includeDeepPassive: body.includeDeepPassive,
    includeFrameSeven: body.includeFrameSeven === true,
    includeVigolium: body.includeVigolium === true,
    includeNeuroSploit: body.includeNeuroSploit === true,
    neurosploit: normalizeAutoNeuroSploitConfig(body.neurosploit),
    // Política explícita de autonomia da IA por sessão. O nível 4 continua
    // sujeito à confirmação humana por ação destrutiva (não há execução livre).
    // Kill-switch operacional: assertAutoAutonomyAllowed na rota HTTP / MCP.
    autonomyLevel: ['observation', 'assisted', 'authorized', 'authorized_opsec'].includes(String(body.autonomyLevel || '').toLowerCase())
      ? String(body.autonomyLevel).toLowerCase() : 'observation',
    frameSevenAuth: body.includeFrameSeven === true && body.frameSevenAuth === true,
    vigoliumUseCodex: body.includeVigolium === true && body.vigoliumUseCodex === true,
    engagementId: body.engagementId ? String(body.engagementId).trim() : null,
    resumeSessionId: body.resumeSessionId ? String(body.resumeSessionId).trim() : null,
    approvalMode: body.approvalMode === 'deny' ? 'deny' : 'interactive',
    opsecProfile: ['passive', 'stealth', 'standard', 'aggressive'].includes(
      String(body.opsecProfile || '').trim().toLowerCase(),
    ) ? String(body.opsecProfile).trim().toLowerCase() : null,
    bountyContext: normalizeAutoBugBountyContext(body.bountyContext, env),
  };
}

export function buildAutoResumePolicy(req, body = {}, limits = null, engineTimeouts = null) {
  const uniqueSorted = (values) => [...new Set((values || [])
    .map((value) => String(value || '').trim())
    .filter(Boolean))].sort();
  const envSource = body?.env || process.env;
  const effectiveLimits = limits && typeof limits === 'object'
    ? limits
    : autoSessionLimits(envSource);
  const effectiveEngineTimeouts = engineTimeouts && typeof engineTimeouts === 'object'
    ? engineTimeouts
    : autoEngineTimeouts(envSource);
  return Object.freeze({
    schemaVersion: 1,
    mode: String(req?.mode || 'balanced'),
    requestedModules: uniqueSorted(req?.modules),
    includeHexstrike: req?.includeHexstrike === true,
    includeDeepPassive: req?.includeDeepPassive !== false,
    includeFrameSeven: req?.includeFrameSeven === true,
    frameSevenAuth: req?.frameSevenAuth === true,
    includeVigolium: req?.includeVigolium === true,
    vigoliumUseCodex: req?.vigoliumUseCodex === true,
    ...(req?.includeNeuroSploit === true ? {
      includeNeuroSploit: true,
      neurosploit: req.neurosploit,
    } : {}),
    autonomyLevel: String(req?.autonomyLevel || 'observation'),
    engagementId: req?.engagementId || null,
    approvalMode: req?.approvalMode === 'deny' ? 'deny' : 'interactive',
    opsecProfile: req?.opsecProfile || null,
    bountyContext: req?.bountyContext || null,
    autoAiReports: body?.autoAiReports === true,
    limits: Object.freeze({
      maxIterations: Number(effectiveLimits.maxIterations),
      sessionTimeoutMs: Number(effectiveLimits.sessionTimeoutMs),
    }),
    engineTimeouts: Object.freeze({
      pipelineTimeoutMs: Number(effectiveEngineTimeouts.pipelineTimeoutMs),
      engineSettleGraceMs: Number(effectiveEngineTimeouts.engineSettleGraceMs),
      phaseSettleGraceMs: Number(effectiveEngineTimeouts.phaseSettleGraceMs),
      framesevenAuthTimeoutMs: Number(effectiveEngineTimeouts.framesevenAuthTimeoutMs),
      framesevenBeforeScanTimeoutMs: Number(effectiveEngineTimeouts.framesevenBeforeScanTimeoutMs),
    }),
  });
}

export function assertAutoResumePolicyCompatible(restoredState, resumePolicy) {
  if (!restoredState) return;
  if (!restoredState.resumePolicy || restoredState.resumePolicy.schemaVersion !== 1) {
    throw new Error('snapshot AUTO antigo/incompleto: política de retomada ausente');
  }
  if (JSON.stringify(restoredState.resumePolicy) !== JSON.stringify(resumePolicy)) {
    throw new Error('retomada não pode alterar módulos, motores, engagement ou política');
  }
}

export async function runAutoRecon({
  body = {},
  runPipeline,
  emit = () => {},
  ROOT,
  env = process.env,
  forgeSandboxRunner = null,
  runFrameSevenImpl = runFrameSeven,
  readFrameSevenReportImpl = readAndMergeFrameSevenReport,
  publicFrameSevenReportUrlImpl = publicFrameSevenReportUrl,
  pipelineOverrides = {},
  signal,
  principal = null,
  getEngagementImpl = getEngagement,
  inspectVigoliumSourceIdentityImpl = inspectVigoliumSourceIdentity,
  listVigoliumModulesImpl = null,
  runNeuroSploitImpl = null,
} = {}) {
  if (typeof runPipeline !== 'function') {
    throw new Error('runPipeline ausente para Modo Auto');
  }
  assertPersistentPrincipalBinding(env);
  // Copie o ambiente executável uma única vez. Mudanças posteriores no objeto
  // injetado ou em `process.env` não podem alterar o plano já apresentado.
  const executionEnv = Object.freeze({ ...env });
  const req = normalizeAutoRequest(body, executionEnv);
  const redactionPolicy = loadAutoRedactionPolicy(executionEnv);
  if (
    req.includeVigolium
    && (
      String(body.vigoliumInputFile || '').trim()
      || String(body.vigoliumInputType || '').trim()
      || String(env.GHOSTRECON_VIGOLIUM_INPUT_FILE || '').trim()
      || String(env.GHOSTRECON_VIGOLIUM_INPUT_TYPE || '').trim()
    )
  ) {
    throw new Error(
      'Vigolium -T não é permitido no Auto: o arquivo não integra o plano efetivo nem possui alvos/escopo selados',
    );
  }
  if (req.includeVigolium && hasAutoVigoliumAuthMaterial(body, executionEnv)) {
    throw new Error(
      'Auth Vigolium pré-carregada não é permitida no Auto; use o fluxo autenticado com browser e aprovação específica',
    );
  }
  const baseVigoliumRuntime = req.includeVigolium
    ? resolveVigoliumEffectiveConfig({
        ...body,
        modules: [],
        engine: 'node',
        vigoliumAgent: 'none',
        vigoliumUseCodex: req.vigoliumUseCodex,
        vigoliumAuth: null,
        vigoliumAuthFile: null,
        vigoliumAuthEntries: [],
        vigoliumAuthFiles: [],
        vigoliumInputFile: null,
        vigoliumInputType: null,
      }, { env: executionEnv })
    : null;
  const baseVigoliumRuntimeBinding = baseVigoliumRuntime
    ? bindAutoRuntimeValue({
        ...baseVigoliumRuntime,
        vigoliumChildEnv: buildVigoliumChildEnv(baseVigoliumRuntime, executionEnv),
      })
    : null;
  if (pipelineOverrides && Object.keys(pipelineOverrides).length > 0) {
    throw new Error(
      'pipelineOverrides não é permitido no Auto: todo parâmetro executável deve integrar o plano efetivo hashado',
    );
  }
  if (body.frameSevenAuth === true && !req.includeFrameSeven) {
    throw new Error('FrameSeven autenticado exige includeFrameSeven=true');
  }
  if (body.vigoliumUseCodex === true && !req.includeVigolium) {
    throw new Error('Vigolium com Codex exige includeVigolium=true');
  }
  if (req.includeFrameSeven && req.autonomyLevel === 'observation') {
    throw new Error('FrameSeven envia requests ao alvo e exige autonomia assistida ou superior');
  }
  if (req.frameSevenAuth && !['authorized', 'authorized_opsec'].includes(req.autonomyLevel)) {
    throw new Error('FrameSeven autenticado exige autonomia autorizada e recon.intrusive');
  }
  if (req.includeVigolium && !['authorized', 'authorized_opsec'].includes(req.autonomyLevel)) {
    throw new Error('Vigolium DAST exige autonomia autorizada e recon.intrusive');
  }
  if (req.includeNeuroSploit && !['authorized', 'authorized_opsec'].includes(req.autonomyLevel)) {
    throw new Error('NeuroSploit exige autonomia autorizada e recon.intrusive');
  }
  if (req.includeNeuroSploit && !req.neurosploit.profileId) {
    throw new Error('NeuroSploit no Auto exige um perfil API/Codex pronto');
  }
  if (req.includeNeuroSploit && typeof runNeuroSploitImpl !== 'function') {
    throw new Error('runner NeuroSploit ausente para o Modo Auto');
  }
  const events = [];
  const restoredState = req.resumeSessionId
    ? await readAutoSessionSnapshot(ROOT, req.resumeSessionId, env)
    : null;
  if (restoredState && restoredState.target !== req.target) throw new Error('sessão pertence a outro alvo');
  if (restoredState) {
    assertNoRetiredModules([
      ...(restoredState.resumePolicy?.requestedModules || []),
      ...(restoredState.checkpoint?.nextModules || []),
      ...(restoredState.checkpoint?.executedModules || []),
    ]);
  }
  if (restoredState && !['failed', 'interrupted', 'timed_out', 'stalled', 'budget_exceeded'].includes(restoredState.status)) {
    throw new Error(`sessão ${restoredState.status} não pode ser retomada`);
  }
  if (restoredState?.autonomyLevel && restoredState.autonomyLevel !== req.autonomyLevel) {
    throw new Error('retomada não pode alterar o nível de autonomia');
  }
  // Na retomada, a policy usa limits/timeouts congelados do snapshot (não o env).
  const resumePolicyLimits = restoredState?.resumePolicy?.limits
    || restoredState?.limits
    || autoSessionLimits(executionEnv);
  const resumeEngineTimeouts = restoredState?.resumePolicy?.engineTimeouts
    || autoEngineTimeouts(executionEnv);
  const resumePolicy = buildAutoResumePolicy(
    req,
    body,
    resumePolicyLimits,
    resumeEngineTimeouts,
  );
  assertAutoResumePolicyCompatible(restoredState, resumePolicy);
  const engineTimeouts = resumePolicy.engineTimeouts;
  if (restoredState) {
    // Valide estrutura e versão antes de carregar catálogo ou executar motor.
    // Snapshots históricos/incompletos nunca
    // alcançam um caminho executável.
    assertAutoResumeSnapshotCompatible(restoredState, {
      expectedPromptVersion: AUTO_PROMPT_VERSION,
    });
  }
  const restoredOwnerId = String(restoredState?.owner?.sub || '').trim() || null;
  const principalId = String(principal?.sub || restoredOwnerId || '').trim() || null;
  if (restoredOwnerId && principal?.sub && restoredOwnerId !== String(principal.sub)) {
    throw new Error('sessão pertence a outro operador');
  }
  const catalog = await buildAutoToolCatalog({
    includeHexstrike: req.includeHexstrike,
    includeDeepPassive: req.includeDeepPassive !== false,
    includeIntrusive: ['authorized', 'authorized_opsec'].includes(req.autonomyLevel),
    includeFrameSeven: req.includeFrameSeven,
    frameSevenAuth: req.frameSevenAuth,
    includeVigolium: req.includeVigolium,
    includeNeuroSploit: req.includeNeuroSploit,
    forgeRuntimeAvailable: Boolean(forgeSandboxRunner),
    ghostRoot: ROOT,
    target: req.target,
    env: executionEnv,
    vigoliumRuntimeBinding: baseVigoliumRuntimeBinding,
  });
  const catalogHash = computeAutoCatalogHash(catalog);
  if (restoredState) {
    assertAutoResumeSnapshotCompatible(restoredState, {
      expectedCatalogHash: catalogHash,
      expectedPromptVersion: AUTO_PROMPT_VERSION,
    });
  }
  // O claim `wx` é o ponto de não retorno da retomada: ele ocorre antes de
  // registrar a sessão ou executar qualquer engine. Assim,
  // duas APIs e um rollback do snapshot não repetem o mesmo plano pronto.
  const resumeClaim = restoredState
    ? await claimAutoResumeCheckpoint(ROOT, restoredState, {
        env,
        principal: principal || restoredState.owner || null,
      })
    : null;
  const requestRunId = restoredState?.requestRunId || `auto-${Date.now().toString(36)}-${randomBytes(4).toString('hex')}`;
  const sessionId = restoredState?.sessionId || `session-${Date.now().toString(36)}-${randomBytes(3).toString('hex')}`;
  const session = createAutoSession({
    sessionId,
    requestRunId,
    target: req.target,
    ownerPrincipal: principal || restoredState?.owner || null,
    env,
    restoredState,
  });
  session.state.autonomyLevel = req.autonomyLevel;
  session.state.includeFrameSeven = req.includeFrameSeven;
  session.state.frameSevenAuth = req.frameSevenAuth;
  session.state.includeVigolium = req.includeVigolium;
  session.state.vigoliumUseCodex = req.vigoliumUseCodex;
  session.state.includeNeuroSploit = req.includeNeuroSploit;
  session.state.neurosploit = req.includeNeuroSploit ? req.neurosploit : null;
  session.state.engagementId = req.engagementId;
  session.state.mode = req.mode;
  session.state.opsecProfile = req.opsecProfile;
  session.state.bountyContext = req.bountyContext;
  session.state.resumePolicy = resumePolicy;
  session.state.catalogHash = catalogHash;
  session.state.promptVersion = AUTO_PROMPT_VERSION;
  session.state.resumeClaimId = resumeClaim?.claimId || null;
  try {
    registerActiveAutoSession(session, env);
  } catch (error) {
    await session.close('failed');
    throw error;
  }
  let propagateExternalAbort = null;
  if (signal) {
    if (signal.aborted) session.abort(signal.reason || 'client_disconnected');
    else {
      propagateExternalAbort = () => session.abort(signal.reason || 'client_disconnected');
      signal.addEventListener('abort', propagateExternalAbort, { once: true });
      session.resources.push({
        close: () => signal.removeEventListener('abort', propagateExternalAbort),
      });
    }
  }
  const AUTO_TERMINAL_PHASES = new Set([
    'completed', 'partial', 'failed', 'cancelled', 'interrupted',
    'timed_out', 'stalled', 'budget_exceeded',
  ]);
  const captureEmit = (event) => {
    if (session.signal.aborted) {
      const phase = event?.type === 'auto_session' ? String(event.phase || '') : '';
      const allowAfterAbort = (
        (event?.type === 'auto_session' && AUTO_TERMINAL_PHASES.has(phase))
        || event?.type === 'auto_persist_failed'
        || event?.type === 'error'
      );
      if (!allowAfterAbort) return null;
    }
    const safeEvent = publicAutoEvent(event, { root: ROOT });
    session.touch(safeEvent);
    events.push(safeEvent);
    sendSafe(emit, safeEvent);
    return safeEvent;
  };
  const rawRequestApproval = session.requestApproval.bind(session);
  session.requestApproval = async (details = {}, timeoutMs) => {
    const pending = rawRequestApproval(details, timeoutMs);
    if (req.approvalMode === 'deny' && session.state.pendingApproval?.status === 'pending') {
      const approvalId = session.state.pendingApproval.approvalId;
      captureEmit({
        type: 'auto_approval_required',
        sessionId,
        approval: session.state.pendingApproval,
      });
      captureEmit({
        type: 'auto_approval_auto_denied',
        sessionId,
        approvalId,
        reason: 'non_interactive_client',
      });
      session.resolveApproval?.(
        approvalId,
        false,
        'cliente não interativo: aprovação antecipada não é aceita',
      );
      return pending;
    }
    if (session.state.pendingApproval?.status === 'pending') {
      // Persistir aprovação pendente antes do NDJSON/espera (crash-safe).
      await writeAutoSessionSnapshot(ROOT, session.state, env);
      captureEmit({
        type: 'auto_approval_required',
        sessionId,
        approval: session.state.pendingApproval,
      });
    }
    return pending;
  };

  try {
  const heartbeat = setInterval(() => captureEmit({
    type: 'auto_heartbeat', sessionId, iteration: session.state.iteration,
    elapsedMs: Date.now() - Date.parse(session.state.startedAt),
    lastActivityAt: session.state.lastActivityAt,
    currentStage: session.state.currentStage,
    currentModule: session.state.currentModule,
  }), Math.max(5_000, Math.min(60_000, Number(env.GHOSTRECON_AUTO_HEARTBEAT_MS || 15_000))));
  heartbeat.unref?.();
  session.resources.push({ close: () => clearInterval(heartbeat) });
  // Watchdog determinístico da sessão/pipeline. Não existe mais conceito de
  // turno de provider: a atividade é medida apenas pelos eventos operacionais.
  const configuredStallTimeout = Number(env.GHOSTRECON_AUTO_STALL_TIMEOUT_MS || 0);
  const stallTimeoutMs = Math.max(30_000, Math.min(
    session.limits.sessionTimeoutMs,
    Number.isFinite(configuredStallTimeout) && configuredStallTimeout > 0
      ? configuredStallTimeout
      : session.limits.sessionTimeoutMs,
  ));
  const watchdog = setInterval(() => {
    const idleMs = typeof session.getIdleMs === 'function'
      ? session.getIdleMs()
      : Date.now() - Date.parse(session.state.lastActivityAt || session.state.startedAt);
    if (idleMs < stallTimeoutMs || session.signal.aborted) return;
    captureEmit({
      type: 'auto_stall_detected', idleMs, stallTimeoutMs,
      currentStage: session.state.currentStage, currentModule: session.state.currentModule,
    });
    session.abort(`auto_stall_timeout:${session.state.currentStage || 'unknown'}`);
  }, Math.max(5_000, Math.min(30_000, Math.floor(stallTimeoutMs / 4))));
  watchdog.unref?.();
  session.resources.push({ close: () => clearInterval(watchdog) });
  captureEmit({
    type: 'auto_session',
    phase: 'started',
    sessionId,
    requestRunId,
    mode: req.mode,
    autonomyLevel: req.autonomyLevel,
    includeFrameSeven: req.includeFrameSeven,
    frameSevenAuth: req.frameSevenAuth,
    includeVigolium: req.includeVigolium,
    vigoliumUseCodex: req.vigoliumUseCodex,
    includeNeuroSploit: req.includeNeuroSploit,
    opsecProfile: req.opsecProfile,
    bountyContext: req.bountyContext,
    limits: session.limits,
    redactionPolicy: {
      version: redactionPolicy.version,
      source: redactionPolicy.source,
      extrasCount: redactionPolicy.extras.length,
    },
  });
  if (!restoredState || restoredState.checkpoint.status === 'planning') {
    session.state.iteration = 0;
    session.state.checkpoint = createAutoCheckpoint(session.state, {
      status: 'planning',
      currentIteration: 0,
    });
  }
  // O primeiro snapshot novo já contém os vínculos do protocolo de retomada;
  // nunca persista um estado "running" sem catálogo, prompt e checkpoint.
  await writeAutoSessionSnapshot(ROOT, session.state, env);
  captureEmit({
    type: 'auto_catalog',
    modules: catalog.modules.map((m) => ({ id: m.id, source: m.source, class: m.class, available: m.available !== false })),
    hexstrike: catalog.hexstrike ? {
      installed: Boolean(catalog.hexstrike.installed),
      reachable: Boolean(catalog.hexstrike.reachable),
      baseUrl: catalog.hexstrike.baseUrl || null,
    } : null,
    neurosploit: catalog.engines?.neurosploit ? {
      available: catalog.engines.neurosploit.available === true,
      identity: catalog.engines.neurosploit.identity || null,
      contextContract: catalog.engines.neurosploit.contextContract || null,
    } : null,
  });

  const ragContext = {
    dir: '',
    items: [],
    deterministic: true,
  };
  session.state.memoriesUsed = [];
  captureEmit({
    type: 'auto_rag',
    phase: 'disabled_for_deterministic_planning',
    dir: '',
    items: 0,
    error: null,
  });
  session.assertActive();

  const resumedReadyCheckpoint = restoredState
    && ['ready_for_iteration', 'ready_for_next_iteration'].includes(restoredState.checkpoint.status)
    ? restoredState.checkpoint
    : null;
  const deterministicDecision = resumedReadyCheckpoint
    ? {
        action: 'run_modules',
        requestedModules: [...resumedReadyCheckpoint.nextModules],
        source: 'validated_checkpoint',
      }
    : {
        action: 'run_modules',
        requestedModules: [...req.modules],
        source: 'operator_and_profile',
      };
  session.assertActive();
  captureEmit({
    type: 'auto_deterministic_plan',
    source: deterministicDecision.source,
    requestedModules: deterministicDecision.requestedModules,
  });
  // Na retomada, a lista do checkpoint é a única fonte do próximo plano. Não
  // reintroduza módulos do request original nem defaults do planner.
  const operatorRequestedModules = resumedReadyCheckpoint
    ? [...resumedReadyCheckpoint.nextModules]
    : [
        ...req.modules,
        ...(req.includeFrameSeven
          ? [req.frameSevenAuth ? 'frameseven_authenticated' : 'frameseven_recon']
          : []),
        ...(req.includeVigolium ? ['vigolium_dast'] : []),
      ];
  const plan = createAutoPlan({
    target: req.target,
    mode: req.mode,
    requestedModules: [...new Set(operatorRequestedModules)],
    catalog,
    includeHexstrike: req.includeHexstrike,
    includeDeepPassive: req.includeDeepPassive,
    ragContext,
    autonomyLevel: req.autonomyLevel,
  });
  plan.sessionId = sessionId;
  plan.autonomyLevel = req.autonomyLevel;
  plan.limits = session.limits;
  plan.catalogHash = catalogHash;
  plan.promptVersion = AUTO_PROMPT_VERSION;
  plan.opsecProfile = req.opsecProfile;
  plan.bugBountyContext = req.bountyContext;
  captureEmit({ type: 'auto_plan', plan });
  const planAction = String(plan.action || (plan.modules?.length ? 'run_modules' : 'finish'));
  if (
    !resumedReadyCheckpoint
    && ['run_modules', 'continue_with_context'].includes(planAction)
    && plan.modules?.length
  ) {
    session.state.iteration = 0;
    session.state.checkpoint = createAutoCheckpoint(session.state, {
      status: 'ready_for_iteration',
      currentIteration: 0,
      nextIteration: 1,
      nextModules: plan.modules,
      activePlan: {
        iteration: 1,
        hash: computeAutoReadyPlanHash({
          catalogHash,
          promptVersion: AUTO_PROMPT_VERSION,
          iteration: 1,
          modules: plan.modules,
          resumePolicyHash: computeAutoResumePolicyHash(resumePolicy),
        }),
        modules: plan.modules,
        stage: 'ready',
        engineOutcomes: [],
        moduleOutcomes: [],
      },
    });
    await writeAutoSessionSnapshot(ROOT, session.state, env);
    const initialClaim = await claimAutoResumeCheckpoint(ROOT, session.state, {
      env,
      principal: principal || session.state.owner || null,
    });
    session.state.resumeClaimId = initialClaim.claimId;
    captureEmit({
      type: 'auto_checkpoint_claimed',
      sessionId,
      checkpointId: session.state.checkpoint.checkpointId,
      claimId: initialClaim.claimId,
      purpose: 'initial_execution',
    });
  }
  const planMemory = await writeAutoDecisionMarkdown({
    root: ROOT,
    env,
    requestRunId,
    target: req.target,
    kind: 'plan',
    title: `Auto plan - ${req.target}`,
    summary: 'Modo Auto determinístico selecionou módulos e política antes do pipeline.',
    plan,
    catalog: {
      modules: catalog.modules.map((m) => ({ id: m.id, source: m.source, class: m.class, available: m.available !== false })),
      hexstrike: catalog.hexstrike ? {
        installed: Boolean(catalog.hexstrike.installed),
        reachable: Boolean(catalog.hexstrike.reachable),
        baseUrl: catalog.hexstrike.baseUrl || null,
      } : null,
    },
    events,
    tags: ['plan', req.mode],
    principalId: principalId || session.state.owner?.sub || '',
    engagementId: req.engagementId || '',
  }).catch((e) => ({ error: e?.message || String(e) }));
  captureEmit({ type: 'auto_rag', phase: 'plan_saved', memory: planMemory });
  assertDurableRagPersist(planMemory, { env, captureEmit, sessionId, requestRunId, stage: 'plan' });

  if (!['run_modules', 'continue_with_context'].includes(planAction) || !plan.modules?.length) {
    const evaluation = evaluateAutoRun({ events: [], plan });
    evaluation.observation = { findings: 0, warnings: 0, errors: 0 };
    evaluation.iterations = [];
    evaluation.next = 'no_execution_requested';
    session.state.checkpoint = createAutoCheckpoint(session.state, {
      status: 'completed',
      currentIteration: Number(session.state.iteration || 0),
    });
    captureEmit({ type: 'auto_evaluation', evaluation });
    captureEmit({ type: 'auto_no_execution', sessionId, action: planAction });
    const finalSession = await session.close('completed');
    const terminal = await persistTerminalSession({
      ROOT, env, session, finalSession, captureEmit, sessionId, requestRunId,
      preferredPhase: 'completed',
      evaluation,
      moduleOutcomes: [],
      plan,
      events,
    });
    return { sessionId, requestRunId, plan, evaluation, events, session: terminal.finalSession };
  }

  let iteration = Number(session.state.checkpoint?.nextIteration || 1);
  let iterationPlan = session.state.checkpoint?.nextModules?.length
    ? { ...plan, modules: session.state.checkpoint.nextModules }
    : plan;
  let evaluation = null;
  let iterationSealedScopePolicy = null;
  const executedModules = new Set(session.state.checkpoint?.executedModules || []);
  const iterationHistory = [...(session.state.checkpoint?.iterationHistory || [])];
  let engagement = req.engagementId ? await getEngagementImpl(req.engagementId) : null;
  if (req.engagementId && !engagement) throw new Error(`engagement não encontrado: ${req.engagementId}`);
  const engagementAuthorizationBinding = computeAutoEngagementAuthorizationBinding(
    engagement,
    req.engagementId,
  );
  const frameSevenAvailable = Boolean(catalog.engines?.frameseven?.available);
  const phaseSettleGraceMs = Number(engineTimeouts.phaseSettleGraceMs);
  const requestedOutOfScope = parseOutOfScopeClientInput(body.outOfScope);
  const engagementOutOfScope = parseOutOfScopeClientInput(engagement?.exclusions);
  const effectivePlanBody = Object.freeze({
    engagementId: req.engagementId,
    engagementAuthorizationBinding,
    outOfScope: mergeOutOfScopeLists(requestedOutOfScope, engagementOutOfScope),
    includeHexstrike: req.includeHexstrike,
    includeFrameSeven: req.includeFrameSeven,
    frameSevenAuth: req.frameSevenAuth,
    includeVigolium: req.includeVigolium,
    vigoliumUseCodex: req.vigoliumUseCodex,
    includeNeuroSploit: req.includeNeuroSploit,
    neurosploit: req.neurosploit,
    opsecProfile: req.opsecProfile,
    bountyContext: req.bountyContext,
    autoAiReports: body.autoAiReports === true,
    phaseSettleGraceMs,
  });
  while (true) {
  session.assertActive();
  captureEmit({ type: 'auto_iteration_started', sessionId, iteration, modules: iterationPlan.modules });
  const iterationEventStart = events.length;
  const buildIterationEffectivePlan = async (candidatePlan, forceFrameSevenRecon) => {
    let candidate = buildEffectiveAutoPlan({
      plan: candidatePlan,
      catalog,
      body: effectivePlanBody,
      autonomyLevel: req.autonomyLevel,
      frameSevenAvailable,
      forceFrameSevenRecon,
    });
    const sealedScopePolicy = engagement
      ? sealEngineScopePolicy(createEngagementScopePolicy({
          rootDomain: req.target,
          engagement,
          engagementId: req.engagementId,
          authorizationBinding: engagementAuthorizationBinding,
        }))
      : null;
    if (sealedScopePolicy && candidate.engines?.frameseven?.enabled) {
      assertEngineScopeEnforcementAvailable({
        engine: 'frameseven',
        sealedPolicy: sealedScopePolicy,
        env: executionEnv,
        engineDeclaresSupport: catalog?.engines?.frameseven?.supportsSealedScopePolicy === true,
      });
    }
    let snapshot = await resolveAutoVigoliumRuntimeSnapshot({
      body,
      effectivePlan: candidate,
      catalog,
      env: executionEnv,
      useCodex: req.vigoliumUseCodex,
      listVigoliumModulesImpl,
      ghostRoot: ROOT,
      sealedScopePolicy,
    });
    if (
      candidate.engines.vigolium.agent === 'audit'
      && !String(snapshot.runtime?.vigoliumSource || '').trim()
    ) {
      throw new Error(
        'vigolium_audit exige fonte Git local dentro da raiz autorizada antes da aprovação',
      );
    }
    if (snapshot.runtime?.vigoliumSource) {
      const sourceAllowedRoots = resolveVigoliumSourceAllowedRoots(ROOT, executionEnv);
      const sourceIdentity = await inspectVigoliumSourceIdentityImpl(
        snapshot.runtime.vigoliumSource,
        {
          allowedRoots: sourceAllowedRoots,
          signal: session.signal,
          timeoutMs: snapshot.runtime.vigoliumAgentTimeoutMs,
          env: executionEnv,
        },
      );
      snapshot = await resolveAutoVigoliumRuntimeSnapshot({
        body,
        effectivePlan: candidate,
        catalog,
        env: executionEnv,
        useCodex: req.vigoliumUseCodex,
        sourceIdentity,
        sourceAllowedRoots,
        listVigoliumModulesImpl,
        ghostRoot: ROOT,
        sealedScopePolicy,
      });
    }
    if (snapshot.publicPlan) {
      candidate = buildEffectiveAutoPlan({
        plan: candidatePlan,
        catalog,
        body: {
          ...effectivePlanBody,
          vigoliumRuntimePlan: snapshot.publicPlan,
        },
        autonomyLevel: req.autonomyLevel,
        frameSevenAvailable,
        forceFrameSevenRecon,
      });
    }
    return {
      plan: candidate,
      vigoliumRuntime: snapshot.runtime,
      sealedScopePolicy,
    };
  };
  const forceFrameSevenRecon = req.includeFrameSeven
    && iteration === 1
    && !executedModules.has(
      req.frameSevenAuth ? 'frameseven_authenticated' : 'frameseven_recon',
    );
  let builtIteration = await buildIterationEffectivePlan(
    iterationPlan,
    forceFrameSevenRecon,
  );
  let effectivePlan = builtIteration.plan;
  let vigoliumRuntimeConfig = builtIteration.vigoliumRuntime;
  iterationSealedScopePolicy = builtIteration.sealedScopePolicy || null;
  const revalidateEngagementForPlan = async (stage) => {
    const currentEngagement = req.engagementId
      ? await getEngagementImpl(req.engagementId)
      : engagement;
    const currentBinding = computeAutoEngagementAuthorizationBinding(
      currentEngagement,
      req.engagementId,
    );
    const checklist = preRunChecklist({
      engagement: currentEngagement,
      target: req.target,
      modules: effectivePlan.expandedModules,
      playbook: null,
      intrusiveModules: effectivePlan.intrusiveModules,
      requireFormalAuthorization: effectivePlan.requiresFormalAuthorization === true
        || (effectivePlan.activeModules?.length || 0) > 0
        || (effectivePlan.intrusiveModules?.length || 0) > 0,
    });
    const bindingMatches = currentBinding === engagementAuthorizationBinding;
    captureEmit({
      type: 'auto_preflight_revalidated',
      sessionId,
      iteration,
      stage,
      planHash: effectivePlan.hash,
      engagementId: req.engagementId,
      bindingMatches,
      checklist,
    });
    if (req.engagementId && !currentEngagement) {
      const error = new Error(`engagement removido antes da execução: ${req.engagementId}`);
      error.code = 'AUTO_ENGAGEMENT_INVALIDATED';
      throw error;
    }
    if (!checklist.ok) {
      const error = new Error(
        `Checklist AUTO bloqueou o plano em ${stage}: ${checklist.errors.join('; ')}`,
      );
      error.code = 'AUTO_ENGAGEMENT_INVALIDATED';
      throw error;
    }
    if (!bindingMatches) {
      const error = new Error(
        'Autorização do engagement mudou após o plano ser congelado; gere um novo plano e uma nova aprovação',
      );
      error.code = 'AUTO_ENGAGEMENT_CHANGED';
      throw error;
    }
    engagement = currentEngagement;
    return {
      checklist,
      scopePolicy: currentEngagement
        ? createEngagementScopePolicy({
            rootDomain: req.target,
            engagement: currentEngagement,
            engagementId: req.engagementId,
            authorizationBinding: currentBinding,
          })
        : null,
    };
  };
  const candidateChecklist = preRunChecklist({
    engagement,
    target: req.target,
    modules: effectivePlan.expandedModules,
    playbook: null,
    intrusiveModules: effectivePlan.intrusiveModules,
    requireFormalAuthorization: effectivePlan.requiresFormalAuthorization === true
      || (effectivePlan.activeModules?.length || 0) > 0
      || (effectivePlan.intrusiveModules?.length || 0) > 0,
  });
  captureEmit({
    type: 'auto_preflight',
    sessionId,
    iteration,
    planHash: effectivePlan.hash,
    requiresHumanApproval: effectivePlan.requiresHumanApproval === true,
    checklist: candidateChecklist,
  });
  if (!candidateChecklist.ok) {
    throw new Error(`Checklist AUTO bloqueou o plano: ${candidateChecklist.errors.join('; ')}`);
  }

  let approvalGranted = false;
  if (effectivePlan.requiresHumanApproval) {
    const approved = await session.requestApproval(effectivePlanApprovalDetails(effectivePlan));
    if (!approved) {
      captureEmit({
        type: 'auto_approval_denied',
        sessionId,
        planHash: effectivePlan.hash,
        modules: effectivePlan.expandedModules,
      });
      builtIteration = await buildIterationEffectivePlan(
        { target: req.target, mode: iterationPlan.mode, action: 'finish', modules: [] },
        false,
      );
      effectivePlan = builtIteration.plan;
      vigoliumRuntimeConfig = builtIteration.vigoliumRuntime;
      iterationSealedScopePolicy = builtIteration.sealedScopePolicy || null;
    } else {
      approvalGranted = true;
      captureEmit({
        type: 'auto_approval_granted',
        sessionId,
        planHash: effectivePlan.hash,
        modules: effectivePlan.expandedModules,
      });
    }
  }
  session.assertActive();

  if (!effectivePlan.selectedModules.length) {
    evaluation = evaluateAutoRun({ events: events.slice(iterationEventStart), plan: iterationPlan });
    evaluation.observation = { findings: 0, warnings: 0, errors: 0 };
    const deterministicOutcome = { action: 'finish', source: 'operator_denied_plan' };
    iterationHistory.push({
      iteration,
      modules: [],
      effectivePlanHash: effectivePlan.hash,
      observation: evaluation.observation,
      decision: deterministicOutcome,
    });
    session.state.iteration = iteration;
    session.state.checkpoint = createAutoCheckpoint(session.state, {
      status: 'completed',
      currentIteration: iteration,
      executedModules: [...executedModules],
      iterationHistory,
    });
    await writeAutoSessionSnapshot(ROOT, session.state, env);
    captureEmit({ type: 'auto_iteration_completed', sessionId, iteration, decision: 'finish', reason: 'operator_denied_plan' });
    break;
  }

  await revalidateEngagementForPlan(
    approvalGranted ? 'after_plan_approval' : 'before_final_gate',
  );
  const gate = gateModules({
    modules: effectivePlan.expandedModules,
    profile: effectivePlan.opsecProfile,
    confirm: approvalGranted || effectivePlan.intrusiveModules.length === 0,
    engagement,
  });
  if (!gate.ok) {
    captureEmit({ type: 'auto_step', step: 'opsec', status: 'blocked', opsec: gate, planHash: effectivePlan.hash });
    throw new Error(`Modo Auto bloqueado por OPSEC: ${gate.reason || gate.blocked?.join(', ')}`);
  }

  session.state.iteration = iteration;
  session.state.effectivePlanHash = effectivePlan.hash;
  session.state.currentEffectivePlan = {
    hash: effectivePlan.hash,
    iteration,
    selectedModules: effectivePlan.selectedModules,
    engines: effectivePlan.engines,
  };
  session.state.checkpoint = createAutoCheckpoint(session.state, {
    status: 'iteration_in_progress',
    currentIteration: iteration,
    executedModules: [...executedModules],
    iterationHistory,
    activePlan: {
      iteration,
      hash: effectivePlan.hash,
      modules: effectivePlan.selectedModules,
      stage: 'running',
      engineOutcomes: [],
      moduleOutcomes: [],
    },
  });
  await writeAutoSessionSnapshot(ROOT, session.state, env);
  captureEmit({ type: 'auto_effective_plan', sessionId, iteration, effectivePlan });

  const pipelineBody = {
    domain: req.target,
    exactMatch: false,
    modules: effectivePlan.pipelineModules,
    profile: effectivePlan.profile,
    opsecProfile: effectivePlan.opsecProfile,
    outOfScope: effectivePlan.execution.outOfScope,
    autoAiReports: effectivePlan.execution.autoAiReports,
    bountyContext: effectivePlan.execution.bountyContext,
    autonomyLevel: req.autonomyLevel,
    requestRunId,
    engagementId: req.engagementId,
    engagementOperator: principalId,
    kaliMode: effectivePlan.execution.kaliMode,
    confirmActive: approvalGranted && effectivePlan.execution.confirmActive,
    ...(vigoliumRuntimeConfig || {}),
    // `createPipelineState` reconhece um snapshot como autoritativo somente
    // nesta propriedade. Os campos espalhados acima preservam compatibilidade
    // com consumidores/testes antigos, mas nunca substituem o objeto selado.
    vigoliumRuntimeConfig,
    engine: effectivePlan.engines.vigolium.engine,
    vigoliumAgent: effectivePlan.engines.vigolium.agent,
    vigoliumUseCodex: effectivePlan.engines.vigolium.useCodex,
    vigoliumExpectedIdentity: effectivePlan.engines.vigolium.identity,
    vigoliumInputFile: effectivePlan.engines.vigolium.input.file,
    vigoliumInputType: effectivePlan.engines.vigolium.input.type,
    // A recuperação é exclusiva do Auto. O RUN manual continua fail-fast.
    // Uma fase só é ignorada depois de realmente encerrar ao receber abort;
    // fases não cooperativas interrompem o pipeline para não deixar órfãos.
    autoModeExecution: true,
    continueOnPhaseError: true,
    enablePhaseTimeouts: true,
    phaseTimeoutsMs: effectivePlan.execution.phaseTimeoutsMs,
    phaseSettleGraceMs: effectivePlan.execution.phaseSettleGraceMs,
    forgeSandboxRunner,
  };
  const engineOutcomes = [];
  const moduleOutcomes = [];
  const persistActiveCheckpoint = async (stage = 'running') => {
    session.state.checkpoint = createAutoCheckpoint(session.state, {
      status: 'iteration_in_progress',
      currentIteration: iteration,
      executedModules: [...executedModules],
      iterationHistory,
      activePlan: {
        iteration,
        hash: effectivePlan.hash,
        modules: effectivePlan.selectedModules,
        stage,
        engineOutcomes,
        moduleOutcomes,
      },
    });
    await writeAutoSessionSnapshot(ROOT, session.state, env);
  };
  const recordModuleOutcome = (outcome) => {
    const source = String(outcome?.source || 'inferred');
    const existingIdx = moduleOutcomes.findIndex((item) => item.moduleId === outcome.moduleId);
    if (existingIdx >= 0) {
      const existing = moduleOutcomes[existingIdx];
      const existingSource = String(existing.source || 'inferred');
      // Não sobrescrever outcome real (registry/pipe/engine) com inferência de fase.
      if (existingSource !== 'inferred' && source === 'inferred') return;
      moduleOutcomes[existingIdx] = { ...existing, ...outcome, source };
    } else {
      moduleOutcomes.push({ ...outcome, source });
    }
    captureEmit({
      type: 'auto_module_outcome',
      sessionId,
      iteration,
      planHash: effectivePlan.hash,
      ...outcome,
      source,
    });
    if (outcome.status === 'done') executedModules.add(outcome.moduleId);
  };
  const runGhostReconAndVigolium = async (capturedAuth = null, stageSignal = session.signal) => {
    if (!effectivePlan.engines.ghostrecon.enabled) return true;
    const { scopePolicy } = await revalidateEngagementForPlan(
      'immediately_before_ghostrecon_pipeline',
    );
    const pipelineEventStart = events.length;
    const collectPipelineOutcomes = (fallbackStatus, fallbackError = null) => {
      const lastPipeState = new Map();
      const lastModuleOutcome = new Map();
      for (const event of events.slice(pipelineEventStart)) {
        if (event?.type === 'pipe' && event.name) {
          lastPipeState.set(String(event.name), String(event.state || ''));
        }
        if (event?.type === 'module_outcome' && event.moduleId) {
          // Ignorar module_outcome com moduleId=fase (source pipeline_phase).
          if (event.source === 'pipeline_phase') continue;
          const status = String(event.status || '');
          if (['done', 'skipped', 'skip', 'timeout', 'failed', 'cancelled'].includes(status)) {
            lastModuleOutcome.set(String(event.moduleId), event);
          }
        }
      }
      const knownStatuses = new Set(['done', 'skip', 'skipped', 'timeout', 'failed', 'cancelled']);
      for (const moduleId of effectivePlan.pipelineModules) {
        if (moduleOutcomes.some((item) => item.moduleId === moduleId && item.source !== 'inferred')) {
          continue;
        }
        const catalogItem = catalog.modules.find((item) => item.id === moduleId);
        const phase = autoCapabilityPhase(moduleId, {
          ...(catalogItem?.manifest || {}),
          source: catalogItem?.source || catalogItem?.manifest?.source,
        });
        const fromEvent = lastModuleOutcome.get(moduleId);
        const raw = fromEvent
          ? String(fromEvent.status || '')
          : lastPipeState.get(moduleId);
        const status = raw === 'skip' ? 'skipped'
          : knownStatuses.has(raw) ? (raw === 'skip' ? 'skipped' : raw)
            : fallbackStatus;
        recordModuleOutcome({
          moduleId,
          engine: moduleId.startsWith('vigolium_') ? 'vigolium' : 'ghostrecon',
          status,
          phase,
          source: fromEvent ? (fromEvent.source || 'registry') : (raw ? 'pipe' : 'inferred'),
          error: ['done', 'skipped'].includes(status)
            ? null
            : fromEvent?.error || fallbackError,
        });
      }
    };
    captureEmit({ type: 'engine_started', engine: 'ghostrecon', iteration, planHash: effectivePlan.hash });
    if (effectivePlan.engines.vigolium.enabled) {
      captureEmit({ type: 'engine_started', engine: 'vigolium', iteration, planHash: effectivePlan.hash });
    }
    try {
      const timeoutMs = Math.min(
        Number(engineTimeouts.pipelineTimeoutMs),
        Number(session.limits.sessionTimeoutMs),
      );
      await runWithDeadline({
        name: 'ghostrecon_pipeline',
        timeoutMs,
        parentSignal: stageSignal || session.signal,
        settleGraceMs: Number(engineTimeouts.engineSettleGraceMs),
        work: (iterationSignal) => runPipeline({
          ...pipelineBody,
          auth: capturedAuth || pipelineBody.auth,
          scopePolicy,
          signal: iterationSignal,
          emit: (event) => {
            // O mesmo evento redigido que cruza a fronteira NDJSON precisa ser
            // a fonte do outcome persistido. Usar o objeto cru aqui contornaria
            // a redação central de erros e reasonDetails.
            const outcomeEvent = captureEmit(event)
              || publicAutoEvent(event, { root: ROOT });
            if (
              outcomeEvent?.type === 'module_outcome'
              && outcomeEvent.moduleId
              && outcomeEvent.source !== 'pipeline_phase'
            ) {
              const moduleId = String(outcomeEvent.moduleId);
              const raw = String(outcomeEvent.status || '');
              const status = raw === 'skip' ? 'skipped' : raw;
              if (
                effectivePlan.pipelineModules.includes(moduleId)
                && ['done', 'skipped', 'timeout', 'failed', 'cancelled'].includes(status)
              ) {
                const catalogItem = catalog.modules.find((item) => item.id === moduleId);
                recordModuleOutcome({
                  moduleId,
                  engine: moduleId.startsWith('vigolium_') ? 'vigolium' : 'ghostrecon',
                  status,
                  phase: autoCapabilityPhase(moduleId, {
                    ...(catalogItem?.manifest || {}),
                    source: catalogItem?.source || catalogItem?.manifest?.source,
                  }),
                  source: outcomeEvent.source || 'registry',
                  error: ['done', 'skipped'].includes(status) ? null : (outcomeEvent.error || null),
                  partial: outcomeEvent.partial === true,
                  reason: outcomeEvent.reason || null,
                  attempted: Number.isFinite(Number(outcomeEvent.attempted)) ? Number(outcomeEvent.attempted) : null,
                  serviceCount: Number.isFinite(Number(outcomeEvent.serviceCount)) ? Number(outcomeEvent.serviceCount) : null,
                  resultCount: Number.isFinite(Number(outcomeEvent.resultCount)) ? Number(outcomeEvent.resultCount) : null,
                  negativeCount: Number.isFinite(Number(outcomeEvent.negativeCount)) ? Number(outcomeEvent.negativeCount) : null,
                  timeoutCount: Number.isFinite(Number(outcomeEvent.timeoutCount)) ? Number(outcomeEvent.timeoutCount) : null,
                  failureCount: Number.isFinite(Number(outcomeEvent.failureCount)) ? Number(outcomeEvent.failureCount) : null,
                  skipCount: Number.isFinite(Number(outcomeEvent.skipCount)) ? Number(outcomeEvent.skipCount) : null,
                  cleanupUnconfirmedCount: Number.isFinite(Number(outcomeEvent.cleanupUnconfirmedCount))
                    ? Number(outcomeEvent.cleanupUnconfirmedCount)
                    : null,
                  hostsEligible: Number.isFinite(Number(outcomeEvent.hostsEligible)) ? Number(outcomeEvent.hostsEligible) : null,
                  hostsScanned: Number.isFinite(Number(outcomeEvent.hostsScanned)) ? Number(outcomeEvent.hostsScanned) : null,
                  hostsTruncated: Number.isFinite(Number(outcomeEvent.hostsTruncated)) ? Number(outcomeEvent.hostsTruncated) : null,
                  reasonDetails: Array.isArray(outcomeEvent.reasonDetails)
                    ? outcomeEvent.reasonDetails.map((value) => String(value).slice(0, 120)).slice(0, 5)
                    : [],
                });
              }
            }
            // Legado Auto: pipe terminal de módulo do plano → outcome estável
            // (elimina `inferred` quando o pipeline já emitiu pipe).
            if (outcomeEvent?.type === 'pipe' && outcomeEvent.name) {
              const moduleId = String(outcomeEvent.name);
              if (!effectivePlan.pipelineModules.includes(moduleId)) return;
              const raw = String(outcomeEvent.state || '');
              const status = raw === 'skip' ? 'skipped'
                : raw === 'active' || raw === 'started' ? null
                  : ['done', 'skipped', 'timeout', 'failed', 'cancelled'].includes(raw)
                    ? raw
                    : null;
              if (!status) return;
              if (moduleOutcomes.some((item) => (
                item.moduleId === moduleId && item.source !== 'inferred'
              ))) {
                return;
              }
              const catalogItem = catalog.modules.find((item) => item.id === moduleId);
              recordModuleOutcome({
                moduleId,
                engine: moduleId.startsWith('vigolium_') ? 'vigolium' : 'ghostrecon',
                status,
                phase: autoCapabilityPhase(moduleId, {
                  ...(catalogItem?.manifest || {}),
                  source: catalogItem?.source || catalogItem?.manifest?.source,
                }),
                source: 'pipe',
                error: ['done', 'skipped'].includes(status) ? null : (outcomeEvent.error || null),
              });
            }
          },
        }),
      });
      collectPipelineOutcomes('done');
      session.assertActive();
      const phaseFailures = events.slice(pipelineEventStart).filter((event) => (
        event?.type === 'phase_outcome' && !['done', 'skipped'].includes(String(event.status))
      ));
      captureEmit({
        type: phaseFailures.length ? 'engine_partial' : 'engine_done',
        engine: 'ghostrecon',
        iteration,
        planHash: effectivePlan.hash,
        ...(phaseFailures.length ? {
          phase: 'pipeline',
          failedPhases: phaseFailures.map((event) => String(event.phase || '')).filter(Boolean),
        } : {}),
      });
      engineOutcomes.push({
        engine: 'ghostrecon',
        status: phaseFailures.length ? 'partial' : 'done',
        phaseFailures: phaseFailures.map((event) => ({
          phase: event.phase,
          status: event.status,
          error: event.error || null,
        })),
      });
      if (effectivePlan.engines.vigolium.enabled) {
        const vigoliumModules = effectivePlan.pipelineModules.filter((id) => id.startsWith('vigolium_'));
        const outcomes = moduleOutcomes.filter((item) => vigoliumModules.includes(item.moduleId));
        const status = outcomes.some((item) => ['failed', 'timeout', 'cancelled'].includes(item.status))
          ? outcomes.find((item) => ['failed', 'timeout', 'cancelled'].includes(item.status)).status
          : outcomes.length && outcomes.every((item) => item.status === 'skipped')
            ? 'skipped'
            : 'done';
        captureEmit({ type: `engine_${status}`, engine: 'vigolium', iteration, planHash: effectivePlan.hash });
        engineOutcomes.push({ engine: 'vigolium', status, modules: outcomes });
      }
      await persistActiveCheckpoint('running');
      return true;
    } catch (error) {
      if (session.signal.aborted || stageSignal?.aborted) throw error;
      if (
        error?.code === 'AUTO_DEADLINE_UNSETTLED'
        || isFatalVigoliumExecutionError(error)
      ) {
        throw error;
      }
      const status = /timeout/i.test(String(error?.message || error)) ? 'timeout' : 'failed';
      collectPipelineOutcomes(status, error?.message || String(error));
      captureEmit({ type: `engine_${status}`, engine: 'ghostrecon', iteration, planHash: effectivePlan.hash, error: error?.message || String(error) });
      captureEmit({ type: 'error', engine: 'ghostrecon', recoverable: true, message: error?.message || String(error) });
      engineOutcomes.push({ engine: 'ghostrecon', status, error: error?.message || String(error) });
      if (effectivePlan.engines.vigolium.enabled) {
        const outcomes = moduleOutcomes.filter((item) => item.engine === 'vigolium');
        const vigoliumStatus = outcomes.some((item) => item.status === 'done') ? 'partial' : status;
        captureEmit({ type: `engine_${vigoliumStatus}`, engine: 'vigolium', iteration, planHash: effectivePlan.hash, error: error?.message || String(error) });
        engineOutcomes.push({
          engine: 'vigolium',
          status: vigoliumStatus,
          error: error?.message || String(error),
          modules: outcomes,
        });
      }
      await persistActiveCheckpoint('running');
      return false;
    }
  };

  captureEmit({
    type: 'auto_step',
    step: 'act',
    status: 'running',
    iteration,
    modules: effectivePlan.selectedModules,
    planHash: effectivePlan.hash,
  });
  const frameSevenTarget = /^https?:\/\//i.test(req.target) ? req.target : `https://${req.target}`;
  const frameSevenAuthTimeoutMs = Number(engineTimeouts.framesevenAuthTimeoutMs);
  const runFrameSevenEngine = async (options = {}) => {
    if (!effectivePlan.engines.frameseven.enabled) return true;
    session.assertActive();
    await revalidateEngagementForPlan('immediately_before_frameseven');
    const {
      waitForAuth = null,
      beforeScan = null,
    } = options;
    let scopeFileResource = null;
    try {
      let scopePolicyEnv = null;
      if (iterationSealedScopePolicy) {
        assertEngineScopeEnforcementAvailable({
          engine: 'frameseven',
          sealedPolicy: iterationSealedScopePolicy,
          env: executionEnv,
          engineDeclaresSupport: catalog?.engines?.frameseven?.supportsSealedScopePolicy === true,
        });
        scopeFileResource = await writeSealedScopePolicyFile(iterationSealedScopePolicy);
        if (scopeFileResource) {
          session.resources.push(scopeFileResource);
          scopePolicyEnv = scopePolicyEnvBindings(iterationSealedScopePolicy, {
            policyFile: scopeFileResource.filePath,
          });
        } else {
          scopePolicyEnv = scopePolicyEnvBindings(iterationSealedScopePolicy);
        }
      }
      const result = await runFrameSevenImpl({
        root: ROOT,
        target: frameSevenTarget,
        outputDir: `reports/frameseven-${sessionId}-iteration-${iteration}`,
        authBrowser: effectivePlan.engines.frameseven.authBrowser,
        tools: effectivePlan.engines.frameseven.tools,
        offensiveApproved: effectivePlan.engines.frameseven.offensive === true,
        runTimeoutMs: effectivePlan.engines.frameseven.runTimeoutMs,
        authCaptureTimeoutMs: frameSevenAuthTimeoutMs,
        approvalTimeoutMs: frameSevenAuthTimeoutMs,
        beforeScanTimeoutMs: Number(engineTimeouts.framesevenBeforeScanTimeoutMs),
        expectedBinaryIdentity: effectivePlan.engines.frameseven.identity,
        signal: session.signal,
        emit: captureEmit,
        env,
        scopePolicyEnv,
        waitForAuth,
        beforeScan,
        deferDoneEvent: true,
      });
      let reportMerge;
      try {
        const existingFindings = events.slice(iterationEventStart)
          .filter((event) => event?.type === 'finding' && event.finding)
          .map((event) => event.finding);
        reportMerge = await readFrameSevenReportImpl({
          outputDir: result.outputDir,
          target: frameSevenTarget,
          existingFindings,
          accessMetadata: {
            ownerSub: principal?.sub || null,
            engagementId: req.engagementId,
            authenticated: effectivePlan.engines.frameseven.authBrowser,
            privateReport: effectivePlan.engines.frameseven.authBrowser,
          },
        });
        for (const finding of reportMerge.newFindings) {
          captureEmit({ type: 'finding', finding });
        }
        captureEmit({
          type: 'dedupe_summary',
          engines: ['ghostrecon', 'vigolium', 'frameseven'],
          input: reportMerge.inputCount,
          output: reportMerge.outputCount,
          merged: reportMerge.mergedCount,
          reportErrors: reportMerge.reportErrors?.length || 0,
          ...(publicFrameSevenReportUrlImpl(ROOT, result.outputDir)
            ? { reportUrl: publicFrameSevenReportUrlImpl(ROOT, result.outputDir) }
            : {}),
        });
      } catch (error) {
        if (
          session.signal.aborted
          || error?.name === 'AbortError'
          || error?.code === 'PROCESS_ABORTED'
          || error?.code === 'AUTO_FORGE_CANCELLED'
          || error?.code === 'PROCESS_UNTERMINATED'
          || error?.code === 'FRAMESEVEN_PROCESS_UNTERMINATED'
          || error?.code === 'FRAMESEVEN_BINARY_IDENTITY_MISMATCH'
        ) {
          throw error;
        }
        const message = error?.message || String(error);
        const reportUrl = publicFrameSevenReportUrlImpl(ROOT, result.outputDir);
        captureEmit({
          type: 'engine_partial',
          engine: 'frameseven',
          iteration,
          planHash: effectivePlan.hash,
          phase: 'report_merge',
          error: message,
          recoverable: true,
          ...(reportUrl ? { reportUrl } : {}),
        });
        captureEmit({
          type: 'error',
          engine: 'frameseven',
          phase: 'report_merge',
          recoverable: true,
          message,
        });
        engineOutcomes.push({
          engine: 'frameseven',
          status: 'partial',
          phase: 'report_merge',
          error: message,
        });
        for (const id of effectivePlan.engines.frameseven.moduleIds) {
          recordModuleOutcome({
            moduleId: id,
            engine: 'frameseven',
            status: 'done',
            partial: true,
            phase: 'report_merge',
            error: message,
          });
        }
        await persistActiveCheckpoint('running');
        return false;
      }
      const partial = result.status === 'partial' || reportMerge.incomplete === true;
      const reportUrl = publicFrameSevenReportUrlImpl(ROOT, result.outputDir);
      captureEmit({
        type: partial ? 'engine_partial' : 'engine_done',
        engine: 'frameseven',
        iteration,
        planHash: effectivePlan.hash,
        phase: result.status === 'partial'
          ? 'scan'
          : reportMerge.incomplete
            ? 'report'
            : 'complete',
        recoverable: partial || undefined,
        code: result.code,
        reportErrors: reportMerge.reportErrors?.length || 0,
        ...(reportUrl ? { reportUrl } : {}),
      });
      engineOutcomes.push({
        engine: 'frameseven',
        status: partial ? 'partial' : 'done',
        findings: reportMerge.incomingFindings.length,
        mergedFindings: reportMerge.outputCount,
        reportErrors: reportMerge.reportErrors?.length || 0,
      });
      for (const id of effectivePlan.engines.frameseven.moduleIds) {
        recordModuleOutcome({
          moduleId: id,
          engine: 'frameseven',
          status: 'done',
          partial,
          error: null,
        });
      }
      await persistActiveCheckpoint('running');
      return !partial;
    } catch (error) {
      if (
        session.signal.aborted
        || error?.name === 'AbortError'
        || error?.code === 'PROCESS_ABORTED'
        || error?.code === 'AUTO_FORGE_CANCELLED'
        || error?.code === 'AUTO_DEADLINE_UNSETTLED'
        || error?.code === 'AUTO_ENGAGEMENT_INVALIDATED'
        || error?.code === 'AUTO_ENGAGEMENT_CHANGED'
        || error?.code === 'PROCESS_UNTERMINATED'
        || error?.code === 'FRAMESEVEN_PROCESS_UNTERMINATED'
        || error?.code === 'FRAMESEVEN_BINARY_IDENTITY_MISMATCH'
        || isFatalVigoliumExecutionError(error)
      ) {
        throw error;
      }
      const status = error?.code === 'PROCESS_TIMEOUT'
        || error?.code === 'AUTO_FORGE_TIMEOUT'
        || /timeout/i.test(String(error?.message || error))
        ? 'timeout'
        : 'failed';
      captureEmit({ type: 'error', engine: 'frameseven', recoverable: true, message: error?.message || String(error) });
      engineOutcomes.push({ engine: 'frameseven', status, error: error?.message || String(error) });
      for (const id of effectivePlan.engines.frameseven.moduleIds) {
        recordModuleOutcome({
          moduleId: id,
          engine: 'frameseven',
          status,
          error: error?.message || String(error),
        });
      }
      await persistActiveCheckpoint('running');
      return false;
    }
  };

  if (effectivePlan.engines.frameseven.enabled && effectivePlan.engines.frameseven.authBrowser) {
    await runFrameSevenEngine({
      waitForAuth: () => session.requestApproval({
        kind: 'authentication',
        intrusive: true,
        requiredScope: 'recon.intrusive',
        module: 'frameseven',
        target: req.target,
        action: 'fechar navegador e compartilhar a sessão temporária com os motores',
        risk: 'sessão autenticada temporária; nenhuma senha será armazenada',
        planHash: effectivePlan.hash,
        denialBehavior: 'a sessão capturada será descartada e nenhum motor autenticado será iniciado',
      }, frameSevenAuthTimeoutMs),
      beforeScan: async (capturedAuth, { signal: stageSignal } = {}) => {
        await revalidateEngagementForPlan('after_authenticated_session_confirmation');
        await runGhostReconAndVigolium(capturedAuth, stageSignal || session.signal);
        await revalidateEngagementForPlan(
          'immediately_before_authenticated_frameseven_scan',
        );
      },
    });
  } else {
    await runGhostReconAndVigolium();
    await runFrameSevenEngine();
  }
  if (effectivePlan.engines.neurosploit?.enabled) {
    await revalidateEngagementForPlan('immediately_before_neurosploit');
    captureEmit({ type: 'engine_started', engine: 'neurosploit', iteration, planHash: effectivePlan.hash });
    try {
      const priorEvents = events.slice(iterationEventStart);
      const result = await runNeuroSploitImpl({
        root: ROOT,
        sessionId,
        requestRunId,
        owner: principalId,
        target: req.target,
        engagementId: req.engagementId,
        effectivePlan: { ...effectivePlan, iteration },
        engineOutcomes: [...engineOutcomes],
        moduleOutcomes: [...moduleOutcomes],
        findings: priorEvents
          .filter((event) => event?.type === 'finding' && event.finding)
          .map((event) => event.finding),
        signal: session.signal,
        emit: captureEmit,
      });
      captureEmit({
        type: 'engine_done',
        engine: 'neurosploit',
        iteration,
        planHash: effectivePlan.hash,
        jobId: result.jobId,
        runId: result.runId,
        findings: result.findings?.length || 0,
        reportReady: result.reportReady === true,
      });
      engineOutcomes.push({
        engine: 'neurosploit',
        status: 'done',
        jobId: result.jobId,
        runId: result.runId,
        findings: result.findings?.length || 0,
        cortex: result.cortex || null,
      });
      recordModuleOutcome({
        moduleId: 'neurosploit_auto',
        engine: 'neurosploit',
        status: 'done',
        phase: 'neurosploit',
        source: 'engine',
        resultCount: result.findings?.length || 0,
      });
    } catch (error) {
      if (session.signal.aborted || error?.name === 'AbortError') throw error;
      const message = error?.message || String(error);
      captureEmit({
        type: 'engine_failed',
        engine: 'neurosploit',
        iteration,
        planHash: effectivePlan.hash,
        error: message,
        recoverable: true,
      });
      captureEmit({ type: 'error', engine: 'neurosploit', recoverable: true, message });
      engineOutcomes.push({ engine: 'neurosploit', status: 'failed', error: message });
      recordModuleOutcome({
        moduleId: 'neurosploit_auto',
        engine: 'neurosploit',
        status: 'failed',
        phase: 'neurosploit',
        source: 'engine',
        error: message,
      });
    }
    await persistActiveCheckpoint('running');
  }
  captureEmit({ type: 'auto_step', step: 'act', status: 'done' });
  // A partir daqui todos os motores terminaram. Um crash durante avaliação não
  // pode fazer a mesma iteração voltar a executar; registre a fronteira antes
  // da avaliação determinística.
  await persistActiveCheckpoint('evaluating');

  for (const outcome of engineOutcomes) {
    captureEmit({ type: 'auto_engine_outcome', sessionId, iteration, planHash: effectivePlan.hash, ...outcome });
  }
  const iterationEvents = events.slice(iterationEventStart);
  const observedPlan = {
    ...iterationPlan,
    modules: effectivePlan.selectedModules,
    effectivePlanHash: effectivePlan.hash,
    engineOutcomes,
    moduleOutcomes,
  };
  const observationBundle = {
    ...buildAutoObservationBundle({ events: iterationEvents, plan: observedPlan }),
    ...(req.bountyContext ? { bugBountyContext: req.bountyContext } : {}),
  };
  captureEmit({
    type: 'auto_observation',
    iteration,
    findings: observationBundle.findings.length,
    warnings: observationBundle.warnings.length,
    errors: observationBundle.errors.length,
  });
  evaluation = evaluateAutoRun({
    events: iterationEvents,
    plan: observedPlan,
    moduleOutcomes,
  });
  evaluation.observation = {
    findings: observationBundle.findings.length,
    warnings: observationBundle.warnings.length,
    errors: observationBundle.errors.length,
  };
  evaluation.engineOutcomes = engineOutcomes;
  evaluation.moduleOutcomes = moduleOutcomes;
  evaluation.effectivePlanHash = effectivePlan.hash;
  captureEmit({ type: 'auto_deterministic_evaluation', iteration, evaluation });
  captureEmit({ type: 'auto_evaluation', evaluation });
  const evalMemory = await writeAutoDecisionMarkdown({
    root: ROOT,
    env,
    requestRunId,
    target: req.target,
    kind: 'evaluation',
    title: 'Auto deterministic evaluation - ' + req.target,
    summary: 'Avaliação determinística após o pipeline GHOSTRECON.',
    plan: observedPlan,
    evaluation,
    events,
    tags: ['evaluation', 'deterministic', evaluation.ok ? 'ok' : 'error'],
    principalId: principalId || session.state.owner?.sub || '',
    engagementId: req.engagementId || '',
  }).catch((e) => ({ error: e?.message || String(e) }));
  captureEmit({ type: 'auto_rag', phase: 'evaluation_saved', memory: evalMemory });
  assertDurableRagPersist(evalMemory, { env, captureEmit, sessionId, requestRunId, stage: 'evaluation' });
  const deterministicOutcome = { action: 'finish', source: 'deterministic_evaluation' };
  iterationHistory.push({
    iteration,
    modules: [...effectivePlan.selectedModules],
    effectivePlanHash: effectivePlan.hash,
    engineOutcomes,
    moduleOutcomes,
    observation: evaluation.observation,
    decision: deterministicOutcome,
  });
  captureEmit({ type: 'auto_iteration_completed', sessionId, iteration, decision: 'finish' });
  session.state.checkpoint = createAutoCheckpoint(session.state, {
    status: 'completed',
    currentIteration: iteration,
    executedModules: [...executedModules],
    iterationHistory,
  });
  await writeAutoSessionSnapshot(ROOT, session.state, env);
  break;
  }
  evaluation.iterations = iterationHistory;
  const terminalPhase = sessionTerminalFromEvaluation(evaluation);
  session.assertActive();
  const finalSession = await session.close(terminalPhase);
  const terminal = await persistTerminalSession({
    ROOT, env, session, finalSession, captureEmit, sessionId, requestRunId,
    preferredPhase: terminalPhase,
    evaluation,
    moduleOutcomes: evaluation?.moduleOutcomes || [],
    plan,
    events,
  });
  return {
    sessionId,
    requestRunId,
    runId: requestRunId,
    plan,
    evaluation,
    events,
    session: terminal.finalSession,
  };
  } catch (error) {
    const { status, cause } = terminalStatus(error, session);
    if (session.state.catalogHash && session.state.promptVersion) {
      const activePlan = session.state.checkpoint?.activePlan || null;
      session.state.checkpoint = createAutoCheckpoint(session.state, {
        status: 'failed',
        currentIteration: Number(session.state.iteration || 0),
        nextIteration: null,
        nextModules: [],
        executedModules: session.state.checkpoint?.executedModules || [],
        iterationHistory: session.state.checkpoint?.iterationHistory || [],
        activePlan,
      });
    }
    const failedSession = await session.close(status);
    failedSession.error = error?.message || String(error);
    failedSession.terminationCause = cause;
    await writeAutoSessionSnapshot(ROOT, failedSession, env).catch((snapshotError) => {
      captureEmit({
        type: 'auto_persist_failed',
        stage: 'terminal_snapshot',
        sessionId,
        requestRunId,
        error: snapshotError?.message || String(snapshotError),
      });
      return null;
    });
    captureEmit({
      type: 'auto_session',
      phase: status,
      terminationCause: cause,
      session: failedSession,
      error: failedSession.error,
    });
    throw error;
  } finally {
    unregisterActiveAutoSession(sessionId);
  }
}
