import { createHash, randomBytes } from 'node:crypto';
import { detectAutoProviders } from './provider-detector.mjs';
import { buildAutoToolCatalog } from './tool-catalog.mjs';
import { createAutoPlan, evaluateAutoRun } from './planner.mjs';
import { loadAutoRagContext, writeAutoDecisionMarkdown, writeAutoRagNote } from './rag-memory.mjs';
import { createCursorHandoff } from './providers/cursor.mjs';
import { runAgentCouncil } from './council/council-runner.mjs';
import { createPendingForgeRequest } from './forge/forge-store.mjs';
import { generatePendingArtifact } from './forge/generate-artifact.mjs';
import { buildAutoObservationBundle } from './observation-builder.mjs';
import { validateAndTestForgePackage } from './forge/validate-package.mjs';
import { reviewForgePackage } from './forge/code-review.mjs';
import { runForgeCorrectionLoop } from './forge/correction-loop.mjs';
import { gateModules } from '../modules/opsec.mjs';
import {
  assertAutoResumeSnapshotCompatible,
  claimAutoResumeCheckpoint,
  computeAutoReadyPlanHash,
  computeAutoResumePolicyHash,
  createAutoCheckpoint,
  createAutoSession,
  readAutoSessionSnapshot,
  writeAutoSessionSnapshot,
} from './session-store.mjs';
import { registerActiveAutoSession, unregisterActiveAutoSession } from './active-sessions.mjs';
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
import { redactAutoValue } from './redaction.mjs';
import { isFatalVigoliumExecutionError } from '../../bridge/vigolium-errors.mjs';

const AUTO_PROMPT_VERSION = 'auto-council-v3';

function stableCatalogValue(value) {
  if (Array.isArray(value)) return value.map(stableCatalogValue);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, stableCatalogValue(value[key])]),
  );
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

function terminalStatus(error, session) {
  if (!session?.signal?.aborted) return { status: 'failed', cause: 'failed' };
  const reason = String(session.signal.reason?.message || session.signal.reason || error?.message || '');
  if (/stall/i.test(reason)) return { status: 'stalled', cause: reason };
  if (/timeout|timed.out/i.test(reason)) return { status: 'timed_out', cause: reason };
  if (/budget|custo/i.test(reason)) return { status: 'budget_exceeded', cause: reason };
  if (/client|stream|disconnect/i.test(reason)) return { status: 'cancelled', cause: 'client_disconnected' };
  return { status: 'cancelled', cause: reason || 'operator_cancelled' };
}

export function normalizeAutoRequest(body = {}) {
  const commanders = Array.isArray(body.commanders)
    ? body.commanders
    : Array.isArray(body.providers)
      ? body.providers
      : typeof body.commander === 'string'
        ? [body.commander]
        : [];
  return {
    target: body.domain || body.target || '',
    mode: body.autoMode || body.mode || 'balanced',
    commanders,
    modules: Array.isArray(body.modules) ? body.modules.map(String) : [],
    openrouterModel:
      body.openrouterModel != null
        ? String(body.openrouterModel).trim()
        : body.model != null
          ? String(body.model).trim()
          : null,
    includeHexstrike: body.includeHexstrike === true,
    includeDeepPassive: body.includeDeepPassive,
    includeFrameSeven: body.includeFrameSeven === true,
    includeVigolium: body.includeVigolium === true,
    // Política explícita de autonomia da IA por sessão. O nível 4 continua
    // sujeito à confirmação humana por ação destrutiva (não há execução livre).
    autonomyLevel: ['observation', 'assisted', 'authorized', 'authorized_opsec'].includes(String(body.autonomyLevel || '').toLowerCase())
      ? String(body.autonomyLevel).toLowerCase() : 'observation',
    frameSevenAuth: body.includeFrameSeven === true && body.frameSevenAuth === true,
    vigoliumUseCodex: body.includeVigolium === true && body.vigoliumUseCodex === true,
    engagementId: body.engagementId ? String(body.engagementId).trim() : null,
    resumeSessionId: body.resumeSessionId ? String(body.resumeSessionId).trim() : null,
    approvalMode: body.approvalMode === 'deny' ? 'deny' : 'interactive',
  };
}

export function buildAutoResumePolicy(req, body = {}) {
  const uniqueSorted = (values) => [...new Set((values || [])
    .map((value) => String(value || '').trim())
    .filter(Boolean))].sort();
  return Object.freeze({
    schemaVersion: 1,
    mode: String(req?.mode || 'balanced'),
    commanders: uniqueSorted(req?.commanders),
    requestedModules: uniqueSorted(req?.modules),
    openrouterModel: req?.openrouterModel || null,
    includeHexstrike: req?.includeHexstrike === true,
    includeDeepPassive: req?.includeDeepPassive !== false,
    includeFrameSeven: req?.includeFrameSeven === true,
    frameSevenAuth: req?.frameSevenAuth === true,
    includeVigolium: req?.includeVigolium === true,
    vigoliumUseCodex: req?.vigoliumUseCodex === true,
    autonomyLevel: String(req?.autonomyLevel || 'observation'),
    engagementId: req?.engagementId || null,
    approvalMode: req?.approvalMode === 'deny' ? 'deny' : 'interactive',
    opsecProfile: String(body?.opsecProfile || '').trim().toLowerCase() || null,
    autoAiReports: body?.autoAiReports === true,
  });
}

export function assertAutoResumePolicyCompatible(restoredState, resumePolicy) {
  if (!restoredState) return;
  if (!restoredState.resumePolicy || restoredState.resumePolicy.schemaVersion !== 1) {
    throw new Error('snapshot AUTO antigo/incompleto: política de retomada ausente');
  }
  if (JSON.stringify(restoredState.resumePolicy) !== JSON.stringify(resumePolicy)) {
    throw new Error('retomada não pode alterar providers, módulos, motores, engagement ou política');
  }
}

export async function runAutoRecon({
  body = {},
  runPipeline,
  emit = () => {},
  ROOT,
  env = process.env,
  fetchImpl = globalThis.fetch,
  execFileImpl,
  forgeSandboxRunner = null,
  runFrameSevenImpl = runFrameSeven,
  readFrameSevenReportImpl = readAndMergeFrameSevenReport,
  publicFrameSevenReportUrlImpl = publicFrameSevenReportUrl,
  pipelineOverrides = {},
  signal,
  principal = null,
  getEngagementImpl = getEngagement,
} = {}) {
  if (typeof runPipeline !== 'function') {
    throw new Error('runPipeline ausente para Modo Auto');
  }
  const req = normalizeAutoRequest(body);
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
  const resumePolicy = buildAutoResumePolicy(req, body);
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
  const events = [];
  const restoredState = req.resumeSessionId
    ? await readAutoSessionSnapshot(ROOT, req.resumeSessionId, env)
    : null;
  if (restoredState && restoredState.target !== req.target) throw new Error('sessão pertence a outro alvo');
  if (restoredState && !['failed', 'interrupted', 'timed_out', 'stalled', 'budget_exceeded'].includes(restoredState.status)) {
    throw new Error(`sessão ${restoredState.status} não pode ser retomada`);
  }
  if (restoredState?.autonomyLevel && restoredState.autonomyLevel !== req.autonomyLevel) {
    throw new Error('retomada não pode alterar o nível de autonomia');
  }
  assertAutoResumePolicyCompatible(restoredState, resumePolicy);
  if (restoredState) {
    // Valide a estrutura e a versão antes de detectar providers, carregar RAG
    // ou iniciar qualquer planner. Snapshots históricos/incompletos nunca
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
    forgeRuntimeAvailable: Boolean(forgeSandboxRunner),
    ghostRoot: ROOT,
    target: req.target,
    env,
  });
  const catalogHash = computeAutoCatalogHash(catalog);
  if (restoredState) {
    assertAutoResumeSnapshotCompatible(restoredState, {
      expectedCatalogHash: catalogHash,
      expectedPromptVersion: AUTO_PROMPT_VERSION,
    });
  }
  // O claim `wx` é o ponto de não retorno da retomada: ele ocorre antes de
  // registrar a sessão, chamar providers ou executar qualquer engine. Assim,
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
    providers: req.commanders,
    ownerPrincipal: principal || restoredState?.owner || null,
    env,
    restoredState,
  });
  session.state.autonomyLevel = req.autonomyLevel;
  session.state.includeFrameSeven = req.includeFrameSeven;
  session.state.frameSevenAuth = req.frameSevenAuth;
  session.state.includeVigolium = req.includeVigolium;
  session.state.vigoliumUseCodex = req.vigoliumUseCodex;
  session.state.engagementId = req.engagementId;
  session.state.mode = req.mode;
  session.state.resumePolicy = resumePolicy;
  session.state.catalogHash = catalogHash;
  session.state.promptVersion = AUTO_PROMPT_VERSION;
  session.state.resumeClaimId = resumeClaim?.claimId || null;
  try {
    registerActiveAutoSession(session);
  } catch (error) {
    session.close('failed');
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
  const captureEmit = (event) => {
    const safeEvent = publicAutoEvent(event, { root: ROOT });
    session.touch(safeEvent);
    events.push(safeEvent);
    sendSafe(emit, safeEvent);
  };
  const rawRequestApproval = session.requestApproval.bind(session);
  session.requestApproval = (details = {}, timeoutMs) => {
    const pending = rawRequestApproval(details, timeoutMs);
    if (session.state.pendingApproval) captureEmit({
      type: 'auto_approval_required',
      sessionId,
      approval: session.state.pendingApproval,
    });
    if (req.approvalMode === 'deny' && session.state.pendingApproval?.status === 'pending') {
      const approvalId = session.state.pendingApproval.approvalId;
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
    }
    return pending;
  };

  try {
  const heartbeat = setInterval(() => captureEmit({
    type: 'auto_heartbeat', sessionId, iteration: session.state.iteration,
    agentCalls: session.state.agentCalls, elapsedMs: Date.now() - Date.parse(session.state.startedAt),
    lastActivityAt: session.state.lastActivityAt,
    currentStage: session.state.currentStage,
    currentModule: session.state.currentModule,
  }), Math.max(5_000, Math.min(60_000, Number(env.GHOSTRECON_AUTO_HEARTBEAT_MS || 15_000))));
  heartbeat.unref?.();
  session.resources.push({ close: () => clearInterval(heartbeat) });
  // O watchdog não pode ficar atrás do timeout do turno. O padrão é uma margem
  // curta sobre o limite do agente (210 s para o padrão de 180 s), e pode ser
  // aumentado explicitamente por configuração.
  const configuredStallTimeout = Number(env.GHOSTRECON_AUTO_STALL_TIMEOUT_MS || 0);
  const stallTimeoutMs = Math.max(
    session.limits.agentTimeoutMs + 30_000,
    Math.min(1_800_000, Number.isFinite(configuredStallTimeout) && configuredStallTimeout > 0
      ? configuredStallTimeout : session.limits.agentTimeoutMs + 30_000),
  );
  const watchdog = setInterval(() => {
    const idleMs = Date.now() - Date.parse(session.state.lastActivityAt || session.state.startedAt);
    // O limite de turno do agente não se aplica a módulos do pipeline. Audits
    // passivos (como CORS) podem aguardar vários requests sequenciais.
    const inAgentTurn = String(session.state.currentStage || '').startsWith('agent:');
    const effectiveTimeoutMs = inAgentTurn ? stallTimeoutMs : session.limits.sessionTimeoutMs;
    if (idleMs < effectiveTimeoutMs || session.signal.aborted) return;
    captureEmit({
      type: 'auto_stall_detected', idleMs, stallTimeoutMs: effectiveTimeoutMs,
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
    commanders: req.commanders,
    limits: session.limits,
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
  });

  let ragContext = await loadAutoRagContext({
    root: ROOT,
    env,
    target: req.target,
    modules: req.modules,
    decisionType: 'plan',
  }).catch((e) => ({
    dir: '',
    items: [],
    error: e?.message || String(e),
  }));
  session.state.memoriesUsed = (ragContext.items || []).map((item) => item.name);
  captureEmit({
    type: 'auto_rag',
    phase: 'loaded',
    dir: ragContext.dir || '',
    items: Array.isArray(ragContext.items) ? ragContext.items.length : 0,
    error: ragContext.error || null,
  });
  const providers = await detectAutoProviders({ selected: req.commanders, env, fetchImpl, execFileImpl });
  if (req.openrouterModel) {
    const openrouter = providers.providers.find((p) => p.id === 'openrouter');
    if (openrouter) openrouter.defaultModel = req.openrouterModel;
  }
  captureEmit({ type: 'auto_providers', ...providers });

  const resumedReadyCheckpoint = restoredState
    && ['ready_for_iteration', 'ready_for_next_iteration'].includes(restoredState.checkpoint.status)
    ? restoredState.checkpoint
    : null;
  let council = resumedReadyCheckpoint
    ? {
        selected: [],
        proposals: [],
        reviews: [],
        finalDecision: {
          action: 'run_modules',
          objective: 'Retomar plano autorizado persistido',
          reasoningSummary: ['Checkpoint compatível validado; retomando exatamente os módulos congelados.'],
          evidenceRefs: [],
          requestedModules: [...resumedReadyCheckpoint.nextModules],
          rejectedModules: [],
          confidence: 1,
          assumptions: [],
          operatorQuestion: null,
          forgeRequest: null,
        },
      }
    : await runAgentCouncil({
    providers: providers.providers,
    target: req.target,
    mode: req.mode,
    catalog,
    ragContext,
    root: ROOT,
    env,
    fetchImpl,
    execFileImpl,
    iteration: 1,
    onTurn: (turn) => {
      if (turn.phase === 'started') {
        captureEmit({ type: 'auto_agent_turn_started', provider: turn.provider, role: turn.role, iteration: turn.iteration });
      } else if (turn.phase === 'completed') {
        captureEmit({
          type: 'auto_agent_turn_completed', provider: turn.provider, role: turn.role,
          iteration: turn.iteration, latencyMs: turn.latencyMs, decision: turn.decision,
        });
      } else {
        captureEmit({
          type: 'auto_agent_turn_failed', provider: turn.provider, role: turn.role,
          iteration: turn.iteration, error: turn.error, fallback: 'council_or_deterministic_plan',
        });
      }
    },
    session,
    allowIntrusive: ['authorized', 'authorized_opsec'].includes(req.autonomyLevel),
    autonomyLevel: req.autonomyLevel,
        frameSevenAuth: req.frameSevenAuth,
      });
  if (council.finalDecision?.action === 'ask_operator') {
    const question = council.finalDecision.operatorQuestion || 'O conselho precisa de uma decisão do operador.';
    const approved = await session.requestApproval({
      kind: 'operator_question',
      target: req.target,
      module: 'auto_planner',
      action: question,
      risk: 'a resposta será devolvida ao conselho; nenhuma ferramenta roda durante esta espera',
    });
    const operatorResponse = {
      schemaVersion: 1,
      operatorDecision: {
        question,
        approved,
        reason: String(session.state.pendingApproval?.reason || '').slice(0, 1000),
      },
      findings: [],
      warnings: [],
      errors: [],
      instruction: 'A resposta do operador é contexto de decisão, não autorização para ampliar escopo ou risco.',
    };
    captureEmit({ type: 'auto_operator_answered', sessionId, approved, question });
    if (approved) {
      const resumedCouncil = await runAgentCouncil({
        providers: providers.providers,
        target: req.target,
        mode: req.mode,
        catalog,
        ragContext,
        root: ROOT,
        env,
        fetchImpl,
        execFileImpl,
        iteration: 1,
        observationBundle: operatorResponse,
        onTurn: (turn) => {
          if (turn.phase === 'started') {
            captureEmit({ type: 'auto_agent_turn_started', provider: turn.provider, role: turn.role, iteration: 1 });
          } else if (turn.phase === 'completed') {
            captureEmit({
              type: 'auto_agent_turn_completed',
              provider: turn.provider,
              role: turn.role,
              iteration: 1,
              latencyMs: turn.latencyMs,
              decision: turn.decision,
            });
          } else {
            captureEmit({
              type: 'auto_agent_turn_failed',
              provider: turn.provider,
              role: turn.role,
              iteration: 1,
              error: turn.error,
              fallback: 'finish_after_operator_question',
            });
          }
        },
        session,
        allowIntrusive: ['authorized', 'authorized_opsec'].includes(req.autonomyLevel),
        autonomyLevel: req.autonomyLevel,
      });
      council = resumedCouncil.finalDecision?.action === 'ask_operator'
        ? {
            ...resumedCouncil,
            finalDecision: {
              ...resumedCouncil.finalDecision,
              action: 'finish',
              requestedModules: [],
              operatorQuestion: null,
              reasoningSummary: [
                ...(resumedCouncil.finalDecision.reasoningSummary || []),
                'O conselho repetiu a pergunta; a sessão foi encerrada sem executar módulos.',
              ].slice(0, 20),
            },
          }
        : resumedCouncil;
    } else {
      council = {
        ...council,
        finalDecision: {
          action: 'finish',
          objective: 'Encerrar após decisão do operador',
          reasoningSummary: ['O operador não autorizou continuar após a pergunta do conselho.'],
          evidenceRefs: [],
          requestedModules: [],
          rejectedModules: [],
          confidence: 1,
          assumptions: [],
          operatorQuestion: null,
          forgeRequest: null,
        },
      };
    }
  }
  const successfulTurns = [...council.proposals, ...council.reviews].filter((turn) => turn.ok && turn.decision);
  for (const turn of successfulTurns) {
    const memory = await writeAutoRagNote({
      root: ROOT,
      env,
      kind: 'decision',
      title: `${turn.provider} ${turn.role} decision - ${req.target}`,
      target: req.target,
      tags: ['decision', turn.provider, turn.role, `iteration-${turn.iteration}`],
      body: [
        `- Request run: \`${requestRunId}\``,
        `- Provider: \`${turn.provider}\``,
        `- Model: \`${turn.model || 'default'}\``,
        `- Role: \`${turn.role}\``,
        `- Iteration: \`${turn.iteration}\``,
        '',
        '## Decision',
        '',
        `\`\`\`json\n${JSON.stringify(turn.decision, null, 2)}\n\`\`\``,
      ].join('\n'),
      metadata: {
        sessionId, requestRunId, provider: turn.provider, model: turn.model || null,
        role: turn.role, iteration: turn.iteration, latencyMs: turn.latencyMs, usage: turn.usage || null,
        promptVersion: AUTO_PROMPT_VERSION, catalogHash, memoriesUsed: session.state.memoriesUsed,
      },
    }).catch((e) => ({ error: e?.message || String(e) }));
    captureEmit({
      type: 'auto_memory_written', provider: turn.provider,
      decision: memory?.name || null, error: memory?.error || null,
    });
  }
  const agentDecision = council.finalDecision;
  captureEmit({
    type: 'auto_council_verdict',
    selected: council.selected,
    proposals: council.proposals.filter((t) => t.ok).map((t) => t.provider),
    reviews: council.reviews.filter((t) => t.ok).map((t) => t.provider),
    decision: agentDecision,
    fallback: agentDecision ? null : 'deterministic_plan',
  });
  let forge = null;
  if (agentDecision?.action === 'forge_module' && agentDecision.forgeRequest) {
    const generator = providers.providers.find((p) => p.id === 'claude_code' && p.selected && p.usable)
      || providers.providers.find((p) => p.id === 'codex' && p.selected && p.usable)
      || null;
    forge = await createPendingForgeRequest({
      root: ROOT,
      requestRunId,
      target: req.target,
      decision: agentDecision,
      council,
      authorOverride: generator?.id || null,
      authorModelOverride: generator?.defaultModel || null,
    }).catch((e) => ({ error: e?.message || String(e) }));
    captureEmit({
      type: 'auto_forge_status',
      status: forge?.error ? 'error' : 'proposed',
      forgeId: forge?.forgeId || null,
      author: forge?.author || agentDecision.forgeRequest.author || null,
      error: forge?.error || null,
      pipelineEnabled: false,
    });
    if (!forge?.error && generator && !/^(0|false|no|off)$/i.test(String(env.GHOSTRECON_AUTO_FORGE_GENERATE || '1'))) {
      captureEmit({ type: 'auto_forge_status', status: 'generating', forgeId: forge.forgeId, author: generator.id, pipelineEnabled: false });
      const generated = await generatePendingArtifact({
        provider: generator.id,
        request: agentDecision.forgeRequest,
        target: req.target,
        root: ROOT,
        pendingDir: forge.dir,
        env,
        execFileImpl,
        signal: session.signal,
      }).catch((e) => {
        if (session.signal.aborted) throw session.signal.reason || e;
        return { ok: false, error: e?.message || String(e) };
      });
      forge.generated = generated;
      captureEmit({
        type: 'auto_forge_status', status: generated.ok ? 'generated_pending_validation' : 'generation_failed',
        forgeId: forge.forgeId, author: generator.id, error: generated.error || null, pipelineEnabled: false,
      });
      if (generated.ok) {
        const gates = await validateAndTestForgePackage(forge.dir, {
          env,
          isolatedRunner: forgeSandboxRunner,
          signal: session.signal,
        }).catch((e) => {
          if (session.signal.aborted) throw session.signal.reason || e;
          return { ok: false, status: 'validation_error', error: e?.message || String(e) };
        });
        forge.gates = gates;
        captureEmit({
          type: 'auto_forge_status', status: gates.status || (gates.ok ? 'pending_ai_code_review' : 'validation_failed'),
          forgeId: forge.forgeId, author: generator.id, error: gates.error || null,
          validationOk: Boolean(gates.validation?.ok), testsOk: Boolean(gates.tests?.ok), pipelineEnabled: false,
        });
        if (gates.ok) {
          const codeReview = await reviewForgePackage({
            pendingDir: forge.dir, root: ROOT, providers: providers.providers,
            env, fetchImpl, execFileImpl, signal: session.signal,
          }).catch((e) => {
            if (session.signal.aborted) throw session.signal.reason || e;
            return { approved: false, status: 'review_error', error: e?.message || String(e) };
          });
          forge.codeReview = codeReview;
          captureEmit({
            type: 'auto_forge_status', status: codeReview.status,
            forgeId: forge.forgeId, author: generator.id, error: codeReview.error || null,
            approvals: codeReview.approvals || 0, pipelineEnabled: false,
          });
          if (codeReview.status === 'changes_requested') {
            captureEmit({ type: 'auto_forge_status', status: 'correction_in_progress', forgeId: forge.forgeId, author: generator.id, pipelineEnabled: false });
            const correction = await runForgeCorrectionLoop({
              pendingDir: forge.dir, root: ROOT, provider: generator.id, target: req.target,
              providers: providers.providers, env, fetchImpl, execFileImpl,
              isolatedRunner: forgeSandboxRunner, signal: session.signal,
              initialReview: codeReview,
            }).catch((e) => {
              if (session.signal.aborted) throw session.signal.reason || e;
              return { ok: false, status: 'correction_failed', error: e?.message || String(e) };
            });
            forge.correction = correction;
            forge.codeReview = correction.finalReview || codeReview;
            captureEmit({
              type: 'auto_forge_status', status: correction.status, forgeId: forge.forgeId,
              author: generator.id, attempts: correction.attempts || 0, error: correction.error || null,
              pipelineEnabled: false,
            });
          }
        }
      }
    }
    await writeAutoRagNote({
      root: ROOT,
      env,
      kind: 'module-forge',
      title: `Module Forge request - ${agentDecision.forgeRequest.proposedId}`,
      target: req.target,
      tags: ['module-forge', 'pending', agentDecision.forgeRequest.author || 'council'],
      body: [
        `- Request run: \`${requestRunId}\``,
        `- Forge ID: \`${forge?.forgeId || 'error'}\``,
        '- Pipeline enabled: `false`',
        '',
        '## Forge request',
        '',
        `\`\`\`json\n${JSON.stringify(agentDecision.forgeRequest, null, 2)}\n\`\`\``,
      ].join('\n'),
      metadata: { requestRunId, forge: publicAutoEvent({ forge }).forge },
    }).catch(() => null);
  }

  // Na retomada, a lista do checkpoint é a única fonte do próximo plano. Não
  // reintroduza módulos do request original nem defaults do planner.
  const operatorRequestedModules = resumedReadyCheckpoint
    ? []
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
    providers: providers.providers,
    catalog,
    openrouterModel: req.openrouterModel,
    includeHexstrike: req.includeHexstrike,
    includeDeepPassive: req.includeDeepPassive,
    ragContext,
    agentDecision,
    autonomyLevel: req.autonomyLevel,
  });
  plan.sessionId = sessionId;
  plan.autonomyLevel = req.autonomyLevel;
  plan.limits = session.limits;
  plan.catalogHash = catalogHash;
  plan.promptVersion = AUTO_PROMPT_VERSION;
  captureEmit({ type: 'auto_plan', plan });
  const planAction = String(plan.action || plan.agentDecision?.action || (plan.modules?.length ? 'run_modules' : 'finish'));
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
    summary: 'Modo Auto selected commanders, modules and execution policy before running the pipeline.',
    plan,
    providers,
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
  }).catch((e) => ({ error: e?.message || String(e) }));
  captureEmit({ type: 'auto_rag', phase: 'plan_saved', memory: planMemory });

  const cursorSelected = (plan.commanders?.selected || req.commanders || []).includes('cursor');
  if (cursorSelected) {
    const cursorHandoff = await createCursorHandoff({
      root: ROOT,
      env,
      requestRunId,
      target: req.target,
      plan,
      providers,
      ragContext,
      execFileImpl,
    }).catch((e) => ({ ok: false, error: e?.message || String(e) }));
    captureEmit({
      type: 'auto_cursor',
      phase: 'handoff_ready',
      mode: cursorHandoff?.state?.mode || 'handoff',
      installed: Boolean(cursorHandoff?.state?.installed),
      agentInstalled: Boolean(cursorHandoff?.state?.agentInstalled),
      task: cursorHandoff?.task || null,
      error: cursorHandoff?.error || null,
    });
  }

  if (!['run_modules', 'continue_with_context'].includes(planAction) || !plan.modules?.length) {
    const evaluation = evaluateAutoRun({ events: [], plan });
    evaluation.agentDecision = agentDecision;
    evaluation.observation = { findings: 0, warnings: 0, errors: 0 };
    evaluation.iterations = [];
    evaluation.next = planAction === 'forge_module'
      ? 'await_operator_review_of_forge_package'
      : 'no_execution_requested';
    session.state.checkpoint = createAutoCheckpoint(session.state, {
      status: 'completed',
      currentIteration: Number(session.state.iteration || 0),
    });
    captureEmit({ type: 'auto_evaluation', evaluation });
    captureEmit({ type: 'auto_no_execution', sessionId, action: planAction });
    const finalSession = session.close('completed');
    await writeAutoSessionSnapshot(ROOT, finalSession, env);
    captureEmit({ type: 'auto_session', phase: 'completed', session: finalSession });
    return { sessionId, requestRunId, plan, evaluation, events };
  }

  let iteration = Number(session.state.checkpoint?.nextIteration || 1);
  let iterationPlan = session.state.checkpoint?.nextModules?.length
    ? { ...plan, modules: session.state.checkpoint.nextModules }
    : plan;
  let evaluation = null;
  const executedModules = new Set(session.state.checkpoint?.executedModules || []);
  const iterationHistory = [...(session.state.checkpoint?.iterationHistory || [])];
  let engagement = req.engagementId ? await getEngagementImpl(req.engagementId) : null;
  if (req.engagementId && !engagement) throw new Error(`engagement não encontrado: ${req.engagementId}`);
  const engagementAuthorizationBinding = computeAutoEngagementAuthorizationBinding(
    engagement,
    req.engagementId,
  );
  const frameSevenAvailable = Boolean(catalog.engines?.frameseven?.available);
  const phaseSettleGraceMs = boundedNumber(
    env.GHOSTRECON_AUTO_PHASE_SETTLE_GRACE_MS,
    2_000,
    100,
    30_000,
  );
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
    opsecProfile: body.opsecProfile,
    autoAiReports: body.autoAiReports === true,
    phaseSettleGraceMs,
  });
  while (true) {
  session.assertActive();
  captureEmit({ type: 'auto_iteration_started', sessionId, iteration, modules: iterationPlan.modules });
  const iterationEventStart = events.length;
  let effectivePlan = buildEffectiveAutoPlan({
    plan: iterationPlan,
    catalog,
    body: effectivePlanBody,
    autonomyLevel: req.autonomyLevel,
    frameSevenAvailable,
    forceFrameSevenRecon: req.includeFrameSeven
      && iteration === 1
      && !executedModules.has(req.frameSevenAuth ? 'frameseven_authenticated' : 'frameseven_recon'),
  });
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
      requireFormalAuthorization: effectivePlan.intrusiveModules.length > 0,
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
    requireFormalAuthorization: effectivePlan.intrusiveModules.length > 0,
  });
  captureEmit({
    type: 'auto_preflight',
    sessionId,
    iteration,
    planHash: effectivePlan.hash,
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
      effectivePlan = buildEffectiveAutoPlan({
        plan: { target: req.target, mode: iterationPlan.mode, action: 'finish', modules: [] },
        catalog,
        body: effectivePlanBody,
        autonomyLevel: req.autonomyLevel,
        frameSevenAvailable,
        forceFrameSevenRecon: false,
      });
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

  if (!effectivePlan.selectedModules.length) {
    evaluation = evaluateAutoRun({ events: events.slice(iterationEventStart), plan: iterationPlan });
    evaluation.agentDecision = { action: 'finish', requestedModules: [] };
    evaluation.observation = { findings: 0, warnings: 0, errors: 0 };
    iterationHistory.push({
      iteration,
      modules: [],
      effectivePlanHash: effectivePlan.hash,
      observation: evaluation.observation,
      decision: evaluation.agentDecision,
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
    autonomyLevel: req.autonomyLevel,
    requestRunId,
    engagementId: req.engagementId,
    engagementOperator: principalId,
    kaliMode: effectivePlan.execution.kaliMode,
    confirmActive: approvalGranted && effectivePlan.execution.confirmActive,
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
    moduleOutcomes.push(outcome);
    captureEmit({
      type: 'auto_module_outcome',
      sessionId,
      iteration,
      planHash: effectivePlan.hash,
      ...outcome,
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
      const lastPhaseOutcome = new Map();
      for (const event of events.slice(pipelineEventStart)) {
        if (event?.type === 'pipe' && event.name) {
          lastPipeState.set(String(event.name), String(event.state || ''));
        }
        if (event?.type === 'phase_outcome' && event.phase) {
          lastPhaseOutcome.set(String(event.phase), event);
        }
      }
      const knownStatuses = new Set(['done', 'skip', 'skipped', 'timeout', 'failed', 'cancelled']);
      for (const moduleId of effectivePlan.pipelineModules) {
        if (moduleOutcomes.some((item) => item.moduleId === moduleId)) continue;
        const raw = lastPipeState.get(moduleId);
        const catalogItem = catalog.modules.find((item) => item.id === moduleId);
        const phase = autoCapabilityPhase(moduleId, {
          ...(catalogItem?.manifest || {}),
          source: catalogItem?.source || catalogItem?.manifest?.source,
        });
        const phaseOutcome = phase ? lastPhaseOutcome.get(phase) : null;
        const phaseStatus = String(phaseOutcome?.status || '');
        const status = raw === 'skip' ? 'skipped'
          : knownStatuses.has(raw) ? raw
            : knownStatuses.has(phaseStatus) ? phaseStatus
              : fallbackStatus;
        recordModuleOutcome({
          moduleId,
          engine: moduleId.startsWith('vigolium_') ? 'vigolium' : 'ghostrecon',
          status,
          phase,
          error: ['done', 'skipped'].includes(status)
            ? null
            : phaseOutcome?.error || fallbackError,
        });
      }
    };
    captureEmit({ type: 'engine_started', engine: 'ghostrecon', iteration, planHash: effectivePlan.hash });
    if (effectivePlan.engines.vigolium.enabled) {
      captureEmit({ type: 'engine_started', engine: 'vigolium', iteration, planHash: effectivePlan.hash });
    }
    try {
      const timeoutMs = boundedNumber(
        env.GHOSTRECON_AUTO_PIPELINE_TIMEOUT_MS,
        20 * 60_000,
        30_000,
        session.limits.sessionTimeoutMs,
      );
      await runWithDeadline({
        name: 'ghostrecon_pipeline',
        timeoutMs,
        parentSignal: stageSignal || session.signal,
        settleGraceMs: boundedNumber(
          env.GHOSTRECON_AUTO_ENGINE_SETTLE_GRACE_MS,
          7_500,
          500,
          30_000,
        ),
        work: (iterationSignal) => runPipeline({
          ...pipelineBody,
          auth: capturedAuth || pipelineBody.auth,
          scopePolicy,
          signal: iterationSignal,
          emit: captureEmit,
        }),
      });
      collectPipelineOutcomes('done');
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
  const frameSevenAuthTimeoutMs = boundedNumber(
    env.GHOSTRECON_FRAMESEVEN_AUTH_TIMEOUT_MS,
    10 * 60_000,
    5_000,
    30 * 60_000,
  );
  const runFrameSevenEngine = async (options = {}) => {
    if (!effectivePlan.engines.frameseven.enabled) return true;
    await revalidateEngagementForPlan('immediately_before_frameseven');
    const {
      waitForAuth = null,
      beforeScan = null,
    } = options;
    try {
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
        beforeScanTimeoutMs: boundedNumber(
          env.GHOSTRECON_FRAMESEVEN_BEFORE_SCAN_TIMEOUT_MS,
          30 * 60_000,
          5_000,
          60 * 60_000,
        ),
        expectedBinaryIdentity: effectivePlan.engines.frameseven.identity,
        signal: session.signal,
        emit: captureEmit,
        env,
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
  captureEmit({ type: 'auto_step', step: 'act', status: 'done' });
  // A partir daqui todos os motores terminaram. Um crash durante avaliação não
  // pode fazer a mesma iteração voltar a executar; registre a fronteira antes
  // de invocar novamente o conselho.
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
  const observationBundle = buildAutoObservationBundle({ events: iterationEvents, plan: observedPlan });
  const technologies = [...new Set(observationBundle.findings.map((finding) => finding.type).filter(Boolean))];
  ragContext = await loadAutoRagContext({
    root: ROOT, env, target: req.target, technologies,
    modules: effectivePlan.selectedModules, decisionType: 'evaluation',
  }).catch(() => ragContext);
  captureEmit({
    type: 'auto_observation',
    iteration,
    findings: observationBundle.findings.length,
    warnings: observationBundle.warnings.length,
    errors: observationBundle.errors.length,
  });
  const postTurnHandler = (turn) => {
    if (turn.phase === 'started') {
      captureEmit({ type: 'auto_agent_turn_started', provider: turn.provider, role: turn.role, iteration: iteration + 1 });
    } else if (turn.phase === 'completed') {
      captureEmit({
        type: 'auto_agent_turn_completed', provider: turn.provider, role: turn.role,
        iteration: iteration + 1, latencyMs: turn.latencyMs, decision: turn.decision,
      });
    } else {
      captureEmit({
        type: 'auto_agent_turn_failed', provider: turn.provider, role: turn.role,
        iteration: iteration + 1, error: turn.error, fallback: 'heuristic_evaluation',
      });
    }
  };
  let evaluationCouncil = await runAgentCouncil({
    providers: providers.providers,
    target: req.target,
    mode: req.mode,
    catalog,
    ragContext,
    root: ROOT,
    env,
    fetchImpl,
    execFileImpl,
    iteration: iteration + 1,
    observationBundle,
    onTurn: postTurnHandler,
    session,
    allowIntrusive: ['authorized', 'authorized_opsec'].includes(req.autonomyLevel),
    autonomyLevel: req.autonomyLevel,
  });
  if (evaluationCouncil.finalDecision?.action === 'ask_operator') {
    const question = evaluationCouncil.finalDecision.operatorQuestion
      || 'O conselho precisa de uma decisão do operador antes de continuar.';
    const approved = await session.requestApproval({
      kind: 'operator_question',
      target: req.target,
      module: 'auto_post_pipeline_planner',
      action: question,
      risk: 'nenhum módulo adicional será executado antes desta resposta',
      planHash: effectivePlan.hash,
    });
    captureEmit({ type: 'auto_operator_answered', sessionId, iteration: iteration + 1, approved, question });
    if (approved) {
      const operatorObservation = {
        ...observationBundle,
        operatorDecision: { approved: true, question },
        instruction: `${observationBundle.instruction} A resposta do operador não amplia escopo nem substitui os gates.`,
      };
      const resumedCouncil = await runAgentCouncil({
        providers: providers.providers,
        target: req.target,
        mode: req.mode,
        catalog,
        ragContext,
        root: ROOT,
        env,
        fetchImpl,
        execFileImpl,
        iteration: iteration + 1,
        observationBundle: operatorObservation,
        onTurn: postTurnHandler,
        session,
        allowIntrusive: ['authorized', 'authorized_opsec'].includes(req.autonomyLevel),
        autonomyLevel: req.autonomyLevel,
      });
      evaluationCouncil = resumedCouncil.finalDecision?.action === 'ask_operator'
        ? {
            ...resumedCouncil,
            finalDecision: {
              action: 'finish',
              objective: 'Encerrar após pergunta repetida do conselho',
              reasoningSummary: ['O conselho repetiu a pergunta após a resposta do operador.'],
              evidenceRefs: [],
              requestedModules: [],
              rejectedModules: [],
              confidence: 1,
              assumptions: [],
              operatorQuestion: null,
              forgeRequest: null,
            },
          }
        : resumedCouncil;
    } else {
      evaluationCouncil = {
        ...evaluationCouncil,
        finalDecision: {
          action: 'finish',
          objective: 'Encerrar após decisão do operador',
          reasoningSummary: ['O operador não autorizou a continuação proposta pelo conselho.'],
          evidenceRefs: [],
          requestedModules: [],
          rejectedModules: [],
          confidence: 1,
          assumptions: [],
          operatorQuestion: null,
          forgeRequest: null,
        },
      };
    }
  }
  const evaluationTurns = [...evaluationCouncil.proposals, ...evaluationCouncil.reviews].filter((turn) => turn.ok && turn.decision);
  for (const turn of evaluationTurns) {
    const memory = await writeAutoRagNote({
      root: ROOT,
      env,
      kind: 'decision',
      title: `${turn.provider} post-pipeline ${turn.role} - ${req.target}`,
      target: req.target,
      tags: ['decision', 'post-pipeline', turn.provider, turn.role, `iteration-${iteration}`],
      body: [
        `- Request run: \`${requestRunId}\``,
        `- Provider: \`${turn.provider}\``,
        `- Role: \`${turn.role}\``,
        '',
        '## Decision', '',
        `\`\`\`json\n${JSON.stringify(turn.decision, null, 2)}\n\`\`\``,
      ].join('\n'),
      metadata: { sessionId, requestRunId, provider: turn.provider, role: turn.role, iteration, usage: turn.usage || null },
    }).catch((e) => ({ error: e?.message || String(e) }));
    captureEmit({ type: 'auto_memory_written', provider: turn.provider, decision: memory?.name || null, error: memory?.error || null });
  }
  const nextDecision = evaluationCouncil.finalDecision;
  captureEmit({
    type: 'auto_council_verdict',
    phase: 'post_pipeline',
    selected: evaluationCouncil.selected,
    proposals: evaluationCouncil.proposals.filter((t) => t.ok).map((t) => t.provider),
    reviews: evaluationCouncil.reviews.filter((t) => t.ok).map((t) => t.provider),
    decision: nextDecision,
    fallback: nextDecision ? null : 'heuristic_evaluation',
  });
  let postForge = null;
  if (nextDecision?.action === 'forge_module' && nextDecision.forgeRequest) {
    const generator = providers.providers.find((p) => p.id === 'claude_code' && p.selected && p.usable)
      || providers.providers.find((p) => p.id === 'codex' && p.selected && p.usable)
      || null;
    postForge = await createPendingForgeRequest({
      root: ROOT, requestRunId, target: req.target, decision: nextDecision, council: evaluationCouncil,
      authorOverride: generator?.id || null, authorModelOverride: generator?.defaultModel || null,
    }).catch((e) => ({ error: e?.message || String(e) }));
    captureEmit({
      type: 'auto_forge_status', status: postForge?.error ? 'error' : 'proposed',
      forgeId: postForge?.forgeId || null, author: postForge?.author || null,
      error: postForge?.error || null, pipelineEnabled: false,
    });
    if (!postForge?.error && generator && !/^(0|false|no|off)$/i.test(String(env.GHOSTRECON_AUTO_FORGE_GENERATE || '1'))) {
      const generated = await generatePendingArtifact({
        provider: generator.id, request: nextDecision.forgeRequest, target: req.target,
        root: ROOT, pendingDir: postForge.dir, env, execFileImpl, signal: session.signal,
      }).catch((e) => {
        if (session.signal.aborted) throw session.signal.reason || e;
        return { ok: false, error: e?.message || String(e) };
      });
      postForge.generated = generated;
      captureEmit({
        type: 'auto_forge_status', status: generated.ok ? 'generated_pending_validation' : 'generation_failed',
        forgeId: postForge.forgeId, author: generator.id, error: generated.error || null, pipelineEnabled: false,
      });
      if (generated.ok) {
        const gates = await validateAndTestForgePackage(postForge.dir, {
          env,
          isolatedRunner: forgeSandboxRunner,
          signal: session.signal,
        }).catch((e) => {
          if (session.signal.aborted) throw session.signal.reason || e;
          return { ok: false, status: 'validation_error', error: e?.message || String(e) };
        });
        postForge.gates = gates;
        captureEmit({
          type: 'auto_forge_status', status: gates.status || (gates.ok ? 'pending_ai_code_review' : 'validation_failed'),
          forgeId: postForge.forgeId, author: generator.id, error: gates.error || null,
          validationOk: Boolean(gates.validation?.ok), testsOk: Boolean(gates.tests?.ok), pipelineEnabled: false,
        });
        if (gates.ok) {
          const codeReview = await reviewForgePackage({
            pendingDir: postForge.dir, root: ROOT, providers: providers.providers,
            env, fetchImpl, execFileImpl, signal: session.signal,
          }).catch((e) => {
            if (session.signal.aborted) throw session.signal.reason || e;
            return { approved: false, status: 'review_error', error: e?.message || String(e) };
          });
          postForge.codeReview = codeReview;
          captureEmit({
            type: 'auto_forge_status', status: codeReview.status,
            forgeId: postForge.forgeId, author: generator.id, error: codeReview.error || null,
            approvals: codeReview.approvals || 0, pipelineEnabled: false,
          });
          if (codeReview.status === 'changes_requested') {
            captureEmit({ type: 'auto_forge_status', status: 'correction_in_progress', forgeId: postForge.forgeId, author: generator.id, pipelineEnabled: false });
            const correction = await runForgeCorrectionLoop({
              pendingDir: postForge.dir, root: ROOT, provider: generator.id, target: req.target,
              providers: providers.providers, env, fetchImpl, execFileImpl,
              isolatedRunner: forgeSandboxRunner, signal: session.signal,
              initialReview: codeReview,
            }).catch((e) => {
              if (session.signal.aborted) throw session.signal.reason || e;
              return { ok: false, status: 'correction_failed', error: e?.message || String(e) };
            });
            postForge.correction = correction;
            postForge.codeReview = correction.finalReview || codeReview;
            captureEmit({
              type: 'auto_forge_status', status: correction.status, forgeId: postForge.forgeId,
              author: generator.id, attempts: correction.attempts || 0, error: correction.error || null,
              pipelineEnabled: false,
            });
          }
        }
      }
    }
    await writeAutoRagNote({
      root: ROOT,
      env,
      kind: 'decision',
      title: `Post-pipeline Module Forge - ${nextDecision.forgeRequest.proposedId}`,
      target: req.target,
      tags: ['module-forge', 'post-pipeline', postForge?.generated?.ok ? 'generated' : 'pending'],
      body: [
        `- Request run: \`${requestRunId}\``,
        `- Forge ID: \`${postForge?.forgeId || 'error'}\``,
        '- Pipeline enabled: `false`',
        '',
        '## Forge request', '',
        `\`\`\`json\n${JSON.stringify(nextDecision.forgeRequest, null, 2)}\n\`\`\``,
      ].join('\n'),
      metadata: { requestRunId, forge: publicAutoEvent({ forge: postForge }).forge },
    }).catch(() => null);
  }

  evaluation = evaluateAutoRun({ events: iterationEvents, plan: observedPlan });
  evaluation.agentDecision = nextDecision;
  evaluation.observation = {
    findings: observationBundle.findings.length,
    warnings: observationBundle.warnings.length,
    errors: observationBundle.errors.length,
  };
  evaluation.forge = publicAutoEvent({ forge: postForge }).forge;
  evaluation.engineOutcomes = engineOutcomes;
  evaluation.moduleOutcomes = moduleOutcomes;
  evaluation.effectivePlanHash = effectivePlan.hash;
  captureEmit({ type: 'auto_evaluation', evaluation });
  const evalMemory = await writeAutoDecisionMarkdown({
    root: ROOT,
    env,
    requestRunId,
    target: req.target,
    kind: 'evaluation',
    title: `Auto evaluation - ${req.target}`,
    summary: 'Modo Auto evaluation after running the GHOSTRECON pipeline.',
    plan: observedPlan,
    evaluation,
    providers,
    events,
    tags: ['evaluation', evaluation.ok ? 'ok' : 'error'],
  }).catch((e) => ({ error: e?.message || String(e) }));
  captureEmit({ type: 'auto_rag', phase: 'evaluation_saved', memory: evalMemory });
  iterationHistory.push({
    iteration,
    modules: [...effectivePlan.selectedModules],
    effectivePlanHash: effectivePlan.hash,
    engineOutcomes,
    moduleOutcomes,
    observation: evaluation.observation,
    decision: nextDecision,
  });
  captureEmit({ type: 'auto_iteration_completed', sessionId, iteration, decision: nextDecision?.action || 'finish' });
  const requestedNext = (nextDecision?.requestedModules || []).filter((id) => !executedModules.has(id));
  const wantsAnotherIteration = ['run_modules', 'continue_with_context'].includes(nextDecision?.action) && requestedNext.length > 0;
  if (wantsAnotherIteration && iteration < session.limits.maxIterations) {
    session.state.checkpoint = createAutoCheckpoint(session.state, {
      status: 'ready_for_next_iteration',
      currentIteration: iteration,
      nextIteration: iteration + 1,
      nextModules: requestedNext,
      executedModules: [...executedModules],
      iterationHistory,
      activePlan: {
        iteration: iteration + 1,
        hash: computeAutoReadyPlanHash({
          catalogHash,
          promptVersion: AUTO_PROMPT_VERSION,
          iteration: iteration + 1,
          modules: requestedNext,
          resumePolicyHash: computeAutoResumePolicyHash(resumePolicy),
        }),
        modules: requestedNext,
        stage: 'ready',
        engineOutcomes: [],
        moduleOutcomes: [],
      },
    });
    await writeAutoSessionSnapshot(ROOT, session.state, env);
    const nextClaim = await claimAutoResumeCheckpoint(ROOT, session.state, {
      env,
      principal: principal || session.state.owner || null,
    });
    session.state.resumeClaimId = nextClaim.claimId;
    captureEmit({
      type: 'auto_checkpoint_claimed',
      sessionId,
      checkpointId: session.state.checkpoint.checkpointId,
      claimId: nextClaim.claimId,
      purpose: 'next_iteration',
    });
    iteration += 1;
    iterationPlan = { ...iterationPlan, modules: requestedNext, agentDecision: nextDecision };
    continue;
  }
  session.state.checkpoint = createAutoCheckpoint(session.state, {
    status: 'completed',
    currentIteration: iteration,
    executedModules: [...executedModules],
    iterationHistory,
  });
  await writeAutoSessionSnapshot(ROOT, session.state, env);
  if (wantsAnotherIteration && iteration >= session.limits.maxIterations) {
    captureEmit({ type: 'auto_limit_reached', limit: 'maxIterations', value: session.limits.maxIterations });
  }
  break;
  }
  evaluation.iterations = iterationHistory;
  const finalSession = session.close('completed');
  await writeAutoSessionSnapshot(ROOT, finalSession, env);
  captureEmit({ type: 'auto_session', phase: 'completed', session: finalSession });
  return { sessionId, requestRunId, plan, evaluation, events };
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
    const failedSession = session.close(status);
    failedSession.error = error?.message || String(error);
    failedSession.terminationCause = cause;
    await writeAutoSessionSnapshot(ROOT, failedSession, env).catch(() => null);
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
