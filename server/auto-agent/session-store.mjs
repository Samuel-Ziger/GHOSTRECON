import fs from 'node:fs/promises';
import path from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import { hostname } from 'node:os';
import { readFileSync } from 'node:fs';
import { redactAutoText, redactAutoValue } from './redaction.mjs';
import { resolveAutoRagPartitionKey } from './rag-memory.mjs';

const SESSION_ID_RE = /^session-[a-z0-9-]{8,100}$/i;
const CHECKPOINT_ID_RE = /^checkpoint-[a-z0-9-]{8,140}$/i;
const MODULE_ID_RE = /^[a-z0-9][a-z0-9_.:-]{0,127}$/i;
const SHA256_RE = /^[a-f0-9]{64}$/i;
const CHECKPOINT_STATUSES = new Set([
  'planning',
  'ready_for_iteration',
  'iteration_in_progress',
  'ready_for_next_iteration',
  'completed',
  'failed',
]);
const RESUMABLE_CHECKPOINT_STATUSES = new Set([
  'ready_for_iteration',
  'ready_for_next_iteration',
]);
const ENGINE_OUTCOME_STATUSES = new Set([
  'done',
  'partial',
  'skipped',
  'failed',
  'timeout',
  'cancelled',
]);
const MODULE_OUTCOME_STATUSES = new Set([
  'done',
  'skipped',
  'failed',
  'timeout',
  'cancelled',
]);
const LEGACY_AUTO_CHECKPOINT_VERSION = 1;
export const AUTO_CHECKPOINT_VERSION = 2;
const AUTO_SESSION_STATUSES = new Set([
  'running',
  'completed',
  'partial',
  'cancelled',
  'failed',
  'interrupted',
  'timed_out',
  'stalled',
  'budget_exceeded',
]);

function bounded(env, key, fallback, min, max) {
  const value = Number(env?.[key] ?? fallback);
  return Math.max(min, Math.min(max, Number.isFinite(value) ? value : fallback));
}

export function autoSessionLimits(env = process.env) {
  return Object.freeze({
    maxIterations: bounded(env, 'GHOSTRECON_AUTO_MAX_ITERATIONS', 3, 1, 10),
    sessionTimeoutMs: bounded(env, 'GHOSTRECON_AUTO_SESSION_TIMEOUT_MS', 1_800_000, 30_000, 7_200_000),
    agentTimeoutMs: bounded(env, 'GHOSTRECON_AUTO_AGENT_TIMEOUT_MS', 180_000, 5_000, 900_000),
    maxAgentCalls: bounded(env, 'GHOSTRECON_AUTO_MAX_AGENT_CALLS', 12, 1, 100),
    maxContextChars: bounded(env, 'GHOSTRECON_AUTO_MAX_CONTEXT_CHARS', 120_000, 10_000, 1_000_000),
    maxCostUsd: bounded(env, 'GHOSTRECON_AUTO_MAX_COST_USD', 10, 0, 10_000),
  });
}

/** Timeouts de engines congelados na resumePolicy (não renovados no resume). */
export function autoEngineTimeouts(env = process.env) {
  return Object.freeze({
    pipelineTimeoutMs: bounded(env, 'GHOSTRECON_AUTO_PIPELINE_TIMEOUT_MS', 20 * 60_000, 30_000, 7_200_000),
    engineSettleGraceMs: bounded(env, 'GHOSTRECON_AUTO_ENGINE_SETTLE_GRACE_MS', 7_500, 500, 30_000),
    phaseSettleGraceMs: bounded(env, 'GHOSTRECON_AUTO_PHASE_SETTLE_GRACE_MS', 2_000, 100, 30_000),
    framesevenAuthTimeoutMs: bounded(env, 'GHOSTRECON_FRAMESEVEN_AUTH_TIMEOUT_MS', 10 * 60_000, 5_000, 30 * 60_000),
    framesevenBeforeScanTimeoutMs: bounded(
      env,
      'GHOSTRECON_FRAMESEVEN_BEFORE_SCAN_TIMEOUT_MS',
      30 * 60_000,
      5_000,
      60 * 60_000,
    ),
  });
}

/** Intersecta limits restaurados com o env atual (sempre o mais restritivo). */
export function intersectAutoSessionLimits(restoredLimits, envLimits) {
  const left = restoredLimits && typeof restoredLimits === 'object' ? restoredLimits : {};
  const right = envLimits && typeof envLimits === 'object' ? envLimits : autoSessionLimits();
  return Object.freeze({
    maxIterations: Math.min(
      Number(left.maxIterations) || right.maxIterations,
      right.maxIterations,
    ),
    sessionTimeoutMs: Math.min(
      Number(left.sessionTimeoutMs) || right.sessionTimeoutMs,
      right.sessionTimeoutMs,
    ),
    agentTimeoutMs: Math.min(
      Number(left.agentTimeoutMs) || right.agentTimeoutMs,
      right.agentTimeoutMs,
    ),
    maxAgentCalls: Math.min(
      Number(left.maxAgentCalls) || right.maxAgentCalls,
      right.maxAgentCalls,
    ),
    maxContextChars: Math.min(
      Number(left.maxContextChars) || right.maxContextChars,
      right.maxContextChars,
    ),
    maxCostUsd: Math.min(
      Number(left.maxCostUsd) || right.maxCostUsd,
      right.maxCostUsd,
    ),
  });
}

function normalizeOwner(principal) {
  const sub = String(principal?.sub || '').trim();
  if (!sub) return null;
  return {
    sub,
    role: String(principal?.role || '').trim() || null,
    via: String(principal?.via || '').trim() || null,
  };
}

function assertSnapshot(condition, message) {
  if (!condition) throw new Error(`snapshot de sessão AUTO inválido: ${message}`);
}

function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(
    Object.keys(value)
      .sort()
      .map((key) => [key, stableValue(value[key])]),
  );
}

function sha256Stable(value) {
  return createHash('sha256')
    .update(JSON.stringify(stableValue(value)))
    .digest('hex');
}

export function computeAutoResumePolicyHash(resumePolicy) {
  return sha256Stable(resumePolicy && typeof resumePolicy === 'object' ? resumePolicy : null);
}

export function computeAutoReadyPlanHash({
  catalogHash,
  promptVersion,
  iteration,
  modules,
  resumePolicyHash,
}) {
  return sha256Stable({
    catalogHash: String(catalogHash || ''),
    promptVersion: String(promptVersion || ''),
    iteration: Number(iteration),
    modules: Array.isArray(modules) ? modules.map(String) : [],
    resumePolicyHash: String(resumePolicyHash || ''),
  });
}

function checkpointHashPayload(checkpoint) {
  const { checkpointHash: _checkpointHash, ...payload } = checkpoint || {};
  return payload;
}

export function computeAutoCheckpointHash(checkpoint) {
  return sha256Stable(checkpointHashPayload(checkpoint));
}

function sameStringArray(left, right) {
  return Array.isArray(left)
    && Array.isArray(right)
    && left.length === right.length
    && left.every((value, index) => String(value) === String(right[index]));
}

function assertModuleIds(values, field, { allowEmpty = true } = {}) {
  assertSnapshot(Array.isArray(values), field);
  assertSnapshot(allowEmpty || values.length > 0, `${field} vazio`);
  assertSnapshot(values.length <= 500, `${field} excede o limite`);
  assertSnapshot(values.every((value) => MODULE_ID_RE.test(String(value || ''))), `${field} contém ID inválido`);
  assertSnapshot(new Set(values).size === values.length, `${field} contém IDs duplicados`);
}

export function validateAutoCheckpoint(checkpoint, {
  session = null,
  maxIterations = 10,
  expectedCatalogHash = null,
  expectedPromptVersion = null,
  requireResumable = false,
} = {}) {
  assertSnapshot(checkpoint && typeof checkpoint === 'object' && !Array.isArray(checkpoint), 'checkpoint');
  assertSnapshot(
    [LEGACY_AUTO_CHECKPOINT_VERSION, AUTO_CHECKPOINT_VERSION].includes(checkpoint.checkpointVersion),
    'checkpointVersion não suportada',
  );
  const semanticCheckpoint = checkpoint.checkpointVersion === AUTO_CHECKPOINT_VERSION;
  assertSnapshot(CHECKPOINT_ID_RE.test(String(checkpoint.checkpointId || '')), 'checkpoint.checkpointId');
  assertSnapshot(
    Number.isInteger(checkpoint.sequence) && checkpoint.sequence >= 1 && checkpoint.sequence <= 100_000,
    'checkpoint.sequence',
  );
  assertSnapshot(CHECKPOINT_STATUSES.has(String(checkpoint.status || '')), 'checkpoint.status');
  assertSnapshot(SESSION_ID_RE.test(String(checkpoint.sessionId || '')), 'checkpoint.sessionId');
  assertSnapshot(
    typeof checkpoint.requestRunId === 'string' && checkpoint.requestRunId.trim(),
    'checkpoint.requestRunId',
  );
  assertSnapshot(typeof checkpoint.target === 'string' && checkpoint.target.trim(), 'checkpoint.target');
  assertSnapshot(SHA256_RE.test(String(checkpoint.catalogHash || '')), 'checkpoint.catalogHash');
  if (semanticCheckpoint) {
    assertSnapshot(
      SHA256_RE.test(String(checkpoint.resumePolicyHash || '')),
      'checkpoint.resumePolicyHash',
    );
  }
  assertSnapshot(
    typeof checkpoint.promptVersion === 'string'
      && checkpoint.promptVersion.trim()
      && checkpoint.promptVersion.length <= 200,
    'checkpoint.promptVersion',
  );
  assertSnapshot(Number.isFinite(Date.parse(checkpoint.updatedAt)), 'checkpoint.updatedAt');
  assertSnapshot(SHA256_RE.test(String(checkpoint.checkpointHash || '')), 'checkpoint.checkpointHash');
  assertSnapshot(
    checkpoint.previousCheckpointHash == null
      || SHA256_RE.test(String(checkpoint.previousCheckpointHash)),
    'checkpoint.previousCheckpointHash',
  );
  assertSnapshot(
    checkpoint.checkpointHash === computeAutoCheckpointHash(checkpoint),
    'checkpointHash não corresponde ao conteúdo',
  );

  const boundedMaxIterations = Math.max(1, Math.min(10, Number(maxIterations) || 10));
  assertSnapshot(
    Number.isInteger(checkpoint.currentIteration)
      && checkpoint.currentIteration >= 0
      && checkpoint.currentIteration <= boundedMaxIterations,
    'checkpoint.currentIteration',
  );
  assertSnapshot(
    checkpoint.nextIteration == null
      || (
        Number.isInteger(checkpoint.nextIteration)
        && checkpoint.nextIteration >= 1
        && checkpoint.nextIteration <= boundedMaxIterations
      ),
    'checkpoint.nextIteration',
  );
  assertModuleIds(checkpoint.nextModules, 'checkpoint.nextModules');
  assertModuleIds(checkpoint.executedModules, 'checkpoint.executedModules');
  assertSnapshot(
    Array.isArray(checkpoint.iterationHistory)
      && checkpoint.iterationHistory.length <= boundedMaxIterations,
    'checkpoint.iterationHistory',
  );
  const seenIterations = new Set();
  for (const [historyIndex, row] of checkpoint.iterationHistory.entries()) {
    assertSnapshot(row && typeof row === 'object' && !Array.isArray(row), 'checkpoint.iterationHistory item');
    assertSnapshot(
      Number.isInteger(row.iteration)
        && row.iteration >= 1
        && row.iteration <= boundedMaxIterations
        && !seenIterations.has(row.iteration),
      'checkpoint.iterationHistory.iteration',
    );
    seenIterations.add(row.iteration);
    assertSnapshot(
      row.iteration === historyIndex + 1
        && row.iteration <= checkpoint.currentIteration,
      'checkpoint.iterationHistory fora de sequência',
    );
    assertModuleIds(row.modules || [], 'checkpoint.iterationHistory.modules');
    assertSnapshot(
      SHA256_RE.test(String(row.effectivePlanHash || '')),
      'checkpoint.iterationHistory.effectivePlanHash',
    );
  }

  if (checkpoint.activePlan != null) {
    const active = checkpoint.activePlan;
    assertSnapshot(active && typeof active === 'object' && !Array.isArray(active), 'checkpoint.activePlan');
    assertSnapshot(
      Number.isInteger(active.iteration)
        && active.iteration >= 1
        && active.iteration <= boundedMaxIterations,
      'checkpoint.activePlan.iteration',
    );
    assertSnapshot(SHA256_RE.test(String(active.hash || '')), 'checkpoint.activePlan.hash');
    assertModuleIds(active.modules, 'checkpoint.activePlan.modules', { allowEmpty: false });
    assertSnapshot(
      ['ready', 'running', 'evaluating'].includes(String(active.stage || '')),
      'checkpoint.activePlan.stage',
    );
    assertSnapshot(Array.isArray(active.engineOutcomes), 'checkpoint.activePlan.engineOutcomes');
    assertSnapshot(Array.isArray(active.moduleOutcomes), 'checkpoint.activePlan.moduleOutcomes');
    assertSnapshot(active.engineOutcomes.length <= 20, 'checkpoint.activePlan.engineOutcomes excede o limite');
    assertSnapshot(active.moduleOutcomes.length <= 500, 'checkpoint.activePlan.moduleOutcomes excede o limite');
    for (const outcome of active.engineOutcomes) {
      assertSnapshot(
        outcome && typeof outcome === 'object' && !Array.isArray(outcome),
        'checkpoint.activePlan.engineOutcomes item',
      );
      assertSnapshot(
        typeof outcome.engine === 'string' && MODULE_ID_RE.test(outcome.engine),
        'checkpoint.activePlan.engineOutcomes.engine',
      );
      assertSnapshot(
        ENGINE_OUTCOME_STATUSES.has(String(outcome.status || '')),
        'checkpoint.activePlan.engineOutcomes.status',
      );
    }
    for (const outcome of active.moduleOutcomes) {
      assertSnapshot(
        outcome && typeof outcome === 'object' && !Array.isArray(outcome),
        'checkpoint.activePlan.moduleOutcomes item',
      );
      assertSnapshot(
        MODULE_ID_RE.test(String(outcome.moduleId || '')),
        'checkpoint.activePlan.moduleOutcomes.moduleId',
      );
      assertSnapshot(
        MODULE_OUTCOME_STATUSES.has(String(outcome.status || '')),
        'checkpoint.activePlan.moduleOutcomes.status',
      );
    }
    if (semanticCheckpoint && active.stage === 'ready') {
      assertSnapshot(
        active.hash === computeAutoReadyPlanHash({
          catalogHash: checkpoint.catalogHash,
          promptVersion: checkpoint.promptVersion,
          iteration: active.iteration,
          modules: active.modules,
          resumePolicyHash: checkpoint.resumePolicyHash,
        }),
        'checkpoint.activePlan.hash semântico divergente',
      );
    }
  }

  if (checkpoint.status === 'planning') {
    assertSnapshot(checkpoint.currentIteration === 0, 'checkpoint planning com iteração iniciada');
    assertSnapshot(checkpoint.nextIteration == null, 'checkpoint planning com nextIteration');
    assertSnapshot(checkpoint.nextModules.length === 0, 'checkpoint planning com nextModules');
    assertSnapshot(checkpoint.activePlan == null, 'checkpoint planning com activePlan');
  }
  if (['ready_for_iteration', 'ready_for_next_iteration'].includes(checkpoint.status)) {
    assertSnapshot(checkpoint.nextIteration != null, 'checkpoint retomável sem nextIteration');
    assertModuleIds(checkpoint.nextModules, 'checkpoint.nextModules', { allowEmpty: false });
    assertSnapshot(
      checkpoint.activePlan?.stage === 'ready'
        && checkpoint.activePlan.iteration === checkpoint.nextIteration,
      'checkpoint retomável sem activePlan pronto',
    );
    assertSnapshot(
      sameStringArray(checkpoint.nextModules, checkpoint.activePlan.modules),
      'checkpoint.nextModules divergente de activePlan.modules',
    );
    assertSnapshot(
      checkpoint.status !== 'ready_for_next_iteration'
        || checkpoint.nextIteration === checkpoint.currentIteration + 1,
      'checkpoint ready_for_next_iteration fora de sequência',
    );
    assertSnapshot(
      checkpoint.status !== 'ready_for_iteration'
        || (
          checkpoint.currentIteration === 0
          && checkpoint.nextIteration === 1
          && checkpoint.iterationHistory.length === 0
        ),
      'checkpoint ready_for_iteration fora de sequência',
    );
    assertSnapshot(
      checkpoint.status !== 'ready_for_next_iteration'
        || checkpoint.iterationHistory.length === checkpoint.currentIteration,
      'checkpoint ready_for_next_iteration sem histórico completo',
    );
  }
  if (checkpoint.status === 'iteration_in_progress') {
    assertSnapshot(
      checkpoint.activePlan
        && checkpoint.activePlan.iteration === checkpoint.currentIteration
        && ['running', 'evaluating'].includes(checkpoint.activePlan.stage),
      'checkpoint em execução sem activePlan',
    );
  }
  if (checkpoint.status === 'completed') {
    assertSnapshot(checkpoint.nextIteration == null, 'checkpoint concluído com nextIteration');
    assertSnapshot(checkpoint.nextModules.length === 0, 'checkpoint concluído com nextModules');
    assertSnapshot(
      checkpoint.iterationHistory.length === checkpoint.currentIteration,
      'checkpoint concluído sem histórico completo',
    );
  }

  if (session) {
    assertSnapshot(checkpoint.sessionId === session.sessionId, 'checkpoint vinculado a outra sessão');
    assertSnapshot(checkpoint.requestRunId === session.requestRunId, 'checkpoint vinculado a outro requestRunId');
    assertSnapshot(checkpoint.target === session.target, 'checkpoint vinculado a outro alvo');
    assertSnapshot(checkpoint.catalogHash === session.catalogHash, 'checkpoint catalogHash divergente');
    assertSnapshot(checkpoint.promptVersion === session.promptVersion, 'checkpoint promptVersion divergente');
    if (semanticCheckpoint) {
      const expectedResumePolicyHash = computeAutoResumePolicyHash(session.resumePolicy);
      assertSnapshot(
        checkpoint.resumePolicyHash === expectedResumePolicyHash,
        'checkpoint resumePolicy divergente da sessão',
      );
    }
    assertSnapshot(
      Number(session.iteration) === checkpoint.currentIteration,
      'checkpoint.currentIteration divergente da sessão',
    );
  }
  if (expectedCatalogHash) {
    assertSnapshot(checkpoint.catalogHash === expectedCatalogHash, 'checkpoint catalogHash incompatível');
  }
  if (expectedPromptVersion) {
    assertSnapshot(checkpoint.promptVersion === expectedPromptVersion, 'checkpoint promptVersion incompatível');
  }
  if (requireResumable) {
    assertSnapshot(
      semanticCheckpoint,
      'checkpoint legado não é retomável; gere um novo checkpoint pronto',
    );
    assertSnapshot(
      RESUMABLE_CHECKPOINT_STATUSES.has(checkpoint.status),
      checkpoint.status === 'iteration_in_progress'
        ? 'checkpoint indica execução interrompida; retomada recusada para impedir replay'
        : `checkpoint ${checkpoint.status} não é retomável`,
    );
  }
  return checkpoint;
}

export function createAutoCheckpoint(sessionState, {
  status,
  currentIteration = Number(sessionState?.iteration || 0),
  nextIteration = null,
  nextModules = [],
  executedModules = [],
  iterationHistory = [],
  activePlan = null,
  now = Date.now(),
} = {}) {
  assertSnapshot(
    sessionState?.catalogHash && sessionState?.promptVersion && sessionState?.resumePolicy,
    'checkpoint exige catalogHash, promptVersion e resumePolicy',
  );
  const previous = sessionState?.checkpoint || null;
  const sequence = Number(previous?.sequence || 0) + 1;
  const rawCheckpoint = {
    checkpointVersion: AUTO_CHECKPOINT_VERSION,
    checkpointId: `checkpoint-${String(sessionState.sessionId || 'session').replace(/^session-/, '').slice(0, 80)}-${sequence}`,
    sequence,
    status,
    sessionId: sessionState.sessionId,
    requestRunId: sessionState.requestRunId,
    target: sessionState.target,
    catalogHash: sessionState.catalogHash,
    resumePolicyHash: computeAutoResumePolicyHash(sessionState.resumePolicy),
    promptVersion: sessionState.promptVersion,
    currentIteration,
    nextIteration,
    nextModules: [...new Set((nextModules || []).map(String))],
    executedModules: [...new Set((executedModules || []).map(String))],
    iterationHistory: Array.isArray(iterationHistory) ? iterationHistory : [],
    activePlan: activePlan == null ? null : activePlan,
    previousCheckpointHash: previous?.checkpointHash || null,
    updatedAt: new Date(now).toISOString(),
  };
  // Faça uma cópia redigida antes de calcular o hash. Isso impede que mutações
  // posteriores em iterationHistory/outcomes alterem silenciosamente um
  // checkpoint já persistido e mantém a redação idempotente no snapshot.
  const checkpoint = redactAutoValue(rawCheckpoint, {
    preserveSensitiveKeys: new Set(['sessionId']),
  });
  checkpoint.checkpointHash = computeAutoCheckpointHash(checkpoint);
  validateAutoCheckpoint(checkpoint, {
    session: sessionState,
    maxIterations: sessionState?.limits?.maxIterations,
  });
  return checkpoint;
}

export function assertAutoResumeSnapshotCompatible(snapshot, {
  expectedCatalogHash = null,
  expectedPromptVersion,
  maxIterations = snapshot?.limits?.maxIterations,
} = {}) {
  assertSnapshot(snapshot && typeof snapshot === 'object', 'snapshot de retomada ausente');
  assertSnapshot(SHA256_RE.test(String(snapshot.catalogHash || '')), 'catalogHash ausente/inválido');
  assertSnapshot(
    typeof snapshot.promptVersion === 'string' && snapshot.promptVersion.trim(),
    'promptVersion ausente/inválida',
  );
  if (expectedPromptVersion) {
    assertSnapshot(snapshot.promptVersion === expectedPromptVersion, 'promptVersion incompatível');
  }
  if (expectedCatalogHash) {
    assertSnapshot(snapshot.catalogHash === expectedCatalogHash, 'catalogHash incompatível');
  }
  validateAutoCheckpoint(snapshot.checkpoint, {
    session: snapshot,
    maxIterations,
    expectedCatalogHash: expectedCatalogHash || snapshot.catalogHash,
    expectedPromptVersion: snapshot.promptVersion,
    requireResumable: true,
  });
  return snapshot;
}

function recordApprovalTransition(state, {
  approvalId,
  from,
  to,
  reason = '',
  at = new Date().toISOString(),
} = {}) {
  if (!state || typeof state !== 'object') return;
  if (!Array.isArray(state.approvalTransitions)) state.approvalTransitions = [];
  state.approvalTransitions.push({
    approvalId: String(approvalId || ''),
    from: String(from || ''),
    to: String(to || ''),
    reason: redactAutoText(String(reason || '')).slice(0, 500),
    at: String(at || new Date().toISOString()),
  });
  if (state.approvalTransitions.length > 40) {
    state.approvalTransitions = state.approvalTransitions.slice(-40);
  }
}

function expireOrphanedApproval(state, {
  now = Date.now(),
  reason = 'approval_restored_without_live_resolver',
} = {}) {
  if (state?.pendingApproval?.status !== 'pending') return false;
  const previousStatus = state.pendingApproval.status;
  state.pendingApproval = {
    ...state.pendingApproval,
    status: 'expired',
    reason: redactAutoText(String(reason)).slice(0, 500),
    resolvedAt: new Date(now).toISOString(),
  };
  recordApprovalTransition(state, {
    approvalId: state.pendingApproval.approvalId,
    from: previousStatus,
    to: 'expired',
    reason,
    at: state.pendingApproval.resolvedAt,
  });
  return true;
}

export function validateAutoSessionSnapshot(snapshot, expectedSessionId = null) {
  assertSnapshot(snapshot && typeof snapshot === 'object' && !Array.isArray(snapshot), 'objeto esperado');
  assertSnapshot(snapshot.schemaVersion === 1, 'schemaVersion não suportada');
  assertSnapshot(SESSION_ID_RE.test(String(snapshot.sessionId || '')), 'sessionId');
  if (expectedSessionId) assertSnapshot(snapshot.sessionId === expectedSessionId, 'sessionId não corresponde ao arquivo');
  assertSnapshot(typeof snapshot.requestRunId === 'string' && snapshot.requestRunId.trim(), 'requestRunId');
  assertSnapshot(typeof snapshot.target === 'string' && snapshot.target.trim(), 'target');
  assertSnapshot(AUTO_SESSION_STATUSES.has(String(snapshot.status || '')), 'status');
  assertSnapshot(Number.isFinite(Date.parse(snapshot.startedAt)), 'startedAt');
  assertSnapshot(Number.isInteger(Number(snapshot.iteration)) && Number(snapshot.iteration) >= 0, 'iteration');
  assertSnapshot(snapshot.limits && typeof snapshot.limits === 'object' && !Array.isArray(snapshot.limits), 'limits');
  if (snapshot.owner != null) assertSnapshot(Boolean(normalizeOwner(snapshot.owner)), 'owner');
  if (snapshot.runtimeLease != null) {
    assertSnapshot(
      snapshot.runtimeLease
        && typeof snapshot.runtimeLease === 'object'
        && snapshot.runtimeLease.schemaVersion === 1
        && Number.isInteger(snapshot.runtimeLease.pid)
        && snapshot.runtimeLease.pid > 0
        && typeof snapshot.runtimeLease.hostname === 'string'
        && snapshot.runtimeLease.hostname.trim()
        && Number.isFinite(Date.parse(snapshot.runtimeLease.acquiredAt)),
      'runtimeLease',
    );
    if (snapshot.runtimeLease.releasedAt != null) {
      assertSnapshot(Number.isFinite(Date.parse(snapshot.runtimeLease.releasedAt)), 'runtimeLease.releasedAt');
    }
  }
  if (snapshot.pendingApproval != null) {
    assertSnapshot(
      snapshot.pendingApproval && typeof snapshot.pendingApproval === 'object'
        && typeof snapshot.pendingApproval.approvalId === 'string',
      'pendingApproval',
    );
  }
  if (snapshot.approvalTransitions != null) {
    assertSnapshot(Array.isArray(snapshot.approvalTransitions), 'approvalTransitions');
    assertSnapshot(snapshot.approvalTransitions.length <= 40, 'approvalTransitions excede o limite');
    for (const row of snapshot.approvalTransitions) {
      assertSnapshot(row && typeof row === 'object' && !Array.isArray(row), 'approvalTransitions item');
      assertSnapshot(typeof row.approvalId === 'string', 'approvalTransitions.approvalId');
      assertSnapshot(typeof row.to === 'string' && row.to.trim(), 'approvalTransitions.to');
    }
  }
  if (snapshot.checkpoint != null) {
    assertSnapshot(snapshot.checkpoint && typeof snapshot.checkpoint === 'object' && !Array.isArray(snapshot.checkpoint), 'checkpoint');
    if (snapshot.checkpoint.checkpointVersion != null) {
      validateAutoCheckpoint(snapshot.checkpoint, {
        session: snapshot,
        maxIterations: snapshot.limits.maxIterations,
      });
    } else {
      // Snapshots históricos continuam legíveis para inspeção/cancelamento,
      // porém não passam no protocolo estrito de retomada.
      if (snapshot.checkpoint.nextModules != null) assertSnapshot(Array.isArray(snapshot.checkpoint.nextModules), 'checkpoint.nextModules');
      if (snapshot.checkpoint.executedModules != null) assertSnapshot(Array.isArray(snapshot.checkpoint.executedModules), 'checkpoint.executedModules');
      if (snapshot.checkpoint.iterationHistory != null) assertSnapshot(Array.isArray(snapshot.checkpoint.iterationHistory), 'checkpoint.iterationHistory');
    }
  }
  if (snapshot.resumePolicy != null) {
    assertSnapshot(
      snapshot.resumePolicy
        && typeof snapshot.resumePolicy === 'object'
        && !Array.isArray(snapshot.resumePolicy)
        && snapshot.resumePolicy.schemaVersion === 1,
      'resumePolicy',
    );
  }
  return snapshot;
}

async function writeJsonAtomic(file, value) {
  const temp = path.join(
    path.dirname(file),
    `.${path.basename(file)}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`,
  );
  let handle = null;
  let directoryHandle = null;
  try {
    handle = await fs.open(temp, 'wx', 0o600);
    await handle.writeFile(JSON.stringify(value, null, 2), 'utf8');
    await handle.sync();
    await handle.close();
    handle = null;
    await fs.rename(temp, file);
    await fs.chmod(file, 0o600);
    // O rename é atômico; o fsync do diretório torna a troca durável frente a
    // queda do processo/host depois que o checkpoint foi anunciado.
    // Em Windows, fsync de diretório costuma falhar com EPERM/EINVAL — o
    // rename já garante a troca atômica; ignore só esses códigos de plataforma.
    try {
      directoryHandle = await fs.open(path.dirname(file), 'r');
      await directoryHandle.sync();
      await directoryHandle.close();
      directoryHandle = null;
    } catch (error) {
      if (directoryHandle) {
        await directoryHandle.close().catch(() => {});
        directoryHandle = null;
      }
      if (!['EPERM', 'EINVAL', 'EBADF', 'ENOTSUP'].includes(String(error?.code || ''))) {
        throw error;
      }
    }
  } finally {
    if (handle) await handle.close().catch(() => {});
    if (directoryHandle) await directoryHandle.close().catch(() => {});
    await fs.rm(temp, { force: true }).catch(() => {});
  }
}

function resolveAutoRagRoot(root, env = process.env) {
  const configured = String(env.GHOSTRECON_AUTO_RAG_DIR || '').trim();
  return configured ? path.resolve(configured) : path.join(root, 'data', 'auto-rag');
}

function sessionPartitionEnabled(env = process.env) {
  return !/^(0|false|no|off)$/i.test(String(env.GHOSTRECON_AUTO_SESSION_PARTITION ?? '1'));
}

function ownerSub(owner) {
  return String(normalizeOwner(owner)?.sub || '').trim();
}

/** Diretório do snapshot: tenants/…/sessions/{id} quando há owner; legado sessions/{id}. */
export function resolveAutoSessionSnapshotDir(root, {
  sessionId,
  owner = null,
  engagementId = '',
  target = '',
  env = process.env,
} = {}) {
  const ragRoot = resolveAutoRagRoot(root, env);
  const safeId = String(sessionId || '').trim();
  const legacy = path.join(ragRoot, 'sessions', safeId);
  const principalId = ownerSub(owner);
  if (!sessionPartitionEnabled(env) || !principalId || !SESSION_ID_RE.test(safeId)) {
    return legacy;
  }
  const part = resolveAutoRagPartitionKey({
    principalId,
    engagementId: String(engagementId || ''),
    target: String(target || ''),
  });
  return path.join(ragRoot, 'tenants', part, 'sessions', safeId);
}

async function listSessionSnapshotDirs(ragRoot) {
  const dirs = [];
  const legacyRoot = path.join(ragRoot, 'sessions');
  for (const entry of await fs.readdir(legacyRoot, { withFileTypes: true }).catch(() => [])) {
    if (entry.isDirectory()) dirs.push(path.join(legacyRoot, entry.name));
  }
  const tenantsRoot = path.join(ragRoot, 'tenants');
  const stack = [tenantsRoot];
  while (stack.length) {
    const current = stack.pop();
    const entries = await fs.readdir(current, { withFileTypes: true }).catch(() => []);
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      const full = path.join(current, entry.name);
      if (entry.name === 'sessions') {
        for (const sessionEntry of await fs.readdir(full, { withFileTypes: true }).catch(() => [])) {
          if (sessionEntry.isDirectory()) dirs.push(path.join(full, sessionEntry.name));
        }
      } else {
        stack.push(full);
      }
    }
  }
  return dirs;
}

async function loadSessionSnapshotFile(file, expectedSessionId = null, env = process.env) {
  const stat = await fs.stat(file);
  const maxBytes = bounded(env, 'GHOSTRECON_AUTO_SESSION_SNAPSHOT_MAX_BYTES', 5_000_000, 10_000, 50_000_000);
  if (stat.size > maxBytes) throw new Error(`snapshot de sessão AUTO excede ${maxBytes} bytes`);
  let snapshot;
  try {
    snapshot = JSON.parse(await fs.readFile(file, 'utf8'));
  } catch (error) {
    throw new Error(`snapshot de sessão AUTO inválido: ${error?.message || error}`);
  }
  return validateAutoSessionSnapshot(snapshot, expectedSessionId || snapshot?.sessionId);
}

function autoResumeClaimError(message, code = 'AUTO_RESUME_CHECKPOINT_CLAIM_FAILED') {
  const error = new Error(message);
  error.code = code;
  return error;
}

/**
 * Consome de forma permanente um checkpoint pronto antes que qualquer provider
 * ou engine volte a executar. O arquivo `wx` funciona como CAS entre processos
 * e como watermark anti-rollback: restaurar um session.json antigo não remove
 * o claim já durável.
 */
export async function claimAutoResumeCheckpoint(root, snapshot, {
  env = process.env,
  principal = null,
  now = Date.now(),
} = {}) {
  assertAutoResumeSnapshotCompatible(snapshot);
  const checkpoint = snapshot.checkpoint;
  const sessionDir = resolveAutoSessionSnapshotDir(root, {
    sessionId: snapshot.sessionId,
    owner: principal || snapshot.owner,
    engagementId: snapshot.engagementId || snapshot.resumePolicy?.engagementId || '',
    target: snapshot.target || '',
    env,
  });
  const claimsDir = path.join(sessionDir, 'resume-claims');
  await fs.mkdir(claimsDir, { recursive: true, mode: 0o700 });
  await fs.chmod(claimsDir, 0o700);
  const claimFile = path.join(claimsDir, `${checkpoint.checkpointHash}.json`);
  const owner = normalizeOwner(principal) || normalizeOwner(snapshot.owner);
  const claim = redactAutoValue({
    schemaVersion: 1,
    claimId: `resume-claim-${randomBytes(16).toString('hex')}`,
    sessionId: snapshot.sessionId,
    requestRunId: snapshot.requestRunId,
    checkpointId: checkpoint.checkpointId,
    checkpointHash: checkpoint.checkpointHash,
    checkpointSequence: checkpoint.sequence,
    target: snapshot.target,
    owner,
    claimedAt: new Date(now).toISOString(),
    runtime: createAutoRuntimeLease(now),
  }, {
    preserveSensitiveKeys: new Set(['sessionId']),
  });

  let handle = null;
  let directoryHandle = null;
  try {
    handle = await fs.open(claimFile, 'wx', 0o600);
    await handle.writeFile(JSON.stringify(claim, null, 2), 'utf8');
    await handle.sync();
    await handle.close();
    handle = null;
    try {
      directoryHandle = await fs.open(claimsDir, 'r');
      await directoryHandle.sync();
      await directoryHandle.close();
      directoryHandle = null;
    } catch (syncError) {
      if (directoryHandle) {
        await directoryHandle.close().catch(() => {});
        directoryHandle = null;
      }
      if (!['EPERM', 'EINVAL', 'EBADF', 'ENOTSUP'].includes(String(syncError?.code || ''))) {
        throw syncError;
      }
    }
    return Object.freeze({ ...claim, file: claimFile });
  } catch (error) {
    if (error?.code === 'EEXIST') {
      throw autoResumeClaimError(
        'checkpoint de retomada já foi consumido; replay recusado',
        'AUTO_RESUME_CHECKPOINT_ALREADY_CLAIMED',
      );
    }
    throw error;
  } finally {
    if (handle) await handle.close().catch(() => {});
    if (directoryHandle) await directoryHandle.close().catch(() => {});
  }
}

export async function readAutoResumeCheckpointClaim(root, sessionId, checkpointHash, env = process.env, {
  owner = null,
  engagementId = '',
  target = '',
} = {}) {
  const safeSessionId = String(sessionId || '').trim();
  const safeHash = String(checkpointHash || '').trim().toLowerCase();
  if (!SESSION_ID_RE.test(safeSessionId)) throw new Error('sessionId inválido');
  if (!SHA256_RE.test(safeHash)) throw new Error('checkpointHash inválido');
  const sessionDir = resolveAutoSessionSnapshotDir(root, {
    sessionId: safeSessionId,
    owner,
    engagementId,
    target,
    env,
  });
  const candidates = [
    path.join(sessionDir, 'resume-claims', `${safeHash}.json`),
    path.join(resolveAutoRagRoot(root, env), 'sessions', safeSessionId, 'resume-claims', `${safeHash}.json`),
  ];
  let file = candidates[0];
  for (const candidate of [...new Set(candidates)]) {
    try {
      await fs.stat(candidate);
      file = candidate;
      break;
    } catch {
      // try next
    }
  }
  return JSON.parse(await fs.readFile(file, 'utf8'));
}

function runtimeProcessStartToken(pid = process.pid) {
  if (process.platform !== 'linux') return null;
  try {
    const raw = readFileSync(`/proc/${pid}/stat`, 'utf8');
    const closeParen = raw.lastIndexOf(')');
    if (closeParen < 0) return null;
    // Depois de comm, o primeiro campo é state (campo 3); starttime é o 22.
    return raw.slice(closeParen + 1).trim().split(/\s+/)[19] || null;
  } catch {
    return null;
  }
}

export function createAutoRuntimeLease(now = Date.now()) {
  return Object.freeze({
    schemaVersion: 1,
    pid: process.pid,
    hostname: hostname(),
    // "token" é reservado pelo redator para credenciais; startTicks é apenas
    // o campo 22 de /proc/<pid>/stat usado contra reutilização de PID.
    processStartTicks: runtimeProcessStartToken(process.pid),
    acquiredAt: new Date(now).toISOString(),
  });
}

export async function isAutoRuntimeLeaseLive(runtimeLease) {
  if (
    !runtimeLease
    || runtimeLease.schemaVersion !== 1
    || !Number.isInteger(runtimeLease.pid)
    || runtimeLease.pid <= 0
    || runtimeLease.hostname !== hostname()
    || runtimeLease.releasedAt
  ) return false;
  try {
    process.kill(runtimeLease.pid, 0);
  } catch (error) {
    if (error?.code !== 'EPERM') return false;
  }
  const expectedStart = String(runtimeLease.processStartTicks || runtimeLease.processStartToken || '');
  if (!expectedStart) return true;
  return runtimeProcessStartToken(runtimeLease.pid) === expectedStart;
}

export function createAutoSession({
  sessionId,
  requestRunId,
  target,
  providers = [],
  ownerPrincipal = null,
  env = process.env,
  restoredState = null,
} = {}) {
  const envLimits = autoSessionLimits(env);
  const limits = restoredState?.limits
    ? intersectAutoSessionLimits(restoredState.limits, envLimits)
    : envLimits;
  const controller = new AbortController();
  const nowMs = Date.now();
  const requestedOwner = normalizeOwner(ownerPrincipal);
  const restoredOwner = normalizeOwner(restoredState?.owner);
  if (requestedOwner && restoredOwner && requestedOwner.sub !== restoredOwner.sub) {
    throw new Error('sessão AUTO pertence a outro principal');
  }
  const restoredStartedMs = Date.parse(String(restoredState?.startedAt || ''));
  const startedAtMs = Number.isFinite(restoredStartedMs) ? restoredStartedMs : nowMs;
  const restoredDeadlineMs = Date.parse(String(restoredState?.deadlineAt || ''));
  const deadlineAt = Number.isFinite(restoredDeadlineMs)
    ? new Date(restoredDeadlineMs).toISOString()
    : new Date(nowMs + limits.sessionTimeoutMs).toISOString();
  const remainingMs = Math.max(1_000, Date.parse(deadlineAt) - nowMs);
  const state = {
    schemaVersion: 1, sessionId, requestRunId, target, startedAt: new Date(startedAtMs).toISOString(),
    status: 'running', iteration: 0, agentCalls: 0, usage: {}, costUsd: 0,
    lastActivityAt: new Date(nowMs).toISOString(), currentStage: 'starting', currentModule: null,
    providers: providers.map((p) => typeof p === 'string' ? p : p?.id).filter(Boolean),
    owner: requestedOwner,
    limits,
    deadlineAt,
    ...(restoredState || {}),
    // Identidade/status/deadline/limits congelados; counters (agentCalls/costUsd/usage/iteration)
    // vêm do spread de restoredState e não são zerados aqui.
    sessionId, requestRunId, target, status: 'running', limits, deadlineAt,
    budgetVerifiable: restoredState?.budgetVerifiable !== false,
    startedAt: Number.isFinite(restoredStartedMs)
      ? new Date(restoredStartedMs).toISOString()
      : (restoredState?.startedAt || new Date(startedAtMs).toISOString()),
    runtimeLease: createAutoRuntimeLease(nowMs),
  };
  state.owner = requestedOwner || restoredOwner || null;
  state.deadlineAt = deadlineAt;
  state.limits = limits;
  // Runtime-only: não vai ao snapshot. Turnos concorrentes não podem mascarar stall.
  const activeAgentTurns = new Map();
  const agentTurnKey = (event) => `${event?.provider || 'unknown'}:${event?.role || 'turn'}`;
  const oldestAgentTurnMs = () => (activeAgentTurns.size
    ? Math.min(...activeAgentTurns.values())
    : null);
  if (restoredState) {
    expireOrphanedApproval(state, {
      now: nowMs,
      reason: 'approval_expired_during_session_restore',
    });
  }
  const timer = setTimeout(
    () => controller.abort(new Error('auto_session_timeout')),
    remainingMs,
  );
  timer.unref?.();
  return {
    state,
    limits,
    signal: controller.signal,
    abort(reason = 'cancelled') { controller.abort(new Error(String(reason))); },
    requestApproval(details = {}, timeoutMs = 120_000) {
      if (controller.signal.aborted) return Promise.reject(controller.signal.reason || new Error('sessão AUTO cancelada'));
      if (state.pendingApproval?.status === 'pending') {
        return Promise.reject(new Error('sessão AUTO já possui aprovação humana pendente'));
      }
      const approvalId = `approval-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
      const intrusive = details?.intrusive === true
        || details?.requiredScope === 'recon.intrusive';
      state.pendingApproval = {
        ...redactAutoValue(details && typeof details === 'object' ? details : {}),
        approvalId,
        intrusive,
        requestedAt: new Date().toISOString(),
        status: 'pending',
      };
      return new Promise((resolve, reject) => {
        let settled = false;
        let approvalTimer = null;
        const onAbort = () => {
          settle('cancelled', {
            error: controller.signal.reason || new Error('sessão AUTO cancelada'),
            reason: controller.signal.reason?.message || 'sessão AUTO cancelada',
          });
        };
        const resolveApproval = (id, approved, reason = '') => {
          if (id !== approvalId || state.pendingApproval?.status !== 'pending') return false;
          return settle(approved ? 'approved' : 'denied', { approved: Boolean(approved), reason });
        };
        const settle = (status, { approved = false, reason = '', error = null } = {}) => {
          if (settled) return false;
          settled = true;
          clearTimeout(approvalTimer);
          controller.signal.removeEventListener('abort', onAbort);
          if (state.pendingApproval?.approvalId === approvalId) {
            const previousStatus = state.pendingApproval.status;
            const resolvedAt = new Date().toISOString();
            state.pendingApproval = {
              ...state.pendingApproval,
              status,
              reason: redactAutoText(String(reason || '')).slice(0, 500),
              resolvedAt,
            };
            recordApprovalTransition(state, {
              approvalId,
              from: previousStatus,
              to: status,
              reason,
              at: resolvedAt,
            });
          }
          if (this.resolveApproval === resolveApproval) this.resolveApproval = null;
          if (error) reject(error);
          else resolve(Boolean(approved));
          return true;
        };
        this.resolveApproval = resolveApproval;
        approvalTimer = setTimeout(() => {
          settle('expired', { error: new Error('aprovação humana expirou'), reason: 'timeout' });
        }, Math.max(5_000, timeoutMs));
        controller.signal.addEventListener('abort', onAbort, { once: true });
        if (controller.signal.aborted) onAbort();
      });
    },
    touch(event = null) {
      if (event?.type === 'auto_heartbeat') return;
      if (event?.type === 'auto_agent_turn_started') {
        activeAgentTurns.set(agentTurnKey(event), Date.now());
        state.currentStage = `agent:${event.provider || 'unknown'}:${event.role || 'turn'}`;
        state.currentModule = null;
        const oldest = oldestAgentTurnMs();
        state.lastActivityAt = new Date(oldest || Date.now()).toISOString();
        return;
      }
      if (event?.type === 'auto_agent_turn_completed' || event?.type === 'auto_agent_turn_failed') {
        activeAgentTurns.delete(agentTurnKey(event));
        if (activeAgentTurns.size === 0) {
          state.currentStage = 'idle';
          state.currentModule = null;
          state.lastActivityAt = new Date().toISOString();
        } else {
          const [remaining] = activeAgentTurns.keys();
          state.currentStage = `agent:${remaining}`;
          state.lastActivityAt = new Date(oldestAgentTurnMs()).toISOString();
        }
        return;
      }
      state.lastActivityAt = new Date().toISOString();
      if (event?.type === 'auto_step') {
        const stepStatus = String(event.status || 'running');
        if (['done', 'blocked', 'failed', 'cancelled', 'skipped'].includes(stepStatus)) {
          state.currentStage = 'idle';
          state.currentModule = null;
        } else {
          state.currentStage = `${event.step || 'step'}:${stepStatus}`;
        }
      } else if (event?.type === 'auto_iteration_started') {
        state.currentStage = `iteration:${event.iteration || state.iteration}`;
      } else if (event?.type === 'pipe' && event.state === 'active') {
        state.currentStage = 'pipeline';
        state.currentModule = event.name || null;
      } else if (event?.type === 'pipe' && event.name === state.currentModule
        && ['done', 'skip', 'failed', 'timeout', 'cancelled'].includes(event.state)) {
        state.currentModule = null;
      }
    },
    /** Idle para stall: com turns paralelos, ancora no turno mais antigo. */
    getAgentIdleMs(now = Date.now()) {
      if (activeAgentTurns.size > 0) return now - oldestAgentTurnMs();
      return now - Date.parse(state.lastActivityAt || state.startedAt);
    },
    hasActiveAgentTurns() {
      return activeAgentTurns.size > 0;
    },
    assertActive() {
      if (controller.signal.aborted) throw controller.signal.reason || new Error('sessão AUTO cancelada');
      const deadlineMs = Date.parse(String(state.deadlineAt || ''));
      if (Number.isFinite(deadlineMs) && Date.now() >= deadlineMs) {
        throw new Error('limite de tempo da sessão AUTO atingido');
      }
    },
    reserveAgentCall(provider) {
      this.assertActive();
      const maxCalls = Number(state.limits?.maxAgentCalls ?? limits.maxAgentCalls);
      if (state.agentCalls >= maxCalls) throw new Error('limite de chamadas de IA atingido');
      state.agentCalls += 1;
      state.usage[provider] ||= { calls: 0, promptTokens: 0, completionTokens: 0, totalTokens: 0, costUsd: 0 };
      state.usage[provider].calls += 1;
    },
    recordUsage(provider, usage = {}) {
      const u = usage && typeof usage === 'object' ? usage : {};
      const row = state.usage[provider] ||= { calls: 0, promptTokens: 0, completionTokens: 0, totalTokens: 0, costUsd: 0 };
      row.promptTokens += Number(u.prompt_tokens ?? u.input_tokens ?? 0) || 0;
      row.completionTokens += Number(u.completion_tokens ?? u.output_tokens ?? 0) || 0;
      row.totalTokens += Number(u.total_tokens ?? 0) || 0;
      const key = String(provider || '').toUpperCase().replace(/[^A-Z0-9]/g, '_');
      const inputRate = Number(env[`GHOSTRECON_AUTO_${key}_INPUT_USD_PER_MILLION`] || 0);
      const outputRate = Number(env[`GHOSTRECON_AUTO_${key}_OUTPUT_USD_PER_MILLION`] || 0);
      const estimated = ((Number(u.prompt_tokens ?? u.input_tokens ?? 0) || 0) * inputRate
        + (Number(u.completion_tokens ?? u.output_tokens ?? 0) || 0) * outputRate) / 1_000_000;
      const reported = Number(u.cost ?? u.cost_usd);
      const cost = Number.isFinite(reported) ? reported : estimated;
      row.costUsd += cost;
      row.costEstimated = !Number.isFinite(reported);
      if (!Number.isFinite(reported)) {
        // Sem custo reportado pelo provider, o orçamento deixa de ser verificável.
        state.budgetVerifiable = false;
      }
      state.costUsd += cost;
      const maxCost = Number(state.limits?.maxCostUsd ?? limits.maxCostUsd);
      if (maxCost > 0 && state.costUsd > maxCost) {
        const reason = state.budgetVerifiable === false
          ? 'budget de custo da sessão atingido (estimativa não verificável)'
          : 'budget de custo da sessão atingido';
        controller.abort(new Error(reason));
      }
    },
    async close(status = 'completed') {
      clearTimeout(timer);
      activeAgentTurns.clear();
      state.currentStage = 'closing';
      state.currentModule = null;
      const pending = [...(this.resources || [])];
      this.resources = [];
      const cleanupErrors = [];
      for (const resource of pending) {
        try {
          const result = resource?.close?.() ?? resource?.dispose?.();
          if (result && typeof result.then === 'function') await result;
        } catch (error) {
          cleanupErrors.push(String(error?.message || error).slice(0, 500));
        }
      }
      let finalStatus = status;
      if (cleanupErrors.length) {
        state.cleanupErrors = cleanupErrors.slice(0, 20);
        state.cleanupFailed = true;
        if (['completed', 'partial'].includes(String(finalStatus))) {
          finalStatus = 'failed';
          state.error = state.error || `cleanup_failed: ${cleanupErrors[0]}`;
          state.terminationCause = 'cleanup_failed';
        }
      }
      state.status = finalStatus;
      state.finishedAt = new Date().toISOString();
      state.currentStage = null;
      const originMs = Date.parse(String(state.startedAt || '')) || startedAtMs;
      state.durationMs = Date.now() - originMs;
      if (state.runtimeLease && !state.runtimeLease.releasedAt) {
        state.runtimeLease = {
          ...state.runtimeLease,
          releasedAt: state.finishedAt,
        };
      }
      return state;
    },
    resources: [],
  };
}

export async function writeAutoSessionSnapshot(root, session, env = process.env) {
  validateAutoSessionSnapshot(session, session?.sessionId);
  // `sessionId` é metadado estrutural, não material autenticador. O redator
  // genérico considera qualquer chave "session*" sensível; preserve somente
  // este identificador e remova credenciais de todos os demais campos antes
  // que o snapshot alcance o disco.
  const safeSession = redactAutoValue(session, {
    preserveSensitiveKeys: new Set(['sessionId']),
  });
  validateAutoSessionSnapshot(safeSession, session?.sessionId);
  const dir = resolveAutoSessionSnapshotDir(root, {
    sessionId: safeSession.sessionId,
    owner: safeSession.owner,
    engagementId: safeSession.engagementId || safeSession.resumePolicy?.engagementId || '',
    target: safeSession.target || '',
    env,
  });
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  await fs.chmod(dir, 0o700);
  const file = path.join(dir, 'session.json');
  await writeJsonAtomic(file, safeSession);
  return file;
}

export async function readAutoSessionSnapshot(root, sessionId, env = process.env, {
  principal = null,
  engagementId = '',
  target = '',
} = {}) {
  const safe = String(sessionId || '').trim();
  if (!SESSION_ID_RE.test(safe)) throw new Error('sessionId inválido');
  const preferredDir = resolveAutoSessionSnapshotDir(root, {
    sessionId: safe,
    owner: principal,
    engagementId,
    target,
    env,
  });
  const candidates = [
    path.join(preferredDir, 'session.json'),
    path.join(resolveAutoRagRoot(root, env), 'sessions', safe, 'session.json'),
  ];
  const seen = new Set();
  for (const file of candidates) {
    if (seen.has(file)) continue;
    seen.add(file);
    try {
      return await loadSessionSnapshotFile(file, safe, env);
    } catch (error) {
      if (error?.code === 'ENOENT' || /ENOENT|não encontr|no such file/i.test(String(error?.message || ''))) {
        continue;
      }
      if (error?.message?.includes('snapshot de sessão AUTO')) throw error;
    }
  }
  for (const dir of await listSessionSnapshotDirs(resolveAutoRagRoot(root, env))) {
    if (path.basename(dir) !== safe) continue;
    const file = path.join(dir, 'session.json');
    if (seen.has(file)) continue;
    try {
      const snapshot = await loadSessionSnapshotFile(file, safe, env);
      if (principal) {
        const owner = normalizeOwner(snapshot.owner);
        const want = normalizeOwner(principal);
        if (owner?.sub && want?.sub && owner.sub !== want.sub) {
          throw new Error('sessão AUTO pertence a outro principal');
        }
      }
      return snapshot;
    } catch (error) {
      if (error?.code === 'ENOENT') continue;
      if (error?.message === 'sessão AUTO pertence a outro principal') throw error;
      // Snapshot encontrado mas inválido/corrompido: não mascarar como missing.
      if (/inválido|excede/i.test(String(error?.message || ''))) throw error;
    }
  }
  throw new Error(`snapshot de sessão AUTO não encontrado: ${safe}`);
}

export async function reconcileOrphanedAutoSessions(root, env = process.env, now = Date.now()) {
  const ragRoot = resolveAutoRagRoot(root, env);
  const dirs = await listSessionSnapshotDirs(ragRoot);
  const reconciled = [];
  const errors = [];
  for (const dir of dirs) {
    const file = path.join(dir, 'session.json');
    try {
      const state = JSON.parse(await fs.readFile(file, 'utf8'));
      if (state.status !== 'running') continue;
      if (await isAutoRuntimeLeaseLive(state.runtimeLease)) continue;
      const leaseHost = String(state.runtimeLease?.hostname || '');
      const lastActivityMs = Date.parse(state.lastActivityAt || state.startedAt || '');
      const remoteLeaseGraceMs = bounded(
        env,
        'GHOSTRECON_AUTO_REMOTE_LEASE_GRACE_MS',
        Number(state.limits?.sessionTimeoutMs) || 1_800_000,
        30_000,
        7_200_000,
      );
      if (
        leaseHost
        && leaseHost !== hostname()
        && Number.isFinite(lastActivityMs)
        && now - lastActivityMs < remoteLeaseGraceMs
      ) continue;
      state.status = 'interrupted';
      state.finishedAt = new Date(now).toISOString();
      state.durationMs = Math.max(0, now - Date.parse(state.startedAt || now));
      state.error = state.error || 'server_restarted_before_session_completed';
      state.currentStage = 'interrupted';
      expireOrphanedApproval(state, {
        now,
        reason: 'approval_expired_after_server_restart',
      });
      validateAutoSessionSnapshot(state, state.sessionId || path.basename(dir));
      const safeState = redactAutoValue(state, {
        preserveSensitiveKeys: new Set(['sessionId']),
      });
      validateAutoSessionSnapshot(safeState, state.sessionId || path.basename(dir));
      await writeJsonAtomic(file, safeState);
      reconciled.push(state.sessionId || path.basename(dir));
    } catch (error) {
      errors.push({
        dir,
        error: error?.message || String(error),
      });
    }
  }
  // Metadados de auditoria sem poluir o array (deepEqual dos testes).
  reconcileOrphanedAutoSessions.lastReport = {
    scanned: dirs.length,
    reconciled: reconciled.length,
    errors,
    at: new Date(now).toISOString(),
  };
  return reconciled;
}

/**
 * Reconciliação de startup aguardável e auditável (antes de aceitar tráfego Auto).
 */
export async function runAutoStartupReconciliation(root, env = process.env, {
  now = Date.now(),
  logger = console,
  onAudit = null,
} = {}) {
  const dirsBefore = await listSessionSnapshotDirs(resolveAutoRagRoot(root, env));
  const reconciled = await reconcileOrphanedAutoSessions(root, env, now);
  const last = reconcileOrphanedAutoSessions.lastReport || {
    scanned: dirsBefore.length,
    reconciled: reconciled.length,
    errors: [],
    at: new Date(now).toISOString(),
  };
  const report = {
    ok: true,
    ...last,
    sessionIds: [...reconciled],
  };
  if (report.sessionIds.length) {
    logger?.warn?.(
      `[auto] reconciliadas ${report.sessionIds.length} sessão(ões) órfã(s): ${report.sessionIds.join(', ')}`,
    );
  }
  if (report.errors?.length) {
    logger?.warn?.(
      `[auto] falhas ao reconciliar snapshots: ${report.errors.length}`,
    );
  }
  try {
    onAudit?.(report);
  } catch {
    // auditoria não pode impedir o boot
  }
  return report;
}
