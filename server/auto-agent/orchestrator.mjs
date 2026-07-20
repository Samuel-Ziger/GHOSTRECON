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
import { expandIntrusiveRunModules, gateModules } from '../modules/opsec.mjs';
import { createAutoSession, readAutoSessionSnapshot, writeAutoSessionSnapshot } from './session-store.mjs';
import { registerActiveAutoSession, unregisterActiveAutoSession } from './active-sessions.mjs';
import fs from 'node:fs/promises';
import { runFrameSeven, resolveFrameSevenBinary } from '../integrations/frameseven-adapter.mjs';

function sendSafe(emit, obj) {
  try { emit(obj); } catch { /* ignore */ }
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
    includeHexstrike: body.includeHexstrike !== false,
    includeDeepPassive: body.includeDeepPassive,
    // Política explícita de autonomia da IA por sessão. O nível 4 continua
    // sujeito à confirmação humana por ação destrutiva (não há execução livre).
    autonomyLevel: ['observation', 'assisted', 'authorized', 'authorized_opsec'].includes(String(body.autonomyLevel || '').toLowerCase())
      ? String(body.autonomyLevel).toLowerCase() : 'observation',
    frameSevenAuth: body.frameSevenAuth === true,
    vigoliumUseCodex: body.vigoliumUseCodex === true,
    resumeSessionId: body.resumeSessionId ? String(body.resumeSessionId).trim() : null,
  };
}

export async function runAutoRecon({
  body = {},
  runPipeline,
  emit = () => {},
  ROOT,
  env = process.env,
  fetchImpl = globalThis.fetch,
  execFileImpl,
  pipelineOverrides = {},
  signal,
} = {}) {
  if (typeof runPipeline !== 'function') {
    throw new Error('runPipeline ausente para Modo Auto');
  }
  const req = normalizeAutoRequest(body);
  const events = [];
  const restoredState = req.resumeSessionId
    ? await readAutoSessionSnapshot(ROOT, req.resumeSessionId, env)
    : null;
  if (restoredState && restoredState.target !== req.target) throw new Error('sessão pertence a outro alvo');
  if (restoredState && ['completed', 'cancelled'].includes(restoredState.status)) {
    throw new Error(`sessão ${restoredState.status} não pode ser retomada`);
  }
  const requestRunId = restoredState?.requestRunId || `auto-${Date.now().toString(36)}-${randomBytes(4).toString('hex')}`;
  const sessionId = restoredState?.sessionId || `session-${Date.now().toString(36)}-${randomBytes(3).toString('hex')}`;
  const session = createAutoSession({ sessionId, requestRunId, target: req.target, providers: req.commanders, env, restoredState });
  session.state.autonomyLevel = req.autonomyLevel;
  session.state.frameSevenAuth = req.frameSevenAuth;
  registerActiveAutoSession(session);
  if (signal) {
    if (signal.aborted) session.abort(signal.reason || 'client_disconnected');
    else signal.addEventListener('abort', () => session.abort(signal.reason || 'client_disconnected'), { once: true });
  }
  const captureEmit = (event) => {
    session.touch(event);
    events.push(event);
    sendSafe(emit, event);
  };
  const rawRequestApproval = session.requestApproval.bind(session);
  session.requestApproval = (details = {}, timeoutMs) => {
    const pending = rawRequestApproval(details, timeoutMs);
    if (session.state.pendingApproval) captureEmit({
      type: 'auto_approval_required',
      sessionId,
      approval: session.state.pendingApproval,
    });
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
  captureEmit({ type: 'auto_session', phase: 'started', sessionId, requestRunId, mode: req.mode, autonomyLevel: req.autonomyLevel, frameSevenAuth: req.frameSevenAuth, commanders: req.commanders, limits: session.limits });
  await writeAutoSessionSnapshot(ROOT, session.state, env);
  let ragContext = await loadAutoRagContext({ root: ROOT, env, target: req.target, modules: req.modules, decisionType: 'plan' }).catch((e) => ({
    dir: '',
    items: [],
    error: e?.message || String(e),
  }));
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

  const catalog = await buildAutoToolCatalog({
    includeHexstrike: req.includeHexstrike,
    includeDeepPassive: req.includeDeepPassive !== false,
    includeIntrusive: ['authorized', 'authorized_opsec'].includes(req.autonomyLevel),
    ghostRoot: ROOT,
  });
  const catalogHash = createHash('sha256').update(JSON.stringify(catalog.modules.map((m) => ({ id: m.id, class: m.class, available: m.available !== false })))).digest('hex');
  session.state.catalogHash = catalogHash;
  session.state.promptVersion = 'auto-council-v2';
  session.state.memoriesUsed = (ragContext.items || []).map((item) => item.name);
  captureEmit({
    type: 'auto_catalog',
    modules: catalog.modules.map((m) => ({ id: m.id, source: m.source, class: m.class, available: m.available !== false })),
    hexstrike: catalog.hexstrike ? {
      installed: Boolean(catalog.hexstrike.installed),
      reachable: Boolean(catalog.hexstrike.reachable),
      baseUrl: catalog.hexstrike.baseUrl || null,
    } : null,
  });

  const council = await runAgentCouncil({
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
  const successfulTurns = [...council.proposals, ...council.reviews].filter((turn) => turn.ok && turn.decision);
  for (const turn of successfulTurns) {
    const memory = await writeAutoRagNote({
      root: ROOT,
      env,
      kind: 'module-forge',
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
        promptVersion: 'auto-council-v2', catalogHash, memoriesUsed: session.state.memoriesUsed,
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
      path: forge?.dir || null,
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
      }).catch((e) => ({ ok: false, error: e?.message || String(e) }));
      forge.generated = generated;
      captureEmit({
        type: 'auto_forge_status', status: generated.ok ? 'generated_pending_validation' : 'generation_failed',
        forgeId: forge.forgeId, author: generator.id, error: generated.error || null, pipelineEnabled: false,
      });
      if (generated.ok) {
        const gates = await validateAndTestForgePackage(forge.dir, { env }).catch((e) => ({ ok: false, status: 'validation_error', error: e?.message || String(e) }));
        forge.gates = gates;
        captureEmit({
          type: 'auto_forge_status', status: gates.status || (gates.ok ? 'pending_ai_code_review' : 'validation_failed'),
          forgeId: forge.forgeId, author: generator.id, error: gates.error || null,
          validationOk: Boolean(gates.validation?.ok), testsOk: Boolean(gates.tests?.ok), pipelineEnabled: false,
        });
        if (gates.ok) {
          const codeReview = await reviewForgePackage({
            pendingDir: forge.dir, root: ROOT, providers: providers.providers,
            env, fetchImpl, execFileImpl,
          }).catch((e) => ({ approved: false, status: 'review_error', error: e?.message || String(e) }));
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
              providers: providers.providers, env, fetchImpl, execFileImpl, initialReview: codeReview,
            }).catch((e) => ({ ok: false, status: 'correction_failed', error: e?.message || String(e) }));
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
      kind: 'decision',
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
      metadata: { requestRunId, forge },
    }).catch(() => null);
  }

  const plan = createAutoPlan({
    target: req.target,
    mode: req.mode,
    requestedModules: req.modules,
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
  plan.promptVersion = 'auto-council-v2';
  captureEmit({ type: 'auto_plan', plan });
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

  let iteration = Number(session.state.checkpoint?.nextIteration || 1);
  let iterationPlan = session.state.checkpoint?.nextModules?.length
    ? { ...plan, modules: session.state.checkpoint.nextModules }
    : plan;
  let evaluation = null;
  const executedModules = new Set(session.state.checkpoint?.executedModules || []);
  const iterationHistory = [...(session.state.checkpoint?.iterationHistory || [])];
  while (true) {
  session.assertActive();
  session.state.iteration = iteration;
  await writeAutoSessionSnapshot(ROOT, session.state, env);
  captureEmit({ type: 'auto_iteration_started', sessionId, iteration, modules: iterationPlan.modules });
  const iterationEventStart = events.length;
  const pipelineBody = {
    ...body,
    domain: req.target,
    modules: iterationPlan.modules,
    profile: body.profile || (iterationPlan.mode === 'quick' ? 'quick' : 'standard'),
    opsecProfile: body.opsecProfile || (['authorized', 'authorized_opsec'].includes(req.autonomyLevel) ? 'aggressive' : 'standard'),
    autoAiReports: body.autoAiReports === true,
    autonomyLevel: req.autonomyLevel,
    signal: session.signal,
    requestRunId,
    ...pipelineOverrides,
  };
  const gate = gateModules({
    modules: expandIntrusiveRunModules({
      modules: pipelineBody.modules,
      engine: pipelineBody.engine,
      vigoliumAgent: pipelineBody.vigoliumAgent,
    }),
    profile: pipelineBody.opsecProfile,
    confirm: pipelineBody.confirmActive === true || String(env.GHOSTRECON_CONFIRM_ACTIVE || '').trim() === '1',
  });
  if (!gate.ok) {
    captureEmit({ type: 'auto_step', step: 'opsec', status: 'blocked', opsec: gate });
    throw new Error(`Modo Auto bloqueado por OPSEC: ${gate.reason || gate.blocked?.join(', ')}`);
  }

  if (gate.acknowledged?.length && ['authorized', 'authorized_opsec'].includes(req.autonomyLevel)) {
    const approved = await session.requestApproval({
      module: gate.acknowledged.join(', '), target: req.target,
      action: 'executar módulos intrusivos autorizados',
      risk: req.autonomyLevel === 'authorized_opsec' ? 'alto — perfil OPSEC completo' : 'ativo — requer confirmação humana',
    });
    if (!approved) {
      captureEmit({ type: 'auto_approval_denied', sessionId, modules: gate.acknowledged });
      pipelineBody.modules = pipelineBody.modules.filter((id) => !gate.acknowledged.includes(id));
    } else {
      captureEmit({ type: 'auto_approval_granted', sessionId, modules: gate.acknowledged });
    }
  }

  const integratedPipelineBody = {
    ...pipelineBody,
    modules: [...new Set([...pipelineBody.modules, 'vigolium_dast', 'vigolium_audit'])],
    engine: 'both',
    vigoliumAgent: 'audit',
    vigoliumUseCodex: req.vigoliumUseCodex,
  };
  const runGhostReconAndVigolium = async (capturedAuth = null) => {
    captureEmit({ type: 'engine_started', engine: 'ghostrecon', iteration });
    await runPipeline({
      ...integratedPipelineBody,
      auth: capturedAuth || integratedPipelineBody.auth,
      emit: captureEmit,
    });
    captureEmit({ type: 'engine_done', engine: 'ghostrecon', iteration });
    captureEmit({ type: 'engine_done', engine: 'vigolium', iteration });
  };

  captureEmit({ type: 'auto_step', step: 'act', status: 'running', iteration, modules: integratedPipelineBody.modules });
  const frameSevenBinary = resolveFrameSevenBinary(ROOT, env);
  const frameSevenAvailable = await fs.access(frameSevenBinary).then(() => true).catch(() => false);
  const frameSevenTarget = /^https?:\/\//i.test(req.target) ? req.target : `https://${req.target}`;
  if (!frameSevenAvailable) {
    captureEmit({ type: 'engine_unavailable', engine: 'frameseven', binary: frameSevenBinary });
    await runGhostReconAndVigolium();
  } else if (req.frameSevenAuth) {
    await runFrameSeven({
      root: ROOT,
      target: frameSevenTarget,
      outputDir: `reports/frameseven-${sessionId}`,
      authBrowser: true,
      signal: session.signal,
      emit: captureEmit,
      waitForAuth: () => session.requestApproval({
        kind: 'authentication', module: 'frameseven', target: req.target,
        action: 'fechar navegador e compartilhar a sessão temporária com os motores',
        risk: 'sessão autenticada temporária; nenhuma senha será armazenada',
      }, Number(env.GHOSTRECON_FRAMESEVEN_AUTH_TIMEOUT_MS || 10 * 60_000)),
      beforeScan: (capturedAuth) => runGhostReconAndVigolium(capturedAuth),
      env,
    });
  } else {
    await runGhostReconAndVigolium();
    await runFrameSeven({
      root: ROOT, target: frameSevenTarget, outputDir: `reports/frameseven-${sessionId}`,
      authBrowser: false, signal: session.signal, emit: captureEmit, env,
    });
  }
  captureEmit({ type: 'auto_step', step: 'act', status: 'done' });

  for (const id of iterationPlan.modules) executedModules.add(id);
  const iterationEvents = events.slice(iterationEventStart);
  const observationBundle = buildAutoObservationBundle({ events: iterationEvents, plan: iterationPlan });
  const technologies = [...new Set(observationBundle.findings.map((finding) => finding.type).filter(Boolean))];
  ragContext = await loadAutoRagContext({
    root: ROOT, env, target: req.target, technologies,
    modules: iterationPlan.modules, decisionType: 'evaluation',
  }).catch(() => ragContext);
  captureEmit({
    type: 'auto_observation',
    iteration,
    findings: observationBundle.findings.length,
    warnings: observationBundle.warnings.length,
    errors: observationBundle.errors.length,
  });
  const evaluationCouncil = await runAgentCouncil({
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
    onTurn: (turn) => {
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
    },
    session,
  });
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
      path: postForge?.dir || null, error: postForge?.error || null, pipelineEnabled: false,
    });
    if (!postForge?.error && generator && !/^(0|false|no|off)$/i.test(String(env.GHOSTRECON_AUTO_FORGE_GENERATE || '1'))) {
      const generated = await generatePendingArtifact({
        provider: generator.id, request: nextDecision.forgeRequest, target: req.target,
        root: ROOT, pendingDir: postForge.dir, env, execFileImpl,
      }).catch((e) => ({ ok: false, error: e?.message || String(e) }));
      postForge.generated = generated;
      captureEmit({
        type: 'auto_forge_status', status: generated.ok ? 'generated_pending_validation' : 'generation_failed',
        forgeId: postForge.forgeId, author: generator.id, error: generated.error || null, pipelineEnabled: false,
      });
      if (generated.ok) {
        const gates = await validateAndTestForgePackage(postForge.dir, { env }).catch((e) => ({ ok: false, status: 'validation_error', error: e?.message || String(e) }));
        postForge.gates = gates;
        captureEmit({
          type: 'auto_forge_status', status: gates.status || (gates.ok ? 'pending_ai_code_review' : 'validation_failed'),
          forgeId: postForge.forgeId, author: generator.id, error: gates.error || null,
          validationOk: Boolean(gates.validation?.ok), testsOk: Boolean(gates.tests?.ok), pipelineEnabled: false,
        });
        if (gates.ok) {
          const codeReview = await reviewForgePackage({
            pendingDir: postForge.dir, root: ROOT, providers: providers.providers,
            env, fetchImpl, execFileImpl,
          }).catch((e) => ({ approved: false, status: 'review_error', error: e?.message || String(e) }));
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
              providers: providers.providers, env, fetchImpl, execFileImpl, initialReview: codeReview,
            }).catch((e) => ({ ok: false, status: 'correction_failed', error: e?.message || String(e) }));
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
      kind: 'module-forge',
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
      metadata: { requestRunId, forge: postForge },
    }).catch(() => null);
  }

  evaluation = evaluateAutoRun({ events: iterationEvents, plan: iterationPlan });
  evaluation.agentDecision = nextDecision;
  evaluation.observation = {
    findings: observationBundle.findings.length,
    warnings: observationBundle.warnings.length,
    errors: observationBundle.errors.length,
  };
  evaluation.forge = postForge;
  captureEmit({ type: 'auto_evaluation', evaluation });
  const evalMemory = await writeAutoDecisionMarkdown({
    root: ROOT,
    env,
    requestRunId,
    target: req.target,
    kind: 'evaluation',
    title: `Auto evaluation - ${req.target}`,
    summary: 'Modo Auto evaluation after running the GHOSTRECON pipeline.',
    plan: iterationPlan,
    evaluation,
    providers,
    events,
    tags: ['evaluation', evaluation.ok ? 'ok' : 'error'],
  }).catch((e) => ({ error: e?.message || String(e) }));
  captureEmit({ type: 'auto_rag', phase: 'evaluation_saved', memory: evalMemory });
  iterationHistory.push({ iteration, modules: [...iterationPlan.modules], observation: evaluation.observation, decision: nextDecision });
  captureEmit({ type: 'auto_iteration_completed', sessionId, iteration, decision: nextDecision?.action || 'finish' });
  const requestedNext = (nextDecision?.requestedModules || []).filter((id) => !executedModules.has(id));
  const wantsAnotherIteration = ['run_modules', 'continue_with_context'].includes(nextDecision?.action) && requestedNext.length > 0;
  if (wantsAnotherIteration && iteration < session.limits.maxIterations) {
    session.state.checkpoint = {
      status: 'ready_for_next_iteration', nextIteration: iteration + 1, nextModules: requestedNext,
      executedModules: [...executedModules], iterationHistory,
    };
    await writeAutoSessionSnapshot(ROOT, session.state, env);
    iteration += 1;
    iterationPlan = { ...iterationPlan, modules: requestedNext, agentDecision: nextDecision };
    continue;
  }
  session.state.checkpoint = {
    status: 'completed', nextIteration: null, nextModules: [],
    executedModules: [...executedModules], iterationHistory,
  };
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
    const status = session.signal.aborted ? 'cancelled' : 'failed';
    const failedSession = session.close(status);
    failedSession.error = error?.message || String(error);
    await writeAutoSessionSnapshot(ROOT, failedSession, env).catch(() => null);
    captureEmit({ type: 'auto_session', phase: status, session: failedSession, error: failedSession.error });
    throw error;
  } finally {
    unregisterActiveAutoSession(sessionId);
  }
}
