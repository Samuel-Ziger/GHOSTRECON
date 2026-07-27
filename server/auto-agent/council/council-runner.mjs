import { decideWithCodex } from '../providers/codex.mjs';
import { decideWithOpenRouter } from '../providers/openrouter.mjs';
import { decideWithGhost } from '../providers/ghost.mjs';
import { decideWithClaudeCode } from '../providers/claude-code.mjs';
import { decideWithLocalModel } from '../providers/local-model.mjs';
import { decideWithCodexAppServer } from '../providers/codex-app-server.mjs';
import { decideWithCursor } from '../providers/cursor.mjs';
import { normalizeAndValidateAgentDecision } from '../decision-contract.mjs';
import {
  availableCatalogIds,
  availableEvidenceRefs,
  catalogModuleRiskClass,
} from '../providers/shared.mjs';

function providerRunner(id) {
  if (id === 'codex') return decideWithCodex;
  if (id === 'openrouter') return decideWithOpenRouter;
  if (id === 'skynet') return decideWithGhost;
  if (id === 'claude_code') return decideWithClaudeCode;
  if (id === 'local_model') return decideWithLocalModel;
  if (id === 'cursor') return decideWithCursor;
  return null;
}

function effectiveSelected(providers = []) {
  return providers.filter((p) => p.selected && p.usable !== false && providerRunner(p.id));
}

function validTurns(turns) {
  return turns.filter((turn) => turn.ok && turn.decision);
}

function turnWeight(turn) {
  return Math.max(0.25, Number(turn.decision.confidence || 0))
    + Math.min(0.5, (turn.decision.evidenceRefs?.length || 0) * 0.1);
}

function moduleConsensus(turns, catalog) {
  const valid = validTurns(turns);
  if (!valid.length) {
    return { requestedModules: [], tiedModules: [], riskDivergence: [], explicitConflicts: [] };
  }
  const scores = new Map();
  const requesters = new Map();
  const rejecters = new Map();
  const totalWeight = valid.reduce((sum, turn) => sum + turnWeight(turn), 0);
  for (const turn of valid) {
    const weight = turnWeight(turn);
    for (const id of new Set(turn.decision.requestedModules || [])) {
      scores.set(id, (scores.get(id) || 0) + weight);
      if (!requesters.has(id)) requesters.set(id, new Set());
      requesters.get(id).add(turn.provider);
    }
    for (const rejection of turn.decision.rejectedModules || []) {
      if (!rejecters.has(rejection.id)) rejecters.set(rejection.id, new Set());
      rejecters.get(rejection.id).add(turn.provider);
    }
  }
  const half = totalWeight / 2;
  const epsilon = 1e-9;
  const requestedModules = [...scores.entries()]
    .filter(([, score]) => score > half + epsilon)
    .map(([id]) => id);
  const tiedModules = [...scores.entries()]
    .filter(([, score]) => Math.abs(score - half) <= epsilon)
    .map(([id]) => id);
  const catalogById = new Map((catalog?.modules || []).map((module) => [module.id, module]));
  const riskDivergence = requestedModules.filter((id) => {
    const module = catalogById.get(id);
    return catalogModuleRiskClass(module) === 'intrusive'
      && (requesters.get(id)?.size || 0) < valid.length;
  });
  const explicitConflicts = requestedModules.filter((id) => (
    (requesters.get(id)?.size || 0) > 0 && (rejecters.get(id)?.size || 0) > 0
  ));
  return { requestedModules, tiedModules, riskDivergence, explicitConflicts };
}

function weightedActionConsensus(turns, candidateActions) {
  const valid = validTurns(turns).filter((turn) => candidateActions.includes(turn.decision.action));
  if (!valid.length) return { winner: null, tied: [] };
  const scores = new Map();
  const totalWeight = valid.reduce((sum, turn) => sum + turnWeight(turn), 0);
  for (const turn of valid) {
    scores.set(turn.decision.action, (scores.get(turn.decision.action) || 0) + turnWeight(turn));
  }
  const half = totalWeight / 2;
  const epsilon = 1e-9;
  const tied = [...scores.entries()]
    .filter(([, score]) => Math.abs(score - half) <= epsilon)
    .map(([action]) => action);
  const winner = [...scores.entries()].find(([, score]) => score > half + epsilon)?.[0] || null;
  return { winner, tied };
}

function conflictQuestion({
  tiedModules = [],
  riskDivergence = [],
  explicitConflicts = [],
  actionTie = [],
  forgeConflicts = [],
  executionDivergence = false,
} = {}) {
  const reasons = [];
  if (tiedModules.length) reasons.push(`empate nos módulos ${tiedModules.join(', ')}`);
  if (riskDivergence.length) reasons.push(`divergência sobre risco intrusivo em ${riskDivergence.join(', ')}`);
  if (explicitConflicts.length) reasons.push(`módulos simultaneamente solicitados e rejeitados: ${explicitConflicts.join(', ')}`);
  if (actionTie.length) reasons.push(`empate entre ações ${actionTie.join(', ')}`);
  if (forgeConflicts.length) reasons.push(`propostas Forge conflitantes: ${forgeConflicts.join(', ')}`);
  if (executionDivergence) reasons.push('divergência entre executar e não executar');
  return `O conselho precisa da decisão do operador (${reasons.join('; ') || 'consenso insuficiente'}).`;
}

function actionConsensus(turns, moduleVerdict, forgeVerdict) {
  const valid = validTurns(turns);
  const { requestedModules } = moduleVerdict;
  const askTurn = valid.find((turn) => turn.decision.action === 'ask_operator');
  const executionDivergence = requestedModules.length > 0
    && valid.some((turn) => !['run_modules', 'continue_with_context'].includes(turn.decision.action));
  const executionActions = weightedActionConsensus(turns, ['run_modules', 'continue_with_context']);
  const terminalActions = weightedActionConsensus(turns, ['finish', 'abstain', 'forge_module']);
  const conflicts = (
    moduleVerdict.tiedModules.length
    || moduleVerdict.riskDivergence.length
    || moduleVerdict.explicitConflicts.length
    || forgeVerdict.conflicts.length
    || executionDivergence
  );
  if (askTurn || conflicts) {
    return {
      action: 'ask_operator',
      operatorQuestion: askTurn?.decision.operatorQuestion || conflictQuestion({
        ...moduleVerdict,
        actionTie: requestedModules.length ? executionActions.tied : terminalActions.tied,
        forgeConflicts: forgeVerdict.conflicts,
        executionDivergence,
      }),
      requestedModules: [],
      forgeRequest: null,
      conflicted: true,
    };
  }
  if (forgeVerdict.request) {
    return {
      action: 'forge_module', operatorQuestion: null, requestedModules: [],
      forgeRequest: forgeVerdict.request, conflicted: false,
    };
  }
  if (requestedModules.length) {
    if (!executionActions.winner && executionActions.tied.length) {
      return {
        action: 'ask_operator',
        operatorQuestion: conflictQuestion({ actionTie: executionActions.tied }),
        requestedModules: [],
        forgeRequest: null,
        conflicted: true,
      };
    }
    return {
      action: executionActions.winner || 'run_modules',
      operatorQuestion: null,
      requestedModules,
      forgeRequest: null,
      conflicted: false,
    };
  }
  if (!terminalActions.winner && terminalActions.tied.length) {
    return {
      action: 'ask_operator',
      operatorQuestion: conflictQuestion({ actionTie: terminalActions.tied }),
      requestedModules: [],
      forgeRequest: null,
      conflicted: true,
    };
  }
  return {
    action: terminalActions.winner || 'abstain',
    operatorQuestion: null,
    requestedModules: [],
    forgeRequest: null,
    conflicted: false,
  };
}

function forgeConsensus(turns) {
  const valid = validTurns(turns);
  const candidates = valid.filter((t) => t.decision.action === 'forge_module' && t.decision.forgeRequest);
  if (!candidates.length) return { request: null, conflicts: [] };
  const threshold = Math.floor(valid.length / 2) + 1;
  const groups = new Map();
  for (const turn of candidates) {
    const id = turn.decision.forgeRequest.proposedId;
    if (!groups.has(id)) groups.set(id, []);
    groups.get(id).push(turn);
  }
  const ranked = [...groups.entries()].sort((a, b) => b[1].length - a[1].length);
  const winner = ranked[0];
  if (!winner || winner[1].length < threshold) {
    return {
      request: null,
      conflicts: candidates.length >= threshold ? ranked.map(([id]) => id) : [],
    };
  }
  return { request: { ...winner[1][0].decision.forgeRequest }, conflicts: [] };
}

export async function runAgentCouncil({
  providers = [],
  target,
  mode,
  catalog,
  ragContext,
  root,
  env = process.env,
  fetchImpl = globalThis.fetch,
  execFileImpl,
  iteration = 1,
  onTurn = () => {},
  observationBundle = null,
  session = null,
  allowIntrusive = false,
  autonomyLevel = 'observation',
} = {}) {
  const selected = effectiveSelected(providers);
  const runTurn = async (p, role, peerDecisions = []) => {
    const runner = providerRunner(p.id);
    onTurn({ phase: 'started', provider: p.id, role, iteration });
    try {
      session?.reserveAgentCall(p.id);
      const preferredRunner = p.id === 'codex' && session && !/^(0|false|no|off)$/i.test(String(env.GHOSTRECON_CODEX_APP_SERVER || '1'))
        ? decideWithCodexAppServer : runner;
      let result;
      try {
        result = await preferredRunner({
          target, mode, catalog, ragContext, root, env, fetchImpl, execFileImpl,
          role, iteration, peerDecisions,
          observationBundle,
          model: p.id === 'openrouter' ? p.defaultModel : null,
          signal: session?.signal,
          maxContextChars: session?.limits?.maxContextChars,
          session,
          allowIntrusive,
          autonomyLevel,
        });
      } catch (error) {
        if (preferredRunner !== runner && !session?.signal?.aborted) {
          try {
            result = await runner({
              target, mode, catalog, ragContext, root, env, fetchImpl, execFileImpl,
              role, iteration, peerDecisions, observationBundle, signal: session?.signal,
              maxContextChars: session?.limits?.maxContextChars,
              allowIntrusive,
              autonomyLevel,
            });
          } catch (fallbackError) {
            throw new Error(
              `Codex App Server falhou: ${error?.message || error}; `
              + `fallback codex exec falhou: ${fallbackError?.message || fallbackError}`,
              { cause: fallbackError },
            );
          }
          result.transport = { ...(result.transport || {}), fallbackFrom: 'codex app-server', fallbackReason: error?.message || String(error) };
        } else throw error;
      }
      session?.recordUsage(p.id, result?.usage);
      const turn = { ...result, ok: true, provider: p.id, role, iteration };
      onTurn({ phase: 'completed', ...turn });
      return turn;
    } catch (e) {
      const turn = { ok: false, provider: p.id, role, iteration, error: e?.message || String(e) };
      onTurn({ phase: 'failed', ...turn });
      return turn;
    }
  };

  const proposals = await Promise.all(selected.map((p) => runTurn(p, 'planner')));
  const successfulProposals = proposals.filter((t) => t.ok).map((t) => ({
    provider: t.provider,
    model: t.model || null,
    decision: t.decision,
  }));
  const reviews = successfulProposals.length > 1
    ? await Promise.all(selected.map((p) => runTurn(
      p,
      'reviewer',
      successfulProposals.filter((x) => x.provider !== p.id),
    )))
    : [];
  const verdictTurns = reviews.some((t) => t.ok) ? reviews : proposals;
  const moduleVerdict = moduleConsensus(verdictTurns, catalog);
  const forgeVerdict = forgeConsensus(verdictTurns);
  const actionVerdict = actionConsensus(verdictTurns, moduleVerdict, forgeVerdict);
  const successful = validTurns(verdictTurns);
  const confidence = successful.length
    ? successful.reduce((sum, t) => sum + Number(t.decision?.confidence || 0), 0) / successful.length
    : 0;
  const candidateDecision = successful.length ? {
    action: actionVerdict.action,
    objective: 'Decisão consolidada pelo conselho de agentes selecionados',
    reasoningSummary: successful.flatMap((t) => (t.decision?.reasoningSummary || []).map((x) => `${t.provider}: ${x}`)).slice(0, 20),
    evidenceRefs: [...new Set(successful.flatMap((t) => t.decision?.evidenceRefs || []))],
    requestedModules: actionVerdict.requestedModules,
    rejectedModules: successful.flatMap((t) => t.decision?.rejectedModules || []),
    confidence: actionVerdict.conflicted ? 0 : Math.max(0, Math.min(1, confidence)),
    assumptions: [...new Set(successful.flatMap((t) => t.decision?.assumptions || []))],
    operatorQuestion: actionVerdict.operatorQuestion,
    forgeRequest: actionVerdict.forgeRequest,
  } : null;
  let finalDecision = null;
  let validationErrors = [];
  if (candidateDecision) {
    const validation = normalizeAndValidateAgentDecision(candidateDecision, {
      catalogModuleIds: availableCatalogIds(catalog, { allowIntrusive, autonomyLevel }),
      availableEvidenceRefs: availableEvidenceRefs({ ragContext, observationBundle }),
    });
    validationErrors = validation.errors || [];
    if (validation.ok) {
      finalDecision = validation.decision;
    } else {
      const safeFallback = normalizeAndValidateAgentDecision({
        action: 'ask_operator',
        objective: 'Revisar veredito inválido do conselho',
        reasoningSummary: ['O veredito consolidado falhou na validação canônica.'],
        evidenceRefs: [],
        requestedModules: [],
        rejectedModules: [],
        confidence: 0,
        assumptions: [],
        operatorQuestion: 'O conselho produziu um veredito inválido. Deseja revisar as decisões individuais?',
        forgeRequest: null,
      }, {
        catalogModuleIds: availableCatalogIds(catalog, { allowIntrusive, autonomyLevel }),
        availableEvidenceRefs: availableEvidenceRefs({ ragContext, observationBundle }),
      });
      finalDecision = safeFallback.decision;
    }
    finalDecision.council = {
      selected: selected.map((p) => p.id),
      proposalProviders: proposals.filter((t) => t.ok).map((t) => t.provider),
      reviewProviders: reviews.filter((t) => t.ok).map((t) => t.provider),
      quorum: successful.length,
      validationErrors,
      conflicts: {
        tiedModules: moduleVerdict.tiedModules,
        riskDivergence: moduleVerdict.riskDivergence,
        explicitConflicts: moduleVerdict.explicitConflicts,
        forge: forgeVerdict.conflicts,
      },
    };
  }
  return { selected: selected.map((p) => p.id), proposals, reviews, finalDecision };
}
