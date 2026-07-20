import { decideWithCodex } from '../providers/codex.mjs';
import { decideWithOpenRouter } from '../providers/openrouter.mjs';
import { decideWithGhost } from '../providers/ghost.mjs';
import { decideWithClaudeCode } from '../providers/claude-code.mjs';
import { decideWithLocalModel } from '../providers/local-model.mjs';
import { decideWithCodexAppServer } from '../providers/codex-app-server.mjs';
import { decideWithCursor } from '../providers/cursor.mjs';

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

function moduleConsensus(turns, fallback = []) {
  const valid = turns.filter((t) => t.ok && t.decision);
  if (!valid.length) return [...fallback];
  const scores = new Map();
  const totalWeight = valid.reduce((sum, turn) => sum + Math.max(0.25, Number(turn.decision.confidence || 0)) + Math.min(0.5, (turn.decision.evidenceRefs?.length || 0) * 0.1), 0);
  for (const turn of valid) {
    const weight = Math.max(0.25, Number(turn.decision.confidence || 0)) + Math.min(0.5, (turn.decision.evidenceRefs?.length || 0) * 0.1);
    for (const id of new Set(turn.decision.requestedModules || [])) scores.set(id, (scores.get(id) || 0) + weight);
  }
  return [...scores.entries()].filter(([, score]) => score >= totalWeight / 2).map(([id]) => id);
}

function actionConsensus(turns, requestedModules, forgeRequest) {
  if (forgeRequest) return { action: 'forge_module', operatorQuestion: null };
  if (requestedModules.length) return { action: 'run_modules', operatorQuestion: null };
  const valid = turns.filter((turn) => turn.ok && turn.decision);
  const actions = new Set(valid.map((turn) => turn.decision.action));
  if (actions.has('ask_operator')) {
    return { action: 'ask_operator', operatorQuestion: valid.find((turn) => turn.decision.action === 'ask_operator')?.decision.operatorQuestion || 'O conselho precisa de uma decisão do operador.' };
  }
  if (actions.has('finish') && actions.has('continue_with_context')) {
    return { action: 'ask_operator', operatorQuestion: 'O conselho divergiu entre concluir e continuar a sessão.' };
  }
  if (actions.has('continue_with_context')) return { action: 'continue_with_context', operatorQuestion: null };
  if (actions.has('finish')) return { action: 'finish', operatorQuestion: null };
  return { action: 'abstain', operatorQuestion: null };
}

function forgeConsensus(turns) {
  const valid = turns.filter((t) => t.ok && t.decision);
  const candidates = valid.filter((t) => t.decision.action === 'forge_module' && t.decision.forgeRequest);
  if (!candidates.length) return null;
  const threshold = Math.floor(valid.length / 2) + 1;
  const groups = new Map();
  for (const turn of candidates) {
    const id = turn.decision.forgeRequest.proposedId;
    if (!groups.has(id)) groups.set(id, []);
    groups.get(id).push(turn);
  }
  const winner = [...groups.entries()].sort((a, b) => b[1].length - a[1].length)[0];
  if (!winner || winner[1].length < threshold) return null;
  return {
    ...winner[1][0].decision.forgeRequest,
    author: winner[1][0].provider,
    authorModel: winner[1][0].model || null,
    approvals: winner[1].map((t) => t.provider),
  };
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
        });
      } catch (error) {
        if (preferredRunner !== runner && !session?.signal?.aborted) {
          try {
            result = await runner({
              target, mode, catalog, ragContext, root, env, fetchImpl, execFileImpl,
              role, iteration, peerDecisions, observationBundle, signal: session?.signal,
              maxContextChars: session?.limits?.maxContextChars,
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
  const requestedModules = moduleConsensus(verdictTurns, moduleConsensus(proposals));
  const forgeRequest = forgeConsensus(verdictTurns) || forgeConsensus(proposals);
  const actionVerdict = actionConsensus(verdictTurns, requestedModules, forgeRequest);
  const successful = verdictTurns.filter((t) => t.ok);
  const confidence = successful.length
    ? successful.reduce((sum, t) => sum + Number(t.decision?.confidence || 0), 0) / successful.length
    : 0;
  const finalDecision = successful.length ? {
    action: actionVerdict.action,
    objective: 'Decisão consolidada pelo conselho de agentes selecionados',
    reasoningSummary: successful.flatMap((t) => (t.decision?.reasoningSummary || []).map((x) => `${t.provider}: ${x}`)).slice(0, 30),
    evidenceRefs: [...new Set(successful.flatMap((t) => t.decision?.evidenceRefs || []))],
    requestedModules,
    rejectedModules: successful.flatMap((t) => t.decision?.rejectedModules || []),
    confidence: Math.max(0, Math.min(1, confidence)),
    assumptions: [...new Set(successful.flatMap((t) => t.decision?.assumptions || []))],
    operatorQuestion: actionVerdict.operatorQuestion,
    forgeRequest,
    council: {
      selected: selected.map((p) => p.id),
      proposalProviders: proposals.filter((t) => t.ok).map((t) => t.provider),
      reviewProviders: reviews.filter((t) => t.ok).map((t) => t.provider),
      quorum: successful.length,
    },
  } : null;
  return { selected: selected.map((p) => p.id), proposals, reviews, finalDecision };
}
