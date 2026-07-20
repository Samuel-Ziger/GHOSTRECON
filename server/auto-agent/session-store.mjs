import fs from 'node:fs/promises';
import path from 'node:path';

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

export function createAutoSession({ sessionId, requestRunId, target, providers = [], env = process.env, restoredState = null } = {}) {
  const limits = autoSessionLimits(env);
  const controller = new AbortController();
  const startedAt = Date.now();
  const state = {
    schemaVersion: 1, sessionId, requestRunId, target, startedAt: new Date(startedAt).toISOString(),
    status: 'running', iteration: 0, agentCalls: 0, usage: {}, costUsd: 0,
    providers: providers.map((p) => p.id), limits,
    ...(restoredState || {}),
    sessionId, requestRunId, target, status: 'running', limits,
  };
  const timer = setTimeout(() => controller.abort(new Error('auto_session_timeout')), limits.sessionTimeoutMs);
  timer.unref?.();
  return {
    state,
    limits,
    signal: controller.signal,
    abort(reason = 'cancelled') { controller.abort(new Error(String(reason))); },
    assertActive() {
      if (controller.signal.aborted) throw controller.signal.reason || new Error('sessão AUTO cancelada');
      if (Date.now() - startedAt >= limits.sessionTimeoutMs) throw new Error('limite de tempo da sessão AUTO atingido');
    },
    reserveAgentCall(provider) {
      this.assertActive();
      if (state.agentCalls >= limits.maxAgentCalls) throw new Error('limite de chamadas de IA atingido');
      state.agentCalls += 1;
      state.usage[provider] ||= { calls: 0, promptTokens: 0, completionTokens: 0, totalTokens: 0, costUsd: 0 };
      state.usage[provider].calls += 1;
    },
    recordUsage(provider, usage = {}) {
      const row = state.usage[provider] ||= { calls: 0, promptTokens: 0, completionTokens: 0, totalTokens: 0, costUsd: 0 };
      row.promptTokens += Number(usage.prompt_tokens ?? usage.input_tokens ?? 0) || 0;
      row.completionTokens += Number(usage.completion_tokens ?? usage.output_tokens ?? 0) || 0;
      row.totalTokens += Number(usage.total_tokens ?? 0) || 0;
      const key = String(provider || '').toUpperCase().replace(/[^A-Z0-9]/g, '_');
      const inputRate = Number(env[`GHOSTRECON_AUTO_${key}_INPUT_USD_PER_MILLION`] || 0);
      const outputRate = Number(env[`GHOSTRECON_AUTO_${key}_OUTPUT_USD_PER_MILLION`] || 0);
      const estimated = ((Number(usage.prompt_tokens ?? usage.input_tokens ?? 0) || 0) * inputRate
        + (Number(usage.completion_tokens ?? usage.output_tokens ?? 0) || 0) * outputRate) / 1_000_000;
      const reported = Number(usage.cost ?? usage.cost_usd);
      const cost = Number.isFinite(reported) ? reported : estimated;
      row.costUsd += cost;
      row.costEstimated = !Number.isFinite(reported);
      state.costUsd += cost;
      if (limits.maxCostUsd > 0 && state.costUsd > limits.maxCostUsd) controller.abort(new Error('budget de custo da sessão atingido'));
    },
    close(status = 'completed') {
      clearTimeout(timer);
      for (const resource of this.resources || []) {
        try { resource.close?.(); } catch { /* ignore */ }
      }
      state.status = status;
      state.finishedAt = new Date().toISOString();
      state.durationMs = Date.now() - startedAt;
      return state;
    },
    resources: [],
  };
}

export async function writeAutoSessionSnapshot(root, session, env = process.env) {
  const configured = String(env.GHOSTRECON_AUTO_RAG_DIR || '').trim();
  const ragRoot = configured ? path.resolve(configured) : path.join(root, 'data', 'auto-rag');
  const dir = path.join(ragRoot, 'sessions', session.sessionId);
  await fs.mkdir(dir, { recursive: true });
  const file = path.join(dir, 'session.json');
  await fs.writeFile(file, JSON.stringify(session, null, 2), 'utf8');
  return file;
}

export async function readAutoSessionSnapshot(root, sessionId, env = process.env) {
  const safe = String(sessionId || '').trim();
  if (!/^session-[a-z0-9-]{8,100}$/i.test(safe)) throw new Error('sessionId inválido');
  const configured = String(env.GHOSTRECON_AUTO_RAG_DIR || '').trim();
  const ragRoot = configured ? path.resolve(configured) : path.join(root, 'data', 'auto-rag');
  const file = path.join(ragRoot, 'sessions', safe, 'session.json');
  return fs.readFile(file, 'utf8').then(JSON.parse);
}
