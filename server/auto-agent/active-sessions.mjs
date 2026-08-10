const activeSessions = new Map();

function envLimit(env, key, fallback) {
  const parsed = Number(env?.[key] ?? fallback);
  if (!Number.isFinite(parsed) || parsed < 0) return fallback;
  return Math.floor(parsed);
}

export function autoConcurrencyLimits(env = process.env) {
  return {
    maxGlobal: envLimit(env, 'GHOSTRECON_AUTO_MAX_SESSIONS_GLOBAL', 8),
    maxPerPrincipal: envLimit(env, 'GHOSTRECON_AUTO_MAX_SESSIONS_PER_PRINCIPAL', 2),
    maxPerEngine: envLimit(env, 'GHOSTRECON_AUTO_MAX_SESSIONS_PER_ENGINE', 4),
  };
}

function sessionEngines(session) {
  const state = sessionState(session);
  const engines = state?.engines || state?.checkpoint?.activePlan?.engines || {};
  const ids = [];
  if (engines?.frameseven?.enabled) ids.push('frameseven');
  if (engines?.vigolium?.enabled) ids.push('vigolium');
  if (engines?.ghostrecon?.enabled !== false) ids.push('ghostrecon');
  if (!ids.length) ids.push('ghostrecon');
  return ids;
}

/**
 * @returns {null | { code: string, message: string, limits: object, counts: object }}
 */
export function assertAutoConcurrencyAvailable(session, env = process.env) {
  const limits = autoConcurrencyLimits(env);
  const ownerSub = String(sessionState(session)?.owner?.sub || '').trim();
  const engines = sessionEngines(session);
  let globalCount = 0;
  let principalCount = 0;
  const engineCounts = Object.create(null);
  for (const active of activeSessions.values()) {
    globalCount += 1;
    const activeOwner = String(sessionState(active)?.owner?.sub || '').trim();
    if (ownerSub && activeOwner === ownerSub) principalCount += 1;
    for (const engine of sessionEngines(active)) {
      engineCounts[engine] = (engineCounts[engine] || 0) + 1;
    }
  }
  if (limits.maxGlobal > 0 && globalCount >= limits.maxGlobal) {
    return {
      code: 'AUTO_CONCURRENCY_LIMIT',
      message: `limite global de sessões Auto atingido (${limits.maxGlobal})`,
      limits,
      counts: { global: globalCount, principal: principalCount, engines: engineCounts },
    };
  }
  if (ownerSub && limits.maxPerPrincipal > 0 && principalCount >= limits.maxPerPrincipal) {
    return {
      code: 'AUTO_CONCURRENCY_LIMIT',
      message: `limite de sessões Auto por principal atingido (${limits.maxPerPrincipal})`,
      limits,
      counts: { global: globalCount, principal: principalCount, engines: engineCounts },
    };
  }
  if (limits.maxPerEngine > 0) {
    for (const engine of engines) {
      if ((engineCounts[engine] || 0) >= limits.maxPerEngine) {
        return {
          code: 'AUTO_CONCURRENCY_LIMIT',
          message: `limite de sessões Auto para engine ${engine} atingido (${limits.maxPerEngine})`,
          limits,
          counts: { global: globalCount, principal: principalCount, engines: engineCounts },
        };
      }
    }
  }
  return null;
}

function principalOwner(principal) {
  const sub = String(principal?.sub || '').trim();
  if (!sub) return null;
  return {
    sub,
    role: String(principal?.role || '').trim() || null,
    via: String(principal?.via || '').trim() || null,
  };
}

function sessionState(session) {
  return session?.state && typeof session.state === 'object' ? session.state : session;
}

export function autoSessionOwnership(session, principal) {
  if (!session) return 'not_found';
  const ownerSub = String(sessionState(session)?.owner?.sub || '').trim();
  const principalSub = String(principal?.sub || '').trim();
  if (!ownerSub) return 'unowned';
  if (!principalSub || ownerSub !== principalSub) return 'forbidden';
  return 'owned';
}

export function bindActiveAutoSessionOwner(sessionId, principal) {
  const session = activeSessions.get(String(sessionId || ''));
  const owner = principalOwner(principal);
  if (!session || !owner) return false;
  const current = principalOwner(session.state.owner);
  if (current && current.sub !== owner.sub) return false;
  session.state.owner = current || owner;
  return true;
}

export function registerActiveAutoSession(session, env = process.env) {
  if (!session?.state?.sessionId) throw new Error('sessão AUTO inválida');
  const sessionId = String(session.state.sessionId);
  if (activeSessions.has(sessionId)) throw new Error(`sessão AUTO já está ativa: ${sessionId}`);
  const limit = assertAutoConcurrencyAvailable(session, env);
  if (limit) {
    const error = new Error(limit.message);
    error.code = limit.code;
    error.limits = limit.limits;
    error.counts = limit.counts;
    throw error;
  }
  activeSessions.set(sessionId, session);
}

export function unregisterActiveAutoSession(sessionId) {
  activeSessions.delete(String(sessionId || ''));
}

export function cancelActiveAutoSession(sessionId, reason = 'cancelled_by_operator', { principal = null } = {}) {
  const session = activeSessions.get(String(sessionId || ''));
  if (!session) return false;
  if (principal && autoSessionOwnership(session, principal) !== 'owned') return false;
  session.abort(reason);
  return true;
}

export function getActiveAutoSession(sessionId) {
  return activeSessions.get(String(sessionId || '')) || null;
}

export function listActiveAutoSessions({ principal = null } = {}) {
  return [...activeSessions.values()]
    .filter((session) => !principal || autoSessionOwnership(session, principal) === 'owned')
    .map((session) => ({
      sessionId: session.state.sessionId,
      requestRunId: session.state.requestRunId,
      target: session.state.target,
      iteration: session.state.iteration,
      startedAt: session.state.startedAt,
      lastActivityAt: session.state.lastActivityAt,
      currentStage: session.state.currentStage,
      currentModule: session.state.currentModule,
    }));
}
