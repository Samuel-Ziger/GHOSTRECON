const activeSessions = new Map();

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

export function registerActiveAutoSession(session) {
  if (!session?.state?.sessionId) throw new Error('sessão AUTO inválida');
  const sessionId = String(session.state.sessionId);
  if (activeSessions.has(sessionId)) throw new Error(`sessão AUTO já está ativa: ${sessionId}`);
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
