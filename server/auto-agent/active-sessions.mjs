const activeSessions = new Map();

export function registerActiveAutoSession(session) {
  if (!session?.state?.sessionId) throw new Error('sessão AUTO inválida');
  activeSessions.set(session.state.sessionId, session);
}

export function unregisterActiveAutoSession(sessionId) {
  activeSessions.delete(String(sessionId || ''));
}

export function cancelActiveAutoSession(sessionId, reason = 'cancelled_by_operator') {
  const session = activeSessions.get(String(sessionId || ''));
  if (!session) return false;
  session.abort(reason);
  return true;
}

export function listActiveAutoSessions() {
  return [...activeSessions.values()].map((session) => ({
    sessionId: session.state.sessionId,
    requestRunId: session.state.requestRunId,
    target: session.state.target,
    iteration: session.state.iteration,
    startedAt: session.state.startedAt,
  }));
}
