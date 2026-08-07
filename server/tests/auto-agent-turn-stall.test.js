import test from 'node:test';
import assert from 'node:assert/strict';
import { createAutoSession } from '../auto-agent/session-store.mjs';

test('turno paralelo antigo não é mascarado por provider mais novo', async () => {
  const session = createAutoSession({
    sessionId: 'session-stall-parallel01',
    requestRunId: 'run-stall-parallel01',
    target: 'example.test',
  });
  try {
    session.touch({ type: 'auto_agent_turn_started', provider: 'codex', role: 'planner' });
    const idleAfterA = session.getAgentIdleMs();
    await new Promise((resolve) => setTimeout(resolve, 30));
    session.touch({ type: 'auto_agent_turn_started', provider: 'openrouter', role: 'planner' });
    const idleAfterB = session.getAgentIdleMs();
    // B começou depois; idle ainda ancora em A (≥ 30ms).
    assert.ok(idleAfterB >= 25, `idleAfterB=${idleAfterB}`);
    assert.ok(idleAfterB >= idleAfterA, 'idle não deve diminuir quando B entra');
    assert.equal(session.hasActiveAgentTurns(), true);

    session.touch({ type: 'auto_agent_turn_completed', provider: 'openrouter', role: 'planner' });
    assert.equal(session.hasActiveAgentTurns(), true);
    const idleOnlyA = session.getAgentIdleMs();
    assert.ok(idleOnlyA >= 25);

    session.touch({ type: 'auto_agent_turn_completed', provider: 'codex', role: 'planner' });
    assert.equal(session.hasActiveAgentTurns(), false);
    assert.equal(session.state.currentStage, 'idle');
  } finally {
    await session.close('cancelled');
  }
});
