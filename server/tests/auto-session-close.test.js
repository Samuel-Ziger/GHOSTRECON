import test from 'node:test';
import assert from 'node:assert/strict';
import { createAutoSession } from '../auto-agent/session-store.mjs';

test('session.close aguarda resources async antes de finishedAt', async () => {
  const session = createAutoSession({
    sessionId: 'session-close-async01',
    requestRunId: 'run-close-async01',
    target: 'example.test',
  });
  let closedAt = 0;
  session.resources.push({
    async close() {
      await new Promise((resolve) => setTimeout(resolve, 40));
      closedAt = Date.now();
    },
  });
  const before = Date.now();
  const state = await session.close('completed');
  assert.ok(closedAt >= before);
  assert.ok(Date.parse(state.finishedAt) >= closedAt);
  assert.equal(state.status, 'completed');
  assert.equal(state.currentStage, null);
  assert.equal(session.resources.length, 0);
});
