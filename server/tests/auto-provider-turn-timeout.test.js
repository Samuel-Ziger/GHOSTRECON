import test from 'node:test';
import assert from 'node:assert/strict';
import { runAgentCouncil } from '../auto-agent/council/council-runner.mjs';
import { createAutoSession } from '../auto-agent/session-store.mjs';

test('turno de provider respeita agentTimeoutMs isolado via AbortSignal', async () => {
  const session = createAutoSession({
    sessionId: 'session-turn-timeout01',
    requestRunId: 'run-turn-timeout01',
    target: 'example.test',
    env: {
      GHOSTRECON_AUTO_MAX_AGENT_CALLS: '10',
      GHOSTRECON_AUTO_AGENT_TIMEOUT_MS: '180000',
    },
  });
  session.limits = Object.freeze({ ...session.limits, agentTimeoutMs: 50 });
  session.state.limits = session.limits;
  session.state.cloudEvidenceConsent = true;
  try {
    await assert.rejects(
      () => runAgentCouncil({
        providers: [{
          id: 'openrouter',
          selected: true,
          usable: true,
          dataPlane: 'cloud',
          defaultModel: 'test/model',
        }],
        target: 'example.test',
        mode: 'balanced',
        catalog: { modules: [{ id: 'headers', class: 'passive', available: true, manifest: { name: 'headers' } }] },
        ragContext: { items: [] },
        session,
        env: {
          OPENROUTER_API_KEY: 'test-key',
          GHOSTRECON_CODEX_APP_SERVER: '0',
          GHOSTRECON_AUTO_CLOUD_EVIDENCE_CONSENT: '1',
        },
        fetchImpl: async (_url, opts = {}) => {
          await new Promise((_, reject) => {
            const signal = opts.signal;
            if (!signal) {
              setTimeout(() => reject(new Error('hang sem signal')), 5_000);
              return;
            }
            const onAbort = () => reject(signal.reason || new DOMException('aborted', 'AbortError'));
            if (signal.aborted) onAbort();
            else signal.addEventListener('abort', onAbort, { once: true });
          });
          return { ok: false, status: 599, json: async () => ({}) };
        },
      }),
      (error) => error?.code === 'AUTO_PROVIDER_TURN_TIMEOUT'
        || /provider_turn_timeout/i.test(String(error?.message || error)),
    );
  } finally {
    await session.close('cancelled');
  }
});
