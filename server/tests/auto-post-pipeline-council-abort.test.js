import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { runAutoRecon } from '../auto-agent/orchestrator.mjs';
import { getActiveAutoSession } from '../auto-agent/active-sessions.mjs';

function decision(action = 'run_modules', modules = ['rdap']) {
  return {
    action,
    objective: 'authorized_recon',
    reasoningSummary: ['fixture'],
    evidenceRefs: [],
    requestedModules: modules,
    rejectedModules: [],
    confidence: 0.9,
    assumptions: [],
    operatorQuestion: null,
    forgeRequest: null,
  };
}

test('abort no conselho pós-pipeline não anuncia heuristic_evaluation', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-auto-postpipe-'));
  const emitted = [];
  let openrouterCalls = 0;
  let sessionId = null;
  try {
    await assert.rejects(
      runAutoRecon({
        body: {
          domain: 'example.test',
          mode: 'balanced',
          commanders: ['openrouter'],
          modules: ['rdap'],
          autonomyLevel: 'observation',
          approvalMode: 'deny',
          cloudEvidenceConsent: true,
        },
        ROOT: root,
        env: {
          OPENROUTER_API_KEY: 'test',
          GHOSTRECON_AUTO_CLOUD_EVIDENCE_CONSENT: '1',
          GHOSTRECON_AUTO_RAG_ENABLED: '0',
          GHOSTRECON_AUTO_HEARTBEAT_MS: '60000',
        },
        principal: { sub: 'operator-postpipe', role: 'operator' },
        runPipeline: async ({ emit }) => {
          emit({ type: 'pipe', name: 'rdap', state: 'done' });
        },
        fetchImpl: async () => {
          openrouterCalls += 1;
          // 1 = planner; chamadas seguintes = pós-pipeline / review.
          if (openrouterCalls >= 2) {
            const active = getActiveAutoSession(sessionId);
            active?.abort('cancelled_during_post_pipeline');
            const err = new Error('cancelled_during_post_pipeline');
            err.name = 'AbortError';
            throw err;
          }
          return {
            ok: true,
            status: 200,
            json: async () => ({
              choices: [{ message: { content: JSON.stringify(decision('run_modules', ['rdap'])) } }],
            }),
          };
        },
        emit: (event) => {
          emitted.push(event);
          if (event.type === 'auto_session' && event.phase === 'started') {
            sessionId = event.sessionId;
          }
        },
      }),
      (error) => /cancelled_during_post_pipeline|abort|cancel/i.test(String(error?.message || error)),
    );

    assert.ok(openrouterCalls >= 2);
    assert.equal(
      emitted.some((event) => event?.fallback === 'heuristic_evaluation'),
      false,
    );
    assert.ok(emitted.some((event) => (
      event.type === 'auto_session'
      && ['cancelled', 'interrupted', 'failed'].includes(event.phase)
    )));
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});
