import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { runAutoRecon } from '../auto-agent/orchestrator.mjs';

function finishDecision() {
  return {
    action: 'finish',
    objective: 'done',
    reasoningSummary: ['ok'],
    evidenceRefs: [],
    requestedModules: [],
    rejectedModules: [],
    confidence: 0.9,
    assumptions: [],
    operatorQuestion: null,
    forgeRequest: null,
  };
}

test('desconexão HTTP aborta e captureEmit não segue com eventos não-terminais', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-auto-disconnect-'));
  const controller = new AbortController();
  const emitted = [];
  let pipelineStarted = false;
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
        signal: controller.signal,
        principal: { sub: 'operator-disconnect', role: 'operator' },
        runPipeline: async () => {
          pipelineStarted = true;
          controller.abort(new Error('cliente desconectado'));
          await new Promise((resolve) => setTimeout(resolve, 20));
        },
        fetchImpl: async () => ({
          ok: true,
          status: 200,
          json: async () => ({
            choices: [{ message: { content: JSON.stringify(finishDecision()) } }],
          }),
        }),
        emit: (event) => emitted.push(event),
      }),
      (error) => /desconect|abort|cancel/i.test(String(error?.message || error)),
    );

    assert.equal(pipelineStarted, true);
    const afterAbort = [];
    let sawAbort = false;
    for (const event of emitted) {
      if (event?.type === 'auto_session' && ['cancelled', 'interrupted', 'failed', 'timed_out', 'stalled', 'budget_exceeded'].includes(event.phase)) {
        sawAbort = true;
        afterAbort.push(event);
        continue;
      }
      if (!sawAbort) continue;
      afterAbort.push(event);
    }
    // Após o terminal (ou a partir do abort), só terminais/persist/error podem aparecer.
    for (const event of afterAbort) {
      if (event?.type === 'auto_session') {
        assert.ok(['cancelled', 'interrupted', 'failed', 'timed_out', 'stalled', 'budget_exceeded', 'partial', 'completed'].includes(event.phase));
      } else {
        assert.ok(['auto_persist_failed', 'error'].includes(event?.type), event?.type);
      }
    }
    assert.equal(
      emitted.some((event) => event?.type === 'auto_heartbeat' && sawAbort),
      false,
    );
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});
