import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { runAutoRecon } from '../auto-agent/orchestrator.mjs';
import { readAutoSessionSnapshot } from '../auto-agent/session-store.mjs';
import { getActiveAutoSession } from '../auto-agent/active-sessions.mjs';

test('aprovação pendente é persistida no snapshot antes da espera', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-auto-approval-persist-'));
  const binary = path.join(root, 'FrameSeven', 'bin', 'frameseven', 'cli', 'v1');
  let sessionId = null;
  let snapshotBeforeResolve = null;
  try {
    await fs.mkdir(path.dirname(binary), { recursive: true });
    await fs.writeFile(binary, '#!/bin/sh\nexit 0\n', { mode: 0o755 });
    await fs.chmod(binary, 0o755);

    const runPromise = runAutoRecon({
      body: {
        domain: 'example.com',
        mode: 'balanced',
        commanders: [],
        modules: ['frameseven_recon'],
        includeFrameSeven: true,
        autonomyLevel: 'assisted',
        approvalMode: 'interactive',
      },
      ROOT: root,
      env: {
        GHOSTRECON_AUTO_RAG_ENABLED: '0',
        GHOSTRECON_AUTO_HEARTBEAT_MS: '60000',
        GHOSTRECON_ENGINE_SCOPE_SUPPORT: '1',
      },
      runPipeline: async () => {},
      runFrameSevenImpl: async () => ({ status: 'done', code: 0, outputDir: root }),
      emit: async (event) => {
        if (event.type === 'auto_approval_required') {
          sessionId = event.sessionId;
          snapshotBeforeResolve = await readAutoSessionSnapshot(root, sessionId, {
            GHOSTRECON_AUTO_RAG_ENABLED: '0',
          });
          const active = getActiveAutoSession(sessionId);
          active?.resolveApproval(
            event.approval.approvalId,
            true,
            'fixture aprovada após persistência',
          );
        }
      },
      fetchImpl: async () => ({ ok: false, status: 503 }),
      execFileImpl: async () => {
        throw new Error('provider indisponível');
      },
    });

    await runPromise;
    assert.ok(sessionId, 'esperava auto_approval_required');
    assert.ok(snapshotBeforeResolve, 'snapshot deveria existir antes do resolve');
    assert.equal(snapshotBeforeResolve.pendingApproval?.status, 'pending');
    assert.ok(snapshotBeforeResolve.pendingApproval?.approvalId);

    const finalSnapshot = await readAutoSessionSnapshot(root, sessionId, {
      GHOSTRECON_AUTO_RAG_ENABLED: '0',
    });
    assert.ok(Array.isArray(finalSnapshot.approvalTransitions));
    assert.ok(finalSnapshot.approvalTransitions.some((row) => (
      row.approvalId === snapshotBeforeResolve.pendingApproval.approvalId
      && row.from === 'pending'
      && row.to === 'approved'
    )));
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});
