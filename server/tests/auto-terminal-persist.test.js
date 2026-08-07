import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { runAutoRecon } from '../auto-agent/orchestrator.mjs';

test('falha de persistência do snapshot impede auto_session completed', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-auto-persist-block-'));
  const emitted = [];
  try {
    // RAG dir como arquivo: mkdir do snapshot falha (persistência obrigatória).
    const fileAsDir = path.join(root, 'blocked-rag');
    await fs.writeFile(fileAsDir, 'not-a-dir', 'utf8');
    await assert.rejects(
      runAutoRecon({
        body: {
          domain: 'example.test',
          commanders: [],
          modules: [],
          autonomyLevel: 'observation',
          approvalMode: 'deny',
        },
        ROOT: root,
        env: {
          GHOSTRECON_AUTO_RAG_ENABLED: '0',
          GHOSTRECON_AUTO_RAG_DIR: fileAsDir,
          GHOSTRECON_AUTO_HEARTBEAT_MS: '60000',
        },
        principal: { sub: 'persist-op', role: 'operator' },
        runPipeline: async () => {
          assert.fail('pipeline não deve iniciar sem snapshot inicial');
        },
        emit: (event) => emitted.push(event),
      }),
      (error) => Boolean(error),
    );
    assert.equal(
      emitted.some((event) => event.type === 'auto_session' && event.phase === 'completed'),
      false,
    );
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});
