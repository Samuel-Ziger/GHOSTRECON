import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { createPendingForgeRequest, resolveForgeRoot } from '../auto-agent/forge/forge-store.mjs';

test('Forge store rejeita author path traversal e cria dirs 0700', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-forge-hard-'));
  try {
    await assert.rejects(
      createPendingForgeRequest({
        root,
        requestRunId: 'run-1',
        target: 'example.com',
        decision: {
          forgeRequest: {
            proposedId: 'safe_module',
            intrusive: false,
            author: '../escape',
            approvals: [],
          },
        },
      }),
      /path inválido|fora do store/i,
    );

    const pending = await createPendingForgeRequest({
      root,
      requestRunId: 'run-2',
      target: 'example.com',
      decision: {
        forgeRequest: {
          proposedId: 'safe_module',
          intrusive: false,
          author: 'council',
          approvals: [],
        },
      },
    });
    assert.ok(pending.dir.startsWith(resolveForgeRoot(root)));
    const st = await fs.stat(pending.dir);
    if (process.platform !== 'win32') {
      assert.equal(st.mode & 0o777, 0o700);
    }
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});
