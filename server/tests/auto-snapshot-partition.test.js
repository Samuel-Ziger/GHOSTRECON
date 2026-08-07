import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import {
  createAutoSession,
  readAutoSessionSnapshot,
  resolveAutoSessionSnapshotDir,
  writeAutoSessionSnapshot,
} from '../auto-agent/session-store.mjs';
import { resolveAutoRagPartitionKey } from '../auto-agent/rag-memory.mjs';

test('snapshot Auto é particionado por principal/engagement/alvo', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-auto-snap-part-'));
  try {
    const owner = { sub: 'alice', role: 'operator' };
    const session = createAutoSession({
      sessionId: 'session-partition-alice-1',
      requestRunId: 'run-part-1',
      target: 'a.example.test',
      ownerPrincipal: owner,
    });
    session.state.engagementId = 'ENG-A';
    const file = await writeAutoSessionSnapshot(root, session.state, {});
    const part = resolveAutoRagPartitionKey({
      principalId: 'alice',
      engagementId: 'ENG-A',
      target: 'a.example.test',
    });
    assert.match(file.replace(/\\/g, '/'), new RegExp(`tenants/${part}/sessions/session-partition-alice-1`));
    assert.equal(
      resolveAutoSessionSnapshotDir(root, {
        sessionId: 'session-partition-alice-1',
        owner,
        engagementId: 'ENG-A',
        target: 'a.example.test',
      }).replace(/\\/g, '/').includes(`tenants/${part}/sessions/`),
      true,
    );

    const loaded = await readAutoSessionSnapshot(root, 'session-partition-alice-1', {}, {
      principal: owner,
      engagementId: 'ENG-A',
      target: 'a.example.test',
    });
    assert.equal(loaded.owner.sub, 'alice');
    assert.equal(loaded.engagementId, 'ENG-A');

    await assert.rejects(
      readAutoSessionSnapshot(root, 'session-partition-alice-1', {}, {
        principal: { sub: 'bob', role: 'operator' },
      }),
      /outro principal|não encontrado/i,
    );

    const legacy = path.join(root, 'data/auto-rag/sessions/session-partition-alice-1/session.json');
    await assert.rejects(fs.stat(legacy), { code: 'ENOENT' });
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});
