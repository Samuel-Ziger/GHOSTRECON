import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import {
  listAutoRagMarkdown,
  resolveAutoRagPartitionKey,
  writeAutoRagNote,
} from '../auto-agent/rag-memory.mjs';
import { resolveAutoRagRequestPartition } from '../routes/auto-recon.mjs';

test('resolveAutoRagRequestPartition exige principal e isola por keys', () => {
  assert.throws(
    () => resolveAutoRagRequestPartition({ principal: null, query: {} }),
    (error) => error?.status === 401,
  );
  const part = resolveAutoRagRequestPartition({
    principal: { sub: 'alice' },
    query: { target: 'a.example.test', engagementId: 'ENG-A' },
  });
  assert.deepEqual(part, {
    principalId: 'alice',
    engagementId: 'ENG-A',
    target: 'a.example.test',
  });
  assert.notEqual(
    resolveAutoRagPartitionKey(part),
    resolveAutoRagPartitionKey({
      principalId: 'bob',
      engagementId: 'ENG-A',
      target: 'a.example.test',
    }),
  );
});

test('listagem RAG particionada não cruza principals', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-rag-part-'));
  const env = {
    GHOSTRECON_AUTO_RAG_ENABLED: '1',
    GHOSTRECON_AUTO_RAG_PARTITION: '1',
    GHOSTRECON_AUTO_RAG_DIR: path.join(root, 'vault'),
  };
  try {
    await writeAutoRagNote({
      root,
      env,
      title: 'alice secret',
      body: 'token-alice',
      target: 'example.test',
      principalId: 'alice',
      engagementId: 'ENG-1',
    });
    await writeAutoRagNote({
      root,
      env,
      title: 'bob secret',
      body: 'token-bob',
      target: 'example.test',
      principalId: 'bob',
      engagementId: 'ENG-1',
    });

    const alice = await listAutoRagMarkdown({
      root,
      env,
      limit: 50,
      principalId: 'alice',
      engagementId: 'ENG-1',
      target: 'example.test',
    });
    const bob = await listAutoRagMarkdown({
      root,
      env,
      limit: 50,
      principalId: 'bob',
      engagementId: 'ENG-1',
      target: 'example.test',
    });

    assert.equal(alice.length, 1);
    assert.equal(bob.length, 1);
    assert.match(alice[0].preview, /token-alice/);
    assert.doesNotMatch(alice[0].preview, /token-bob/);
    assert.match(bob[0].preview, /token-bob/);
    assert.doesNotMatch(bob[0].preview, /token-alice/);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});
