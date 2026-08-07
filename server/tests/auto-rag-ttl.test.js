import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import {
  listAutoRagMarkdown,
  loadAutoRagContext,
  pruneExpiredAutoRagMarkdown,
  readAutoRagMarkdown,
  writeAutoRagNote,
} from '../auto-agent/rag-memory.mjs';

test('memória RAG expirada não é listada, lida nem carregada no contexto', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-rag-ttl-'));
  const env = {
    GHOSTRECON_AUTO_RAG_ENABLED: '1',
    GHOSTRECON_AUTO_RAG_PARTITION: '1',
    GHOSTRECON_AUTO_RAG_DIR: path.join(root, 'vault'),
    GHOSTRECON_AUTO_RAG_TTL_DAYS: '1',
  };
  try {
    const fresh = await writeAutoRagNote({
      root,
      env,
      title: 'fresh note',
      body: 'still-valid',
      target: 'example.test',
      principalId: 'alice',
      engagementId: 'ENG-1',
    });
    const staleDir = path.dirname(fresh.filePath);
    const staleName = '2010-01-01T00-00-00-000Z-stale-note-deadbeef.md';
    const stalePath = path.join(staleDir, staleName);
    await fs.writeFile(stalePath, [
      '---',
      'type: "ghostrecon-auto-memory"',
      'kind: "note"',
      'target: "example.test"',
      'created: "2010-01-01T00:00:00.000Z"',
      'tags: ["note"]',
      '---',
      '',
      '# stale note',
      '',
      'expired-secret',
      '',
    ].join('\n'), 'utf8');

    const listed = await listAutoRagMarkdown({
      root,
      env,
      limit: 50,
      principalId: 'alice',
      engagementId: 'ENG-1',
      target: 'example.test',
    });
    assert.ok(listed.some((item) => item.path === fresh.filePath));
    assert.equal(listed.some((item) => item.path === stalePath), false);

    await assert.rejects(
      readAutoRagMarkdown(`notes/${staleName}`, {
        root,
        env,
        principalId: 'alice',
        engagementId: 'ENG-1',
        target: 'example.test',
      }),
      (error) => error?.code === 'AUTO_RAG_EXPIRED',
    );

    const ctx = await loadAutoRagContext({
      root,
      env,
      target: 'example.test',
      principalId: 'alice',
      engagementId: 'ENG-1',
      limit: 20,
    });
    assert.equal(ctx.items.some((item) => /stale/.test(item.name)), false);
    assert.ok(ctx.items.some((item) => /fresh/.test(item.name)));

    const pruned = await pruneExpiredAutoRagMarkdown({
      root,
      env,
      principalId: 'alice',
      engagementId: 'ENG-1',
      target: 'example.test',
    });
    assert.ok(pruned.removed >= 1);
    await assert.rejects(fs.stat(stalePath), { code: 'ENOENT' });
    await fs.stat(fresh.filePath);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});
