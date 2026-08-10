import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { buildAutoToolCatalog } from '../auto-agent/tool-catalog.mjs';

test('catálogo Auto: FrameSeven sem binário fica unavailable com readiness tipada', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-catalog-ready-'));
  try {
    const catalog = await buildAutoToolCatalog({
      root,
      ghostRoot: root,
      includeFrameSeven: true,
      env: {},
    });
    const fsMods = catalog.modules.filter((m) => String(m.source || '').includes('frameseven')
      || String(m.id || '').startsWith('frameseven'));
    assert.ok(fsMods.length > 0);
    for (const mod of fsMods) {
      assert.equal(mod.available, false);
      assert.ok(mod.readiness);
      assert.equal(mod.readiness.ok, false);
      assert.ok(mod.readiness.reason);
      assert.ok(Array.isArray(mod.readiness.checks));
    }
    assert.equal(catalog.engines?.frameseven?.supportsSealedScopePolicy, false);

    const legacy = catalog.modules.find((m) => m.id === 'rdap' || m.id === 'subdomains');
    assert.ok(legacy);
    assert.equal(legacy.available, true);
    assert.equal(legacy.readiness?.ok, true);
    assert.ok(['legacy_assumed', 'ready'].includes(legacy.readiness?.reason));
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('redação cloud não destrói catalogHash em redactAutoValue', async () => {
  const { redactAutoText, redactAutoValue } = await import('../auto-agent/redaction.mjs');
  const hash = 'a'.repeat(64);
  const structural = redactAutoValue({ catalogHash: hash, note: 'user@example.com' });
  assert.equal(structural.catalogHash, hash);
  const cloud = redactAutoText(`plan ${hash} mail user@example.com`, {});
  assert.match(cloud, /\[REDACTED\]/);
  assert.equal(cloud.includes(hash), false);
});
