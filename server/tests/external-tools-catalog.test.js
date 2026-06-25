import test from 'node:test';
import assert from 'node:assert/strict';

import { getExternalToolPack, listExternalToolPacks } from '../modules/external-tools/catalog.mjs';

test('external tool catalog exposes unique pipeline placements', () => {
  const packs = listExternalToolPacks();
  assert.ok(packs.length >= 10);

  const ids = new Set();
  for (const pack of packs) {
    assert.ok(pack.id);
    assert.ok(pack.name);
    assert.ok(pack.pipelineStage);
    assert.ok(pack.category);
    assert.ok(pack.entrypoint);
    assert.ok(pack.language);
    assert.equal(ids.has(pack.id), false, `duplicate id: ${pack.id}`);
    ids.add(pack.id);
  }

  assert.ok(packs.some((pack) => pack.pipelineStage === 'discovery'));
  assert.ok(packs.some((pack) => pack.pipelineStage === 'surface'));
  assert.ok(packs.some((pack) => pack.pipelineStage === 'validation'));
  assert.ok(packs.some((pack) => pack.pipelineStage === 'aggressive'));
  assert.ok(packs.some((pack) => pack.pipelineStage === 'standalone'));
});

test('external tool lookup normalizes kebab-case aliases', () => {
  assert.equal(getExternalToolPack('ssl-audit-kit')?.id, 'ssl_audit_kit');
  assert.equal(getExternalToolPack('idor_scanner')?.pipelineStage, 'validation');
});
