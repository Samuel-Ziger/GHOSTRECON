import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { listVigoliumModules } from '../../bridge/vigolium-catalog.mjs';

describe('vigolium catalog', () => {
  it('lista metadados locais dos modulos', async () => {
    const out = await listVigoliumModules({ root: process.cwd(), q: 'authz' });
    assert.equal(out.ok, true);
    assert.ok(out.counts.total > 0);
    const authz = out.modules.find((m) => m.id === 'authz-compare');
    assert.ok(authz);
    assert.equal(authz.kind, 'active');
    assert.ok(authz.tags.includes('access-control'));
    assert.ok(authz.tags.includes('idor'));
  });

  it('filtra por tag e kind sem executar Vigolium', async () => {
    const byTag = await listVigoliumModules({ root: process.cwd(), tag: 'access-control' });
    assert.ok(byTag.modules.length > 0);
    assert.ok(byTag.modules.every((m) => m.tags.includes('access-control')));

    const passive = await listVigoliumModules({ root: process.cwd(), kind: 'passive', q: 'fingerprint' });
    assert.ok(passive.modules.length > 0);
    assert.ok(passive.modules.every((m) => m.kind === 'passive'));
  });
});
