import { after, before, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { listVigoliumModules } from '../../bridge/vigolium-catalog.mjs';

let fixtureRoot;

async function writeModule(kind, dirName, metadata) {
  const dir = path.join(fixtureRoot, 'vigolium', 'pkg', 'modules', kind, dirName);
  await fs.mkdir(dir, { recursive: true });
  await fs.writeFile(path.join(dir, 'metadata.go'), metadata, 'utf8');
}

describe('vigolium catalog', () => {
  before(async () => {
    fixtureRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-vigolium-catalog-'));
    await writeModule('active', 'authz_compare', `package authz_compare
const (
  ModuleID = "authz-compare"
  ModuleName = "Authorization comparison"
  ModuleShort = "Compare access-control responses"
  ModuleDesc = "Authorized IDOR and access-control comparison"
  ModuleSeverity = severity.High
  ModuleConfidence = severity.Medium
)
var ModuleTags = []string{"access-control", "idor"}
`);
    await writeModule('passive', 'fingerprint', `package fingerprint
const (
  ModuleID = "fingerprint"
  ModuleName = "Passive fingerprint"
  ModuleShort = "Fingerprint public responses"
  ModuleDesc = "Passive technology fingerprinting"
  ModuleSeverity = severity.Info
  ModuleConfidence = severity.High
)
var ModuleTags = []string{"fingerprint", "passive"}
`);
  });

  after(async () => {
    await fs.rm(fixtureRoot, { recursive: true, force: true });
  });

  it('lista metadados locais dos modulos', async () => {
    const out = await listVigoliumModules({ root: fixtureRoot, q: 'authz' });
    assert.equal(out.ok, true);
    assert.ok(out.counts.total > 0);
    const authz = out.modules.find((m) => m.id === 'authz-compare');
    assert.ok(authz);
    assert.equal(authz.kind, 'active');
    assert.ok(authz.tags.includes('access-control'));
    assert.ok(authz.tags.includes('idor'));
  });

  it('filtra por tag e kind sem executar Vigolium', async () => {
    const byTag = await listVigoliumModules({ root: fixtureRoot, tag: 'access-control' });
    assert.ok(byTag.modules.length > 0);
    assert.ok(byTag.modules.every((m) => m.tags.includes('access-control')));

    const passive = await listVigoliumModules({ root: fixtureRoot, kind: 'passive', q: 'fingerprint' });
    assert.ok(passive.modules.length > 0);
    assert.ok(passive.modules.every((m) => m.kind === 'passive'));
  });
});
