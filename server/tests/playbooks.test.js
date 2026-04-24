import test from 'node:test';
import assert from 'node:assert/strict';
import { listPlaybooks, resolvePlaybook, parseMinimalYaml } from '../modules/playbooks/loader.mjs';

test('listPlaybooks: carrega os bundled', async () => {
  const list = await listPlaybooks();
  const names = list.map((p) => p.name);
  assert.ok(names.includes('api-first'), `esperava api-first, vi ${names.join(',')}`);
  assert.ok(names.includes('wordpress'));
  assert.ok(names.includes('cloud-takeover'));
  assert.ok(names.includes('subdomain-hunt'));
});

test('resolvePlaybook: api-first tem modules', async () => {
  const pb = await resolvePlaybook('api-first');
  assert.equal(pb.name, 'api-first');
  assert.ok(Array.isArray(pb.modules));
  assert.ok(pb.modules.length > 3);
  assert.ok(pb.modules.includes('openapi_harvest'));
});

test('resolvePlaybook: case-insensitive', async () => {
  const pb = await resolvePlaybook('API-FIRST');
  assert.equal(pb.name, 'api-first');
});

test('resolvePlaybook: playbook inexistente falha', async () => {
  await assert.rejects(() => resolvePlaybook('xxx-does-not-exist'));
});

test('parseMinimalYaml: basic key/list/scalar', () => {
  const txt = `
name: foo
description: test
profile: standard
modules:
  - a
  - b
tags: [x, y]
num: 42
bool: true
`;
  const parsed = parseMinimalYaml(txt);
  assert.equal(parsed.name, 'foo');
  assert.equal(parsed.profile, 'standard');
  assert.deepEqual(parsed.modules, ['a', 'b']);
  assert.deepEqual(parsed.tags, ['x', 'y']);
  assert.equal(parsed.num, 42);
  assert.equal(parsed.bool, true);
});

test('parseMinimalYaml: ignora comentários', () => {
  const parsed = parseMinimalYaml('name: foo # comment\n# full line\n');
  assert.equal(parsed.name, 'foo');
});
