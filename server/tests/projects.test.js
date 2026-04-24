import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs/promises';
import { listProjects, upsertProject, getProject, removeProject, addProjectScope, removeProjectScope, hostMatchesScope, attachRunToProject } from '../modules/projects.mjs';

// Isola o store por test run usando GHOSTRECON_PROJECTS_DIR.
function setupIsolatedStore() {
  const dir = path.join(os.tmpdir(), `ghostrecon-test-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`);
  process.env.GHOSTRECON_PROJECTS_DIR = dir;
  process.chdir(os.tmpdir());
  return dir;
}

test('projects: upsert + list + get', async () => {
  setupIsolatedStore();
  await upsertProject({ name: 'acme', description: 'Acme Corp', scope: ['*.acme.com'] });
  const list = await listProjects();
  assert.ok(list.find((p) => p.name === 'acme'));
  const p = await getProject('acme');
  assert.equal(p.name, 'acme');
  assert.deepEqual(p.scope, ['*.acme.com']);
});

test('projects: addProjectScope e removeProjectScope', async () => {
  setupIsolatedStore();
  await upsertProject({ name: 'foo', scope: ['*.foo.com'] });
  await addProjectScope('foo', 'api.foo.com');
  let p = await getProject('foo');
  assert.ok(p.scope.includes('api.foo.com'));
  await removeProjectScope('foo', 'api.foo.com');
  p = await getProject('foo');
  assert.ok(!p.scope.includes('api.foo.com'));
});

test('projects: removeProject', async () => {
  setupIsolatedStore();
  await upsertProject({ name: 'tmp' });
  assert.equal(await removeProject('tmp'), true);
  assert.equal(await getProject('tmp'), null);
});

test('projects: attachRunToProject registra no histórico', async () => {
  setupIsolatedStore();
  await upsertProject({ name: 'r' });
  await attachRunToProject('r', { runId: 42, target: 'example.com' });
  const p = await getProject('r');
  assert.equal(p.runs.length, 1);
  assert.equal(p.runs[0].runId, 42);
});

test('projects: attachRunToProject silencioso se projeto não existe', async () => {
  setupIsolatedStore();
  await attachRunToProject('sem-projeto', { runId: 1, target: 'x.com' });
  // Não deve lançar nem criar projeto
  assert.equal(await getProject('sem-projeto'), null);
});

test('projects: upsert rejeita nome inválido', async () => {
  setupIsolatedStore();
  await assert.rejects(() => upsertProject({ name: '' }));
  await assert.rejects(() => upsertProject({ name: 'bad;chars' }));
});

test('hostMatchesScope: apex match', () => {
  assert.equal(hostMatchesScope('example.com', ['example.com']), true);
  assert.equal(hostMatchesScope('api.example.com', ['example.com']), false);
});

test('hostMatchesScope: wildcard', () => {
  assert.equal(hostMatchesScope('api.example.com', ['*.example.com']), true);
  assert.equal(hostMatchesScope('example.com', ['*.example.com']), false); // wildcard requer sub
  assert.equal(hostMatchesScope('other.com', ['*.example.com']), false);
});

test('hostMatchesScope: scope vazio = tudo permitido', () => {
  assert.equal(hostMatchesScope('example.com', []), true);
});
