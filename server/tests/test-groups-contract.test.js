import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

async function listGroup(group) {
  const { stdout } = await execFileAsync(process.execPath, [
    'scripts/run-server-tests.mjs',
    `--group=${group}`,
    '--list',
  ], { cwd: process.cwd() });
  return stdout.trim().split(/\r?\n/).filter(Boolean);
}

test('grupos core e integrações são disjuntos e classificam seus contratos', async () => {
  const [core, integrations] = await Promise.all([listGroup('core'), listGroup('integrations')]);
  const coreSet = new Set(core);
  assert.ok(coreSet.has('auth.test.js'));
  assert.ok(coreSet.has('support-matrix.test.js'));
  assert.ok(integrations.includes('frameseven-integration.test.js'));
  assert.ok(integrations.includes('vigolium-bridge.test.js'));
  assert.ok(integrations.includes('hexstrike-orchestrator.test.js'));
  assert.equal(integrations.some((name) => coreSet.has(name)), false);
  assert.equal(core.some((name) => name === 'pipeline-smoke.test.js'), false);
  assert.equal(integrations.some((name) => name === 'pipeline-smoke.test.js'), false);
});

test('runner recusa grupo desconhecido', async () => {
  await assert.rejects(
    execFileAsync(process.execPath, [
      'scripts/run-server-tests.mjs',
      '--group=unknown',
      '--list',
    ], { cwd: process.cwd() }),
    (error) => error?.code === 2 && /Grupo de testes inválido/.test(error.stderr),
  );
});
