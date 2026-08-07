import test from 'node:test';
import assert from 'node:assert/strict';

import { getRegistryEntry } from '../modules/module-registry.mjs';
import { dispatchRegistryModule } from '../pipeline/dispatcher.mjs';

test('PROCESS_UNTERMINATED emite cancelled/module_outcome sem done', async () => {
  const id = 'panel_exposure_audit';
  const entry = getRegistryEntry(id);
  assert.ok(entry?.run, 'módulo de fixture precisa existir no registry');
  const original = entry.run;
  entry.run = async () => {
    const error = new Error('processo filho não terminou após SIGKILL');
    error.code = 'PROCESS_UNTERMINATED';
    throw error;
  };
  const pipes = [];
  const outcomes = [];
  try {
    const state = {
      modules: [id],
      pipe: (name, status) => pipes.push({ name, status }),
      emit: (event) => {
        if (event?.type === 'module_outcome') outcomes.push(event);
      },
      log: () => {},
      addFinding: () => {},
    };
    await assert.rejects(
      () => dispatchRegistryModule(state, id),
      (error) => error?.code === 'PROCESS_UNTERMINATED',
    );
    assert.ok(pipes.some((row) => row.status === 'cancelled'));
    assert.equal(pipes.some((row) => row.status === 'done'), false);
    assert.ok(outcomes.some((row) => row.status === 'cancelled' && row.moduleId === id));
    assert.equal(outcomes.some((row) => row.status === 'done'), false);
  } finally {
    entry.run = original;
  }
});
