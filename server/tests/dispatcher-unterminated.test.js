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
    const error = new Error(
      'processo filho não terminou após SIGKILL; token=fixture-cancel-secret-123456789',
    );
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
    const cancelled = outcomes.find((row) => row.status === 'cancelled');
    assert.equal(cancelled.error.includes('fixture-cancel-secret'), false);
    assert.equal(cancelled.error.includes('[REDACTED]'), true);
  } finally {
    entry.run = original;
  }
});

test('resultado parcial do runner emite done com partial=true', async () => {
  const id = 'panel_exposure_audit';
  const entry = getRegistryEntry(id);
  assert.ok(entry?.run);
  const original = entry.run;
  entry.run = async () => ({
    findings: [],
    status: 'partial',
    reason: 'fixture_incomplete',
    attempted: 3,
    resultCount: 1,
    outcomeMetrics: {
      ...Object.fromEntries(Array.from(
        { length: 80 },
        (_, index) => [`unsafe_${index}`, index],
      )),
      authorization: 'Bearer fixture-must-not-leak',
      targetUrl: 'https://sensitive.example.test/private',
      attempts: 3,
      completed: 1,
      state_redirect_limit: 1,
      snapshotSchemaVersion: 2,
      canonicalizationVersion: 7,
      baselineBytesRead: 4096,
      baselineBytesRetained: 2048,
      baselineByteLimit: 8192,
      baselineByteLimitReached: false,
      deadlineReached: false,
      complete: true,
      changes: '1',
      secret: 1234,
    },
  });
  const outcomes = [];
  try {
    await dispatchRegistryModule({
      modules: [id],
      pipe: () => {},
      emit: (event) => { if (event?.type === 'module_outcome') outcomes.push(event); },
      log: () => {},
      addFinding: () => {},
    }, id);
    assert.deepEqual(outcomes.at(-1), {
      type: 'module_outcome',
      moduleId: id,
      status: 'done',
      source: 'registry',
      attempted: 3,
      resultCount: 1,
      metrics: {
        attempts: 3,
        completed: 1,
        state_redirect_limit: 1,
        snapshotSchemaVersion: 2,
        canonicalizationVersion: 7,
        baselineBytesRead: 4096,
        baselineBytesRetained: 2048,
        baselineByteLimit: 8192,
        baselineByteLimitReached: false,
        deadlineReached: false,
        complete: true,
      },
      partial: true,
      reason: 'fixture_incomplete',
    });
    assert.equal(JSON.stringify(outcomes).includes('fixture-must-not-leak'), false);
    assert.equal(JSON.stringify(outcomes).includes('sensitive.example.test'), false);
    assert.ok(Object.keys(outcomes.at(-1).metrics).length <= 64);
  } finally {
    entry.run = original;
  }
});

test('timeout cooperativo preserva finding e emite somente terminal timeout', async () => {
  const id = 'panel_exposure_audit';
  const entry = getRegistryEntry(id);
  assert.ok(entry?.run);
  const original = entry.run;
  entry.run = async () => ({
    findings: [{
      type: 'fixture_snapshot',
      prio: 'info',
      score: 1,
      value: 'resultado parcial preservado',
      meta: 'source=fixture',
      url: 'https://example.test/',
    }],
    status: 'timeout',
    partial: true,
    reason: 'module_deadline_exhausted',
    attempted: 2,
    resultCount: 1,
  });
  const outcomes = [];
  const pipes = [];
  const findings = [];
  try {
    await dispatchRegistryModule({
      modules: [id],
      pipe: (name, status) => pipes.push({ name, status }),
      emit: (event) => { if (event?.type === 'module_outcome') outcomes.push(event); },
      log: () => {},
      addFinding: (finding) => findings.push(finding),
    }, id);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].provenance?.how, id);
    assert.equal(pipes.some((row) => row.status === 'timeout'), true);
    assert.equal(pipes.some((row) => row.status === 'done'), false);
    assert.equal(outcomes.length, 1);
    assert.deepEqual(outcomes[0], {
      type: 'module_outcome',
      moduleId: id,
      status: 'timeout',
      source: 'registry',
      attempted: 2,
      resultCount: 1,
      partial: true,
      reason: 'module_deadline_exhausted',
    });
  } finally {
    entry.run = original;
  }
});

test('dispatcher redige e limita reason, error e log antes da fronteira de eventos', async () => {
  const id = 'panel_exposure_audit';
  const entry = getRegistryEntry(id);
  assert.ok(entry?.run);
  const original = entry.run;
  const outcomes = [];
  const logs = [];
  const state = {
    modules: [id],
    pipe: () => {},
    emit: (event) => { if (event?.type === 'module_outcome') outcomes.push(event); },
    log: (message, level) => logs.push({ message, level }),
    addFinding: () => {},
  };
  try {
    entry.run = async () => ({
      findings: [],
      status: 'partial',
      reason: `password=fixture-reason-secret ${'x'.repeat(300)}`,
      logOk: 'Authorization: Bearer fixture-log-secret-123456789',
      logLevel: 'Bearer fixture-level-secret-123456789',
    });
    await dispatchRegistryModule(state, id);

    const failed = new Error('request failed: token=fixture-error-secret-123456789');
    entry.run = async () => { throw failed; };
    await dispatchRegistryModule(state, id);

    const publicText = JSON.stringify({ outcomes, logs });
    assert.equal(publicText.includes('fixture-reason-secret'), false);
    assert.equal(publicText.includes('fixture-log-secret'), false);
    assert.equal(publicText.includes('fixture-error-secret'), false);
    assert.equal(publicText.includes('fixture-level-secret'), false);
    assert.equal(publicText.includes('[REDACTED]'), true);
    assert.equal(logs[0].level, 'info');
    assert.equal(outcomes[0].reason.length <= 240, true);
    assert.equal(outcomes[1].error.length <= 240, true);
    assert.equal(publicText.includes('\0'), false);
  } finally {
    entry.run = original;
  }
});

test('dispatcher redige erro de timeout antes de emitir e preserva a rejeição original', async () => {
  const id = 'panel_exposure_audit';
  const entry = getRegistryEntry(id);
  assert.ok(entry?.run);
  const original = entry.run;
  const timeout = new Error('timeout Authorization: Bearer fixture-timeout-secret-123456789');
  timeout.code = 'PROCESS_TIMEOUT';
  const outcomes = [];
  try {
    entry.run = async () => { throw timeout; };
    await assert.rejects(
      () => dispatchRegistryModule({
        modules: [id],
        pipe: () => {},
        emit: (event) => { if (event?.type === 'module_outcome') outcomes.push(event); },
        log: () => {},
        addFinding: () => {},
      }, id),
      (error) => error === timeout,
    );
    assert.equal(outcomes.length, 1);
    assert.equal(outcomes[0].status, 'timeout');
    assert.equal(outcomes[0].error.includes('fixture-timeout-secret'), false);
    assert.equal(outcomes[0].error.includes('[REDACTED]'), true);
  } finally {
    entry.run = original;
  }
});
