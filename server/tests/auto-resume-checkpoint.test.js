import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { buildAutoToolCatalog } from '../auto-agent/tool-catalog.mjs';
import {
  buildAutoResumePolicy,
  computeAutoCatalogHash,
  normalizeAutoRequest,
  runAutoRecon,
} from '../auto-agent/orchestrator.mjs';
import {
  assertAutoResumeSnapshotCompatible,
  claimAutoResumeCheckpoint,
  computeAutoCheckpointHash,
  computeAutoReadyPlanHash,
  computeAutoResumePolicyHash,
  createAutoCheckpoint,
  createAutoSession,
  readAutoSessionSnapshot,
  reconcileOrphanedAutoSessions,
  validateAutoCheckpoint,
  writeAutoSessionSnapshot,
} from '../auto-agent/session-store.mjs';

const PROMPT_VERSION = 'auto-council-v3';
function requestBody(overrides = {}) {
  return {
    domain: 'example.com',
    autoMode: 'balanced',
    commanders: [],
    modules: ['rdap'],
    includeDeepPassive: false,
    includeHexstrike: false,
    autonomyLevel: 'observation',
    approvalMode: 'deny',
    ...overrides,
  };
}

async function makeCheckpointSession(root, {
  checkpointStatus,
  sessionId,
  iteration = checkpointStatus === 'ready_for_iteration' ? 0 : 1,
} = {}) {
  const body = requestBody();
  const req = normalizeAutoRequest(body);
  const catalog = await buildAutoToolCatalog({
    includeHexstrike: false,
    includeDeepPassive: false,
    includeIntrusive: false,
    includeFrameSeven: false,
    includeVigolium: false,
    forgeRuntimeAvailable: false,
    ghostRoot: root,
  });
  const session = createAutoSession({
    sessionId,
    requestRunId: `run-${sessionId}`,
    target: req.target,
    providers: req.commanders,
  });
  Object.assign(session.state, {
    autonomyLevel: req.autonomyLevel,
    includeFrameSeven: false,
    frameSevenAuth: false,
    includeVigolium: false,
    vigoliumUseCodex: false,
    engagementId: null,
    mode: req.mode,
    resumePolicy: buildAutoResumePolicy(req, body),
    catalogHash: computeAutoCatalogHash(catalog),
    promptVersion: PROMPT_VERSION,
    iteration,
  });
  const planHash = computeAutoReadyPlanHash({
    catalogHash: session.state.catalogHash,
    promptVersion: session.state.promptVersion,
    iteration: checkpointStatus === 'ready_for_iteration' ? 1 : iteration,
    modules: ['rdap'],
    resumePolicyHash: computeAutoResumePolicyHash(session.state.resumePolicy),
  });

  const history = iteration > 0
    ? [{
        iteration: 1,
        modules: ['rdap'],
        effectivePlanHash: planHash,
      }]
    : [];
  const activePlan = checkpointStatus === 'completed'
    ? null
    : {
        iteration: checkpointStatus === 'ready_for_iteration' ? 1 : iteration,
        hash: planHash,
        modules: ['rdap'],
        stage: checkpointStatus === 'ready_for_iteration' ? 'ready' : 'running',
        engineOutcomes: [],
        moduleOutcomes: [],
      };
  session.state.checkpoint = createAutoCheckpoint(session.state, {
    status: checkpointStatus,
    currentIteration: iteration,
    nextIteration: checkpointStatus === 'ready_for_iteration' ? 1 : null,
    nextModules: checkpointStatus === 'ready_for_iteration' ? ['rdap'] : [],
    executedModules: checkpointStatus === 'completed' ? ['rdap'] : [],
    iterationHistory: history,
    activePlan,
  });
  return { body, catalog, session };
}

test('checkpoint versionado faz round-trip atômico e valida vínculos de retomada', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-auto-checkpoint-'));
  const env = { GHOSTRECON_AUTO_RAG_DIR: path.join(root, 'rag') };
  const { session } = await makeCheckpointSession(root, {
    checkpointStatus: 'ready_for_iteration',
    sessionId: 'session-checkpoint-ready01',
  });
  try {
    const file = await writeAutoSessionSnapshot(root, session.state, env);
    const restored = await readAutoSessionSnapshot(root, session.state.sessionId, env);
    assert.equal(restored.checkpoint.checkpointVersion, 2);
    assert.equal(restored.checkpoint.status, 'ready_for_iteration');
    assert.equal(
      restored.checkpoint.checkpointHash,
      computeAutoCheckpointHash(restored.checkpoint),
    );
    assert.doesNotThrow(() => assertAutoResumeSnapshotCompatible(restored, {
      expectedCatalogHash: session.state.catalogHash,
      expectedPromptVersion: PROMPT_VERSION,
    }));
    assert.deepEqual(await fs.readdir(path.dirname(file)), ['session.json']);
  } finally {
    session.close('cancelled');
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('checkpoint rejeita hash adulterado, IDs inválidos, campos ausentes e bounds', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-auto-checkpoint-invalid-'));
  const { session } = await makeCheckpointSession(root, {
    checkpointStatus: 'ready_for_iteration',
    sessionId: 'session-checkpoint-invalid01',
  });
  try {
    const base = structuredClone(session.state.checkpoint);

    const tampered = structuredClone(base);
    tampered.nextModules = ['security_headers'];
    assert.throws(() => validateAutoCheckpoint(tampered), /checkpointHash/);

    const invalidId = structuredClone(base);
    invalidId.nextModules = ['bad module'];
    invalidId.checkpointHash = computeAutoCheckpointHash(invalidId);
    assert.throws(() => validateAutoCheckpoint(invalidId), /ID inválido/);

    const invalidBound = structuredClone(base);
    invalidBound.nextIteration = 99;
    invalidBound.checkpointHash = computeAutoCheckpointHash(invalidBound);
    assert.throws(
      () => validateAutoCheckpoint(invalidBound, { maxIterations: 3 }),
      /nextIteration/,
    );

    const mismatchedPlan = structuredClone(base);
    mismatchedPlan.nextModules = ['security_headers'];
    mismatchedPlan.checkpointHash = computeAutoCheckpointHash(mismatchedPlan);
    assert.throws(
      () => validateAutoCheckpoint(mismatchedPlan, { session: session.state }),
      /nextModules divergente/,
    );

    const forgedPlanHash = structuredClone(base);
    forgedPlanHash.activePlan.hash = 'b'.repeat(64);
    forgedPlanHash.checkpointHash = computeAutoCheckpointHash(forgedPlanHash);
    assert.throws(
      () => validateAutoCheckpoint(forgedPlanHash, { session: session.state }),
      /hash semântico divergente/,
    );

    const missingVersion = structuredClone(base);
    delete missingVersion.checkpointVersion;
    missingVersion.checkpointHash = computeAutoCheckpointHash(missingVersion);
    assert.throws(() => validateAutoCheckpoint(missingVersion), /checkpointVersion/);

    const missingHash = structuredClone(base);
    delete missingHash.checkpointHash;
    assert.throws(() => validateAutoCheckpoint(missingHash), /checkpointHash/);

    const missingPrompt = { ...session.state, promptVersion: null };
    assert.throws(
      () => assertAutoResumeSnapshotCompatible(missingPrompt),
      /promptVersion ausente/,
    );
  } finally {
    session.close('cancelled');
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('somente checkpoints ready são retomáveis e planning falha fechado', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-auto-planning-checkpoint-'));
  const { session } = await makeCheckpointSession(root, {
    checkpointStatus: 'ready_for_iteration',
    sessionId: 'session-planning-not-resumable01',
  });
  try {
    session.state.iteration = 0;
    session.state.checkpoint = createAutoCheckpoint(session.state, {
      status: 'planning',
      currentIteration: 0,
      nextIteration: null,
      nextModules: [],
      executedModules: [],
      iterationHistory: [],
      activePlan: null,
    });
    assert.throws(
      () => assertAutoResumeSnapshotCompatible(session.state),
      /checkpoint planning não é retomável/,
    );
  } finally {
    session.close('cancelled');
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('checkpoint v1 permanece legível para inspeção, mas nunca é executado na retomada', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-auto-legacy-v1-'));
  const { session } = await makeCheckpointSession(root, {
    checkpointStatus: 'ready_for_iteration',
    sessionId: 'session-legacy-checkpoint-v1-01',
  });
  try {
    const legacy = structuredClone(session.state.checkpoint);
    legacy.checkpointVersion = 1;
    delete legacy.resumePolicyHash;
    legacy.checkpointHash = computeAutoCheckpointHash(legacy);
    assert.doesNotThrow(() => validateAutoCheckpoint(legacy, {
      session: session.state,
    }));
    assert.throws(
      () => assertAutoResumeSnapshotCompatible({
        ...session.state,
        checkpoint: legacy,
      }),
      /checkpoint legado não é retomável/,
    );
  } finally {
    session.close('cancelled');
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('claim de retomada é atômico, persistente e impede replay após rollback', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-auto-resume-claim-'));
  const env = { GHOSTRECON_AUTO_RAG_DIR: path.join(root, 'rag') };
  const { session } = await makeCheckpointSession(root, {
    checkpointStatus: 'ready_for_iteration',
    sessionId: 'session-resume-claim-atomic01',
  });
  try {
    await writeAutoSessionSnapshot(root, session.state, env);
    const snapshot = await readAutoSessionSnapshot(root, session.state.sessionId, env);
    const results = await Promise.allSettled([
      claimAutoResumeCheckpoint(root, snapshot, { env }),
      claimAutoResumeCheckpoint(root, snapshot, { env }),
    ]);
    assert.equal(results.filter((result) => result.status === 'fulfilled').length, 1);
    const claimed = results.find((result) => result.status === 'fulfilled').value;
    if (process.platform !== 'win32') {
      assert.equal((await fs.stat(claimed.file)).mode & 0o777, 0o600);
      assert.equal((await fs.stat(path.dirname(claimed.file))).mode & 0o777, 0o700);
    }
    const rejected = results.find((result) => result.status === 'rejected');
    assert.equal(rejected.reason.code, 'AUTO_RESUME_CHECKPOINT_ALREADY_CLAIMED');

    // Regravar/retroceder o snapshot não remove o watermark durável.
    await writeAutoSessionSnapshot(root, snapshot, env);
    await assert.rejects(
      claimAutoResumeCheckpoint(root, snapshot, { env }),
      (error) => error?.code === 'AUTO_RESUME_CHECKPOINT_ALREADY_CLAIMED',
    );

    const orphaned = structuredClone(snapshot);
    orphaned.runtimeLease = {
      schemaVersion: 1,
      pid: 2_147_483_000,
      hostname: os.hostname(),
      processStartTicks: 'dead-fixture',
      acquiredAt: new Date(Date.now() - 60_000).toISOString(),
    };
    await writeAutoSessionSnapshot(root, orphaned, env);
    assert.deepEqual(
      await reconcileOrphanedAutoSessions(root, env, Date.now()),
      [snapshot.sessionId],
      'claim histórico não substitui lease viva da sessão',
    );
  } finally {
    session.close('cancelled');
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('snapshot histórico incompleto falha antes de provider ou pipeline', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-auto-historical-'));
  const env = { GHOSTRECON_AUTO_RAG_DIR: path.join(root, 'rag') };
  const body = requestBody();
  const req = normalizeAutoRequest(body);
  const session = createAutoSession({
    sessionId: 'session-historical-resume01',
    requestRunId: 'run-historical-resume01',
    target: req.target,
  });
  let pipelineCalls = 0;
  let providerCalls = 0;
  try {
    session.state.resumePolicy = buildAutoResumePolicy(req, body);
    session.close('interrupted');
    await writeAutoSessionSnapshot(root, session.state, env);

    await assert.rejects(
      runAutoRecon({
        body: { ...body, resumeSessionId: session.state.sessionId },
        ROOT: root,
        env,
        runPipeline: async () => { pipelineCalls += 1; },
        fetchImpl: async () => {
          providerCalls += 1;
          throw new Error('fetch não deveria executar');
        },
        execFileImpl: async () => {
          providerCalls += 1;
          throw new Error('provider não deveria executar');
        },
      }),
      /catalogHash ausente|checkpoint|política de retomada/,
    );
    assert.equal(providerCalls, 0);
    assert.equal(pipelineCalls, 0);
  } finally {
    session.close('cancelled');
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('checkpoint ready compatível retoma exatamente uma vez e termina', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-auto-ready-resume-'));
  const env = {
    GHOSTRECON_AUTO_RAG_DIR: path.join(root, 'rag'),
    GHOSTRECON_AUTO_HEARTBEAT_MS: '60000',
  };
  const { body, session } = await makeCheckpointSession(root, {
    checkpointStatus: 'ready_for_iteration',
    sessionId: 'session-ready-resume-once01',
  });
  let pipelineCalls = 0;
  try {
    session.state.runtimeLease = {
      schemaVersion: 1,
      pid: 2_147_483_000,
      hostname: os.hostname(),
      processStartTicks: 'dead-fixture',
      acquiredAt: new Date(Date.now() - 60_000).toISOString(),
    };
    await writeAutoSessionSnapshot(root, session.state, env);
    session.close('cancelled');
    await reconcileOrphanedAutoSessions(root, env, Date.now());
    const rollbackSnapshot = await readAutoSessionSnapshot(root, session.state.sessionId, env);

    const result = await runAutoRecon({
      body: { ...body, resumeSessionId: session.state.sessionId },
      ROOT: root,
      env,
      runPipeline: async ({ emit }) => {
        pipelineCalls += 1;
        emit({ type: 'pipe', name: 'rdap', state: 'done' });
      },
      fetchImpl: async () => ({ ok: false, status: 503 }),
      execFileImpl: async () => {
        throw new Error('provider indisponível na fixture');
      },
    });
    assert.equal(pipelineCalls, 1);
    assert.equal(result.sessionId, session.state.sessionId);
    const finalSnapshot = await readAutoSessionSnapshot(root, session.state.sessionId, env);
    assert.equal(finalSnapshot.status, 'completed');
    assert.equal(finalSnapshot.checkpoint.status, 'completed');
    assert.deepEqual(finalSnapshot.checkpoint.executedModules, ['rdap']);

    // Simula rollback do session.json depois da conclusão: o claim fica em um
    // arquivo separado e impede que o mesmo plano pronto volte ao pipeline.
    await writeAutoSessionSnapshot(root, rollbackSnapshot, env);
    await assert.rejects(
      runAutoRecon({
        body: { ...body, resumeSessionId: session.state.sessionId },
        ROOT: root,
        env,
        runPipeline: async () => { pipelineCalls += 1; },
        fetchImpl: async () => ({ ok: false, status: 503 }),
        execFileImpl: async () => {
          throw new Error('provider não deveria executar no replay');
        },
      }),
      (error) => error?.code === 'AUTO_RESUME_CHECKPOINT_ALREADY_CLAIMED',
    );
    assert.equal(pipelineCalls, 1);
  } finally {
    session.close('cancelled');
    await fs.rm(root, { recursive: true, force: true });
  }
});

for (const checkpointStatus of ['iteration_in_progress', 'completed']) {
  test(`crash em checkpoint ${checkpointStatus} não repete pipeline`, async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), `ghostrecon-auto-replay-${checkpointStatus}-`));
    const env = { GHOSTRECON_AUTO_RAG_DIR: path.join(root, 'rag') };
    const { body, session } = await makeCheckpointSession(root, {
      checkpointStatus,
      sessionId: `session-replay-${checkpointStatus.replaceAll('_', '-')}-01`,
    });
    let pipelineCalls = 0;
    let providerCalls = 0;
    try {
      // Simula queda depois do checkpoint e antes do fechamento terminal.
      session.state.runtimeLease = {
        schemaVersion: 1,
        pid: 2_147_483_000,
        hostname: os.hostname(),
        processStartToken: 'dead-fixture',
        acquiredAt: new Date(Date.now() - 60_000).toISOString(),
      };
      await writeAutoSessionSnapshot(root, session.state, env);
      session.close('cancelled');
      assert.deepEqual(
        await reconcileOrphanedAutoSessions(root, env, Date.now()),
        [session.state.sessionId],
      );

      await assert.rejects(
        runAutoRecon({
          body: { ...body, resumeSessionId: session.state.sessionId },
          ROOT: root,
          env,
          runPipeline: async () => { pipelineCalls += 1; },
          fetchImpl: async () => {
            providerCalls += 1;
            throw new Error('fetch não deveria executar');
          },
          execFileImpl: async () => {
            providerCalls += 1;
            throw new Error('provider não deveria executar');
          },
        }),
        checkpointStatus === 'iteration_in_progress'
          ? /impedir replay/
          : /checkpoint completed não é retomável/,
      );
      assert.equal(providerCalls, 0);
      assert.equal(pipelineCalls, 0);
    } finally {
      session.close('cancelled');
      await fs.rm(root, { recursive: true, force: true });
    }
  });
}
