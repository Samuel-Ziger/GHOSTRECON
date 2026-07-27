import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { generatePendingArtifact } from '../auto-agent/forge/generate-artifact.mjs';
import { reviewForgePackage } from '../auto-agent/forge/code-review.mjs';
import { validateAndTestForgePackage } from '../auto-agent/forge/validate-package.mjs';
import { validateForgePackage } from '../auto-agent/forge/static-validator.mjs';
import { runForgeCommand } from '../auto-agent/forge/process-runner.mjs';
import {
  createForgeSandboxOperationAttestation,
  runStrongForgeSandboxOperation,
  STRONG_FORGE_SANDBOX_CAPABILITIES,
} from '../auto-agent/forge/sandbox-policy.mjs';
import { createPendingForgeRequest } from '../auto-agent/forge/forge-store.mjs';
import {
  createForgeEngagementBinding,
  manageForgePackage,
  recordForgeRuntimeResult,
  transitionForgePackage,
} from '../auto-agent/forge/lifecycle.mjs';
import { computeForgeArtifactIntegrity } from '../auto-agent/forge/artifact-integrity.mjs';
import {
  listActiveDynamicModules,
  runActiveDynamicModules,
} from '../auto-agent/forge/runtime-loader.mjs';
import { createBubblewrapForgeSandboxRunner } from '../auto-agent/forge/bwrap-runner.mjs';

async function tempDir(t, prefix = 'ghostrecon-forge-security-') {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), prefix));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  return dir;
}

function storedTestAttestation(label = 'fixture') {
  return createForgeSandboxOperationAttestation({
    operation: 'test',
    operationId: `${label}-operation`,
    challenge: `${label}-challenge`,
    runner: 'test-fixture',
  });
}

function activationGuards(fixture, {
  engagementId = 'ENG-FORGE-FIXTURE',
} = {}) {
  const engagement = {
    id: engagementId,
    status: 'active',
    roeSigned: true,
    scopeDomains: [fixture.target],
    scopeIps: [],
    exclusions: [],
    updatedAt: '2026-07-26T00:00:00.000Z',
  };
  const engagementBinding = createForgeEngagementBinding({
    engagement,
    engagementId,
    target: fixture.target,
  });
  return {
    expectedTarget: fixture.target,
    expectedArtifactIntegrity: fixture.artifactIntegrity,
    engagementBinding,
    verifyEngagementBinding: async () => engagementBinding,
  };
}

function attestedRunnerResult(operation, args, value) {
  return {
    ...(value || {}),
    sandboxAttestation: createForgeSandboxOperationAttestation({
      operation,
      operationId: args.operationId,
      challenge: args.attestationChallenge,
      runner: 'test-fixture',
    }),
  };
}

async function writeForgeFixture(dir, {
  id = 'safe_fixture',
  moduleCode = 'export async function run({fetchImpl}) { return { findings: [], fetchImpl: typeof fetchImpl }; }\n',
  testCode = "import test from 'node:test';\nimport {run} from './module.mjs';\ntest('fixture', async () => { await run({fetchImpl: async () => ({})}); });\n",
  author = 'codex',
} = {}) {
  await Promise.all([
    fs.writeFile(path.join(dir, 'forge-request.json'), JSON.stringify({
      proposedId: id,
      gap: 'URL parser with injected fetchImpl',
    })),
    fs.writeFile(path.join(dir, 'manifest.json'), JSON.stringify({
      id,
      name: 'Safe fixture',
      category: 'surface',
      intrusive: false,
      requiresAuth: false,
      requiresKali: false,
      timeoutMs: 5_000,
      concurrency: 1,
      outputs: ['finding'],
    })),
    fs.writeFile(path.join(dir, 'module.mjs'), moduleCode),
    fs.writeFile(path.join(dir, 'module.test.js'), testCode),
    fs.writeFile(path.join(dir, 'provenance.json'), JSON.stringify({ author })),
  ]);
  const artifactIntegrity = await computeForgeArtifactIntegrity(dir);
  await Promise.all([
    fs.writeFile(path.join(dir, 'validation-results.json'), JSON.stringify({
      ok: true,
      artifactIntegrity,
    })),
    fs.writeFile(path.join(dir, 'test-results.json'), JSON.stringify({
      ok: true,
      artifactIntegrity,
    })),
    fs.writeFile(path.join(dir, 'verdict.json'), JSON.stringify({
      validation: { ok: true, artifactIntegrity },
      tests: { ok: true, artifactIntegrity },
      policy: { pipelineEnabled: false },
    })),
  ]);
  return artifactIntegrity;
}

async function createApprovableForge(t, {
  id = 'canary_fixture',
  target = 'example.test',
} = {}) {
  const root = await tempDir(t, 'ghostrecon-forge-activation-');
  const pending = await createPendingForgeRequest({
    root,
    requestRunId: `run-${id}`,
    target,
    decision: {
      forgeRequest: {
        proposedId: id,
        gap: 'fixture local sem rede',
        intrusive: false,
        approvals: ['reviewer-a', 'reviewer-b'],
      },
      council: {},
    },
    council: {},
    authorOverride: 'codex',
  });
  await Promise.all([
    fs.writeFile(path.join(pending.dir, 'manifest.json'), JSON.stringify({
      id,
      name: 'Canary fixture',
      category: 'surface',
      intrusive: false,
      requiresAuth: false,
      requiresKali: false,
      timeoutMs: 5_000,
      concurrency: 1,
      outputs: ['finding'],
    })),
    fs.writeFile(
      path.join(pending.dir, 'module.mjs'),
      'export async function run() { return { findings: [] }; }\n',
    ),
    fs.writeFile(
      path.join(pending.dir, 'module.test.js'),
      "import test from 'node:test';\nimport { run } from './module.mjs';\ntest('safe', async () => { await run({}); });\n",
    ),
  ]);
  const artifactIntegrity = await computeForgeArtifactIntegrity(pending.dir);
  await fs.writeFile(path.join(pending.dir, 'verdict.json'), JSON.stringify({
    status: 'pending_operator_approval',
    validation: { ok: true, artifactIntegrity },
    tests: {
      ok: true,
      artifactIntegrity,
      isolation: storedTestAttestation(id),
    },
    aiReview: {
      approved: true,
      authorExcluded: true,
      quorumMet: true,
      minimumQuorum: 2,
      independentVotes: 2,
      artifactIntegrity,
    },
    policy: { pipelineEnabled: false, operatorApprovalRequired: true },
  }));
  return { root, pending, artifactIntegrity, target };
}

test('Forge falha fechado sem sandbox forte e não executa teste gerado', async (t) => {
  const dir = await tempDir(t);
  await writeForgeFixture(dir);
  let commandCalls = 0;

  const result = await validateAndTestForgePackage(dir, {
    execFileImpl: async () => {
      commandCalls += 1;
      return { stdout: '', stderr: '' };
    },
  });

  assert.equal(result.ok, false);
  assert.equal(result.tests.isolation.strong, false);
  assert.equal(result.tests.tests.reason, 'strong_network_sandbox_required');
  assert.equal(commandCalls, 2, 'somente os dois checks de sintaxe podem executar');
  assert.equal(result.verdict.policy.pipelineEnabled, false);
});

test('lifecycle recusa promoção baseada apenas em permissões do Node', async (t) => {
  const root = await tempDir(t, 'ghostrecon-forge-lifecycle-');
  const pending = await createPendingForgeRequest({
    root,
    requestRunId: 'run-weak-sandbox',
    target: 'example.test',
    decision: {
      forgeRequest: {
        proposedId: 'weak_sandbox_fixture',
        gap: 'fixture local',
        intrusive: false,
        approvals: ['reviewer-a', 'reviewer-b'],
      },
      council: {},
    },
    council: {},
    authorOverride: 'codex',
  });
  await Promise.all([
    fs.writeFile(path.join(pending.dir, 'manifest.json'), JSON.stringify({
      id: 'weak_sandbox_fixture',
      name: 'Weak sandbox fixture',
      category: 'surface',
      intrusive: false,
      requiresAuth: false,
      requiresKali: false,
      timeoutMs: 5_000,
      concurrency: 1,
      outputs: ['finding'],
    })),
    fs.writeFile(
      path.join(pending.dir, 'module.mjs'),
      'export async function run() { return { findings: [] }; }\n',
    ),
    fs.writeFile(
      path.join(pending.dir, 'module.test.js'),
      "import test from 'node:test';\nimport { run } from './module.mjs';\ntest('safe', async () => { await run({}); });\n",
    ),
  ]);
  const artifactIntegrity = await computeForgeArtifactIntegrity(pending.dir);
  await Promise.all([
    fs.writeFile(path.join(pending.dir, 'verdict.json'), JSON.stringify({
      status: 'pending_operator_approval',
      validation: { ok: true, artifactIntegrity },
      tests: {
        ok: true,
        artifactIntegrity,
        isolation: {
          strong: false,
          enforcement: 'node_permission_model',
          network: 'not_enforced',
        },
      },
      aiReview: {
        approved: true,
        authorExcluded: true,
        quorumMet: true,
        minimumQuorum: 2,
        independentVotes: 2,
        artifactIntegrity,
      },
      policy: { pipelineEnabled: false, operatorApprovalRequired: true },
    })),
  ]);

  await assert.rejects(
    transitionForgePackage({
      root,
      forgeId: pending.forgeId,
      decision: 'approve',
      reason: 'fixture',
    }),
    /gates obrigatórios não aprovados/,
  );
});

test('aprovação mantém pacote fora do catálogo global até canário exclusivo concluir', async (t) => {
  const fixture = await createApprovableForge(t);
  const guards = activationGuards(fixture);
  const moved = await transitionForgePackage({
    root: fixture.root,
    forgeId: fixture.pending.forgeId,
    decision: 'approve',
    reason: 'fixture revisada',
    ...guards,
  });

  assert.equal(moved.pipelineEnabled, false);
  assert.equal(typeof moved.activationId, 'string');
  assert.equal((await listActiveDynamicModules(fixture.root)).length, 0);
  assert.equal((await listActiveDynamicModules(fixture.root, {
    target: fixture.target,
    canaryForgeId: 'forge-errado',
  })).length, 0);
  const exclusive = await listActiveDynamicModules(fixture.root, {
    target: fixture.target,
    canaryForgeId: moved.forgeId,
    canaryActivation: {
      activationId: moved.activationId,
      expectedTarget: moved.target,
      expectedArtifactIntegrity: moved.artifactIntegrity,
      engagementBinding: moved.engagementBinding,
    },
  });
  assert.equal(exclusive.length, 1);
  assert.equal(exclusive[0].exclusiveFirstCanary, true);
  await assert.rejects(
    manageForgePackage({
      root: fixture.root,
      forgeId: moved.forgeId,
      action: 'enable',
      reason: 'não pode pular o canário',
    }),
    /aguarda o primeiro canário exclusivo/,
  );

  await assert.rejects(
    recordForgeRuntimeResult({
      root: fixture.root,
      forgeId: moved.forgeId,
      success: true,
    }),
    (error) => error?.code === 'FORGE_ACTIVATION_STALE',
  );
  const changedEngagement = {
    id: moved.engagementBinding.engagementId,
    status: 'active',
    roeSigned: true,
    scopeDomains: [fixture.target],
    scopeIps: [],
    exclusions: ['blocked.example.test'],
    updatedAt: '2026-07-26T00:02:00.000Z',
  };
  const changedBinding = createForgeEngagementBinding({
    engagement: changedEngagement,
    engagementId: changedEngagement.id,
    target: fixture.target,
  });
  await assert.rejects(
    recordForgeRuntimeResult({
      root: fixture.root,
      forgeId: moved.forgeId,
      activationId: moved.activationId,
      expectedTarget: moved.target,
      expectedArtifactIntegrity: moved.artifactIntegrity,
      engagementBinding: changedBinding,
      success: true,
    }),
    (error) => error?.code === 'FORGE_ACTIVATION_STALE',
  );
  const recorded = await recordForgeRuntimeResult({
    root: fixture.root,
    forgeId: moved.forgeId,
    activationId: moved.activationId,
    expectedTarget: moved.target,
    expectedArtifactIntegrity: moved.artifactIntegrity,
    engagementBinding: moved.engagementBinding,
    success: true,
  });
  assert.equal(recorded.pipelineEnabled, true);
  assert.equal((await listActiveDynamicModules(fixture.root, {
    target: fixture.target,
  })).length, 1);
});

test('resultado atrasado do canário não reativa pacote desabilitado', async (t) => {
  const fixture = await createApprovableForge(t, { id: 'late_canary_fixture' });
  const guards = activationGuards(fixture);
  const moved = await transitionForgePackage({
    root: fixture.root,
    forgeId: fixture.pending.forgeId,
    decision: 'approve',
    reason: 'fixture revisada',
    ...guards,
  });
  await manageForgePackage({
    root: fixture.root,
    forgeId: moved.forgeId,
    action: 'disable',
    reason: 'operador cancelou o canário',
  });

  await assert.rejects(
    recordForgeRuntimeResult({
      root: fixture.root,
      forgeId: moved.forgeId,
      activationId: moved.activationId,
      success: true,
    }),
    (error) => error?.code === 'FORGE_ACTIVATION_STALE',
  );
  assert.equal((await listActiveDynamicModules(fixture.root)).length, 0);
});

test('aprovação rejeita gates calculados para versão anterior do artefato', async (t) => {
  const fixture = await createApprovableForge(t, { id: 'tampered_gate_fixture' });
  await fs.appendFile(
    path.join(fixture.pending.dir, 'module.mjs'),
    '\n// alteração posterior aos testes e reviews\n',
  );

  await assert.rejects(
    transitionForgePackage({
      root: fixture.root,
      forgeId: fixture.pending.forgeId,
      decision: 'approve',
      reason: 'não deve aprovar',
    }),
    /gates obrigatórios não aprovados para o artefato atual/,
  );
});

test('aprovação Forge compara por CAS o artefato exibido ao operador', async (t) => {
  const fixture = await createApprovableForge(t, { id: 'artifact_cas_fixture' });
  const guards = activationGuards(fixture);
  const staleArtifactIntegrity = {
    ...guards.expectedArtifactIntegrity,
    artifactSha256: '0'.repeat(64),
  };
  await assert.rejects(
    transitionForgePackage({
      root: fixture.root,
      forgeId: fixture.pending.forgeId,
      decision: 'approve',
      reason: 'artefato apresentado diverge',
      ...guards,
      expectedArtifactIntegrity: staleArtifactIntegrity,
    }),
    (error) => (
      error?.code === 'FORGE_APPROVAL_STALE'
      && /artefato Forge diverge/.test(error.message)
    ),
  );
});

test('aprovação Forge falha fechado se target apresentado mudar sob o lock', async (t) => {
  const fixture = await createApprovableForge(t, { id: 'target_cas_fixture' });
  const guards = activationGuards(fixture);
  const provenancePath = path.join(fixture.pending.dir, 'provenance.json');
  const provenance = JSON.parse(await fs.readFile(provenancePath, 'utf8'));
  provenance.target = 'other.example.test';
  await fs.writeFile(provenancePath, JSON.stringify(provenance));

  await assert.rejects(
    transitionForgePackage({
      root: fixture.root,
      forgeId: fixture.pending.forgeId,
      decision: 'approve',
      reason: 'target apresentado já está obsoleto',
      ...guards,
    }),
    (error) => (
      error?.code === 'FORGE_APPROVAL_STALE'
      && /alvo do pacote Forge diverge/.test(error.message)
    ),
  );
});

test('aprovação Forge falha fechado se binding/version do engagement mudar sob o lock', async (t) => {
  const fixture = await createApprovableForge(t, { id: 'engagement_cas_fixture' });
  const guards = activationGuards(fixture);
  const changedEngagement = {
    id: guards.engagementBinding.engagementId,
    status: 'closed',
    roeSigned: true,
    scopeDomains: [fixture.target],
    scopeIps: [],
    exclusions: [],
    updatedAt: '2026-07-26T00:01:00.000Z',
    closedAt: '2026-07-26T00:01:00.000Z',
  };
  const changedBinding = createForgeEngagementBinding({
    engagement: changedEngagement,
    engagementId: changedEngagement.id,
    target: fixture.target,
  });

  await assert.rejects(
    transitionForgePackage({
      root: fixture.root,
      forgeId: fixture.pending.forgeId,
      decision: 'approve',
      reason: 'engagement já mudou',
      ...guards,
      verifyEngagementBinding: async () => changedBinding,
    }),
    (error) => (
      error?.code === 'FORGE_APPROVAL_STALE'
      && /engagement Forge mudou/.test(error.message)
    ),
  );
});

test('schema, gerador e validator exigem requiresAuth=false', async (t) => {
  const schema = JSON.parse(await fs.readFile(
    new URL('../auto-agent/schemas/forge-artifact.schema.json', import.meta.url),
    'utf8',
  ));
  assert.equal(schema.properties.manifest.properties.requiresAuth.const, false);

  const dir = await tempDir(t, 'ghostrecon-forge-auth-');
  await writeForgeFixture(dir, { id: 'auth_forbidden_fixture' });
  const manifestPath = path.join(dir, 'manifest.json');
  const manifest = JSON.parse(await fs.readFile(manifestPath, 'utf8'));
  manifest.requiresAuth = true;
  await fs.writeFile(manifestPath, JSON.stringify(manifest));
  const validation = await validateForgePackage(dir);
  assert.equal(validation.ok, false);
  assert.ok(validation.errors.includes('manifest.requiresAuth deve ser false'));

  const generatedDir = await tempDir(t, 'ghostrecon-forge-auth-generated-');
  const artifact = {
    moduleCode: 'export async function run() { return { findings: [] }; }',
    testCode: "import test from 'node:test';\nimport { run } from './module.mjs';\ntest('x', async()=>run({}));",
    manifest: {
      id: 'auth_generated_fixture',
      name: 'Auth generated',
      category: 'surface',
      intrusive: false,
      requiresAuth: true,
      requiresKali: false,
      timeoutMs: 5_000,
      concurrency: 1,
      outputs: ['finding'],
    },
    implementationNotes: [],
  };
  await assert.rejects(
    generatePendingArtifact({
      provider: 'claude_code',
      request: { proposedId: 'auth_generated_fixture', gap: 'fixture' },
      target: 'example.test',
      root: generatedDir,
      pendingDir: generatedDir,
      env: { PATH: process.env.PATH },
      execFileImpl: async () => ({
        stdout: JSON.stringify({ structured_output: artifact }),
        stderr: '',
      }),
    }),
    /requiresAuth deve ser false/,
  );
});

test("validator bloqueia bypass globalThis['fetch'] antes de qualquer runner", async (t) => {
  const dir = await tempDir(t);
  await writeForgeFixture(dir, {
    id: 'global_fetch_bypass',
    moduleCode: `
      export async function run() {
        const request = globalThis['fetch'];
        return request('https://example.invalid/');
      }
    `,
  });

  const result = await validateForgePackage(dir);

  assert.equal(result.ok, false);
  assert.equal(
    result.errors.some((error) => error.includes('global_object_access')),
    true,
  );
});

test('review exclui autor e falha com quorum independente insuficiente', async (t) => {
  const dir = await tempDir(t);
  await writeForgeFixture(dir, { author: 'codex' });
  const review = {
    verdict: 'approve',
    summary: 'ok',
    issues: [],
    confidence: 0.95,
  };
  let fetchCalls = 0;

  const result = await reviewForgePackage({
    pendingDir: dir,
    root: dir,
    providers: [
      { id: 'codex', selected: true, usable: true },
      { id: 'openrouter', selected: true, usable: true, defaultModel: 'test/model' },
      { id: 'skynet', selected: true, usable: false },
    ],
    env: { OPENROUTER_API_KEY: 'fixture' },
    fetchImpl: async () => {
      fetchCalls += 1;
      return {
        ok: true,
        status: 200,
        json: async () => ({
          choices: [{ message: { content: JSON.stringify(review) } }],
        }),
      };
    },
  });

  assert.equal(result.status, 'insufficient_review_quorum');
  assert.equal(result.approved, false);
  assert.equal(result.minimumQuorum, 2);
  assert.equal(result.independentVotes, 1);
  assert.equal(result.reviews.some((row) => row.provider === 'codex'), false);
  assert.equal(fetchCalls, 1);
});

test('review não aprova quando o artefato muda durante os pareceres', async (t) => {
  const dir = await tempDir(t, 'ghostrecon-forge-review-integrity-');
  await writeForgeFixture(dir, { author: 'codex' });
  const review = {
    verdict: 'approve',
    summary: 'ok',
    issues: [],
    confidence: 0.95,
  };
  let changed = false;
  const result = await reviewForgePackage({
    pendingDir: dir,
    root: dir,
    providers: [
      { id: 'openrouter', selected: true, usable: true },
      { id: 'skynet', selected: true, usable: true },
    ],
    env: { OPENROUTER_API_KEY: 'fixture' },
    fetchImpl: async () => {
      if (!changed) {
        changed = true;
        await fs.appendFile(path.join(dir, 'module.mjs'), '\n// alteração concorrente\n');
      }
      return {
        ok: true,
        status: 200,
        json: async () => ({
          choices: [{ message: { content: JSON.stringify(review) } }],
        }),
      };
    },
  });

  assert.equal(result.approved, false);
  assert.equal(result.status, 'artifact_changed_during_review');
  assert.equal(result.artifactUnchanged, false);
  const verdict = JSON.parse(await fs.readFile(path.join(dir, 'verdict.json'), 'utf8'));
  assert.equal(verdict.policy.pipelineEnabled, false);
});

test('cancelamento da sessão interrompe geração, review HTTP e testes isolados', async (t) => {
  const generationDir = await tempDir(t, 'ghostrecon-forge-generation-');
  const generationController = new AbortController();
  let generationStarted;
  const generationReady = new Promise((resolve) => {
    generationStarted = resolve;
  });
  const generation = generatePendingArtifact({
    provider: 'claude_code',
    request: { proposedId: 'cancelled_fixture', gap: 'fixture' },
    target: 'example.test',
    root: generationDir,
    pendingDir: generationDir,
    env: { PATH: process.env.PATH },
    signal: generationController.signal,
    execFileImpl: async (_command, _args, options) => {
      generationStarted(options.signal);
      return new Promise(() => {});
    },
  });
  const generationSignal = await generationReady;
  const generationReason = new Error('cancel generation');
  generationController.abort(generationReason);
  await assert.rejects(generation, (error) => error === generationReason);
  assert.equal(generationSignal.aborted, true);

  const reviewDir = await tempDir(t, 'ghostrecon-forge-review-');
  await writeForgeFixture(reviewDir, { author: 'codex' });
  const reviewController = new AbortController();
  let reviewStarted;
  const reviewReady = new Promise((resolve) => {
    reviewStarted = resolve;
  });
  const reviewing = reviewForgePackage({
    pendingDir: reviewDir,
    root: reviewDir,
    providers: [{ id: 'openrouter', selected: true, usable: true }],
    env: { OPENROUTER_API_KEY: 'fixture' },
    signal: reviewController.signal,
    fetchImpl: async (_url, options) => {
      reviewStarted(options.signal);
      return new Promise((_resolve, reject) => {
        options.signal.addEventListener(
          'abort',
          () => reject(options.signal.reason),
          { once: true },
        );
      });
    },
  });
  const reviewSignal = await reviewReady;
  const reviewReason = new Error('cancel review');
  reviewController.abort(reviewReason);
  await assert.rejects(reviewing, (error) => error === reviewReason);
  assert.equal(reviewSignal.aborted, true);

  const testsDir = await tempDir(t, 'ghostrecon-forge-tests-');
  await writeForgeFixture(testsDir);
  const testsController = new AbortController();
  let testsStarted;
  const testsReady = new Promise((resolve) => {
    testsStarted = resolve;
  });
  const testing = validateAndTestForgePackage(testsDir, {
    signal: testsController.signal,
    execFileImpl: async () => ({ stdout: '', stderr: '' }),
    isolatedRunner: {
      capabilities: { ...STRONG_FORGE_SANDBOX_CAPABILITIES },
      async runTests({ signal }) {
        testsStarted(signal);
        return new Promise((_resolve, reject) => {
          signal.addEventListener('abort', () => reject(signal.reason), { once: true });
        });
      },
    },
  });
  const testSignal = await testsReady;
  const testReason = new Error('cancel tests');
  testsController.abort(testReason);
  await assert.rejects(testing, (error) => error === testReason);
  assert.equal(testSignal.aborted, true);
});

test('deadline fataliza quando runner forte ignora abort e não confirma encerramento', async () => {
  let receivedSignal = null;
  const runner = {
    capabilities: { ...STRONG_FORGE_SANDBOX_CAPABILITIES },
    async runModule({ signal }) {
      receivedSignal = signal;
      return new Promise(() => {});
    },
  };

  await assert.rejects(
    runStrongForgeSandboxOperation(
      runner,
      'runtime',
      { moduleId: 'deadline_fixture' },
      { timeoutMs: 100, settleGraceMs: 50, label: 'deadline fixture' },
    ),
    (error) => error?.code === 'AUTO_FORGE_SANDBOX_UNTERMINATED',
  );
  assert.equal(receivedSignal.aborted, true);
  assert.equal(receivedSignal.reason.code, 'AUTO_FORGE_TIMEOUT');
});

test('capabilities declaradas sem atestação real da operação são rejeitadas', async () => {
  const runner = {
    capabilities: { ...STRONG_FORGE_SANDBOX_CAPABILITIES },
    async runModule() {
      return { findings: [] };
    },
  };
  await assert.rejects(
    runStrongForgeSandboxOperation(
      runner,
      'runtime',
      { moduleId: 'declared_only_fixture' },
      { timeoutMs: 1_000 },
    ),
    (error) => error?.code === 'AUTO_FORGE_SANDBOX_ATTESTATION_INVALID',
  );
});

test('kill acknowledgement não libera operação que continua sem settle', async () => {
  let operationId = null;
  const runner = {
    capabilities: { ...STRONG_FORGE_SANDBOX_CAPABILITIES },
    async runModule(args) {
      operationId = args.operationId;
      return new Promise(() => {});
    },
    async terminateOperation(args) {
      return {
        acknowledged: true,
        settled: true,
        operationId: args.operationId,
      };
    },
  };
  await assert.rejects(
    runStrongForgeSandboxOperation(
      runner,
      'runtime',
      { moduleId: 'false_kill_ack_fixture' },
      { timeoutMs: 100, settleGraceMs: 50 },
    ),
    (error) => (
      error?.code === 'AUTO_FORGE_SANDBOX_UNTERMINATED'
      && error?.operationId === operationId
    ),
  );
});

test('cancelamento genérico do chamador é propagado sem conversão', async () => {
  const controller = new AbortController();
  let ready;
  const started = new Promise((resolve) => {
    ready = resolve;
  });
  const reason = new Error('cancelamento genérico');
  const runner = {
    capabilities: { ...STRONG_FORGE_SANDBOX_CAPABILITIES },
    async runModule({ signal }) {
      ready(signal);
      return new Promise((_resolve, reject) => {
        signal.addEventListener('abort', () => reject(signal.reason), { once: true });
      });
    },
  };
  const operation = runStrongForgeSandboxOperation(
    runner,
    'runtime',
    {},
    { signal: controller.signal, timeoutMs: 5_000 },
  );
  const innerSignal = await started;
  controller.abort(reason);

  await assert.rejects(operation, (error) => error === reason);
  assert.equal(innerSignal.aborted, true);
  assert.equal(innerSignal.reason, reason);
});

test('runtime dinâmico registra e propaga cancelamento genérico da sessão', async (t) => {
  const fixture = await createApprovableForge(t, { id: 'runtime_cancel_fixture' });
  const guards = activationGuards(fixture);
  const moved = await transitionForgePackage({
    root: fixture.root,
    forgeId: fixture.pending.forgeId,
    decision: 'approve',
    reason: 'fixture revisada',
    ...guards,
  });
  const controller = new AbortController();
  const reason = new Error('sessão cancelada pelo operador');
  const events = [];
  const running = runActiveDynamicModules({
    ROOT: fixture.root,
    domain: fixture.target,
    requestRunId: 'run-cancel-runtime',
    modules: ['runtime_cancel_fixture'],
    forgeCanaryId: moved.forgeId,
    forgeCanaryActivation: {
      activationId: moved.activationId,
      expectedTarget: moved.target,
      expectedArtifactIntegrity: moved.artifactIntegrity,
      engagementBinding: moved.engagementBinding,
    },
    signal: controller.signal,
    throwIfAborted() {
      if (controller.signal.aborted) throw controller.signal.reason;
    },
    pipe: () => {},
    log: () => {},
    emit: (event) => events.push(event),
    addFinding: () => {},
  }, {
    root: fixture.root,
    isolatedRunner: {
      capabilities: { ...STRONG_FORGE_SANDBOX_CAPABILITIES },
      async runModule({ signal }) {
        queueMicrotask(() => controller.abort(reason));
        return new Promise((_resolve, reject) => {
          signal.addEventListener('abort', () => reject(signal.reason), { once: true });
        });
      },
    },
  });

  await assert.rejects(running, (error) => error === reason);
  assert.ok(events.some((event) => event.type === 'dynamic_module_cancelled'));
});

test(
  'runner Bubblewrap usa namespaces deny-all, ambiente limpo e valida wrapper de runtime',
  { skip: process.platform !== 'linux' },
  async () => {
    const calls = [];
    const runner = await createBubblewrapForgeSandboxRunner({
      runProcessImpl: async (command, args, options) => {
        calls.push({ command, args, options });
        return {
          ok: true,
          code: 0,
          stdout: JSON.stringify({
            ok: true,
            result: { findings: [{ type: 'fixture', value: 'ok' }] },
          }),
          stderr: '',
        };
      },
    });
    const result = await runner.runModule({
      moduleId: 'bwrap_fixture',
      source: 'export async function run() { return { findings: [] }; }',
      context: { target: 'example.test' },
      timeoutMs: 1_000,
      operationId: 'bwrap-fixture-operation',
      attestationChallenge: 'bwrap-fixture-challenge',
    });

    assert.equal(result.findings[0].value, 'ok');
    assert.equal(calls.length, 1);
    assert.equal(calls[0].command, '/usr/bin/bwrap');
    assert.ok(calls[0].args.includes('--unshare-all'));
    assert.ok(calls[0].args.includes('--unshare-user'));
    assert.ok(calls[0].args.includes('--disable-userns'));
    assert.ok(calls[0].args.includes('--clearenv'));
    assert.equal(calls[0].args.includes('--share-net'), false);
    assert.equal(calls[0].options.spawnOpts.env.Authorization, undefined);
    assert.match(calls[0].options.input, /bwrap_fixture/);

    const rejecting = await createBubblewrapForgeSandboxRunner({
      runProcessImpl: async () => ({
        ok: true,
        code: 0,
        stdout: JSON.stringify({ ok: false, error: 'worker recusou' }),
        stderr: '',
      }),
    });
    await assert.rejects(
      rejecting.runModule({
        moduleId: 'bwrap_rejected_fixture',
        source: 'export async function run() { return null; }',
        context: {},
        operationId: 'bwrap-rejected-operation',
        attestationChallenge: 'bwrap-rejected-challenge',
      }),
      (error) => (
        error?.code === 'AUTO_FORGE_RUNTIME_FAILED'
        && /worker recusou/.test(error.message)
      ),
    );
  },
);

function processIsRunning(pid) {
  try {
    process.kill(pid, 0);
    if (process.platform !== 'win32') {
      const stat = readFileSync(`/proc/${pid}/stat`, 'utf8');
      if (stat.split(' ')[2] === 'Z') return false;
    }
    return true;
  } catch {
    return false;
  }
}

async function waitUntilStopped(pid, timeoutMs = 1_500) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (!processIsRunning(pid)) return true;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  return !processIsRunning(pid);
}

test(
  'runner Forge padrão encerra grupo de subprocessos com TERM seguido de KILL',
  { skip: process.platform === 'win32' },
  async () => {
    const controller = new AbortController();
    const childScript = 'process.on("SIGTERM",()=>{}); setInterval(()=>{},1000)';
    const parentScript = `
      const { spawn } = require('node:child_process');
      const { writeSync } = require('node:fs');
      const child = spawn(process.execPath, ['-e', ${JSON.stringify(childScript)}], {
        stdio: 'ignore'
      });
      writeSync(1, String(child.pid));
      process.on('SIGTERM', () => {});
      setInterval(() => {}, 1000);
    `;
    const timer = setTimeout(
      () => controller.abort(new Error('cancel process tree')),
      300,
    );
    let descendantPid = null;
    try {
      await assert.rejects(
        runForgeCommand(process.execPath, ['-e', parentScript], {
          cwd: process.cwd(),
          env: process.env,
          timeoutMs: 5_000,
          signal: controller.signal,
          label: 'Forge process tree fixture',
        }),
        (error) => {
          assert.equal(error.code, 'PROCESS_ABORTED');
          descendantPid = Number.parseInt(error.result?.stdout || '', 10);
          return true;
        },
      );
      assert.equal(Number.isSafeInteger(descendantPid), true);
      assert.equal(await waitUntilStopped(descendantPid), true);
    } finally {
      clearTimeout(timer);
      if (Number.isSafeInteger(descendantPid) && processIsRunning(descendantPid)) {
        try {
          process.kill(descendantPid, 'SIGKILL');
        } catch {
          // best-effort de limpeza da fixture local.
        }
      }
    }
  },
);
