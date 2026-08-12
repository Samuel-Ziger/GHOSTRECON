import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import {
  listAutoRagMarkdown,
  readAutoRagMarkdown,
  writeAutoDecisionMarkdown,
  writeAutoRagNote,
} from '../auto-agent/rag-memory.mjs';
import { buildAutoObservationBundle } from '../auto-agent/observation-builder.mjs';
import { createPendingForgeRequest } from '../auto-agent/forge/forge-store.mjs';
import {
  createForgeEngagementBinding,
  recordForgeRuntimeResult,
  transitionForgePackage,
} from '../auto-agent/forge/lifecycle.mjs';
import {
  listActiveDynamicModules,
  runActiveDynamicModules,
  runIsolatedForgeModule,
} from '../auto-agent/forge/runtime-loader.mjs';
import {
  createForgeSandboxOperationAttestation,
  STRONG_FORGE_SANDBOX_CAPABILITIES,
} from '../auto-agent/forge/sandbox-policy.mjs';
import { computeForgeArtifactIntegrity } from '../auto-agent/forge/artifact-integrity.mjs';

function modeOf(stat) {
  return stat.mode & 0o777;
}

function strongForgeSandbox(implementation = {}) {
  return {
    capabilities: { ...STRONG_FORGE_SANDBOX_CAPABILITIES },
    ...implementation,
  };
}

function storedTestAttestation(label) {
  return createForgeSandboxOperationAttestation({
    operation: 'test',
    operationId: `${label}-operation`,
    challenge: `${label}-challenge`,
    runner: 'test-fixture',
  });
}

async function makeApprovedForge(root, {
  id,
  source,
  timeoutMs = 3000,
} = {}) {
  const pending = await createPendingForgeRequest({
    root,
    requestRunId: `run-${id}`,
    target: 'example.com',
    decision: {
      forgeRequest: {
        proposedId: id,
        gap: 'análise local sem rede',
        intrusive: false,
        approvals: ['reviewer'],
      },
      council: {},
    },
    council: {},
    authorOverride: 'codex',
  });
  await Promise.all([
    fs.writeFile(path.join(pending.dir, 'manifest.json'), JSON.stringify({
      id,
      name: id,
      category: 'surface',
      intrusive: false,
      requiresAuth: false,
      requiresKali: false,
      timeoutMs,
      concurrency: 1,
      outputs: ['finding'],
    })),
    fs.writeFile(path.join(pending.dir, 'module.mjs'), source),
    fs.writeFile(
      path.join(pending.dir, 'module.test.js'),
      "import test from 'node:test';\nimport { run } from './module.mjs';\ntest('fixture', async () => { await run({}); });\n",
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
    })),
  ]);
  const engagement = {
    id: 'ENG-RAG-FORGE',
    status: 'active',
    roeSigned: true,
    scopeDomains: ['example.com'],
    scopeIps: [],
    exclusions: [],
    updatedAt: '2026-07-26T00:00:00.000Z',
  };
  const engagementBinding = createForgeEngagementBinding({
    engagement,
    engagementId: engagement.id,
    target: 'example.com',
  });
  const moved = await transitionForgePackage({
    root,
    forgeId: pending.forgeId,
    decision: 'approve',
    reason: 'fixture sintética revisada',
    expectedTarget: 'example.com',
    expectedArtifactIntegrity: artifactIntegrity,
    engagementBinding,
    verifyEngagementBinding: async () => engagementBinding,
  });
  await recordForgeRuntimeResult({
    root,
    forgeId: pending.forgeId,
    activationId: moved.activationId,
    expectedTarget: moved.target,
    expectedArtifactIntegrity: moved.artifactIntegrity,
    engagementBinding: moved.engagementBinding,
    success: true,
  });
  return moved;
}

test('RAG redige dados sensíveis antes de persistir e de gerar previews', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-rag-redaction-'));
  const ragDir = path.join(root, 'rag');
  const env = { GHOSTRECON_AUTO_RAG_DIR: ragDir };
  const token = 'ghp_abcdefghijklmnopqrstuvwxyz123456';
  const password = 'correct-horse-battery-staple';
  try {
    const note = await writeAutoRagNote({
      root,
      env,
      kind: 'note',
      title: `Token ${token}`,
      target: 'https://user:private-password@example.com/?access_token=url-secret',
      body: `Authorization: Bearer abcdefghijklmnopqrstuvwxyz\nCookie: sid=cookie-secret\npassword=${password}`,
      metadata: {
        accessToken: token,
        nested: { password, harmless: 'ok' },
      },
    });
    const raw = await fs.readFile(note.filePath, 'utf8');
    assert.equal(raw.includes(token), false);
    assert.equal(raw.includes(password), false);
    assert.equal(raw.includes('private-password'), false);
    assert.equal(raw.includes('url-secret'), false);
    assert.match(raw, /\[REDACTED\]/);

    const decision = await writeAutoDecisionMarkdown({
      root,
      env,
      requestRunId: 'run-secret',
      target: 'example.com',
      kind: 'plan',
      plan: { modules: ['security_headers'], sessionToken: token },
      providers: { authorization: 'Bearer abcdefghijklmnopqrstuvwxyz' },
      catalog: { password },
    });
    const decisionRaw = await fs.readFile(decision.filePath, 'utf8');
    assert.equal(decisionRaw.includes(token), false);
    assert.equal(decisionRaw.includes(password), false);
    assert.equal(decisionRaw.includes('abcdefghijklmnopqrstuvwxyz'), false);

    const listed = await listAutoRagMarkdown({ root, env, limit: 10 });
    for (const item of listed) {
      assert.equal(item.preview.includes(token), false);
      assert.equal(item.preview.includes(password), false);
      const read = await readAutoRagMarkdown(item.name, { root, env });
      assert.equal(read.text.includes(token), false);
      assert.equal(read.text.includes(password), false);
    }
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('RAG usa diretórios 0700, arquivos 0600, escrita atômica e limites fail-closed', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-rag-limits-'));
  const ragDir = path.join(root, 'rag');
  const env = {
    GHOSTRECON_AUTO_RAG_DIR: ragDir,
    GHOSTRECON_AUTO_RAG_MAX_FILE_BYTES: '4096',
    GHOSTRECON_AUTO_RAG_MAX_FILES_PER_FOLDER: '1',
  };
  try {
    const first = await writeAutoDecisionMarkdown({
      root,
      env,
      requestRunId: 'run-1',
      target: 'example.com',
      kind: 'plan',
      title: 'Plano limitado',
      summary: 'x'.repeat(20_000),
      plan: { modules: ['security_headers'], context: 'y'.repeat(20_000) },
    });
    assert.equal(modeOf(await fs.stat(ragDir)), 0o700);
    // target ativa o particionamento tenant-aware; valide o diretório efetivo
    // retornado pelo writer em vez de presumir o layout legado não particionado.
    assert.equal(modeOf(await fs.stat(path.join(first.baseDir, 'decisions'))), 0o700);
    assert.equal(modeOf(await fs.stat(first.filePath)), 0o600);
    assert.ok((await fs.stat(first.filePath)).size <= 4096);
    assert.match(await fs.readFile(first.filePath, 'utf8'), /TRUNCATED/);
    const leftovers = (await fs.readdir(path.dirname(first.filePath))).filter((name) => name.endsWith('.tmp'));
    assert.deepEqual(leftovers, []);

    const second = await writeAutoDecisionMarkdown({
      root,
      env,
      requestRunId: 'run-2',
      target: 'example.com',
      kind: 'plan',
    });
    assert.equal(second.skipped, true);
    assert.equal(second.reason, 'rag_file_limit');

    const concurrent = await Promise.all([
      writeAutoRagNote({ root, env, kind: 'note', title: 'concorrente-a', body: 'a' }),
      writeAutoRagNote({ root, env, kind: 'note', title: 'concorrente-b', body: 'b' }),
    ]);
    assert.equal(concurrent.filter((item) => item.skipped === true).length, 1);
    assert.equal(concurrent.filter((item) => item.filePath).length, 1);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('observation bundle deduplica ruído e preserva progresso, timeout e falhas', () => {
  const events = [
    { type: 'pipe', name: 'cors_audit', state: 'active' },
    { type: 'progress', pct: 20 },
    { type: 'finding', finding: { type: 'header', prio: 'low', score: 20, value: 'token=secret-value', url: 'https://example.com' } },
    { type: 'finding', finding: { type: 'header', prio: 'high', score: 90, value: 'token=secret-value', url: 'https://example.com' } },
    { type: 'log', level: 'warn', msg: 'cors timeout after 10s' },
    { type: 'log', level: 'warn', msg: 'cors timeout after 10s' },
    { type: 'pipe', name: 'cors_audit', state: 'timeout' },
    { type: 'progress', pct: 55 },
    { type: 'error', moduleId: 'wayback', message: 'Bearer abcdefghijklmnopqrstuvwxyz failed' },
  ];
  const bundle = buildAutoObservationBundle({
    events,
    plan: { modules: ['cors_audit', 'wayback'] },
  });
  assert.equal(bundle.summary.findingEvents, 2);
  assert.equal(bundle.summary.uniqueFindings, 1);
  assert.equal(bundle.findings[0].count, 2);
  assert.equal(bundle.findings[0].prio, 'high');
  assert.match(bundle.findings[0].value, /REDACTED/);
  assert.equal(bundle.warnings.length, 1);
  assert.equal(bundle.warnings[0].count, 2);
  assert.equal(bundle.progress.highestPct, 55);
  assert.equal(bundle.progress.counts.timeout, 1);
  assert.ok(bundle.failures.some((row) => row.kind === 'timeout' && row.moduleId === 'cors_audit'));
  assert.equal(JSON.stringify(bundle).includes('abcdefghijklmnopqrstuvwxyz'), false);
});

test('runtime Forge delega execução somente à sandbox forte injetada', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-forge-isolated-'));
  try {
    await makeApprovedForge(root, {
      id: 'isolated_module',
      source: `export async function run({ target, fetchImpl }) {
        let blocked = false;
        try { await fetchImpl('https://example.invalid/'); } catch { blocked = true; }
        return { findings: [{ type: 'isolated', prio: 'low', score: 20, value: blocked ? 'network-blocked' : 'network-open', url: 'https://' + target + '/' }] };
      }`,
    });
    const findings = [];
    const events = [];
    let isolatedCalls = 0;
    const result = await runActiveDynamicModules({
      ROOT: root,
      domain: 'example.com',
      requestRunId: 'run-isolated',
      modules: ['isolated_module'],
      pipe: () => {},
      log: () => {},
      emit: (event) => events.push(event),
      addFinding: (finding) => findings.push(finding),
    }, {
      root,
      env: {},
      isolatedRunner: strongForgeSandbox({
        async runModule(args) {
          isolatedCalls += 1;
          return {
            findings: [{
              type: 'isolated',
              prio: 'low',
              score: 20,
              value: 'network-blocked',
              url: `https://${args.context.target}/`,
            }],
            sandboxAttestation: createForgeSandboxOperationAttestation({
              operation: 'runtime',
              operationId: args.operationId,
              challenge: args.attestationChallenge,
              runner: 'test-fixture',
            }),
          };
        },
      }),
    });
    assert.equal(result.executed, 1);
    assert.equal(result.completed, 1);
    assert.equal(isolatedCalls, 1);
    assert.equal(findings[0].value, 'network-blocked');
    assert.ok(events.some((event) => event.type === 'dynamic_module_started' && event.runtime === 'strong_os_sandbox'));
    assert.ok(events.some((event) => event.type === 'dynamic_module_completed'));
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('runtime Forge falha fechado quando sandbox forte não foi configurada', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-forge-no-sandbox-'));
  try {
    await makeApprovedForge(root, {
      id: 'disabled_without_sandbox',
      source: 'export async function run() { return { findings: [] }; }',
    });
    const events = [];
    const result = await runActiveDynamicModules({
      ROOT: root,
      domain: 'example.com',
      requestRunId: 'run-no-sandbox',
      modules: ['disabled_without_sandbox'],
      pipe: () => {},
      log: () => {},
      emit: (event) => events.push(event),
      addFinding: () => {
        throw new Error('módulo não deveria executar');
      },
    }, { root, env: {} });

    assert.equal(result.executed, 0);
    assert.equal(result.skipped, 1);
    assert.ok(events.some((event) => (
      event.type === 'dynamic_module_skipped'
      && event.reason === 'strong_network_sandbox_required'
    )));
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('runtime legado falha fechado e pacote adulterado é invalidado', async () => {
  await assert.rejects(
    runIsolatedForgeModule({
      moduleId: 'unsafe_module',
      source: 'export function run() { return { findings: [{ value: typeof process }] }; }',
      context: { target: 'example.com' },
      timeoutMs: 2000,
    }),
    (error) => (
      error?.code === 'AUTO_FORGE_STRONG_SANDBOX_REQUIRED'
      && /isolamento forte/.test(error.message)
    ),
  );

  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-forge-integrity-'));
  try {
    const active = await makeApprovedForge(root, {
      id: 'sealed_module',
      source: 'export function run() { return { findings: [] }; }',
    });
    assert.equal((await listActiveDynamicModules(root)).length, 1);
    await fs.appendFile(path.join(active.dir, 'module.mjs'), '\n// adulterado depois da aprovação\n');
    assert.equal((await listActiveDynamicModules(root)).length, 0);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('runtime Forge encerra loop síncrono no timeout e registra o módulo', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-forge-timeout-'));
  try {
    await makeApprovedForge(root, {
      id: 'timeout_module',
      source: 'export function run() { while (true) {} }',
      timeoutMs: 1000,
    });
    const events = [];
    const result = await runActiveDynamicModules({
      ROOT: root,
      domain: 'example.com',
      requestRunId: 'run-timeout',
      modules: ['timeout_module'],
      pipe: () => {},
      log: () => {},
      emit: (event) => events.push(event),
      addFinding: () => {},
    }, {
      root,
      env: {},
      isolatedRunner: strongForgeSandbox({
        async runModule() {
          const error = new Error('timeout após 1000ms');
          error.code = 'AUTO_FORGE_TIMEOUT';
          throw error;
        },
      }),
    });
    assert.equal(result.failed, 1);
    assert.ok(events.some((event) => event.type === 'dynamic_module_timeout'));
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});
