import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import assert from 'node:assert/strict';
import Database from 'better-sqlite3';

import * as db from '../modules/db.js';
import {
  closeDb,
  resolveLocalProjectDbDir,
} from '../modules/db-sqlite.js';
import {
  extractApiContractSnapshots,
  findPreviousApiContractSnapshots,
  runApiContractDiff,
} from '../modules/api-contract-diff.mjs';
import { dispatchRegistryModule } from '../pipeline/dispatcher.mjs';

function response(document) {
  return new Response(JSON.stringify(document), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
}

function contract(extraPath = false) {
  return {
    openapi: '3.1.0',
    paths: {
      '/health': { get: { responses: { 200: { description: 'ok' } } } },
      ...(extraPath
        ? { '/users': { get: { responses: { 200: { description: 'ok' } } } } }
        : {}),
    },
  };
}

function rememberEnv(names) {
  return new Map(names.map((name) => [name, process.env[name]]));
}

function restoreEnv(saved) {
  for (const [name, value] of saved) {
    if (value == null) delete process.env[name];
    else process.env[name] = value;
  }
}

test('runner recupera baseline somente da base SQLite do projeto selecionado', async (t) => {
  const savedEnv = rememberEnv(['GHOSTRECON_STORAGE', 'GHOSTRECON_DB']);
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-project-baseline-'));
  const projectName = `api-contract-fixture-${process.pid}-${Date.now()}`;
  const otherProject = `${projectName}-other`;
  const target = 'project.example.test';
  const origin = `https://${target}`;
  const projectDir = resolveLocalProjectDbDir(projectName, target);
  const projectRoot = path.dirname(projectDir);
  process.env.GHOSTRECON_STORAGE = 'sqlite';
  process.env.GHOSTRECON_DB = path.join(tempDir, 'global.db');
  t.after(async () => {
    closeDb();
    restoreEnv(savedEnv);
    await fs.rm(projectRoot, { recursive: true, force: true });
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  const first = await runApiContractDiff({
    origins: [origin],
    domain: target,
    fetchImpl: async (url) => url.endsWith('/openapi.json')
      ? response(contract())
      : new Response('', { status: 404 }),
  });
  const saved = await db.saveRun({
    target,
    localProjectName: projectName,
    exactMatch: true,
    modules: ['api_contract_diff'],
    stats: {},
    findings: first.findings,
    correlation: null,
  });
  assert.ok(saved?.runId > 0);

  const raw = new Database(path.join(projectDir, 'ghostrecon.db'));
  raw.prepare('UPDATE runs SET stats_json = ? WHERE id = ?').run('{invalid-json', saved.runId);
  raw.close();

  const candidates = await db.listRunsForTarget(target, 10, { localProjectName: projectName });
  assert.equal(candidates.length, 1);
  assert.equal(candidates[0]._storageSource, 'sqlite-project');
  assert.deepEqual(candidates[0].stats, {});
  assert.deepEqual(
    await db.listRunsForTarget(target, 10, { localProjectName: otherProject }),
    [],
  );
  const loaded = await db.getRunByStorageRef(candidates[0].id, {
    row: candidates[0],
    localProjectName: projectName,
  });
  assert.equal(extractApiContractSnapshots(loaded).length, 1);

  const findings = [];
  await dispatchRegistryModule({
    originByHost: new Map([[target, { origin }]]),
    domain: target,
    projectNameRaw: projectName,
    outOfScopeList: [],
    scopePolicy: null,
    modules: ['api_contract_diff'],
    fetchImpl: async (url) => url.endsWith('/openapi.json')
      ? response(contract(true))
      : new Response('', { status: 404 }),
    log() {},
    pipe() {},
    emit() {},
    addFinding(finding) { findings.push(finding); },
  }, 'api_contract_diff');
  const diff = findings.find((finding) => finding.type === 'api_contract_diff');
  assert.ok(diff);
  assert.equal(diff.verification.evidence.apiContractDiff.previousRunId, saved.runId);
  assert.deepEqual(diff.verification.evidence.apiContractDiff.addedOperations, ['GET /users']);
});

test('seleção de backend não perde SQLite sem remoto e ordena Date/ISO corretamente', async () => {
  const savedEnv = rememberEnv([
    'GHOSTRECON_STORAGE',
    'DATABASE_URL',
    'SUPABASE_URL',
    'SUPABASE_SERVICE_ROLE_KEY',
    'SUPABASE_ANON_KEY',
    'SUPABASE_KEY',
    'SUPABASE_PUBLISHABLE_KEY',
    'GHOSTRECON_SUPABASE_AUTO',
    'GHOSTRECON_REMOTE_FALLBACK_SQLITE',
  ]);
  try {
    process.env.GHOSTRECON_STORAGE = 'postgres';
    process.env.GHOSTRECON_REMOTE_FALLBACK_SQLITE = '0';
    process.env.DATABASE_URL = 'postgres://fixture.invalid/ghostrecon';
    const ordered = await db.listRunsForTarget('example.test', 10, {
      pgAdapter: {
        async listRunsForTarget() {
          return [
            { id: 1, target: 'example.test', created_at: new Date('2026-09-09T09:00:00Z') },
            { id: 2, target: 'example.test', created_at: '2026-09-09T10:00:00.000Z' },
          ];
        },
      },
    });
    assert.deepEqual(ordered.map((row) => row.id), [2, 1]);

    process.env.GHOSTRECON_REMOTE_FALLBACK_SQLITE = '1';
    const remoteFailure = new Error('remote_baseline_unavailable');
    remoteFailure.code = 'BASELINE_STORAGE_READ_FAILED';
    const degraded = await db.listRunsForTarget('example.test', 10, {
      pgAdapter: {
        async listRunsForTarget() { throw remoteFailure; },
      },
      sqliteAdapter: {
        listRunsForTarget() {
          return [{ id: 8, target: 'example.test', created_at: '2026-09-09T10:30:00Z' }];
        },
      },
    });
    assert.equal(degraded[0]?._storageSource, 'sqlite');
    assert.equal(degraded[0]?._storageDegraded, true);
    assert.match(degraded[0]?._storageWarning, /remote_baseline_unavailable/);
    await assert.rejects(
      db.listRunsForTarget('example.test', 10, {
        pgAdapter: {
          async listRunsForTarget() { throw remoteFailure; },
        },
        sqliteAdapter: {
          listRunsForTarget() { return []; },
        },
      }),
      /remote_baseline_unavailable/,
    );

    delete process.env.DATABASE_URL;
    delete process.env.SUPABASE_URL;
    delete process.env.SUPABASE_SERVICE_ROLE_KEY;
    delete process.env.SUPABASE_ANON_KEY;
    delete process.env.SUPABASE_KEY;
    delete process.env.SUPABASE_PUBLISHABLE_KEY;
    process.env.GHOSTRECON_SUPABASE_AUTO = '0';
    let localRead = false;
    const localOnly = await db.listRunsForTarget('example.test', 10, {
      sqliteAdapter: {
        listRunsForTarget() {
          localRead = true;
          return [{ id: 7, target: 'example.test', created_at: '2026-09-09T11:00:00Z' }];
        },
      },
    });
    assert.equal(localRead, true);
    assert.equal(localOnly[0]?._storageSource, 'sqlite');
  } finally {
    restoreEnv(savedEnv);
  }
});

test('baseline vindo de fallback degradado torna o resultado parcial e suprime diff', async () => {
  const target = 'degraded.example.test';
  const origin = `https://${target}`;
  const fetchImpl = async (url) => url.endsWith('/openapi.json')
    ? response(contract())
    : new Response('', { status: 404 });
  const first = await runApiContractDiff({ origins: [origin], domain: target, fetchImpl });
  const previousSnapshots = await findPreviousApiContractSnapshots({
    target,
    listRunsForTargetFn: async () => [{
      id: 91,
      target,
      _storageSource: 'sqlite',
      _storageDegraded: true,
    }],
    getRunByIdFn: async () => ({ id: 91, target, findings: first.findings }),
  });

  assert.equal(previousSnapshots.storageDegraded, true);
  const second = await runApiContractDiff({
    origins: [origin],
    domain: target,
    fetchImpl: async (url) => url.endsWith('/openapi.json')
      ? response(contract(true))
      : new Response('', { status: 404 }),
    previousSnapshots,
  });
  assert.equal(second.status, 'partial');
  assert.equal(second.reason, 'baseline_storage_degraded');
  assert.ok(second.outcomes.some((item) => item.state === 'baseline_storage_degraded'));
  assert.equal(second.metrics.status, 'partial');
  assert.equal(second.findings.some((item) => item.type === 'api_contract_snapshot'), true);
  assert.equal(second.findings.some((item) => item.type === 'api_contract_diff'), false);
});

test('limite cumulativo de bytes preserva baselines validados e suprime diff parcial', async () => {
  const target = 'baseline-budget.example.test';
  const origin = `https://${target}`;
  const fetchInitial = async (url) => url.endsWith('/openapi.json')
    ? response(contract())
    : new Response('', { status: 404 });
  const first = await runApiContractDiff({
    origins: [origin],
    domain: target,
    fetchImpl: fetchInitial,
  });
  const persistedRuns = new Map([
    [102, {
      id: 102,
      target,
      created_at: '2026-09-12T12:00:00.000Z',
      findings: first.findings,
    }],
    [101, {
      id: 101,
      target,
      created_at: '2026-09-12T11:00:00.000Z',
      findings: first.findings,
    }],
  ]);
  const getRunByIdFn = async (id) => persistedRuns.get(id);
  const newestOnly = await findPreviousApiContractSnapshots({
    target,
    listRunsFn: async () => [{
      id: 102,
      target,
      created_at: '2026-09-12T12:00:00.000Z',
    }],
    getRunByIdFn,
  });
  assert.equal(newestOnly.length, 1);
  assert.ok(newestOnly.baselineBytesRead > 0);
  assert.equal(newestOnly.baselineByteLimitReached, false);

  const limited = await findPreviousApiContractSnapshots({
    target,
    listRunsFn: async () => [
      { id: 101, target, created_at: '2026-09-12T11:00:00.000Z' },
      { id: 102, target, created_at: '2026-09-12T12:00:00.000Z' },
    ],
    getRunByIdFn,
    maxBaselineBytes: newestOnly.baselineBytesRead,
  });
  assert.equal(limited.length, 1);
  assert.equal(limited[0].runId, 102);
  assert.equal(limited.storageDegraded, false);
  assert.equal(limited.baselineByteLimitReached, true);
  assert.equal(limited.baselineBytesRead, newestOnly.baselineBytesRead);
  assert.equal(limited.baselineBytesRetained, newestOnly.baselineBytesRetained);
  assert.equal(limited.baselineByteLimit, newestOnly.baselineBytesRead);

  const second = await runApiContractDiff({
    origins: [origin],
    domain: target,
    fetchImpl: async (url) => url.endsWith('/openapi.json')
      ? response(contract(true))
      : new Response('', { status: 404 }),
    previousSnapshots: limited,
  });
  assert.equal(second.status, 'partial');
  assert.equal(second.reason, 'baseline_byte_limit');
  assert.equal(second.metrics.baselineByteLimitReached, true);
  assert.equal(second.metrics.baselineBytesRead, limited.baselineBytesRead);
  assert.equal(second.metrics.baselineBytesRetained, limited.baselineBytesRetained);
  assert.equal(second.metrics.baselineByteLimit, limited.baselineByteLimit);
  assert.ok(second.outcomes.some((item) => (
    item.state === 'baseline_byte_limit'
      && item.count === limited.baselineBytesRead
      && item.limit === limited.baselineByteLimit
  )));
  assert.equal(second.findings.some((item) => item.type === 'api_contract_snapshot'), true);
  assert.equal(second.findings.some((item) => item.type === 'api_contract_diff'), false);
});

test('SQLite normaliza o alvo persistido antes da busca de baseline', async (t) => {
  const savedEnv = rememberEnv(['GHOSTRECON_STORAGE', 'GHOSTRECON_DB']);
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-target-normalization-'));
  process.env.GHOSTRECON_STORAGE = 'sqlite';
  process.env.GHOSTRECON_DB = path.join(tempDir, 'normalized.db');
  t.after(async () => {
    closeDb();
    restoreEnv(savedEnv);
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  const saved = await db.saveRun({
    target: '  Mixed.Example.TEST  ',
    exactMatch: true,
    modules: ['security_headers'],
    stats: {},
    findings: [],
    correlation: null,
  });
  assert.ok(saved?.runId > 0);
  const rows = await db.listRunsForTarget('mixed.example.test', 10);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].target, 'mixed.example.test');
});
