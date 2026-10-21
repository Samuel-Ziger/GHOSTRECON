import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import assert from 'node:assert/strict';
import Database from 'better-sqlite3';

import {
  extractApiContractSnapshots,
  findPreviousApiContractSnapshots,
  previousApiContractSnapshotFor,
  runApiContractDiff,
} from '../modules/api-contract-diff.mjs';
import { closeDb } from '../modules/db-sqlite.js';
import { dispatchRegistryModule } from '../pipeline/dispatcher.mjs';

function jsonResponse(value) {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
}

function singleSpecFetch(document) {
  return async (url) => new URL(url).pathname === '/openapi.json'
    ? jsonResponse(document)
    : new Response('', { status: 404 });
}

function contractDocument({ includeUsers = false } = {}) {
  return {
    openapi: '3.1.0',
    info: { title: 'Persistence Lab', version: includeUsers ? '2' : '1' },
    paths: {
      '/health': {
        get: { responses: { 200: { description: 'ok' } } },
      },
      ...(includeUsers
        ? {
            '/users': {
              get: {
                parameters: [{ name: 'limit', in: 'query', schema: { type: 'integer' } }],
                responses: { 200: { description: 'ok' } },
              },
            },
          }
        : {}),
    },
  };
}

test('snapshot atravessa save, close, reopen, diff e rejeição de baseline adulterado', async (t) => {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-api-contract-'));
  const dbPath = path.join(tempDir, 'runs.db');
  const previousStorage = process.env.GHOSTRECON_STORAGE;
  const previousDb = process.env.GHOSTRECON_DB;
  process.env.GHOSTRECON_STORAGE = 'sqlite';
  process.env.GHOSTRECON_DB = dbPath;
  t.after(async () => {
    closeDb();
    if (previousStorage == null) delete process.env.GHOSTRECON_STORAGE;
    else process.env.GHOSTRECON_STORAGE = previousStorage;
    if (previousDb == null) delete process.env.GHOSTRECON_DB;
    else process.env.GHOSTRECON_DB = previousDb;
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  const db = await import('../modules/db.js');
  const target = 'example.test';
  const origin = 'https://api.example.test';
  const first = await runApiContractDiff({
    origins: [origin],
    domain: target,
    fetchImpl: singleSpecFetch(contractDocument()),
  });
  assert.equal(first.status, 'done');
  assert.equal(first.findings.filter((finding) => finding.type === 'api_contract_snapshot').length, 1);

  const savedFirst = await db.saveRun({
    target,
    exactMatch: true,
    modules: ['api_contract_diff'],
    stats: { findings: first.findings.length },
    findings: first.findings,
    correlation: null,
  });
  assert.ok(savedFirst?.runId > 0);
  assert.equal(closeDb(), true);

  const raw = new Database(dbPath, { readonly: true });
  const storedJson = raw.prepare('SELECT findings_json FROM runs WHERE id = ?').get(savedFirst.runId)?.findings_json;
  raw.close();
  assert.equal(typeof storedJson, 'string');
  assert.match(storedJson, /apiContractSnapshot/);
  assert.equal(storedJson.includes('"route":"/health"'), true);
  assert.equal(storedJson.includes('[LOCAL_PATH]'), false);

  const listedAfterRestart = await db.listRuns(10);
  assert.equal(listedAfterRestart[0]?.id, savedFirst.runId);
  const loadedAfterRestart = await db.getRunById(savedFirst.runId);
  assert.equal(loadedAfterRestart?.target, target);
  assert.equal(
    loadedAfterRestart?.findings?.[0]?.verification?.evidence?.apiContractSnapshot?.summary?.operations?.[0]?.route,
    '/health',
  );

  const baselines = await findPreviousApiContractSnapshots({
    target,
    listRunsFn: db.listRuns,
    getRunByIdFn: db.getRunById,
  });
  assert.equal(baselines.length, 1);
  assert.equal(
    previousApiContractSnapshotFor(first.summaries[0], baselines)?.runId,
    savedFirst.runId,
  );

  const dispatchedFindings = [];
  const moduleOutcomes = [];
  const dispatched = await dispatchRegistryModule({
    originByHost: new Map([['api.example.test', { origin }]]),
    domain: target,
    outOfScopeList: [],
    scopePolicy: null,
    modules: ['api_contract_diff'],
    fetchImpl: singleSpecFetch(contractDocument({ includeUsers: true })),
    log() {},
    signal: null,
    pipe() {},
    emit(event) {
      if (event?.type === 'module_outcome') moduleOutcomes.push(event);
    },
    addFinding(finding) { dispatchedFindings.push(finding); },
  }, 'api_contract_diff');
  assert.equal(dispatched, true);
  assert.equal(moduleOutcomes.at(-1)?.status, 'done');
  assert.equal(moduleOutcomes.at(-1)?.moduleId, 'api_contract_diff');
  assert.equal(
    dispatchedFindings.every((finding) => finding.provenance?.how === 'api_contract_diff'),
    true,
  );
  const diffFinding = dispatchedFindings.find((finding) => finding.type === 'api_contract_diff');
  assert.ok(diffFinding);
  assert.deepEqual(
    diffFinding.verification.evidence.apiContractDiff.addedOperations,
    ['GET /users'],
  );
  assert.equal(diffFinding.verification.evidence.apiContractDiff.previousRunId, savedFirst.runId);

  const savedSecond = await db.saveRun({
    target,
    exactMatch: true,
    modules: ['api_contract_diff'],
    stats: { findings: dispatchedFindings.length },
    findings: dispatchedFindings,
    correlation: null,
    findingsJson: '{}',
  });
  assert.ok(savedSecond?.runId > savedFirst.runId);
  assert.equal(closeDb(), true);
  const loadedSecond = await db.getRunById(savedSecond.runId);
  assert.equal(
    loadedSecond.findings.some((finding) => finding.type === 'api_contract_diff'),
    true,
  );

  closeDb();
  const tamperDb = new Database(dbPath);
  const tamperedRow = tamperDb.prepare('SELECT findings_json FROM runs WHERE id = ?').get(savedSecond.runId);
  const tampered = JSON.parse(tamperedRow.findings_json);
  const snapshot = tampered.findings.find((finding) => finding.type === 'api_contract_snapshot');
  snapshot.verification.evidence.apiContractSnapshot.provenance.sourceUrl = 'https://outside.test/openapi.json';
  tamperDb.prepare('UPDATE runs SET findings_json = ? WHERE id = ?')
    .run(JSON.stringify(tampered), savedSecond.runId);
  tamperDb.close();

  const afterTamperRestart = await findPreviousApiContractSnapshots({
    target,
    listRunsFn: db.listRuns,
    getRunByIdFn: db.getRunById,
  });
  assert.deepEqual(afterTamperRestart.map((item) => item.runId), [savedFirst.runId]);

  const sensitiveTarget = 'sensitive.example.test';
  const sensitiveOrigin = `https://${sensitiveTarget}`;
  const sensitiveRun = async (token, titleSecret, previousSnapshots = []) => runApiContractDiff({
    origins: [sensitiveOrigin],
    domain: sensitiveTarget,
    previousSnapshots,
    fetchImpl: async (url) => {
      if (url.endsWith('/openapi.json')) {
        return new Response(null, {
          status: 302,
          headers: { location: `/contracts/current.json?token=${token}` },
        });
      }
      if (!new URL(url).pathname.endsWith('/contracts/current.json')) {
        return new Response('', { status: 404 });
      }
      return jsonResponse({
        openapi: '3.1.0',
        info: { title: `Bearer ${titleSecret}`, version: '1' },
        paths: { '/health': { get: { responses: { 200: { description: 'ok' } } } } },
      });
    },
  });
  const sensitiveFirst = await sensitiveRun('fixture-token-one', 'fixturebearersecretone');
  assert.equal(sensitiveFirst.summaries.length, 1);
  assert.equal(sensitiveFirst.summaries[0].title, '[REDACTED]');
  assert.equal(sensitiveFirst.summaries[0].url, `${sensitiveOrigin}/openapi.json`);
  assert.match(sensitiveFirst.summaries[0].resolvedUrl, /token=%5BREDACTED%5D/);
  const savedSensitive = await db.saveRun({
    target: sensitiveTarget,
    exactMatch: true,
    modules: ['api_contract_diff'],
    stats: {},
    findings: sensitiveFirst.findings,
    correlation: null,
  });
  assert.ok(savedSensitive?.runId > savedSecond.runId);
  assert.equal(closeDb(), true);
  for (const storedName of await fs.readdir(tempDir)) {
    const sensitiveStored = await fs.readFile(path.join(tempDir, storedName));
    assert.equal(sensitiveStored.includes(Buffer.from('fixture-token-one')), false);
    assert.equal(sensitiveStored.includes(Buffer.from('fixturebearersecretone')), false);
  }
  const loadedSensitive = await db.getRunById(savedSensitive.runId);
  const sensitiveBaselines = extractApiContractSnapshots(loadedSensitive);
  assert.equal(sensitiveBaselines.length, 1);
  const sensitiveSecond = await sensitiveRun(
    'fixture-token-two',
    'fixturebearersecrettwo',
    sensitiveBaselines,
  );
  assert.equal(
    previousApiContractSnapshotFor(sensitiveSecond.summaries[0], sensitiveBaselines)?.runId,
    savedSensitive.runId,
  );
  assert.equal(
    sensitiveSecond.findings.some((finding) => finding.type === 'api_contract_diff'),
    false,
  );

  const largeTarget = 'large.example.test';
  const largePaths = Object.fromEntries(Array.from({ length: 501 }, (_, index) => [
    `/resource-${String(index).padStart(3, '0')}`,
    { get: { responses: { 200: { description: 'ok' } } } },
  ]));
  const large = await runApiContractDiff({
    origins: [`https://${largeTarget}`],
    domain: largeTarget,
    fetchImpl: singleSpecFetch({ openapi: '3.1.0', paths: largePaths }),
  });
  assert.equal(large.summaries[0].operationCount, 501);
  const savedLarge = await db.saveRun({
    target: largeTarget,
    exactMatch: true,
    modules: ['api_contract_diff'],
    stats: {},
    findings: large.findings,
    correlation: null,
  });
  assert.ok(savedLarge?.runId > savedSensitive.runId);
  assert.equal(closeDb(), true);
  const loadedLarge = await db.getRunById(savedLarge.runId);
  const extractedLarge = extractApiContractSnapshots(loadedLarge);
  assert.equal(extractedLarge.length, 1);
  assert.equal(extractedLarge[0].summary.operations.length, 501);

  const fallbackTarget = 'fallback.example.test';
  const fallbackRun = await runApiContractDiff({
    origins: [`https://${fallbackTarget}`],
    domain: fallbackTarget,
    fetchImpl: singleSpecFetch(contractDocument()),
  });
  const savedStorage = process.env.GHOSTRECON_STORAGE;
  const savedDatabaseUrl = process.env.DATABASE_URL;
  const savedFallbackPolicy = process.env.GHOSTRECON_REMOTE_FALLBACK_SQLITE;
  const pgAdapter = {
    async saveRun() { return null; },
    async listRunsForTarget() { return []; },
    async getRunById() { return null; },
  };
  try {
    process.env.GHOSTRECON_STORAGE = 'postgres';
    process.env.DATABASE_URL = 'postgres://fixture.invalid/ghostrecon';
    process.env.GHOSTRECON_REMOTE_FALLBACK_SQLITE = '1';
    const fallbackSaved = await db.saveRun({
      target: fallbackTarget,
      exactMatch: true,
      modules: ['api_contract_diff'],
      stats: {},
      findings: fallbackRun.findings,
      correlation: null,
    }, { pgAdapter });
    assert.equal(fallbackSaved?.remoteSaveFailed, true);
    assert.equal(closeDb(), true);
    const candidates = await db.listRunsForTarget(
      fallbackTarget,
      10,
      { pgAdapter },
    );
    const localCandidate = candidates.find((row) => row._storageSource === 'sqlite');
    assert.ok(localCandidate);
    const loadedFallback = await db.getRunByStorageRef(localCandidate.id, {
      row: localCandidate,
      pgAdapter,
    });
    assert.equal(extractApiContractSnapshots(loadedFallback).length, 1);
  } finally {
    closeDb();
    if (savedStorage == null) delete process.env.GHOSTRECON_STORAGE;
    else process.env.GHOSTRECON_STORAGE = savedStorage;
    if (savedDatabaseUrl == null) delete process.env.DATABASE_URL;
    else process.env.DATABASE_URL = savedDatabaseUrl;
    if (savedFallbackPolicy == null) delete process.env.GHOSTRECON_REMOTE_FALLBACK_SQLITE;
    else process.env.GHOSTRECON_REMOTE_FALLBACK_SQLITE = savedFallbackPolicy;
  }
});
