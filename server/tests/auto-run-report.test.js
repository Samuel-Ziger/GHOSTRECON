import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import {
  buildAutoRunReportSummary,
  persistAutoRunReport,
} from '../auto-agent/auto-run-report.mjs';
import { pruneExpiredAutoArtifacts } from '../auto-agent/artifact-retention.mjs';
import {
  assertAutoConcurrencyAvailable,
  registerActiveAutoSession,
  unregisterActiveAutoSession,
} from '../auto-agent/active-sessions.mjs';
import { createAutoSession } from '../auto-agent/session-store.mjs';

test('relatório Auto consolidado grava summary.json com runId canônico', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-auto-report-'));
  try {
    const summary = buildAutoRunReportSummary({
      session: {
        sessionId: 'auto-aaaaaaaaaaaa',
        requestRunId: 'auto-run-fixture-1',
        runId: 'auto-run-fixture-1',
        target: 'example.com',
        status: 'partial',
        approvalTransitions: [{ approvalId: 'a1', from: 'pending', to: 'approved' }],
      },
      evaluation: { status: 'partial', ok: true, findings: 2, highSignals: 0, moduleFailures: [] },
      moduleOutcomes: [{ moduleId: 'rdap', status: 'done' }],
      plan: { hash: 'abc', engines: { ghostrecon: { enabled: true } } },
    });
    assert.equal(summary.runId, 'auto-run-fixture-1');
    assert.equal(summary.kind, 'ghostrecon.auto.run-report');

    const written = await persistAutoRunReport({
      root,
      session: {
        sessionId: 'auto-aaaaaaaaaaaa',
        requestRunId: 'auto-run-fixture-1',
        target: 'example.com',
        status: 'partial',
      },
      evaluation: { status: 'partial', ok: true, findings: 1 },
      moduleOutcomes: [{ moduleId: 'rdap', status: 'done' }],
      plan: { hash: 'abc' },
    });
    assert.ok(written?.jsonPath);
    const raw = JSON.parse(await fs.readFile(written.jsonPath, 'utf8'));
    assert.equal(raw.runId, 'auto-run-fixture-1');
    assert.equal(raw.sessionId, 'auto-aaaaaaaaaaaa');
    await fs.access(written.mdPath);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('retenção remove reports Auto expirados e preserva recentes', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-auto-ttl-'));
  try {
    const oldDir = path.join(root, 'reports', 'auto', 'auto-old-run');
    const newDir = path.join(root, 'reports', 'auto', 'auto-new-run');
    await fs.mkdir(oldDir, { recursive: true });
    await fs.mkdir(newDir, { recursive: true });
    await fs.writeFile(path.join(oldDir, 'summary.json'), '{"runId":"auto-old-run"}\n');
    await fs.writeFile(path.join(newDir, 'summary.json'), '{"runId":"auto-new-run"}\n');
    const oldTime = new Date(Date.now() - 10 * 86_400_000);
    await fs.utimes(path.join(oldDir, 'summary.json'), oldTime, oldTime);
    await fs.utimes(oldDir, oldTime, oldTime);

    const result = await pruneExpiredAutoArtifacts(root, {
      GHOSTRECON_AUTO_ARTIFACT_TTL_DAYS: '3',
      GHOSTRECON_AUTO_RAG_ENABLED: '0',
    });
    assert.equal(result.skipped, false);
    await assert.rejects(fs.access(oldDir));
    await fs.access(newDir);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('concorrência Auto bloqueia segundo registro do mesmo principal', () => {
  const env = {
    GHOSTRECON_AUTO_MAX_SESSIONS_GLOBAL: '8',
    GHOSTRECON_AUTO_MAX_SESSIONS_PER_PRINCIPAL: '1',
    GHOSTRECON_AUTO_MAX_SESSIONS_PER_ENGINE: '8',
  };
  const a = createAutoSession({
    sessionId: 'auto-concuraaaaaa',
    requestRunId: 'run-a',
    target: 'example.com',
    ownerPrincipal: { sub: 'operator-1', role: 'operator' },
    env,
  });
  const b = createAutoSession({
    sessionId: 'auto-concurbbbbbb',
    requestRunId: 'run-b',
    target: 'example.com',
    ownerPrincipal: { sub: 'operator-1', role: 'operator' },
    env,
  });
  try {
    registerActiveAutoSession(a, env);
    assert.throws(
      () => registerActiveAutoSession(b, env),
      (error) => error?.code === 'AUTO_CONCURRENCY_LIMIT',
    );
    assert.ok(assertAutoConcurrencyAvailable(b, env));
  } finally {
    unregisterActiveAutoSession(a.state.sessionId);
    unregisterActiveAutoSession(b.state.sessionId);
  }
});
