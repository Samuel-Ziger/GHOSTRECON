import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import {
  createAutoSession,
  reconcileOrphanedAutoSessions,
  runAutoStartupReconciliation,
  writeAutoSessionSnapshot,
} from '../auto-agent/session-store.mjs';
import { prepareAutoReconStartup } from '../routes/auto-recon.mjs';

test('startup reconciliation é aguardável, auditável e expira aprovação pendente', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-auto-startup-'));
  const audits = [];
  const logs = [];
  try {
    const session = createAutoSession({
      sessionId: 'session-startup-orphan-1',
      requestRunId: 'run-startup-orphan',
      target: 'example.test',
      ownerPrincipal: { sub: 'alice', role: 'operator' },
    });
    session.state.engagementId = 'ENG-1';
    session.state.runtimeLease = {
      schemaVersion: 1,
      pid: 2_147_483_111,
      hostname: os.hostname(),
      processStartToken: 'dead-fixture',
      acquiredAt: new Date(Date.now() - 60_000).toISOString(),
    };
    session.state.pendingApproval = {
      approvalId: 'approval-orphan-1',
      status: 'pending',
      kind: 'plan',
      createdAt: new Date().toISOString(),
    };
    await writeAutoSessionSnapshot(root, session.state, {});
    await session.close('running');

    const report = await runAutoStartupReconciliation(root, {}, {
      logger: { warn: (msg) => logs.push(String(msg)) },
      onAudit: (entry) => audits.push(entry),
    });

    assert.equal(report.ok, true);
    assert.deepEqual(report.sessionIds, ['session-startup-orphan-1']);
    assert.ok(report.scanned >= 1);
    assert.equal(audits.length, 1);
    assert.match(logs.join('\n'), /reconciliadas/);

    const snapshotPath = path.join(
      root,
      'data/auto-rag/tenants',
    );
    const found = [];
    async function walk(dir) {
      for (const entry of await fs.readdir(dir, { withFileTypes: true }).catch(() => [])) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) await walk(full);
        else if (entry.name === 'session.json') found.push(full);
      }
    }
    await walk(snapshotPath);
    assert.ok(found.length >= 1);
    const state = JSON.parse(await fs.readFile(found[0], 'utf8'));
    assert.equal(state.status, 'interrupted');
    assert.notEqual(state.pendingApproval?.status, 'pending');

    const prepared = await prepareAutoReconStartup({
      ROOT: root,
      env: {},
      logger: { warn: () => {} },
    });
    assert.equal(prepared.ok, true);
    assert.deepEqual(prepared.sessionIds, []);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('reconcileOrphanedAutoSessions cobre path legado sessions/', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-auto-legacy-recon-'));
  try {
    const session = createAutoSession({
      sessionId: 'session-legacy-recon-1',
      requestRunId: 'run-legacy',
      target: 'legacy.test',
    });
    session.state.runtimeLease = {
      schemaVersion: 1,
      pid: 2_147_483_222,
      hostname: os.hostname(),
      processStartToken: 'dead-fixture',
      acquiredAt: new Date(Date.now() - 60_000).toISOString(),
    };
    const env = { GHOSTRECON_AUTO_SESSION_PARTITION: '0' };
    await writeAutoSessionSnapshot(root, session.state, env);
    await session.close('running');
    const changed = await reconcileOrphanedAutoSessions(root, env, Date.now());
    assert.deepEqual(changed, ['session-legacy-recon-1']);
    assert.ok(reconcileOrphanedAutoSessions.lastReport?.scanned >= 1);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});
