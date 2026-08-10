import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { runAutoRecon } from '../auto-agent/orchestrator.mjs';
import { getActiveAutoSession } from '../auto-agent/active-sessions.mjs';
import { dnsResolvedAddressesEligibleForProbe } from '../modules/scope.js';
import { createEngagementScopePolicy } from '../modules/scope.js';
import { fetchScoped } from '../modules/scoped-fetch.mjs';

function engagement(target = 'example.com', id = 'ENG-E2E') {
  return {
    id,
    status: 'active',
    roeSigned: true,
    scopeDomains: [target],
    scopeIps: ['192.0.2.0/24'],
    exclusions: [],
    window: {
      startsAt: new Date(Date.now() - 60_000).toISOString(),
      endsAt: new Date(Date.now() + 3_600_000).toISOString(),
    },
  };
}

test('E2E hermético: observation passivo completa sem engagement formal', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-e2e-obs-'));
  const emitted = [];
  try {
    const result = await runAutoRecon({
      body: {
        domain: 'example.com',
        autonomyLevel: 'observation',
        commanders: [],
        includeHexstrike: false,
      },
      ROOT: root,
      env: { GHOSTRECON_AUTO_RAG_ENABLED: '0' },
      runPipeline: async ({ emit }) => {
        emit({ type: 'pipe', name: 'rdap', state: 'done' });
        emit({ type: 'finding', finding: { prio: 'low', value: 'ok' } });
      },
      emit: (e) => emitted.push(e),
      fetchImpl: async () => ({ ok: false, status: 503 }),
      execFileImpl: async () => {
        throw new Error('provider off');
      },
    });
    assert.ok(['completed', 'partial'].includes(result.session?.status));
    assert.ok(emitted.some((e) => e.type === 'auto_report_ready' || e.type === 'auto_session'));
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('E2E hermético: assisted deny não executa pipeline', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-e2e-deny-'));
  const eng = engagement();
  let pipeline = 0;
  try {
    const result = await runAutoRecon({
      body: {
        domain: 'example.com',
        autonomyLevel: 'assisted',
        approvalMode: 'deny',
        engagementId: eng.id,
        commanders: [],
      },
      ROOT: root,
      env: { GHOSTRECON_AUTO_RAG_ENABLED: '0' },
      getEngagementImpl: async () => eng,
      runPipeline: async () => {
        pipeline += 1;
      },
      emit: () => {},
      fetchImpl: async () => ({ ok: false, status: 503 }),
      execFileImpl: async () => {
        throw new Error('provider off');
      },
    });
    assert.equal(pipeline, 0);
    assert.equal(result.evaluation?.agentDecision?.action || 'finish', 'finish');
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('E2E hermético: assisted approve corre pipeline e grava relatório', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-e2e-ok-'));
  const eng = engagement();
  const emitted = [];
  try {
    const result = await runAutoRecon({
      body: {
        domain: 'example.com',
        autonomyLevel: 'assisted',
        approvalMode: 'interactive',
        engagementId: eng.id,
        commanders: [],
        modules: ['rdap'],
      },
      ROOT: root,
      env: { GHOSTRECON_AUTO_RAG_ENABLED: '0', GHOSTRECON_AUTO_REPORT_ENABLED: '1' },
      getEngagementImpl: async () => eng,
      runPipeline: async ({ emit }) => {
        emit({ type: 'pipe', name: 'rdap', state: 'done' });
        emit({ type: 'module_outcome', moduleId: 'rdap', status: 'done', source: 'pipe' });
      },
      emit: (event) => {
        emitted.push(event);
        if (event.type === 'auto_approval_required') {
          getActiveAutoSession(event.sessionId)?.resolveApproval(
            event.approval.approvalId,
            true,
            'e2e approve',
          );
        }
      },
      fetchImpl: async () => ({ ok: false, status: 503 }),
      execFileImpl: async () => {
        throw new Error('provider off');
      },
    });
    assert.ok(result.requestRunId);
    assert.ok(emitted.some((e) => e.type === 'auto_report_ready'));
    const reportPath = path.join(root, 'reports', 'auto', result.requestRunId, 'summary.json');
    await fs.access(reportPath);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('E2E hermético: redirect/IP fora de escopo bloqueados', async () => {
  const policy = createEngagementScopePolicy({
    rootDomain: 'lab.example.com',
    engagement: {
      id: 'ENG-SCOPE',
      scopeDomains: ['lab.example.com'],
      scopeIps: ['192.0.2.0/24'],
      exclusions: [],
    },
    engagementId: 'ENG-SCOPE',
    authorizationBinding: 'b'.repeat(64),
  });
  const dns = dnsResolvedAddressesEligibleForProbe(
    ['198.51.100.10'],
    'lab.example.com',
    [],
    policy,
  );
  assert.equal(dns.eligible, false);
  assert.deepEqual(dns.rejectedIps, ['198.51.100.10']);

  const calls = [];
  await assert.rejects(
    () => fetchScoped('https://lab.example.com/path', {
      fetchImpl: async (url) => {
        calls.push(url);
        if (String(url).includes('lab.example.com')) {
          return {
            ok: false,
            status: 302,
            url,
            headers: {
              get(name) {
                return String(name).toLowerCase() === 'location'
                  ? 'https://evil.example/leak'
                  : null;
              },
            },
          };
        }
        return { ok: true, status: 200, url, headers: { get: () => null } };
      },
      urlAllowed: (u) => String(u).includes('lab.example.com'),
    }),
    (error) => error?.code === 'OUT_OF_SCOPE',
  );
  assert.equal(calls.length, 1);
});

test('E2E hermético: pipe terminal vira auto_module_outcome com source pipe', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-e2e-pipe-'));
  const eng = engagement();
  const emitted = [];
  try {
    const result = await runAutoRecon({
      body: {
        domain: 'example.com',
        autonomyLevel: 'assisted',
        approvalMode: 'interactive',
        engagementId: eng.id,
        commanders: [],
        modules: ['rdap'],
      },
      ROOT: root,
      env: { GHOSTRECON_AUTO_RAG_ENABLED: '0' },
      getEngagementImpl: async () => eng,
      runPipeline: async ({ emit }) => {
        emit({ type: 'pipe', name: 'rdap', state: 'done' });
      },
      emit: (event) => {
        emitted.push(event);
        if (event.type === 'auto_approval_required') {
          getActiveAutoSession(event.sessionId)?.resolveApproval(
            event.approval.approvalId,
            true,
            'e2e pipe',
          );
        }
      },
      fetchImpl: async () => ({ ok: false, status: 503 }),
      execFileImpl: async () => {
        throw new Error('provider off');
      },
    });
    const outcome = result.evaluation?.moduleOutcomes?.find((row) => row.moduleId === 'rdap');
    assert.ok(outcome);
    assert.equal(outcome.source, 'pipe');
    assert.equal(outcome.status, 'done');
    assert.ok(emitted.some((e) => e.type === 'auto_module_outcome' && e.moduleId === 'rdap' && e.source === 'pipe'));
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('E2E hermético: providers indisponíveis degradam sem baseline silencioso', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-e2e-deg-'));
  const eng = engagement();
  const emitted = [];
  try {
    await runAutoRecon({
      body: {
        domain: 'example.com',
        autonomyLevel: 'assisted',
        approvalMode: 'interactive',
        engagementId: eng.id,
        commanders: ['codex'],
      },
      ROOT: root,
      env: { GHOSTRECON_AUTO_RAG_ENABLED: '0' },
      getEngagementImpl: async () => eng,
      runPipeline: async () => {},
      emit: (event) => {
        emitted.push(event);
        if (event.type === 'auto_approval_required') {
          getActiveAutoSession(event.sessionId)?.resolveApproval(
            event.approval.approvalId,
            true,
            'e2e',
          );
        }
      },
      fetchImpl: async () => ({ ok: false, status: 503 }),
      execFileImpl: async () => {
        throw new Error('codex missing');
      },
    });
    assert.ok(
      emitted.some((e) => e.type === 'auto_council_degraded' || e.type === 'auto_approval_required'),
    );
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});
