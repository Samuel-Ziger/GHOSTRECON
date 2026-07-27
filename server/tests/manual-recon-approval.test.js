import assert from 'node:assert/strict';
import test from 'node:test';

import {
  buildManualReconPlan,
  createManualReconApprovalStore,
} from '../modules/manual-recon-approval.mjs';

const IDENTITY_A = {
  algorithm: 'sha256',
  sha256: 'a'.repeat(64),
  size: 42,
  dev: 1,
  ino: 2,
  mtimeMs: 3,
  mode: 0o100755,
  path: '/private/path/never-in-plan',
};

function makePlan(overrides = {}) {
  return buildManualReconPlan({
    target: 'lab.example.test',
    engagementId: 'ENG-LAB',
    engagementBinding: 'binding-a',
    selectedModules: ['headers', 'frameseven_active'],
    expandedModules: ['headers', 'frameseven_active'],
    intrusiveModules: ['frameseven_active'],
    execution: {
      profile: 'deep',
      opsecProfile: 'standard',
      engine: 'both',
      outOfScope: ['private.lab.example.test'],
      authorization: 'secret-must-be-ignored',
    },
    frameSeven: {
      enabled: true,
      authenticated: false,
      profile: 'offensive_v1',
      tools: ['recon', 'cve', 'nmap'],
      timeoutMs: 30_000,
      toolTimeoutMs: 300_000,
      concurrency: 10,
      rate: 100,
      identity: IDENTITY_A,
    },
    vigolium: {
      enabled: true,
      agent: 'audit',
      strategy: 'lite',
      identity: { ...IDENTITY_A, sha256: 'b'.repeat(64) },
    },
    ...overrides,
  });
}

test('plano manual é determinístico, não contém segredo/path e muda com bindings efetivos', () => {
  const plan = makePlan();
  const same = makePlan();
  assert.equal(plan.hash, same.hash);
  assert.equal(JSON.stringify(plan).includes('secret-must-be-ignored'), false);
  assert.equal(JSON.stringify(plan).includes('/private/path'), false);

  assert.notEqual(makePlan({ target: 'other.example.test' }).hash, plan.hash);
  assert.notEqual(makePlan({ engagementBinding: 'binding-b' }).hash, plan.hash);
  assert.notEqual(makePlan({ intrusiveModules: ['vigolium_dast'] }).hash, plan.hash);
  assert.notEqual(makePlan({
    frameSeven: {
      ...plan.engines.frameseven,
      tools: ['recon', 'cve'],
    },
  }).hash, plan.hash);
  assert.notEqual(makePlan({
    frameSeven: {
      ...plan.engines.frameseven,
      identity: { ...IDENTITY_A, sha256: 'c'.repeat(64) },
    },
  }).hash, plan.hash);
});

test('aprovação manual é owner-bound, expira e só pode ser consumida uma vez', () => {
  let now = Date.parse('2026-07-26T12:00:00.000Z');
  let counter = 0;
  const store = createManualReconApprovalStore({
    clock: () => now,
    ttlMs: 5_000,
    randomId: () => `fixture-${++counter}`,
  });
  const plan = makePlan();

  const pending = store.issue({ plan, ownerSub: 'operator-a' });
  assert.equal(pending.status, 'pending');
  assert.throws(
    () => store.decide({
      approvalId: pending.approvalId,
      ownerSub: 'operator-b',
      planHash: plan.hash,
      approved: true,
    }),
    (error) => error?.code === 'MANUAL_RECON_APPROVAL_OWNER_MISMATCH',
  );
  const approved = store.decide({
    approvalId: pending.approvalId,
    ownerSub: 'operator-a',
    planHash: plan.hash,
    approved: true,
  });
  assert.equal(approved.status, 'approved');

  const consumed = store.consume({
    approvalId: pending.approvalId,
    ownerSub: 'operator-a',
    planHash: plan.hash,
    target: plan.target,
    engagementBinding: plan.engagement.authorizationBinding,
  });
  assert.equal(consumed.status, 'consumed');
  assert.equal(consumed.approved, true);
  assert.throws(
    () => store.consume({
      approvalId: pending.approvalId,
      ownerSub: 'operator-a',
      planHash: plan.hash,
      target: plan.target,
      engagementBinding: plan.engagement.authorizationBinding,
    }),
    (error) => error?.code === 'MANUAL_RECON_APPROVAL_NOT_FOUND',
  );

  const expiring = store.issue({ plan, ownerSub: 'operator-a' });
  now += 5_001;
  assert.throws(
    () => store.decide({
      approvalId: expiring.approvalId,
      ownerSub: 'operator-a',
      planHash: plan.hash,
      approved: true,
    }),
    (error) => error?.code === 'MANUAL_RECON_APPROVAL_EXPIRED',
  );
});

test('recusa ou mudança do plano invalida a aprovação', () => {
  let counter = 0;
  const store = createManualReconApprovalStore({
    randomId: () => `fixture-${++counter}`,
  });
  const plan = makePlan();
  const denied = store.issue({ plan, ownerSub: 'operator-a' });
  store.decide({
    approvalId: denied.approvalId,
    ownerSub: 'operator-a',
    planHash: plan.hash,
    approved: false,
  });
  assert.throws(
    () => store.consume({
      approvalId: denied.approvalId,
      ownerSub: 'operator-a',
      planHash: plan.hash,
      target: plan.target,
      engagementBinding: plan.engagement.authorizationBinding,
    }),
    (error) => error?.code === 'MANUAL_RECON_APPROVAL_NOT_APPROVED',
  );

  const changed = store.issue({ plan, ownerSub: 'operator-a' });
  const otherPlan = makePlan({ engagementBinding: 'binding-changed' });
  assert.throws(
    () => store.consume({
      approvalId: changed.approvalId,
      ownerSub: 'operator-a',
      planHash: otherPlan.hash,
      target: otherPlan.target,
      engagementBinding: otherPlan.engagement.authorizationBinding,
    }),
    (error) => error?.code === 'MANUAL_RECON_APPROVAL_PLAN_MISMATCH',
  );
  assert.equal(store.size(), 0);
});

test('plano passivo não gera aprovação ofensiva', () => {
  const passive = makePlan({ intrusiveModules: [] });
  assert.equal(passive.requiresHumanApproval, false);
  const store = createManualReconApprovalStore();
  assert.throws(
    () => store.issue({ plan: passive, ownerSub: 'operator-a' }),
    (error) => error?.code === 'MANUAL_RECON_APPROVAL_NOT_REQUIRED',
  );
});
