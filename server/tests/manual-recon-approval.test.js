import assert from 'node:assert/strict';
import test from 'node:test';

import {
  buildManualReconPrivateContext,
  buildManualReconPlan,
  createManualReconApprovalStore,
  summarizeManualReconAuthentication,
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
const SOURCE_IDENTITY_A = {
  version: 1,
  kind: 'git-worktree',
  objectFormat: 'sha1',
  commit: 'c'.repeat(40),
  tree: 'd'.repeat(40),
  trackedEntries: 9,
  dev: 41,
  ino: 42,
  mode: 0o40700,
  uid: 1000,
  gitDirDev: 41,
  gitDirIno: 43,
  path: '/private/source/never-in-plan',
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
      sourceIdentity: SOURCE_IDENTITY_A,
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
  assert.equal(JSON.stringify(plan).includes('/private/source'), false);
  assert.deepEqual(plan.engines.vigolium.sourceIdentity, {
    version: 1,
    kind: 'git-worktree',
    objectFormat: 'sha1',
    commit: SOURCE_IDENTITY_A.commit,
    tree: SOURCE_IDENTITY_A.tree,
    trackedEntries: 9,
  });
  assert.equal(plan.engines.vigolium.sourceIdentity.dev, undefined);

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
  assert.notEqual(makePlan({
    vigolium: {
      ...plan.engines.vigolium,
      sourceIdentity: {
        ...SOURCE_IDENTITY_A,
        tree: 'e'.repeat(40),
      },
    },
  }).hash, plan.hash);
});

test('plano expõe somente resumo de autenticação e nunca material sensível', () => {
  const body = {
    auth: {
      cookie: 'session=private-cookie',
      headers: {
        Authorization: 'Bearer private-token',
        'X-Tenant': 'tenant-private',
      },
    },
    vigoliumAuthEntries: ['operator:Cookie:vigolium-private'],
    vigoliumAuthFiles: ['/private/session.yaml'],
  };
  const authentication = summarizeManualReconAuthentication(body, {
    vigoliumEnabled: true,
  });
  assert.deepEqual(authentication, {
    pipeline: {
      enabled: true,
      hasCookie: true,
      hasAuthorization: true,
      headerCount: 2,
    },
    vigolium: {
      enabled: true,
      sharesPipelineContext: true,
      inlineEntryCount: 1,
      authFileCount: 1,
    },
  });

  const plan = makePlan({ authentication });
  const serialized = JSON.stringify(plan);
  for (const secret of [
    'private-cookie',
    'private-token',
    'tenant-private',
    'vigolium-private',
    '/private/session.yaml',
  ]) {
    assert.equal(serialized.includes(secret), false, secret);
  }
});

test('resumo de autenticação preserva contagens exatas sem expor valores', () => {
  const headers = Object.fromEntries(
    Array.from({ length: 129 }, (_, index) => [`X-Private-${index}`, `value-${index}`]),
  );
  const entries = Array.from({ length: 129 }, (_, index) => `role-${index}:Cookie:sid=${index}`);
  const authentication = summarizeManualReconAuthentication({
    auth: { headers },
    vigoliumAuth: entries.join('\n'),
    vigoliumAuthFiles: Array.from({ length: 65 }, (_, index) => `/private/${index}.json`),
  }, {
    vigoliumEnabled: true,
  });
  assert.equal(authentication.pipeline.headerCount, 129);
  assert.equal(authentication.vigolium.inlineEntryCount, 129);
  assert.equal(authentication.vigolium.authFileCount, 65);
  assert.equal(JSON.stringify(authentication).includes('sid='), false);
  assert.equal(JSON.stringify(authentication).includes('/private/'), false);
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
    (error) => error?.code === 'MANUAL_RECON_APPROVAL_NOT_FOUND',
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

test('aprovação sela contexto privado por HMAC e falha fechado quando credenciais mudam', () => {
  let counter = 0;
  const store = createManualReconApprovalStore({
    randomId: () => `private-${++counter}`,
    bindingKey: Buffer.alloc(32, 7),
  });
  const plan = makePlan();
  const originalBody = {
    domain: plan.target,
    modules: ['headers', 'frameseven_active'],
    auth: {
      ghostreconApiKey: 'transport-key-a',
      cookie: 'sid=original',
      headers: { Authorization: 'Bearer original' },
    },
    vigoliumAuthEntries: ['operator:Cookie:sid=original'],
  };
  const pending = store.issue({
    plan,
    ownerSub: 'operator-a',
    privateContext: buildManualReconPrivateContext(originalBody),
  });
  store.decide({
    approvalId: pending.approvalId,
    ownerSub: 'operator-a',
    planHash: plan.hash,
    approved: true,
  });

  const changedBody = structuredClone(originalBody);
  changedBody.auth.cookie = 'sid=changed';
  assert.throws(
    () => store.consume({
      approvalId: pending.approvalId,
      ownerSub: 'operator-a',
      planHash: plan.hash,
      target: plan.target,
      engagementBinding: plan.engagement.authorizationBinding,
      privateContext: buildManualReconPrivateContext(changedBody),
    }),
    (error) => error?.code === 'MANUAL_RECON_APPROVAL_CONTEXT_MISMATCH',
  );
  assert.equal(store.size(), 0);

  const retry = store.issue({
    plan,
    ownerSub: 'operator-a',
    privateContext: buildManualReconPrivateContext(originalBody),
  });
  store.decide({
    approvalId: retry.approvalId,
    ownerSub: 'operator-a',
    planHash: plan.hash,
    approved: true,
  });
  const sameExecution = structuredClone(originalBody);
  sameExecution.auth.ghostreconApiKey = 'transport-key-b';
  const consumed = store.consume({
    approvalId: retry.approvalId,
    ownerSub: 'operator-a',
    planHash: plan.hash,
    target: plan.target,
    engagementBinding: plan.engagement.authorizationBinding,
    privateContext: buildManualReconPrivateContext(sameExecution),
  });
  assert.equal(consumed.approved, true);
});

test('selo privado cobre arrays inteiros e strings sem colisão por truncamento', () => {
  let counter = 0;
  const plan = makePlan();
  const store = createManualReconApprovalStore({
    randomId: () => `full-${++counter}`,
    bindingKey: Buffer.alloc(32, 11),
  });
  const issueAndApprove = (privateContext) => {
    const pending = store.issue({
      plan,
      ownerSub: 'operator-a',
      privateContext,
    });
    store.decide({
      approvalId: pending.approvalId,
      ownerSub: 'operator-a',
      planHash: plan.hash,
      approved: true,
    });
    return pending;
  };

  const entriesA = Array.from({ length: 513 }, (_, index) => `entry-${index}`);
  const entriesB = [...entriesA];
  entriesB[512] = 'entry-private-changed';
  const arrayApproval = issueAndApprove(buildManualReconPrivateContext({
    vigoliumAuthEntries: entriesA,
  }));
  assert.throws(
    () => store.consume({
      approvalId: arrayApproval.approvalId,
      ownerSub: 'operator-a',
      planHash: plan.hash,
      target: plan.target,
      engagementBinding: plan.engagement.authorizationBinding,
      privateContext: buildManualReconPrivateContext({
        vigoliumAuthEntries: entriesB,
      }),
    }),
    (error) => error?.code === 'MANUAL_RECON_APPROVAL_CONTEXT_MISMATCH',
  );

  const longPrefix = 'a'.repeat(256 * 1024);
  const longApproval = issueAndApprove(buildManualReconPrivateContext({
    auth: { headers: { Authorization: `${longPrefix}A` } },
  }));
  assert.throws(
    () => store.consume({
      approvalId: longApproval.approvalId,
      ownerSub: 'operator-a',
      planHash: plan.hash,
      target: plan.target,
      engagementBinding: plan.engagement.authorizationBinding,
      privateContext: buildManualReconPrivateContext({
        auth: { headers: { Authorization: `${longPrefix}B` } },
      }),
    }),
    (error) => error?.code === 'MANUAL_RECON_APPROVAL_CONTEXT_MISMATCH',
  );
});

test('store limita aprovações pendentes por operador sem expulsar registros existentes', () => {
  let counter = 0;
  const store = createManualReconApprovalStore({
    randomId: () => `quota-${++counter}`,
    maxEntries: 2,
    maxEntriesPerOwner: 1,
    bindingKey: Buffer.alloc(32, 9),
  });
  const plan = makePlan();
  const first = store.issue({ plan, ownerSub: 'operator-a' });
  assert.throws(
    () => store.issue({ plan, ownerSub: 'operator-a' }),
    (error) => error?.code === 'MANUAL_RECON_APPROVAL_OWNER_CAPACITY',
  );
  const second = store.issue({ plan, ownerSub: 'operator-b' });
  assert.throws(
    () => store.issue({ plan, ownerSub: 'operator-c' }),
    (error) => error?.code === 'MANUAL_RECON_APPROVAL_CAPACITY',
  );

  store.decide({
    approvalId: first.approvalId,
    ownerSub: 'operator-a',
    planHash: plan.hash,
    approved: false,
  });
  assert.equal(store.size(), 1);
  const replacement = store.issue({ plan, ownerSub: 'operator-c' });
  assert.equal(replacement.status, 'pending');
  assert.equal(second.status, 'pending');
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
