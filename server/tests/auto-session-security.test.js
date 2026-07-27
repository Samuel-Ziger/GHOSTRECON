import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import {
  createAutoSession,
  readAutoSessionSnapshot,
  reconcileOrphanedAutoSessions,
  writeAutoSessionSnapshot,
} from '../auto-agent/session-store.mjs';
import {
  bindActiveAutoSessionOwner,
  cancelActiveAutoSession,
  listActiveAutoSessions,
  registerActiveAutoSession,
  unregisterActiveAutoSession,
} from '../auto-agent/active-sessions.mjs';
import {
  autoReconRequestIsIntrusive,
  registerAutoReconRoutes,
} from '../routes/auto-recon.mjs';

function principal(sub, scopes = ['recon.read', 'recon.run'], role = 'operator') {
  return {
    sub,
    role,
    via: 'test',
    scopes,
    _scopeSet: new Set(scopes),
  };
}

function mockRequest({
  sub = 'alice',
  scopes,
  role,
  body = {},
  params = {},
  method = 'POST',
  url = '/api/recon/auto/test',
} = {}) {
  return {
    body,
    params,
    method,
    url,
    originalUrl: url,
    headers: { 'user-agent': 'auto-session-security-test' },
    socket: { remoteAddress: '127.0.0.1' },
    principal: principal(sub, scopes, role),
  };
}

function mockResponse() {
  return {
    statusCode: 200,
    body: null,
    chunks: [],
    writableEnded: false,
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; return this; },
    setHeader() {},
    write(chunk) { this.chunks.push(String(chunk)); return true; },
    end() { this.writableEnded = true; },
  };
}

async function callMiddleware(middleware, req) {
  const res = mockResponse();
  let next = false;
  await Promise.resolve(middleware(req, res, () => { next = true; }));
  return { next, res };
}

function registerRoutes(root, audits = []) {
  const routes = [];
  const app = {
    get(pathname, ...handlers) { routes.push({ method: 'GET', pathname, handlers }); },
    post(pathname, ...handlers) { routes.push({ method: 'POST', pathname, handlers }); },
  };
  registerAutoReconRoutes(app, {
    ROOT: root,
    runPipeline: async () => {},
    validateCsrfToken: () => true,
    allowReconRequest: () => true,
    audit: (_req, _principal, decision, extra) => audits.push({ decision, ...extra }),
  });
  return routes;
}

test('autonomia authorized exige escalada recon.intrusive na rota Auto', async () => {
  assert.equal(autoReconRequestIsIntrusive({ autonomyLevel: 'authorized' }), true);
  assert.equal(autoReconRequestIsIntrusive({ autonomyLevel: 'authorized_opsec' }), true);
  assert.equal(autoReconRequestIsIntrusive({ autonomyLevel: 'observation', modules: ['rdap'] }), false);

  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-auto-route-scope-'));
  try {
    const start = registerRoutes(root).find((route) => route.pathname === '/api/recon/auto/stream');
    const operator = mockRequest({
      body: { domain: 'example.com', autonomyLevel: 'authorized' },
      scopes: ['recon.run'],
    });
    const denied = await callMiddleware(start.handlers[0], operator);
    assert.equal(denied.next, false);
    assert.equal(denied.res.statusCode, 403);
    assert.match(denied.res.body.error, /recon\.intrusive/);

    const red = mockRequest({
      body: { domain: 'example.com', autonomyLevel: 'authorized_opsec' },
      scopes: ['recon.run', 'recon.intrusive'],
      role: 'red',
    });
    assert.equal((await callMiddleware(start.handlers[0], red)).next, true);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('registry recusa sessionId duplicado e aplica ownership em listagem/cancelamento', () => {
  const session = createAutoSession({
    sessionId: 'session-owner-security01',
    requestRunId: 'run-owner-security',
    target: 'example.com',
  });
  const alice = principal('alice');
  const bob = principal('bob');
  try {
    registerActiveAutoSession(session);
    assert.throws(() => registerActiveAutoSession(session), /já está ativa/);
    assert.equal(bindActiveAutoSessionOwner(session.state.sessionId, alice), true);
    assert.equal(bindActiveAutoSessionOwner(session.state.sessionId, bob), false);
    assert.equal(listActiveAutoSessions({ principal: alice }).length, 1);
    assert.equal(listActiveAutoSessions({ principal: bob }).length, 0);
    assert.equal(cancelActiveAutoSession(session.state.sessionId, 'bob_attempt', { principal: bob }), false);
    assert.equal(session.signal.aborted, false);
    assert.equal(cancelActiveAutoSession(session.state.sessionId, 'alice_cancel', { principal: alice }), true);
    assert.equal(session.signal.aborted, true);
  } finally {
    unregisterActiveAutoSession(session.state.sessionId);
    session.close('cancelled');
  }
});

test('aprovação é single-flight, classifica risco explícito e rejeita imediatamente no abort', async () => {
  const session = createAutoSession({
    sessionId: 'session-approval-security01',
    requestRunId: 'run-approval-security',
    target: 'example.com',
  });
  session.state.autonomyLevel = 'authorized';
  const approval = session.requestApproval({ action: 'executar módulo ativo não intrusivo' });
  assert.equal(session.state.pendingApproval.intrusive, false);
  await assert.rejects(
    session.requestApproval({ action: 'segunda aprovação' }),
    /já possui aprovação humana pendente/,
  );
  const rejected = assert.rejects(approval, /operator_stop/);
  session.abort('operator_stop');
  await rejected;
  assert.equal(session.state.pendingApproval.status, 'cancelled');
  assert.equal(session.resolveApproval, null);
  session.close('cancelled');

  const intrusiveSession = createAutoSession({
    sessionId: 'session-approval-security02',
    requestRunId: 'run-approval-security-intrusive',
    target: 'example.com',
  });
  const intrusiveApproval = intrusiveSession.requestApproval({
    action: 'executar módulo intrusivo',
    intrusive: true,
    requiredScope: 'recon.intrusive',
  });
  assert.equal(intrusiveSession.state.pendingApproval.intrusive, true);
  intrusiveSession.resolveApproval(
    intrusiveSession.state.pendingApproval.approvalId,
    false,
    'negado no teste',
  );
  assert.equal(await intrusiveApproval, false);
  intrusiveSession.close('completed');
});

test('reconciliação e restauração expiram aprovação órfã e permitem nova aprovação', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-auto-orphan-approval-'));
  const session = createAutoSession({
    sessionId: 'session-orphan-approval01',
    requestRunId: 'run-orphan-approval',
    target: 'example.com',
  });
  let resumed = null;
  try {
    session.state.pendingApproval = {
      approvalId: 'approval-before-restart',
      status: 'pending',
      requestedAt: new Date(Date.now() - 1_000).toISOString(),
      intrusive: true,
    };
    session.state.runtimeLease = {
      schemaVersion: 1,
      pid: 2_147_483_000,
      hostname: os.hostname(),
      processStartToken: 'dead-fixture',
      acquiredAt: new Date(Date.now() - 60_000).toISOString(),
    };
    await writeAutoSessionSnapshot(root, session.state, {});
    session.close('running');

    const reconciledIds = await reconcileOrphanedAutoSessions(root, {}, Date.now());
    assert.deepEqual(reconciledIds, [session.state.sessionId]);
    const reconciled = await readAutoSessionSnapshot(root, session.state.sessionId, {});
    assert.equal(reconciled.status, 'interrupted');
    assert.equal(reconciled.pendingApproval.status, 'expired');
    assert.equal(reconciled.pendingApproval.reason, 'approval_expired_after_server_restart');
    assert.ok(Number.isFinite(Date.parse(reconciled.pendingApproval.resolvedAt)));

    const staleRestoredState = {
      ...reconciled,
      pendingApproval: {
        ...reconciled.pendingApproval,
        status: 'pending',
        reason: '',
        resolvedAt: null,
      },
    };
    resumed = createAutoSession({
      sessionId: staleRestoredState.sessionId,
      requestRunId: staleRestoredState.requestRunId,
      target: staleRestoredState.target,
      restoredState: staleRestoredState,
    });
    assert.equal(resumed.state.pendingApproval.status, 'expired');
    assert.equal(resumed.state.pendingApproval.reason, 'approval_expired_during_session_restore');

    const approval = resumed.requestApproval({ action: 'aprovar plano retomado' });
    assert.equal(resumed.state.pendingApproval.status, 'pending');
    assert.notEqual(resumed.state.pendingApproval.approvalId, 'approval-before-restart');
    assert.equal(resumed.resolveApproval(resumed.state.pendingApproval.approvalId, true, 'ok'), true);
    assert.equal(await approval, true);
  } finally {
    session.close('cancelled');
    resumed?.close('cancelled');
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('reconciliação não interrompe sessão com lease de processo ainda vivo', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-auto-live-lease-'));
  const session = createAutoSession({
    sessionId: 'session-live-runtime-lease01',
    requestRunId: 'run-live-runtime-lease',
    target: 'example.com',
  });
  try {
    await writeAutoSessionSnapshot(root, session.state, {});
    assert.deepEqual(await reconcileOrphanedAutoSessions(root, {}, Date.now()), []);
    const persisted = await readAutoSessionSnapshot(root, session.state.sessionId, {});
    assert.equal(persisted.status, 'running');
    assert.equal(persisted.runtimeLease.pid, process.pid);
  } finally {
    session.close('cancelled');
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('snapshots são atômicos, privados e validados na leitura', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-auto-snapshot-'));
  const session = createAutoSession({
    sessionId: 'session-snapshot-security01',
    requestRunId: 'run-snapshot-security',
    target: 'example.com',
    ownerPrincipal: principal('alice'),
  });
  try {
    const file = await writeAutoSessionSnapshot(root, session.state, {});
    const stat = await fs.stat(file);
    assert.equal(stat.mode & 0o777, 0o600);
    const restored = await readAutoSessionSnapshot(root, session.state.sessionId, {});
    assert.equal(restored.owner.sub, 'alice');
    const entries = await fs.readdir(path.dirname(file));
    assert.deepEqual(entries, ['session.json']);

    await fs.writeFile(file, JSON.stringify({ schemaVersion: 1, sessionId: session.state.sessionId }), { mode: 0o600 });
    await assert.rejects(
      readAutoSessionSnapshot(root, session.state.sessionId, {}),
      /snapshot de sessão AUTO inválido/,
    );
  } finally {
    session.close('cancelled');
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('snapshots e motivos de aprovação redigem segredos sem perder sessionId', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-auto-snapshot-redaction-'));
  const session = createAutoSession({
    sessionId: 'session-snapshot-redact01',
    requestRunId: 'run-snapshot-redact',
    target: 'example.com',
  });
  try {
    const approval = session.requestApproval({
      action: 'validar plano',
      note: 'Authorization: Bearer abcdefghijklmnopqrstuvwxyz',
    });
    session.resolveApproval(
      session.state.pendingApproval.approvalId,
      false,
      'password=super-secret-value',
    );
    assert.equal(await approval, false);

    const file = await writeAutoSessionSnapshot(root, session.state, {});
    const raw = await fs.readFile(file, 'utf8');
    const restored = await readAutoSessionSnapshot(root, session.state.sessionId, {});
    assert.equal(restored.sessionId, session.state.sessionId);
    assert.doesNotMatch(raw, /abcdefghijklmnopqrstuvwxyz/);
    assert.doesNotMatch(raw, /super-secret-value/);
    assert.match(raw, /\[REDACTED\]/);
  } finally {
    session.close('cancelled');
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('rotas list/cancel/approval isolam sessões por principal e auditam decisões', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-auto-owner-routes-'));
  const audits = [];
  const routes = registerRoutes(root, audits);
  const list = routes.find((route) => route.pathname === '/api/recon/auto/sessions');
  const cancel = routes.find((route) => route.pathname === '/api/recon/auto/:sessionId/cancel');
  const approvalRoute = routes.find((route) => route.pathname === '/api/recon/auto/:sessionId/approval');
  const alice = principal('alice', ['recon.read', 'recon.run', 'recon.intrusive'], 'red');
  const bob = principal('bob', ['recon.read', 'recon.run', 'recon.intrusive'], 'red');
  const session = createAutoSession({
    sessionId: 'session-route-security01',
    requestRunId: 'run-route-security',
    target: 'example.com',
  });
  try {
    registerActiveAutoSession(session);
    assert.equal(bindActiveAutoSessionOwner(session.state.sessionId, alice), true);

    const bobList = mockResponse();
    list.handlers.at(-1)({ principal: bob }, bobList);
    assert.deepEqual(bobList.body.sessions, []);

    const bobCancel = mockResponse();
    await cancel.handlers.at(-1)(
      mockRequest({ sub: 'bob', role: 'red', scopes: [...bob.scopes], params: { sessionId: session.state.sessionId } }),
      bobCancel,
    );
    assert.equal(bobCancel.statusCode, 403);
    assert.equal(session.signal.aborted, false);

    session.state.autonomyLevel = 'authorized';
    const approval = session.requestApproval({
      action: 'executar módulo intrusivo',
      intrusive: true,
      requiredScope: 'recon.intrusive',
    });
    const operatorApproval = mockRequest({
      sub: 'alice',
      scopes: ['recon.run'],
      params: { sessionId: session.state.sessionId },
      body: { approvalId: session.state.pendingApproval.approvalId, approved: true },
    });
    const scopeDenied = await callMiddleware(approvalRoute.handlers[0], operatorApproval);
    assert.equal(scopeDenied.next, false);
    assert.equal(scopeDenied.res.statusCode, 403);
    assert.match(scopeDenied.res.body.error, /recon\.intrusive/);

    const bobApproval = mockResponse();
    approvalRoute.handlers.at(-1)(
      mockRequest({
        sub: 'bob',
        role: 'red',
        scopes: [...bob.scopes],
        params: { sessionId: session.state.sessionId },
        body: { approvalId: session.state.pendingApproval.approvalId, approved: true },
      }),
      bobApproval,
    );
    assert.equal(bobApproval.statusCode, 403);

    const aliceApproval = mockResponse();
    approvalRoute.handlers.at(-1)(
      mockRequest({
        sub: 'alice',
        role: 'red',
        scopes: [...alice.scopes],
        params: { sessionId: session.state.sessionId },
        body: { approvalId: session.state.pendingApproval.approvalId, approved: true },
      }),
      aliceApproval,
    );
    assert.equal(aliceApproval.statusCode, 202);
    assert.equal(await approval, true);

    const aliceCancel = mockResponse();
    await cancel.handlers.at(-1)(
      mockRequest({
        sub: 'alice',
        role: 'red',
        scopes: [...alice.scopes],
        params: { sessionId: session.state.sessionId },
      }),
      aliceCancel,
    );
    assert.equal(aliceCancel.statusCode, 202);
    assert.equal(aliceCancel.body.accepted, true);
    assert.equal(aliceCancel.body.terminal, false);
    assert.equal(session.signal.aborted, true);
    assert.ok(audits.some((entry) => entry.action === 'recon.auto.approval' && entry.decision === 'allow'));
    assert.ok(audits.some((entry) => entry.action === 'recon.auto.cancel' && entry.decision === 'deny'));
    assert.ok(audits.some((entry) => entry.action === 'recon.auto.cancel' && entry.decision === 'allow'));
  } finally {
    unregisterActiveAutoSession(session.state.sessionId);
    session.close('cancelled');
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('cancelamento informa sessão terminal e resume recusa snapshot de outro principal', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-auto-terminal-route-'));
  const audits = [];
  const routes = registerRoutes(root, audits);
  const cancel = routes.find((route) => route.pathname === '/api/recon/auto/:sessionId/cancel');
  const start = routes.find((route) => route.pathname === '/api/recon/auto/stream');
  const session = createAutoSession({
    sessionId: 'session-terminal-security01',
    requestRunId: 'run-terminal-security',
    target: 'example.com',
    ownerPrincipal: principal('alice'),
  });
  try {
    session.close('completed');
    await writeAutoSessionSnapshot(root, session.state, {});

    const terminal = mockResponse();
    await cancel.handlers.at(-1)(
      mockRequest({ sub: 'alice', params: { sessionId: session.state.sessionId } }),
      terminal,
    );
    assert.equal(terminal.statusCode, 200);
    assert.equal(terminal.body.accepted, false);
    assert.equal(terminal.body.terminal, true);
    assert.equal(terminal.body.status, 'completed');

    const foreign = mockResponse();
    await cancel.handlers.at(-1)(
      mockRequest({ sub: 'bob', params: { sessionId: session.state.sessionId } }),
      foreign,
    );
    assert.equal(foreign.statusCode, 403);

    const resume = mockResponse();
    await start.handlers.at(-1)(
      mockRequest({
        sub: 'bob',
        body: {
          domain: 'example.com',
          autonomyLevel: 'observation',
          resumeSessionId: session.state.sessionId,
        },
      }),
      resume,
    );
    assert.equal(resume.writableEnded, true);
    assert.match(resume.chunks.join(''), /pertence a outro principal/);
    assert.ok(audits.some((entry) => entry.action === 'recon.auto.resume' && entry.decision === 'deny'));
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});
