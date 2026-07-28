import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import test from 'node:test';

import { registerReconStreamRoutes } from '../routes/recon-stream.mjs';

const VALID_BINARY_IDENTITY = Object.freeze({
  sha256: 'a'.repeat(64),
  size: 123,
  dev: 1,
  ino: 2,
  mtimeMs: 3,
  mode: 0o100755,
});
const VALID_AUTH_FILE_IDENTITY = Object.freeze({
  sha256: 'c'.repeat(64),
  size: 321,
  dev: 7,
  ino: 8,
  mtimeMs: 9,
  mode: 0o100600,
  uid: 1000,
  nlink: 1,
});
const VALID_SOURCE_IDENTITY = Object.freeze({
  version: 1,
  kind: 'git-worktree',
  objectFormat: 'sha1',
  commit: 'd'.repeat(40),
  tree: 'e'.repeat(40),
  trackedEntries: 17,
  dev: 10,
  ino: 11,
  mode: 0o40700,
  uid: 1000,
  gitDirDev: 10,
  gitDirIno: 12,
});

const FRAMESEVEN_OFFENSIVE_TOOLS_V1 = [
  'recon',
  'access',
  'redirect',
  'misconfig',
  'cve',
  'crawler',
  'content',
  'subdomain',
  'ports',
  'nmap',
  'bannergrab',
].join(',');

function activeEngagement(overrides = {}) {
  return {
    id: 'ENG-ROE',
    status: 'active',
    roeSigned: true,
    scopeDomains: ['lab.acme.test'],
    scopeIps: [],
    exclusions: [],
    window: {
      startsAt: '2020-01-01T00:00:00.000Z',
      endsAt: '2099-01-01T00:00:00.000Z',
    },
    ...overrides,
  };
}

function makeRequest(body) {
  const req = new EventEmitter();
  Object.assign(req, {
    body,
    headers: { 'user-agent': 'ghostrecon-test' },
    method: 'POST',
    originalUrl: '/api/recon/stream',
    url: '/api/recon/stream',
    ip: '127.0.0.1',
    principal: {
      sub: 'operator-test',
      role: 'red',
      scopes: ['recon.run', 'recon.intrusive'],
    },
  });
  return req;
}

function makeResponse() {
  const res = new EventEmitter();
  Object.assign(res, {
    chunks: [],
    headers: {},
    destroyed: false,
    writableEnded: false,
    setHeader(name, value) {
      this.headers[String(name).toLowerCase()] = value;
    },
    write(chunk) {
      if (this.destroyed || this.writableEnded) return false;
      this.chunks.push(String(chunk));
      return true;
    },
    end() {
      if (this.writableEnded) return;
      this.writableEnded = true;
      this.emit('finish');
      this.emit('close');
    },
  });
  return res;
}

function eventsFrom(res) {
  return res.chunks
    .join('')
    .split('\n')
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

function makeJsonResponse() {
  return {
    statusCode: 200,
    body: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(body) {
      this.body = body;
      return this;
    },
  };
}

function registerRouteHandlers(overrides = {}, { includeMiddleware = false } = {}) {
  const routes = new Map();
  const app = {
    post(pathname, ...registered) {
      routes.set(pathname, registered);
    },
  };
  registerReconStreamRoutes(app, {
    runPipeline: async () => {},
    validateCsrfToken: () => true,
    allowReconRequest: () => true,
    ROOT: '/tmp/ghostrecon-route-test',
    httpHistory: {
      normalizeHeadersForHistory: () => ({}),
      recordReconHttpHistory: () => {},
      safeJsonBodyForHistory: () => ({}),
    },
    auditAuthImpl: () => {},
    resolveFrameSevenBinaryImpl: () => '/tmp/ghostrecon-route-test/frameseven',
    inspectFrameSevenBinaryIdentityImpl: async () => VALID_BINARY_IDENTITY,
    ...overrides,
  });
  if (includeMiddleware) return routes;
  return new Map(
    [...routes].map(([pathname, handlers]) => [pathname, handlers.at(-1)]),
  );
}

function registerHandler(overrides = {}) {
  const routes = new Map();
  const app = {
    post(pathname, ...registered) {
      routes.set(pathname, registered);
    },
  };
  registerReconStreamRoutes(app, {
    runPipeline: async () => {},
    validateCsrfToken: () => true,
    allowReconRequest: () => true,
    ROOT: '/tmp/ghostrecon-route-test',
    httpHistory: {
      normalizeHeadersForHistory: () => ({}),
      recordReconHttpHistory: () => {},
      safeJsonBodyForHistory: () => ({}),
    },
    auditAuthImpl: () => {},
    manualApprovalStore: {
      issue: () => assert.fail('preflight approval store não esperado neste helper'),
      decide: () => assert.fail('decision approval store não esperado neste helper'),
      consume: () => ({ approved: true, status: 'consumed' }),
    },
    resolveFrameSevenBinaryImpl: () => '/tmp/ghostrecon-route-test/frameseven',
    inspectFrameSevenBinaryIdentityImpl: async () => VALID_BINARY_IDENTITY,
    ...overrides,
  });
  const handlers = routes.get('/api/recon/stream');
  assert.ok(Array.isArray(handlers));
  return handlers.at(-1);
}

function frameSevenBody(overrides = {}) {
  return {
    domain: 'https://lab.acme.test/',
    modules: [],
    includeFrameSeven: true,
    frameSevenAuth: false,
    confirmActive: true,
    manualApproval: { approvalId: 'approval-route-fixture' },
    opsecProfile: 'standard',
    engagementId: 'ENG-ROE',
    ...overrides,
  };
}

function passiveLookingBody(overrides = {}) {
  return {
    domain: 'https://lab.acme.test/',
    modules: ['security_headers'],
    confirmActive: true,
    opsecProfile: 'standard',
    engagementId: 'ENG-ROE',
    ...overrides,
  };
}

test('RBAC classifica o plano implícito e kaliMode antes de entrar no handler do RUN', () => {
  const routes = registerRouteHandlers({}, { includeMiddleware: true });
  const [scopeMiddleware] = routes.get('/api/recon/stream');

  for (const body of [
    passiveLookingBody(),
    passiveLookingBody({ kaliMode: true }),
  ]) {
    const deniedReq = makeRequest(body);
    deniedReq.principal = {
      sub: 'operator-without-intrusive',
      role: 'operator',
      scopes: ['recon.run'],
      _scopeSet: new Set(['recon.run']),
    };
    const deniedRes = makeJsonResponse();
    let deniedNext = false;
    scopeMiddleware(deniedReq, deniedRes, () => {
      deniedNext = true;
    });
    assert.equal(deniedNext, false);
    assert.equal(deniedRes.statusCode, 403);
    assert.match(deniedRes.body.error, /recon\.intrusive/);

    const allowedReq = makeRequest(body);
    allowedReq.principal._scopeSet = new Set(['recon.run', 'recon.intrusive']);
    const allowedRes = makeJsonResponse();
    let allowedNext = false;
    scopeMiddleware(allowedReq, allowedRes, () => {
      allowedNext = true;
    });
    assert.equal(allowedNext, true);
    assert.equal(allowedRes.statusCode, 200);
  }
});

test('RUN conservador mantém implícitas intrusivas desligadas sem confirmação ativa', async () => {
  const routesWithMiddleware = registerRouteHandlers({}, { includeMiddleware: true });
  const [scopeMiddleware] = routesWithMiddleware.get('/api/recon/stream');
  const operatorReq = makeRequest(passiveLookingBody({
    confirmActive: false,
    engagementId: '',
  }));
  operatorReq.principal = {
    sub: 'operator-passive',
    role: 'operator',
    scopes: ['recon.run'],
    _scopeSet: new Set(['recon.run']),
  };
  const middlewareRes = makeJsonResponse();
  let middlewareNext = false;
  scopeMiddleware(operatorReq, middlewareRes, () => {
    middlewareNext = true;
  });
  assert.equal(middlewareNext, true);

  let pipelineArgs = null;
  const handler = registerHandler({
    runPipeline: async (args) => {
      pipelineArgs = args;
    },
  });
  const res = makeResponse();
  await handler(makeRequest(passiveLookingBody({
    confirmActive: false,
    engagementId: '',
  })), res);

  assert.ok(pipelineArgs);
  for (const id of ['evidence_verification', 'active_param_discovery', 'browser_xss_verify']) {
    assert.equal(pipelineArgs.manualEffectiveCapabilities.includes(id), false, id);
  }
  for (const id of ['http_probe', 'asset_discovery', 'high_recheck']) {
    assert.equal(pipelineArgs.manualEffectiveCapabilities.includes(id), true, id);
  }
  const plan = eventsFrom(res).find((event) => event.type === 'manual_effective_plan')?.plan;
  assert.ok(plan);
  assert.equal(plan.requiresHumanApproval, false);
});

test('RUN aparentemente passivo não executa capacidades intrusivas sem aprovação do plano expandido', async () => {
  let pipelineCalls = 0;
  const handler = registerHandler({
    getEngagementImpl: async () => activeEngagement(),
    runPipeline: async () => {
      pipelineCalls += 1;
    },
  });
  const res = makeResponse();

  await handler(makeRequest(passiveLookingBody()), res);

  const events = eventsFrom(res);
  const effectivePlan = events.find((event) => event.type === 'manual_effective_plan')?.plan;
  assert.equal(pipelineCalls, 0);
  assert.ok(effectivePlan);
  for (const id of [
    'http_probe',
    'evidence_verification',
    'active_param_discovery',
    'asset_discovery',
    'high_recheck',
    'browser_xss_verify',
  ]) {
    assert.ok(effectivePlan.expandedModules.includes(id), id);
  }
  assert.deepEqual(
    effectivePlan.intrusiveModules,
    ['evidence_verification', 'active_param_discovery', 'browser_xss_verify'],
  );
  assert.ok(events.some((event) => (
    event.type === 'error'
    && event.code === 'MANUAL_RECON_APPROVAL_REQUIRED'
  )));
});

test('RUN aparentemente passivo só inicia depois de engagement e aprovação vinculada ao plano', async () => {
  let pipelineCalls = 0;
  const routes = registerRouteHandlers({
    getEngagementImpl: async () => activeEngagement(),
    runPipeline: async () => {
      pipelineCalls += 1;
    },
  });
  const body = passiveLookingBody();

  const preflightRes = makeJsonResponse();
  await routes.get('/api/recon/preflight')(makeRequest(body), preflightRes);
  assert.equal(preflightRes.statusCode, 200);
  assert.equal(preflightRes.body.requiresApproval, true);
  assert.ok(preflightRes.body.plan.intrusiveModules.includes('evidence_verification'));

  const approvalRes = makeJsonResponse();
  await routes.get('/api/recon/approval')(makeRequest({
    approvalId: preflightRes.body.approval.approvalId,
    planHash: preflightRes.body.plan.hash,
    approved: true,
  }), approvalRes);
  assert.equal(approvalRes.statusCode, 200);

  const streamRes = makeResponse();
  await routes.get('/api/recon/stream')(makeRequest({
    ...body,
    manualApproval: {
      approvalId: preflightRes.body.approval.approvalId,
      planHash: preflightRes.body.plan.hash,
    },
  }), streamRes);

  assert.equal(pipelineCalls, 1);
  assert.ok(eventsFrom(streamRes).some((event) => event.type === 'manual_approval_consumed'));
});

test('kaliMode exige engagement e aprovação, e o plano aprovado preserva o sentinel intrusivo', async () => {
  let pipelineCalls = 0;
  const noEngagementHandler = registerHandler({
    runPipeline: async () => {
      pipelineCalls += 1;
    },
  });
  const noEngagementRes = makeResponse();
  await noEngagementHandler(makeRequest(passiveLookingBody({
    kaliMode: true,
    engagementId: '',
  })), noEngagementRes);
  assert.equal(pipelineCalls, 0);
  assert.ok(eventsFrom(noEngagementRes).some((event) => (
    event.type === 'error'
    && /engagement formal obrigatório/i.test(JSON.stringify(event.checklist))
  )));

  const routes = registerRouteHandlers({
    getEngagementImpl: async () => activeEngagement(),
    runPipeline: async (args) => {
      pipelineCalls += 1;
      assert.equal(args.kaliMode, true);
    },
  });
  const body = passiveLookingBody({ kaliMode: true });
  const preflightRes = makeJsonResponse();
  await routes.get('/api/recon/preflight')(makeRequest(body), preflightRes);
  assert.equal(preflightRes.statusCode, 200);
  assert.ok(preflightRes.body.plan.expandedModules.includes('kali_active'));
  assert.ok(preflightRes.body.plan.intrusiveModules.includes('kali_active'));

  const withoutApprovalRes = makeResponse();
  await routes.get('/api/recon/stream')(makeRequest(body), withoutApprovalRes);
  assert.equal(pipelineCalls, 0);
  assert.ok(eventsFrom(withoutApprovalRes).some((event) => (
    event.type === 'error'
    && event.code === 'MANUAL_RECON_APPROVAL_REQUIRED'
  )));

  const approvalRes = makeJsonResponse();
  await routes.get('/api/recon/approval')(makeRequest({
    approvalId: preflightRes.body.approval.approvalId,
    planHash: preflightRes.body.plan.hash,
    approved: true,
  }), approvalRes);

  const approvedRes = makeResponse();
  await routes.get('/api/recon/stream')(makeRequest({
    ...body,
    manualApproval: {
      approvalId: preflightRes.body.approval.approvalId,
      planHash: preflightRes.body.plan.hash,
    },
  }), approvedRes);
  assert.equal(pipelineCalls, 1);
});

test('preflight manual apresenta o plano exato e a aprovação é consumida antes do FrameSeven', async () => {
  let pipelineCalls = 0;
  let frameSevenCalls = 0;
  const routes = registerRouteHandlers({
    getEngagementImpl: async () => activeEngagement(),
    runPipeline: async () => {
      pipelineCalls += 1;
    },
    runIntegratedFrameSevenImpl: async (args) => {
      frameSevenCalls += 1;
      await args.pipeline(null, args.emit);
      return { status: 'done' };
    },
  });
  const body = frameSevenBody();
  delete body.manualApproval;

  const preflightRes = makeJsonResponse();
  await routes.get('/api/recon/preflight')(makeRequest(body), preflightRes);
  assert.equal(preflightRes.statusCode, 200);
  assert.equal(preflightRes.body.ok, true);
  assert.equal(preflightRes.body.requiresApproval, true);
  assert.equal(preflightRes.body.plan.engines.frameseven.profile, 'offensive_v1');
  assert.deepEqual(
    preflightRes.body.plan.engines.frameseven.tools,
    FRAMESEVEN_OFFENSIVE_TOOLS_V1.split(','),
  );
  assert.match(preflightRes.body.plan.hash, /^[a-f0-9]{64}$/);
  assert.equal(JSON.stringify(preflightRes.body).includes('/tmp/ghostrecon-route-test'), false);

  const approvalRes = makeJsonResponse();
  await routes.get('/api/recon/approval')(makeRequest({
    approvalId: preflightRes.body.approval.approvalId,
    planHash: preflightRes.body.plan.hash,
    approved: true,
  }), approvalRes);
  assert.equal(approvalRes.statusCode, 200);
  assert.equal(approvalRes.body.approval.status, 'approved');

  const streamReq = makeRequest({
    ...body,
    manualApproval: {
      approvalId: preflightRes.body.approval.approvalId,
      planHash: preflightRes.body.plan.hash,
    },
  });
  const streamRes = makeResponse();
  await routes.get('/api/recon/stream')(streamReq, streamRes);

  assert.equal(pipelineCalls, 1);
  assert.equal(frameSevenCalls, 1);
  assert.ok(eventsFrom(streamRes).some((event) => (
    event.type === 'manual_approval_consumed'
    && event.planHash === preflightRes.body.plan.hash
  )));
});

test('aprovação manual falha fechado quando módulos mudam depois do popup', async () => {
  let pipelineCalls = 0;
  const routes = registerRouteHandlers({
    getEngagementImpl: async () => activeEngagement(),
    runPipeline: async () => {
      pipelineCalls += 1;
    },
  });
  const body = frameSevenBody();
  delete body.manualApproval;
  const preflightRes = makeJsonResponse();
  await routes.get('/api/recon/preflight')(makeRequest(body), preflightRes);
  const approvalRes = makeJsonResponse();
  await routes.get('/api/recon/approval')(makeRequest({
    approvalId: preflightRes.body.approval.approvalId,
    planHash: preflightRes.body.plan.hash,
    approved: true,
  }), approvalRes);

  const streamRes = makeResponse();
  await routes.get('/api/recon/stream')(makeRequest({
    ...body,
    modules: ['security_headers'],
    manualApproval: {
      approvalId: preflightRes.body.approval.approvalId,
      planHash: preflightRes.body.plan.hash,
    },
  }), streamRes);

  assert.equal(pipelineCalls, 0);
  assert.ok(eventsFrom(streamRes).some((event) => (
    event.type === 'error'
    && event.code === 'MANUAL_RECON_APPROVAL_PLAN_MISMATCH'
  )));
});

test('preflight sela autenticação e opções privadas sem expor segredos no plano', async () => {
  let pipelineCalls = 0;
  const routes = registerRouteHandlers({
    getEngagementImpl: async () => activeEngagement(),
    runPipeline: async () => {
      pipelineCalls += 1;
    },
  });
  const body = passiveLookingBody({
    modules: ['security_headers', 'navegation'],
    navigatorMode: true,
    navegation: { exec: true, userMode: true },
    tor: {
      required: true,
      strict: true,
      newnymBeforeRun: true,
      perTargetCircuit: true,
      dnsLeakHost: 'synthetic-dns-check.test',
    },
    identity: {
      enabled: true,
      behavior: true,
      rotation: 'round_robin',
      proxyPool: ['socks5h://operator:private@127.0.0.1:9050'],
    },
    auth: {
      ghostreconApiKey: 'transport-key-never-bound',
      cookie: 'sid=private-cookie-a',
      headers: {
        Authorization: 'Bearer private-token-a',
        'X-Tenant': 'private-tenant-a',
      },
    },
    vigoliumAuthEntries: ['operator:Cookie:vigolium-private-a'],
  });

  const preflightRes = makeJsonResponse();
  await routes.get('/api/recon/preflight')(makeRequest(body), preflightRes);
  assert.equal(preflightRes.statusCode, 200);
  const { plan } = preflightRes.body;
  assert.deepEqual(plan.authentication.pipeline, {
    enabled: true,
    hasCookie: true,
    hasAuthorization: true,
    headerCount: 2,
  });
  assert.equal(plan.execution.navigatorMode, true);
  assert.equal(plan.execution.navigatorExec, true);
  assert.equal(plan.execution.navigatorUserMode, true);
  assert.equal(plan.execution.torRequired, true);
  assert.equal(plan.execution.torStrict, true);
  assert.equal(plan.execution.torNewnymBeforeRun, true);
  assert.equal(plan.execution.torPerTargetCircuit, true);
  assert.match(plan.execution.torDnsLeakHostBinding, /^[a-f0-9]{64}$/);
  assert.equal(plan.execution.proxyCount, 1);
  assert.match(plan.execution.proxyPoolBinding, /^[a-f0-9]{64}$/);
  const serializedPlan = JSON.stringify(plan);
  for (const secret of [
    'private-cookie-a',
    'private-token-a',
    'private-tenant-a',
    'vigolium-private-a',
    'operator:private',
    'synthetic-dns-check.test',
    'transport-key-never-bound',
  ]) {
    assert.equal(serializedPlan.includes(secret), false, secret);
  }

  const approvalRes = makeJsonResponse();
  await routes.get('/api/recon/approval')(makeRequest({
    approvalId: preflightRes.body.approval.approvalId,
    planHash: plan.hash,
    approved: true,
  }), approvalRes);
  assert.equal(approvalRes.statusCode, 200);

  const changedBody = structuredClone(body);
  changedBody.auth.cookie = 'sid=private-cookie-b';
  changedBody.auth.headers.Authorization = 'Bearer private-token-b';
  const streamRes = makeResponse();
  await routes.get('/api/recon/stream')(makeRequest({
    ...changedBody,
    manualApproval: {
      approvalId: preflightRes.body.approval.approvalId,
      planHash: plan.hash,
    },
  }), streamRes);

  assert.equal(pipelineCalls, 0);
  assert.ok(eventsFrom(streamRes).some((event) => (
    event.type === 'error'
    && event.code === 'MANUAL_RECON_APPROVAL_CONTEXT_MISMATCH'
  )));
});

test('RUN manual recusa FrameSeven sem engagement formal mesmo com confirmação ativa', async () => {
  let pipelineCalls = 0;
  let frameSevenCalls = 0;
  let identityCalls = 0;
  const handler = registerHandler({
    runPipeline: async () => { pipelineCalls += 1; },
    getEngagementImpl: async () => null,
    inspectFrameSevenBinaryIdentityImpl: async () => {
      identityCalls += 1;
      return VALID_BINARY_IDENTITY;
    },
    runIntegratedFrameSevenImpl: async () => { frameSevenCalls += 1; },
  });
  const req = makeRequest(frameSevenBody({ engagementId: '' }));
  const res = makeResponse();

  await handler(req, res);

  const events = eventsFrom(res);
  assert.equal(pipelineCalls, 0);
  assert.equal(frameSevenCalls, 0);
  assert.equal(identityCalls, 0);
  assert.ok(events.some((event) => event.type === 'error'
    && /engagement formal obrigatório/i.test(JSON.stringify(event.checklist))));
  assert.equal(req.listenerCount('aborted'), 0);
  assert.equal(res.listenerCount('close'), 0);
});

test('perfil aggressive e confirmActive não substituem ROE assinado do FrameSeven', async () => {
  let frameSevenCalls = 0;
  let identityCalls = 0;
  const handler = registerHandler({
    getEngagementImpl: async () => activeEngagement({ roeSigned: false }),
    inspectFrameSevenBinaryIdentityImpl: async () => {
      identityCalls += 1;
      return VALID_BINARY_IDENTITY;
    },
    runIntegratedFrameSevenImpl: async () => { frameSevenCalls += 1; },
  });
  const req = makeRequest(frameSevenBody({ opsecProfile: 'aggressive', confirmActive: true }));
  const res = makeResponse();

  await handler(req, res);

  const events = eventsFrom(res);
  assert.equal(frameSevenCalls, 0);
  assert.equal(identityCalls, 0);
  assert.ok(events.some((event) => event.type === 'error'
    && /ROE assinado obrigatório/i.test(JSON.stringify(event.checklist))));
});

test('GHOSTRECON_CONFIRM_ACTIVE não substitui a confirmação explícita do RUN HTTP', async (t) => {
  const hadPrevious = Object.hasOwn(process.env, 'GHOSTRECON_CONFIRM_ACTIVE');
  const previous = process.env.GHOSTRECON_CONFIRM_ACTIVE;
  process.env.GHOSTRECON_CONFIRM_ACTIVE = '1';
  t.after(() => {
    if (hadPrevious) process.env.GHOSTRECON_CONFIRM_ACTIVE = previous;
    else delete process.env.GHOSTRECON_CONFIRM_ACTIVE;
  });

  let pipelineCalls = 0;
  let frameSevenCalls = 0;
  const handler = registerHandler({
    getEngagementImpl: async () => activeEngagement(),
    runPipeline: async () => { pipelineCalls += 1; },
    runIntegratedFrameSevenImpl: async () => { frameSevenCalls += 1; },
  });
  const req = makeRequest(frameSevenBody({ confirmActive: false }));
  const res = makeResponse();

  await handler(req, res);

  const events = eventsFrom(res);
  assert.equal(pipelineCalls, 0);
  assert.equal(frameSevenCalls, 0);
  assert.ok(events.some((event) => (
    event.type === 'error'
    && (
      /confirma/i.test(event.message || '')
      || event.opsec?.needsConfirm === true
      || (
        Array.isArray(event.opsec?.needsConfirm)
        && event.opsec.needsConfirm.includes('frameseven_active')
      )
    )
  )));
});

test('RUN manual permite FrameSeven somente com engagement ativo, janela, escopo e ROE válidos', async () => {
  let pipelineCalls = 0;
  let integratedArgs = null;
  const preflightSignals = [];
  const handler = registerHandler({
    getEngagementImpl: async (id, { signal }) => {
      assert.equal(id, 'ENG-ROE');
      assert.equal(signal.aborted, false);
      preflightSignals.push(signal);
      return activeEngagement();
    },
    getShannonCapabilitiesImpl: async ({ signal }) => {
      preflightSignals.push(signal);
      return { ok: true };
    },
    quickValidateTorImpl: async ({ signal }) => {
      preflightSignals.push(signal);
      return {
        validated: true,
        tor: { ip: '127.0.0.2' },
        control: { bootstrap: { tag: 'done' } },
        durationMs: 1,
      };
    },
    torNewnymImpl: async ({ signal }) => {
      preflightSignals.push(signal);
      return { ok: true };
    },
    runPipeline: async ({ signal, requestRunId }) => {
      pipelineCalls += 1;
      assert.equal(signal.aborted, false);
      assert.match(requestRunId, /^req-/);
    },
    runIntegratedFrameSevenImpl: async (args) => {
      integratedArgs = args;
      await args.pipeline(null, args.emit);
      return { status: 'done' };
    },
  });
  const req = makeRequest(frameSevenBody({
    modules: ['shannon_whitebox'],
    tor: { required: true, newnymBeforeRun: true },
  }));
  const res = makeResponse();

  await handler(req, res);

  assert.equal(pipelineCalls, 1);
  assert.equal(integratedArgs.engagementId, 'ENG-ROE');
  assert.equal(integratedArgs.ownerSub, 'operator-test');
  assert.deepEqual(integratedArgs.expectedBinaryIdentity, VALID_BINARY_IDENTITY);
  assert.equal(integratedArgs.tools, FRAMESEVEN_OFFENSIVE_TOOLS_V1);
  assert.equal(integratedArgs.offensiveApproved, true);
  assert.equal(integratedArgs.signal.aborted, false);
  assert.equal(preflightSignals.length, 6);
  for (const signal of preflightSignals) {
    assert.strictEqual(signal, integratedArgs.signal);
  }
  assert.equal(res.writableEnded, true);
  assert.equal(req.listenerCount('aborted'), 0);
  assert.equal(res.listenerCount('close'), 0);
});

test('RUN manual revalida engagement após o pipeline e antes de iniciar o scan FrameSeven', async () => {
  let engagementReads = 0;
  let pipelineCalls = 0;
  let frameSevenScanStarted = false;
  const active = activeEngagement();
  const handler = registerHandler({
    getEngagementImpl: async () => {
      engagementReads += 1;
      return engagementReads < 4 ? active : { ...active, status: 'paused' };
    },
    runPipeline: async () => {
      pipelineCalls += 1;
    },
    runIntegratedFrameSevenImpl: async (args) => {
      await args.pipeline(null, args.emit);
      await args.beforeFrameSevenScan();
      frameSevenScanStarted = true;
    },
  });
  const req = makeRequest(frameSevenBody());
  const res = makeResponse();

  await handler(req, res);

  assert.equal(engagementReads, 4);
  assert.equal(pipelineCalls, 1);
  assert.equal(frameSevenScanStarted, false);
  assert.ok(eventsFrom(res).some((event) => (
    event.type === 'error'
    && /autorização do engagement mudou|engagement inválido/i.test(event.message)
  )));
});

test('RUN manual exige engagement formal para qualquer módulo intrusivo expandido', async () => {
  let pipelineCalls = 0;
  const handler = registerHandler({
    runPipeline: async () => { pipelineCalls += 1; },
  });
  const req = makeRequest({
    domain: 'https://lab.acme.test/',
    modules: ['nmap-aggressive'],
    confirmActive: true,
    opsecProfile: 'aggressive',
  });
  const res = makeResponse();

  await handler(req, res);

  const events = eventsFrom(res);
  assert.equal(pipelineCalls, 0);
  assert.ok(events.some((event) => event.type === 'error'
    && /engagement formal obrigatório/i.test(JSON.stringify(event.checklist))));
});

test('RUN manual bloqueia vigoliumInputFile antes de engagement, fingerprint ou pipeline', async () => {
  let engagementCalls = 0;
  let resolveCalls = 0;
  let pipelineCalls = 0;
  const handler = registerHandler({
    getEngagementImpl: async () => {
      engagementCalls += 1;
      return activeEngagement();
    },
    resolveVigoliumBinaryImpl: async () => {
      resolveCalls += 1;
      return { binary: '/tmp/ghostrecon-route-test/vigolium' };
    },
    runPipeline: async () => { pipelineCalls += 1; },
  });
  const req = makeRequest({
    domain: 'https://lab.acme.test/',
    modules: ['vigolium_dast'],
    vigoliumInputFile: '/tmp/spec-com-outro-alvo.yaml',
    vigoliumInputType: 'openapi',
    confirmActive: true,
    engagementId: 'ENG-ROE',
  });
  const res = makeResponse();

  await handler(req, res);

  assert.equal(engagementCalls, 0);
  assert.equal(resolveCalls, 0);
  assert.equal(pipelineCalls, 0);
  assert.ok(eventsFrom(res).some((event) => (
    event.type === 'error'
    && event.code === 'VIGOLIUM_INPUT_SCOPE_UNSEALED'
  )));
});

test('RUN manual também bloqueia entrada Vigolium injetada pelo ambiente do servidor', async () => {
  let pipelineCalls = 0;
  const handler = registerHandler({
    env: {
      GHOSTRECON_VIGOLIUM_INPUT_FILE: '/tmp/env-out-of-scope.json',
      GHOSTRECON_VIGOLIUM_INPUT_TYPE: 'openapi',
    },
    runPipeline: async () => { pipelineCalls += 1; },
  });
  const req = makeRequest({
    domain: 'https://lab.acme.test/',
    modules: ['vigolium_dast'],
    confirmActive: true,
    engagementId: 'ENG-ROE',
  });
  const res = makeResponse();

  await handler(req, res);

  assert.equal(pipelineCalls, 0);
  assert.ok(eventsFrom(res).some((event) => (
    event.type === 'error'
    && event.code === 'VIGOLIUM_INPUT_SCOPE_UNSEALED'
  )));
});

test('RUN manual sela e propaga a identidade do Vigolium após engagement e gates válidos', async () => {
  const expectedIdentity = Object.freeze({
    sha256: 'b'.repeat(64),
    size: 456,
    dev: 4,
    ino: 5,
    mtimeMs: 6,
    mode: 0o100755,
  });
  let pipelineArgs = null;
  let resolveCalls = 0;
  let inspectCalls = 0;
  const handler = registerHandler({
    getEngagementImpl: async () => activeEngagement(),
    resolveVigoliumBinaryImpl: async (root, options) => {
      resolveCalls += 1;
      assert.equal(root, '/tmp/ghostrecon-route-test');
      assert.equal(options.preferPath, false);
      return { binary: '/tmp/ghostrecon-route-test/vigolium' };
    },
    inspectVigoliumBinaryIdentityImpl: async (binary) => {
      inspectCalls += 1;
      assert.equal(binary, '/tmp/ghostrecon-route-test/vigolium');
      return expectedIdentity;
    },
    runPipeline: async (args) => {
      pipelineArgs = args;
    },
  });
  const req = makeRequest({
    domain: 'https://lab.acme.test/',
    modules: ['vigolium_dast'],
    confirmActive: true,
    manualApproval: { approvalId: 'approval-vigolium-fixture' },
    opsecProfile: 'standard',
    engagementId: 'ENG-ROE',
  });
  const res = makeResponse();

  await handler(req, res);

  assert.equal(resolveCalls, 1);
  assert.equal(inspectCalls, 1);
  assert.ok(pipelineArgs);
  assert.deepEqual(pipelineArgs.vigoliumExpectedIdentity, expectedIdentity);
  assert.equal(pipelineArgs.signal.aborted, false);
  assert.equal(res.writableEnded, true);
});

test('RUN manual recusa extraPath por requisição sem alterar PATH nem iniciar pipeline', async () => {
  const originalPath = process.env.PATH;
  let pipelineCalls = 0;
  const handler = registerHandler({
    getEngagementImpl: async () => activeEngagement(),
    runPipeline: async () => { pipelineCalls += 1; },
  });
  const req = makeRequest({
    domain: 'https://lab.acme.test/',
    modules: [],
    confirmActive: true,
    manualApproval: { approvalId: 'approval-extra-path-fixture' },
    engagementId: 'ENG-ROE',
    extraPath: '/tmp/ghostrecon-route-test/bin',
  });
  const res = makeResponse();

  await handler(req, res);

  assert.equal(pipelineCalls, 0);
  assert.equal(process.env.PATH, originalPath);
  assert.ok(eventsFrom(res).some((event) => event.type === 'error'
    && event.code === 'REQUEST_PATH_OVERRIDE_DISABLED'
    && /configure PATH antes de iniciar/i.test(event.message)));
});

test('desconexão do RUN manual aborta o mesmo signal do pipeline e do FrameSeven', async () => {
  let pipelineSignal = null;
  let frameSevenSignal = null;
  let markFrameSevenStarted;
  const frameSevenStarted = new Promise((resolve) => { markFrameSevenStarted = resolve; });
  const handler = registerHandler({
    getEngagementImpl: async () => activeEngagement(),
    runPipeline: async ({ signal }) => {
      pipelineSignal = signal;
    },
    runIntegratedFrameSevenImpl: async (args) => {
      frameSevenSignal = args.signal;
      await args.pipeline(null, args.emit);
      markFrameSevenStarted();
      await new Promise((resolve, reject) => {
        const onAbort = () => reject(args.signal.reason);
        if (args.signal.aborted) onAbort();
        else args.signal.addEventListener('abort', onAbort, { once: true });
      });
    },
  });
  const req = makeRequest(frameSevenBody());
  const res = makeResponse();

  const running = handler(req, res);
  await frameSevenStarted;
  res.destroyed = true;
  req.emit('aborted');
  res.emit('close');
  await running;

  assert.ok(pipelineSignal);
  assert.strictEqual(pipelineSignal, frameSevenSignal);
  assert.equal(frameSevenSignal.aborted, true);
  assert.equal(frameSevenSignal.reason?.code, 'CLIENT_DISCONNECTED');
  assert.equal(req.listenerCount('aborted'), 0);
  assert.equal(res.listenerCount('close'), 0);
});

test('close da resposta antes de writableEnded também cancela o RUN manual', async () => {
  let frameSevenSignal = null;
  let markFrameSevenStarted;
  const frameSevenStarted = new Promise((resolve) => { markFrameSevenStarted = resolve; });
  const handler = registerHandler({
    getEngagementImpl: async () => activeEngagement(),
    runIntegratedFrameSevenImpl: async ({ signal, pipeline, emit }) => {
      frameSevenSignal = signal;
      await pipeline(null, emit);
      markFrameSevenStarted();
      await new Promise((resolve, reject) => {
        signal.addEventListener('abort', () => reject(signal.reason), { once: true });
      });
    },
  });
  const req = makeRequest(frameSevenBody());
  const res = makeResponse();

  const running = handler(req, res);
  await frameSevenStarted;
  res.destroyed = true;
  res.emit('close');
  await running;

  assert.equal(frameSevenSignal.aborted, true);
  assert.equal(frameSevenSignal.reason?.code, 'CLIENT_DISCONNECTED');
  assert.match(frameSevenSignal.reason?.message || '', /response_close/);
  assert.equal(req.listenerCount('aborted'), 0);
  assert.equal(res.listenerCount('close'), 0);
});

test('configuração Vigolium do ambiente entra no plano e drift após aprovação bloqueia o pipeline', async () => {
  const env = {
    PATH: '/safe/bin',
    GHOSTRECON_ENGINE: 'both',
    GHOSTRECON_VIGOLIUM_STRATEGY: 'balanced',
  };
  let pipelineCalls = 0;
  const routes = registerRouteHandlers({
    env,
    getEngagementImpl: async () => activeEngagement(),
    resolveVigoliumBinaryImpl: async () => ({
      binary: '/tmp/ghostrecon-route-test/vigolium',
      source: 'fixture',
    }),
    inspectVigoliumBinaryIdentityImpl: async () => VALID_BINARY_IDENTITY,
    runPipeline: async () => { pipelineCalls += 1; },
  });
  const body = passiveLookingBody();
  const preflightRes = makeJsonResponse();
  await routes.get('/api/recon/preflight')(makeRequest(body), preflightRes);
  assert.equal(preflightRes.statusCode, 200);
  assert.equal(preflightRes.body.plan.execution.engine, 'both');
  assert.equal(preflightRes.body.plan.engines.vigolium.strategy, 'balanced');
  assert.ok(preflightRes.body.plan.expandedModules.includes('vigolium_dast'));

  const approvalRes = makeJsonResponse();
  await routes.get('/api/recon/approval')(makeRequest({
    approvalId: preflightRes.body.approval.approvalId,
    planHash: preflightRes.body.plan.hash,
    approved: true,
  }), approvalRes);
  env.GHOSTRECON_ENGINE = 'node';
  env.GHOSTRECON_VIGOLIUM_STRATEGY = 'deep';

  const streamRes = makeResponse();
  await routes.get('/api/recon/stream')(makeRequest({
    ...body,
    manualApproval: {
      approvalId: preflightRes.body.approval.approvalId,
      planHash: preflightRes.body.plan.hash,
    },
  }), streamRes);
  assert.equal(pipelineCalls, 0);
  assert.ok(eventsFrom(streamRes).some((event) => (
    event.type === 'error'
    && event.code === 'MANUAL_RECON_APPROVAL_PLAN_MISMATCH'
  )));
});

test('alias vigolium-dast é canónico e snapshot aprovado chega congelado ao pipeline', async () => {
  const env = {
    PATH: '/safe/bin',
    GHOSTRECON_VIGOLIUM_STRATEGY: 'balanced',
    GHOSTRECON_OUT_OF_SCOPE: 'excluded.lab.acme.test',
  };
  let pipelineArgs = null;
  const routes = registerRouteHandlers({
    env,
    getEngagementImpl: async () => activeEngagement(),
    resolveVigoliumBinaryImpl: async () => ({
      binary: '/tmp/ghostrecon-route-test/vigolium',
      source: 'fixture',
    }),
    inspectVigoliumBinaryIdentityImpl: async () => VALID_BINARY_IDENTITY,
    runPipeline: async (args) => { pipelineArgs = args; },
  });
  const body = passiveLookingBody({
    modules: ['vigolium-dast'],
    profile: 'invalid-profile-falls-back',
    outOfScope: ['also-excluded.lab.acme.test'],
  });
  const preflightRes = makeJsonResponse();
  await routes.get('/api/recon/preflight')(makeRequest(body), preflightRes);
  assert.deepEqual(preflightRes.body.plan.selectedModules, ['vigolium_dast']);
  assert.equal(preflightRes.body.plan.execution.profile, 'standard');
  assert.deepEqual(preflightRes.body.plan.execution.outOfScope, [
    'also-excluded.lab.acme.test',
    'excluded.lab.acme.test',
  ]);

  const approvalRes = makeJsonResponse();
  await routes.get('/api/recon/approval')(makeRequest({
    approvalId: preflightRes.body.approval.approvalId,
    planHash: preflightRes.body.plan.hash,
    approved: true,
  }), approvalRes);
  const streamRes = makeResponse();
  await routes.get('/api/recon/stream')(makeRequest({
    ...body,
    manualApproval: {
      approvalId: preflightRes.body.approval.approvalId,
      planHash: preflightRes.body.plan.hash,
    },
  }), streamRes);

  assert.ok(pipelineArgs);
  assert.equal(pipelineArgs.profile, 'standard');
  assert.equal(pipelineArgs.outOfScopeFrozen, true);
  assert.deepEqual(pipelineArgs.outOfScope, [
    'excluded.lab.acme.test',
    'also-excluded.lab.acme.test',
  ]);
  assert.equal(pipelineArgs.vigoliumRuntimeConfig.vigoliumRuntimeConfigFrozen, true);
  assert.equal(pipelineArgs.vigoliumRuntimeConfig.vigoliumRuntimeConfigVersion, 1);
  assert.deepEqual(pipelineArgs.vigoliumRuntimeConfig.vigoliumChildEnv, {
    PATH: '/safe/bin',
    SKIP_EXTERNAL_HARVEST: '1',
    VIGOLIUM_STRATEGY: 'balanced',
  });
});

test('mutação da identidade de auth-file após popup invalida a aprovação', async () => {
  let inspectCalls = 0;
  let pipelineCalls = 0;
  const routes = registerRouteHandlers({
    env: {
      PATH: '/safe/bin',
      GHOSTRECON_VIGOLIUM_AUTH_ROOT: '/synthetic/private-root',
    },
    getEngagementImpl: async () => activeEngagement(),
    resolveVigoliumBinaryImpl: async () => ({
      binary: '/tmp/ghostrecon-route-test/vigolium',
      source: 'fixture',
    }),
    inspectVigoliumBinaryIdentityImpl: async () => VALID_BINARY_IDENTITY,
    inspectVigoliumAuthFileIdentitiesImpl: async (_files, { allowedRoots, signal }) => {
      inspectCalls += 1;
      assert.equal(signal.aborted, false);
      assert.deepEqual(allowedRoots, ['/synthetic/private-root']);
      return [{
        ...VALID_AUTH_FILE_IDENTITY,
        sha256: inspectCalls === 1 ? 'c'.repeat(64) : 'd'.repeat(64),
      }];
    },
    runPipeline: async () => { pipelineCalls += 1; },
  });
  const body = passiveLookingBody({
    modules: ['vigolium_dast'],
    vigoliumAuthFiles: ['/synthetic/private-root/session.json'],
  });
  const preflightRes = makeJsonResponse();
  await routes.get('/api/recon/preflight')(makeRequest(body), preflightRes);
  assert.equal(preflightRes.body.plan.engines.vigolium.authFileIdentityCount, 1);
  const approvalRes = makeJsonResponse();
  await routes.get('/api/recon/approval')(makeRequest({
    approvalId: preflightRes.body.approval.approvalId,
    planHash: preflightRes.body.plan.hash,
    approved: true,
  }), approvalRes);

  const streamRes = makeResponse();
  await routes.get('/api/recon/stream')(makeRequest({
    ...body,
    manualApproval: {
      approvalId: preflightRes.body.approval.approvalId,
      planHash: preflightRes.body.plan.hash,
    },
  }), streamRes);
  assert.equal(inspectCalls, 2);
  assert.equal(pipelineCalls, 0);
  assert.ok(eventsFrom(streamRes).some((event) => (
    event.type === 'error'
    && event.code === 'MANUAL_RECON_APPROVAL_PLAN_MISMATCH'
  )));
});

test('fonte Vigolium local entra no plano por commit/tree e chega congelada ao agente', async () => {
  const sourcePath = '/synthetic/source-root/repository';
  let inspectCalls = 0;
  let pipelineArgs = null;
  const routes = registerRouteHandlers({
    env: {
      PATH: '/safe/bin',
      GHOSTRECON_VIGOLIUM_SOURCE_ROOT: '/synthetic/source-root',
    },
    getEngagementImpl: async () => activeEngagement(),
    resolveVigoliumBinaryImpl: async () => ({
      binary: '/tmp/ghostrecon-route-test/vigolium',
      source: 'fixture',
    }),
    inspectVigoliumBinaryIdentityImpl: async () => VALID_BINARY_IDENTITY,
    inspectVigoliumSourceIdentityImpl: async (source, options) => {
      inspectCalls += 1;
      assert.equal(source, sourcePath);
      assert.deepEqual(options.allowedRoots, ['/synthetic/source-root']);
      assert.equal(options.signal.aborted, false);
      return VALID_SOURCE_IDENTITY;
    },
    runPipeline: async (args) => { pipelineArgs = args; },
  });
  const body = passiveLookingBody({
    modules: ['vigolium_audit'],
    vigoliumAgent: 'audit',
    vigoliumSource: sourcePath,
  });
  const preflightRes = makeJsonResponse();
  await routes.get('/api/recon/preflight')(makeRequest(body), preflightRes);
  assert.equal(preflightRes.statusCode, 200);
  assert.deepEqual(preflightRes.body.plan.engines.vigolium.sourceIdentity, {
    version: 1,
    kind: 'git-worktree',
    objectFormat: 'sha1',
    commit: VALID_SOURCE_IDENTITY.commit,
    tree: VALID_SOURCE_IDENTITY.tree,
    trackedEntries: 17,
  });
  assert.equal(JSON.stringify(preflightRes.body.plan).includes(sourcePath), false);
  assert.equal(preflightRes.body.plan.engines.vigolium.sourceIdentity.dev, undefined);

  const approvalRes = makeJsonResponse();
  await routes.get('/api/recon/approval')(makeRequest({
    approvalId: preflightRes.body.approval.approvalId,
    planHash: preflightRes.body.plan.hash,
    approved: true,
  }), approvalRes);
  const streamRes = makeResponse();
  await routes.get('/api/recon/stream')(makeRequest({
    ...body,
    manualApproval: {
      approvalId: preflightRes.body.approval.approvalId,
      planHash: preflightRes.body.plan.hash,
    },
  }), streamRes);

  assert.equal(inspectCalls, 2);
  assert.ok(pipelineArgs);
  assert.deepEqual(
    pipelineArgs.vigoliumRuntimeConfig.vigoliumExpectedSourceIdentity,
    VALID_SOURCE_IDENTITY,
  );
  assert.deepEqual(
    pipelineArgs.vigoliumRuntimeConfig.vigoliumSourceAllowedRoots,
    ['/synthetic/source-root'],
  );
});

test('preflight recusa fonte Vigolium remota antes de emitir aprovação', async () => {
  let issueCalls = 0;
  const routes = registerRouteHandlers({
    getEngagementImpl: async () => activeEngagement(),
    resolveVigoliumBinaryImpl: async () => ({
      binary: '/tmp/ghostrecon-route-test/vigolium',
      source: 'fixture',
    }),
    inspectVigoliumBinaryIdentityImpl: async () => VALID_BINARY_IDENTITY,
    manualApprovalStore: {
      issue: () => { issueCalls += 1; },
      decide: () => assert.fail('decide não esperado'),
      consume: () => assert.fail('consume não esperado'),
    },
  });
  const res = makeJsonResponse();
  await routes.get('/api/recon/preflight')(makeRequest(passiveLookingBody({
    modules: ['vigolium_audit'],
    vigoliumAgent: 'audit',
    vigoliumSource: 'https://example.invalid/private-repository.git',
  })), res);

  assert.equal(res.statusCode, 400);
  assert.equal(res.body.code, 'VIGOLIUM_SOURCE_REMOTE_FORBIDDEN');
  assert.equal(issueCalls, 0);
  assert.doesNotMatch(JSON.stringify(res.body), /private-repository/);
});

test('close da resposta cancela preflight pendente e não emite aprovação', async () => {
  let issueCalls = 0;
  let observedSignal = null;
  const routes = registerRouteHandlers({
    manualApprovalStore: {
      issue: () => { issueCalls += 1; },
      decide: () => assert.fail('decide não esperado'),
      consume: () => assert.fail('consume não esperado'),
    },
    getEngagementImpl: async (_id, { signal }) => {
      observedSignal = signal;
      await new Promise((resolve, reject) => {
        signal.addEventListener('abort', () => reject(signal.reason), { once: true });
      });
      return activeEngagement();
    },
  });
  const req = makeRequest(passiveLookingBody());
  const res = Object.assign(new EventEmitter(), makeJsonResponse(), {
    writableEnded: false,
  });
  const pending = routes.get('/api/recon/preflight')(req, res);
  await new Promise((resolve) => setImmediate(resolve));
  res.emit('close');
  await pending;

  assert.equal(observedSignal?.aborted, true);
  assert.equal(observedSignal?.reason?.code, 'CLIENT_DISCONNECTED');
  assert.equal(issueCalls, 0);
  assert.equal(res.statusCode, 400);
  assert.equal(res.body.code, 'CLIENT_DISCONNECTED');
  assert.equal(req.listenerCount('aborted'), 0);
  assert.equal(res.listenerCount('close'), 0);
});
