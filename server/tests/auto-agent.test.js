import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { EventEmitter } from 'node:events';
import { PassThrough, Writable } from 'node:stream';

import { detectAutoProviders } from '../auto-agent/provider-detector.mjs';
import { createAutoPlan, evaluateAutoRun } from '../auto-agent/planner.mjs';
import {
  computeAutoCatalogHash,
  computeAutoEngagementAuthorizationBinding,
  assertAutoResumePolicyCompatible,
  buildAutoResumePolicy,
  normalizeAutoRequest,
  runAutoRecon,
  runWithDeadline,
} from '../auto-agent/orchestrator.mjs';
import { decideWithCodex, execFileClosedStdin } from '../auto-agent/providers/codex.mjs';
import { decideWithOpenAiCompatible } from '../auto-agent/providers/openai-compatible.mjs';
import { runAgentCouncil } from '../auto-agent/council/council-runner.mjs';
import { createPendingForgeRequest } from '../auto-agent/forge/forge-store.mjs';
import { decideWithClaudeCode } from '../auto-agent/providers/claude-code.mjs';
import { generatePendingArtifact } from '../auto-agent/forge/generate-artifact.mjs';
import { buildAutoObservationBundle } from '../auto-agent/observation-builder.mjs';
import { validateAndTestForgePackage } from '../auto-agent/forge/validate-package.mjs';
import { reviewForgePackage } from '../auto-agent/forge/code-review.mjs';
import {
  createForgeEngagementBinding,
  listForgePackages,
  readForgePackage,
  recordForgeRuntimeResult,
  transitionForgePackage,
} from '../auto-agent/forge/lifecycle.mjs';
import { runForgeCorrectionLoop } from '../auto-agent/forge/correction-loop.mjs';
import { runActiveDynamicModules } from '../auto-agent/forge/runtime-loader.mjs';
import {
  createForgeSandboxOperationAttestation,
  STRONG_FORGE_SANDBOX_CAPABILITIES,
} from '../auto-agent/forge/sandbox-policy.mjs';
import { computeForgeArtifactIntegrity } from '../auto-agent/forge/artifact-integrity.mjs';
import { repairDecisionEnvelope, validateAgentDecision } from '../auto-agent/decision-contract.mjs';
import { autoSessionLimits, createAutoSession, reconcileOrphanedAutoSessions } from '../auto-agent/session-store.mjs';
import { writeAutoSessionSnapshot } from '../auto-agent/session-store.mjs';
import { CodexAppServerClient } from '../auto-agent/providers/codex-app-server.mjs';
import {
  buildForgeCanaryPipelineContext,
  registerAutoReconRoutes,
  validateForgeCanaryEngagement,
} from '../routes/auto-recon.mjs';
import {
  cancelActiveAutoSession,
  getActiveAutoSession,
  listActiveAutoSessions,
  registerActiveAutoSession,
  unregisterActiveAutoSession,
} from '../auto-agent/active-sessions.mjs';
import { readAndMergeFrameSevenReport } from '../integrations/frameseven-report.mjs';

function strongForgeSandbox(overrides = {}) {
  return {
    capabilities: { ...STRONG_FORGE_SANDBOX_CAPABILITIES },
    async runTests(args) {
      return {
        ok: true,
        code: 0,
        stdout: '',
        stderr: '',
        sandboxAttestation: createForgeSandboxOperationAttestation({
          operation: 'test',
          operationId: args.operationId,
          challenge: args.attestationChallenge,
          runner: 'test-fixture',
        }),
      };
    },
    async runModule(args) {
      return {
        findings: [],
        sandboxAttestation: createForgeSandboxOperationAttestation({
          operation: 'runtime',
          operationId: args.operationId,
          challenge: args.attestationChallenge,
          runner: 'test-fixture',
        }),
      };
    },
    ...overrides,
  };
}

function storedTestAttestation(label = 'fixture') {
  return createForgeSandboxOperationAttestation({
    operation: 'test',
    operationId: `${label}-operation`,
    challenge: `${label}-challenge`,
    runner: 'test-fixture',
  });
}

function forgeActivationGuards({ target, artifactIntegrity }) {
  const engagement = {
    id: 'ENG-FORGE-TEST',
    status: 'active',
    roeSigned: true,
    scopeDomains: [target],
    scopeIps: [],
    exclusions: [],
    updatedAt: '2026-07-26T00:00:00.000Z',
  };
  const engagementBinding = createForgeEngagementBinding({
    engagement,
    engagementId: engagement.id,
    target,
  });
  return {
    expectedTarget: target,
    expectedArtifactIntegrity: artifactIntegrity,
    engagementBinding,
    verifyEngagementBinding: async () => engagementBinding,
  };
}

async function createRouteForgeFixture(root, {
  id = 'route_fixture_module',
  target = 'example.com',
} = {}) {
  const pending = await createPendingForgeRequest({
    root,
    requestRunId: `route-${id}`,
    target,
    decision: {
      forgeRequest: {
        proposedId: id,
        gap: 'fixture local',
        intrusive: false,
        approvals: ['codex'],
      },
      council: {},
    },
    council: {},
    authorOverride: 'codex',
  });
  const manifest = {
    id,
    name: id,
    category: 'surface',
    class: 'passive',
    intrusive: false,
    requiresAuth: false,
    requiresKali: false,
    timeoutMs: 5_000,
    concurrency: 1,
    outputs: ['finding'],
  };
  await Promise.all([
    fs.writeFile(path.join(pending.dir, 'manifest.json'), JSON.stringify(manifest)),
    fs.writeFile(
      path.join(pending.dir, 'module.mjs'),
      'export async function run() { return { findings: [] }; }\n',
    ),
    fs.writeFile(path.join(pending.dir, 'module.test.js'), 'import "./module.mjs";\n'),
  ]);
  const artifactIntegrity = await computeForgeArtifactIntegrity(pending.dir);
  await fs.writeFile(path.join(pending.dir, 'verdict.json'), JSON.stringify({
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
  }));
  return { pending, manifest, artifactIntegrity };
}

test('política de retomada congela providers, motores, engagement e opções da sessão', () => {
  const request = normalizeAutoRequest({
    domain: 'example.com',
    mode: 'deep',
    commanders: ['codex', 'codex'],
    modules: ['rdap'],
    autonomyLevel: 'assisted',
    includeFrameSeven: true,
    includeVigolium: false,
    engagementId: 'ENG-1',
  });
  const policy = buildAutoResumePolicy(request, {
    opsecProfile: 'standard',
    autoAiReports: true,
  });
  assert.deepEqual(policy.commanders, ['codex']);
  assert.equal(policy.includeFrameSeven, true);
  assert.equal(policy.engagementId, 'ENG-1');
  assert.equal(policy.approvalMode, 'interactive');
  assert.doesNotThrow(() => assertAutoResumePolicyCompatible({ resumePolicy: policy }, policy));
  assert.throws(
    () => assertAutoResumePolicyCompatible(
      { resumePolicy: policy },
      { ...policy, includeVigolium: true },
    ),
    /retomada não pode alterar/,
  );
  assert.throws(
    () => assertAutoResumePolicyCompatible(
      { resumePolicy: policy },
      { ...policy, approvalMode: 'deny' },
    ),
    /retomada não pode alterar/,
  );
  assert.throws(
    () => assertAutoResumePolicyCompatible({}, policy),
    /política de retomada ausente/,
  );
  assert.equal(normalizeAutoRequest({ approvalMode: 'deny' }).approvalMode, 'deny');
  assert.equal(normalizeAutoRequest({ approvalMode: 'approve' }).approvalMode, 'interactive');
});

test('binding de autorização do Auto muda somente quando controles do engagement mudam', () => {
  const engagement = {
    id: 'ENG-AUTO-1',
    status: 'active',
    roeSigned: true,
    roeUrl: 'file:///roe/eng-auto-1.pdf',
    scopeDomains: ['example.com'],
    scopeIps: [],
    exclusions: ['blocked.example.com'],
    sourceIps: ['192.0.2.10'],
    window: {
      startsAt: '2026-07-26T00:00:00.000Z',
      endsAt: '2026-07-27T00:00:00.000Z',
      tz: 'America/Sao_Paulo',
    },
    notes: [{ text: 'nota operacional' }],
    runs: [{ runId: 1 }],
  };
  const binding = computeAutoEngagementAuthorizationBinding(engagement, engagement.id);
  assert.match(binding, /^[a-f0-9]{64}$/);
  assert.equal(
    computeAutoEngagementAuthorizationBinding({
      ...engagement,
      notes: [{ text: 'nota alterada' }],
      runs: [{ runId: 2 }],
    }, engagement.id),
    binding,
  );
  assert.notEqual(
    computeAutoEngagementAuthorizationBinding({
      ...engagement,
      exclusions: [...engagement.exclusions, 'new.example.com'],
    }, engagement.id),
    binding,
  );
  assert.notEqual(
    computeAutoEngagementAuthorizationBinding({
      ...engagement,
      status: 'paused',
    }, engagement.id),
    binding,
  );
});

test('catalogHash de retomada cobre metadados executáveis e independe da ordem', () => {
  const base = {
    modules: [
      {
        id: 'headers',
        source: 'ghostrecon',
        class: 'active',
        available: true,
        manifest: { timeoutMs: 1_000, concurrency: 2, phase: 'probe' },
      },
      { id: 'rdap', class: 'passive', available: true },
    ],
  };
  assert.equal(
    computeAutoCatalogHash(base),
    computeAutoCatalogHash({ modules: [...base.modules].reverse() }),
  );
  assert.notEqual(
    computeAutoCatalogHash(base),
    computeAutoCatalogHash({
      modules: [
        { ...base.modules[0], manifest: { ...base.modules[0].manifest, timeoutMs: 2_000 } },
        base.modules[1],
      ],
    }),
  );
  assert.notEqual(
    computeAutoCatalogHash(base),
    computeAutoCatalogHash({
      modules: [{ ...base.modules[0], available: false }, base.modules[1]],
    }),
  );
  assert.notEqual(
    computeAutoCatalogHash(base),
    computeAutoCatalogHash({
      ...base,
      modules: [
        {
          ...base.modules[0],
          forgeId: 'forge-a',
          runtimeIntegrity: { algorithm: 'sha256', artifactSha256: 'a'.repeat(64) },
        },
        base.modules[1],
      ],
    }),
  );
  assert.notEqual(
    computeAutoCatalogHash({ ...base, engines: { frameseven: { available: true, identity: { sha256: 'a'.repeat(64), size: 1 } } } }),
    computeAutoCatalogHash({ ...base, engines: { frameseven: { available: true, identity: { sha256: 'b'.repeat(64), size: 1 } } } }),
  );
});

test('execFileClosedStdin envia EOF para processos que leem stdin', async () => {
  const result = await execFileClosedStdin('/bin/sh', ['-c', 'read value || true; printf eof'], { timeout: 2_000 });
  assert.equal(result.stdout, 'eof');
});

test('execFileClosedStdin encerra o grupo antes de devolver timeout', async () => {
  const startedAt = Date.now();
  await assert.rejects(
    execFileClosedStdin(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], {
      timeout: 50,
      killGraceMs: 100,
    }),
    (error) => error?.code === 'ETIMEDOUT' && error?.killed === true,
  );
  assert.ok(Date.now() - startedAt < 2_000);
});

test('deadline de engine reage imediatamente ao cancelamento da sessão', async () => {
  const controller = new AbortController();
  const reason = new Error('operator_cancelled');
  const startedAt = Date.now();
  const running = runWithDeadline({
    name: 'engine_fixture',
    timeoutMs: 10_000,
    settleGraceMs: 100,
    parentSignal: controller.signal,
    work: (signal) => new Promise((_resolve, reject) => {
      if (signal.aborted) {
        reject(signal.reason);
        return;
      }
      signal.addEventListener('abort', () => reject(signal.reason), { once: true });
    }),
  });
  controller.abort(reason);
  await assert.rejects(running, (error) => error === reason);
  assert.ok(Date.now() - startedAt < 1_000);
});

test('registro de sessões permite cancelar somente a sessão ativa', () => {
  const session = createAutoSession({ sessionId: 'session-cancel-test', requestRunId: 'run-1', target: 'example.com' });
  registerActiveAutoSession(session);
  assert.equal(listActiveAutoSessions().some((item) => item.sessionId === 'session-cancel-test'), true);
  assert.equal(cancelActiveAutoSession('session-cancel-test', 'operator_test'), true);
  assert.equal(session.signal.aborted, true);
  unregisterActiveAutoSession('session-cancel-test');
  assert.equal(cancelActiveAutoSession('session-cancel-test'), false);
  session.close('cancelled');
});

test('sessão running é reconciliada como interrupted após reinício', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-auto-reconcile-'));
  const session = createAutoSession({
    sessionId: 'session-reconcile-test', requestRunId: 'run-reconcile', target: 'example.com',
  });
  session.state.runtimeLease = {
    schemaVersion: 1,
    pid: 2_147_483_000,
    hostname: os.hostname(),
    processStartToken: 'dead-fixture',
    acquiredAt: new Date(Date.now() - 60_000).toISOString(),
  };
  await writeAutoSessionSnapshot(root, session.state, {});
  session.close('running');
  const changed = await reconcileOrphanedAutoSessions(root, {}, Date.now());
  assert.deepEqual(changed, ['session-reconcile-test']);
  const state = JSON.parse(await fs.readFile(path.join(root, 'data/auto-rag/sessions/session-reconcile-test/session.json'), 'utf8'));
  assert.equal(state.status, 'interrupted');
  assert.equal(state.currentStage, 'interrupted');
});

test('detectAutoProviders detecta comandos e OpenRouter sem executar IAs', async () => {
  const seen = [];
  const execFileImpl = async (bin, args) => {
    seen.push([bin, ...args]);
    if (bin === 'codex' && args[0] === 'login' && args[1] === 'status') return { stdout: 'Logged in' };
    if (args[0] === 'codex') return { stdout: 'codex' };
    if (args[0] === 'claude') return { stdout: 'claude' };
    throw new Error('not found');
  };
  const fetchImpl = async (url) => ({
    ok: String(url).includes(':8000') || String(url).includes('openrouter.ai'),
    status: String(url).includes(':8000') || String(url).includes('openrouter.ai') ? 200 : 404,
  });

  const result = await detectAutoProviders({
    selected: ['codex', 'openrouter'],
    env: {
      OPENROUTER_API_KEY: 'sk-test',
      GHOSTRECON_SKYNET_URL: 'http://127.0.0.1:8000',
    },
    execFileImpl,
    fetchImpl,
    platform: 'linux',
  });

  assert.equal(result.ok, true);
  assert.ok(result.commanders.includes('codex'));
  assert.ok(result.commanders.includes('openrouter'));
  assert.equal(result.providers.find((p) => p.id === 'skynet').reachable, true);
  assert.ok(seen.some((row) => row.includes('codex')));
});

test('decisão rejeita evidência inexistente e Forge incompleto', () => {
  const result = validateAgentDecision({
    action: 'forge_module', objective: 'cobrir lacuna', reasoningSummary: ['lacuna'],
    evidenceRefs: ['finding:404'], requestedModules: [], confidence: 0.8,
    forgeRequest: { proposedId: 'gap_module', gap: 'gap', intrusive: false },
  }, { catalogModuleIds: [], availableEvidenceRefs: ['finding:1'] });
  assert.equal(result.ok, false);
  assert.match(result.errors.join(' '), /evidência inexistente|evidências inexistentes/);
  assert.match(result.errors.join(' '), /benefit obrigatório/);
});

test('reparo do envelope Codex preenche apenas campos estruturais ausentes', () => {
  const repaired = repairDecisionEnvelope({ action: 'run_modules', requestedModules: ['security_headers'] }, { objective: 'authorized_recon:test' });
  assert.equal(repaired.action, 'abstain');
  assert.equal(repaired.objective, 'authorized_recon:test');
  assert.equal(repaired.confidence, 0);
  assert.deepEqual(repaired.requestedModules, []);
  const validated = validateAgentDecision(repaired, { catalogModuleIds: [] });
  assert.equal(validated.ok, true);
});

test('contrato aceita alias legado request_modules', () => {
  const repaired = repairDecisionEnvelope({
    action: 'request_modules', objective: 'authorized_recon', confidence: 0.8,
    requestedModules: [], reasoningSummary: [], evidenceRefs: [],
  });
  assert.equal(repaired.action, 'run_modules');
});

test('sessão AUTO aplica limites de chamadas e registra usage', () => {
  const limits = autoSessionLimits({ GHOSTRECON_AUTO_MAX_AGENT_CALLS: '1', GHOSTRECON_AUTO_MAX_ITERATIONS: '2' });
  assert.equal(limits.maxAgentCalls, 1);
  const session = createAutoSession({ sessionId: 's1', requestRunId: 'r1', target: 'example.com', providers: ['codex'], env: { GHOSTRECON_AUTO_MAX_AGENT_CALLS: '1' } });
  session.reserveAgentCall('codex');
  session.recordUsage('codex', { prompt_tokens: 10, completion_tokens: 5, cost: 0.01 });
  assert.throws(() => session.reserveAgentCall('codex'), /limite de chamadas/);
  assert.equal(session.close().usage.codex.promptTokens, 10);
});

test('Codex App Server mantém uma thread para múltiplos turnos', async () => {
  const sent = [];
  const stdout = new PassThrough();
  const stderr = new PassThrough();
  let turn = 0;
  const proc = new EventEmitter();
  proc.stdout = stdout;
  proc.stderr = stderr;
  proc.kill = () => {};
  proc.stdin = new Writable({
    write(chunk, _encoding, callback) {
      const message = JSON.parse(String(chunk));
      sent.push(message);
      if (message.method === 'initialize') stdout.write(`${JSON.stringify({ id: message.id, result: {} })}\n`);
      if (message.method === 'thread/start') stdout.write(`${JSON.stringify({ id: message.id, result: { thread: { id: 'thr-1' } } })}\n`);
      if (message.method === 'turn/start') {
        turn += 1;
        const turnId = `turn-${turn}`;
        stdout.write(`${JSON.stringify({ id: message.id, result: { turn: { id: turnId } } })}\n`);
        queueMicrotask(() => {
          stdout.write(`${JSON.stringify({ method: 'item/agentMessage/delta', params: { turnId, delta: `answer-${turn}` } })}\n`);
          stdout.write(`${JSON.stringify({ method: 'turn/completed', params: { turn: { id: turnId, status: 'completed' } } })}\n`);
        });
      }
      callback();
    },
  });
  const client = new CodexAppServerClient({ root: process.cwd(), env: {}, spawnImpl: () => proc });
  assert.equal(await client.turn({ prompt: 'one', timeoutMs: 1000 }), 'answer-1');
  assert.equal(await client.turn({ prompt: 'two', timeoutMs: 1000 }), 'answer-2');
  assert.equal(sent.filter((message) => message.method === 'thread/start').length, 1);
  client.close();
});

test('timeout RPC encerra Codex App Server antes do fallback', async () => {
  const stdout = new PassThrough();
  const stderr = new PassThrough();
  const signals = [];
  const proc = new EventEmitter();
  proc.stdout = stdout;
  proc.stderr = stderr;
  proc.pid = null;
  proc.kill = (signalName) => {
    signals.push(signalName);
    queueMicrotask(() => proc.emit('exit', null, signalName));
    return true;
  };
  proc.stdin = new Writable({ write(_chunk, _encoding, callback) { callback(); } });
  const client = new CodexAppServerClient({
    root: process.cwd(),
    env: {},
    spawnImpl: () => proc,
  });

  await assert.rejects(
    client.request('initialize', {}, 15),
    (error) => error?.code === 'CODEX_APP_SERVER_REQUEST_TIMEOUT',
  );
  assert.equal(client.closed, true);
  assert.deepEqual(signals, ['SIGTERM']);
});

test('rotas Forge exigem CSRF no lifecycle e expõem comparação autenticável', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-auto-routes-'));
  const routes = [];
  const app = {
    get(pathname, ...handlers) { routes.push({ method: 'GET', pathname, handlers }); },
    post(pathname, ...handlers) { routes.push({ method: 'POST', pathname, handlers }); },
  };
  try {
    registerAutoReconRoutes(app, {
      ROOT: root, runPipeline: async () => {}, validateCsrfToken: () => false, allowReconRequest: () => true,
    });
    const lifecycle = routes.find((route) => route.pathname === '/api/auto-forge/:forgeId/lifecycle');
    const response = { statusCode: 200, status(code) { this.statusCode = code; return this; }, json(body) { this.body = body; } };
    await lifecycle.handlers.at(-1)({ params: { forgeId: 'x' }, body: {} }, response);
    assert.equal(response.statusCode, 403);
    const compare = routes.find((route) => route.pathname === '/api/auto-forge-module/:moduleId/compare');
    const compareResponse = { statusCode: 200, status(code) { this.statusCode = code; return this; }, json(body) { this.body = body; } };
    await compare.handlers.at(-1)({ params: { moduleId: 'safe_module' } }, compareResponse);
    assert.equal(compareResponse.body.ok, true);
    assert.deepEqual(compareResponse.body.versions, []);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('rota de relatório FrameSeven aplica owner/engagement e serve somente artefato sanitizado', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-frameseven-report-route-'));
  const outputDir = path.join(root, 'reports', 'frameseven-owned');
  const routes = [];
  const app = {
    get(pathname, ...handlers) { routes.push({ method: 'GET', pathname, handlers }); },
    post(pathname, ...handlers) { routes.push({ method: 'POST', pathname, handlers }); },
  };
  const engagement = {
    id: 'eng-owned',
    status: 'active',
    roeSigned: true,
    scopeDomains: ['example.com'],
    scopeIps: [],
    exclusions: [],
  };
  const response = () => ({
    statusCode: 200,
    headers: {},
    setHeader(name, value) { this.headers[String(name).toLowerCase()] = String(value); },
    status(code) { this.statusCode = code; return this; },
    type(value) { this.setHeader('content-type', value); return this; },
    send(body) { this.body = body; return this; },
  });
  try {
    await fs.mkdir(outputDir, { recursive: true, mode: 0o700 });
    await fs.writeFile(path.join(outputDir, 'report.json'), JSON.stringify({
      schema_version: 'v1',
      target: 'https://example.com/',
      findings: [{
        module: 'headers',
        severity: 'low',
        title: 'sanitized fixture',
        endpoint: 'https://example.com/',
        evidence: {
          request: 'GET / HTTP/1.1\r\nAuthorization: Bearer private-token',
          response: 'HTTP/1.1 200 OK\r\nSet-Cookie: sid=private-cookie',
          extracted: 'password=private-password',
        },
      }],
      errors: [],
    }));
    await readAndMergeFrameSevenReport({
      outputDir,
      target: 'https://example.com/',
      accessMetadata: {
        ownerSub: 'alice',
        engagementId: engagement.id,
        authenticated: true,
        privateReport: true,
      },
    });
    registerAutoReconRoutes(app, {
      ROOT: root,
      runPipeline: async () => {},
      validateCsrfToken: () => true,
      allowReconRequest: () => true,
      audit: () => {},
      getEngagementImpl: async (id) => id === engagement.id ? engagement : null,
    });
    const route = routes.find((item) => (
      item.method === 'GET'
      && item.pathname === '/api/frameseven/reports/:reportId/:file'
    ));
    assert.ok(route);

    const allowed = response();
    await route.handlers.at(-1)({
      params: { reportId: 'frameseven-owned', file: 'report.html' },
      principal: { sub: 'alice', role: 'operator', scopes: ['recon.read'] },
    }, allowed);
    assert.equal(allowed.statusCode, 200);
    const html = Buffer.from(allowed.body).toString('utf8');
    assert.doesNotMatch(html, /private-token|private-cookie|private-password/);
    assert.match(allowed.headers['content-security-policy'], /^sandbox;/);
    assert.doesNotMatch(allowed.headers['content-security-policy'], /allow-scripts/);

    const denied = response();
    await route.handlers.at(-1)({
      params: { reportId: 'frameseven-owned', file: 'report.html' },
      principal: { sub: 'mallory', role: 'operator', scopes: ['recon.read'] },
    }, denied);
    assert.equal(denied.statusCode, 403);

    const rawPdf = response();
    await route.handlers.at(-1)({
      params: { reportId: 'frameseven-owned', file: 'report.pdf' },
      principal: { sub: 'alice', role: 'operator', scopes: ['recon.read'] },
    }, rawPdf);
    assert.equal(rawPdf.statusCode, 404);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('canário Forge executa somente o módulo aprovado no modo Auto restrito', () => {
  const signal = new AbortController().signal;
  const emit = () => {};
  const forgeSandboxRunner = strongForgeSandbox();
  const context = buildForgeCanaryPipelineContext({
    result: {
      forgeId: 'forge-safe-1',
      moduleId: 'safe_dynamic_module',
      target: 'example.test',
    },
    manifest: { timeoutMs: 12_345 },
    signal,
    emit,
    forgeSandboxRunner,
  });
  assert.equal(context.autoModeExecution, true);
  assert.equal(context.enablePhaseTimeouts, true);
  assert.equal(context.continueOnPhaseError, false);
  assert.deepEqual(context.modules, ['safe_dynamic_module']);
  assert.deepEqual(context.phaseTimeoutsMs, { dynamic_modules: 12_345 });
  assert.equal(context.signal, signal);
  assert.equal(context.emit, emit);
  assert.equal(context.forgeCanaryId, 'forge-safe-1');
  assert.equal(context.forgeSandboxRunner, forgeSandboxRunner);
  assert.equal('kaliMode' in context, false);
  assert.equal('engine' in context, false);
  assert.equal('vigoliumAgent' in context, false);
});

test('rota Forge executa canário direto sem pipeline legado/DNS/finalize e confirma ativação', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-forge-route-canary-'));
  try {
    const pending = await createPendingForgeRequest({
      root,
      requestRunId: 'route-canary-run',
      target: 'example.com',
      decision: {
        forgeRequest: {
          proposedId: 'route_canary_module',
          gap: 'fixture local',
          intrusive: false,
          approvals: ['codex'],
        },
        council: {},
      },
      council: {},
      authorOverride: 'codex',
    });
    const manifest = {
      id: 'route_canary_module',
      name: 'route_canary_module',
      category: 'surface',
      class: 'passive',
      intrusive: false,
      requiresAuth: false,
      requiresKali: false,
      timeoutMs: 5_000,
      concurrency: 1,
      outputs: ['finding'],
    };
    await Promise.all([
      fs.writeFile(path.join(pending.dir, 'manifest.json'), JSON.stringify(manifest)),
      fs.writeFile(
        path.join(pending.dir, 'module.mjs'),
        'export async function run() { return { findings: [] }; }\n',
      ),
      fs.writeFile(
        path.join(pending.dir, 'module.test.js'),
        'import "./module.mjs";\n',
      ),
    ]);
    const artifactIntegrity = await computeForgeArtifactIntegrity(pending.dir);
    await fs.writeFile(path.join(pending.dir, 'verdict.json'), JSON.stringify({
      status: 'pending_operator_approval',
      validation: { ok: true, artifactIntegrity },
      tests: {
        ok: true,
        artifactIntegrity,
        isolation: storedTestAttestation('route-canary'),
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
    }));

    const routes = [];
    const app = {
      get(pathname, ...handlers) { routes.push({ method: 'GET', pathname, handlers }); },
      post(pathname, ...handlers) { routes.push({ method: 'POST', pathname, handlers }); },
    };
    let sandboxContext = null;
    const forgeSandboxRunner = strongForgeSandbox({
      async runModule(args) {
        sandboxContext = args.context;
        return {
          findings: [{ type: 'fixture', value: 'ok' }],
          sandboxAttestation: createForgeSandboxOperationAttestation({
            operation: 'runtime',
            operationId: args.operationId,
            challenge: args.attestationChallenge,
            runner: 'test-fixture',
          }),
        };
      },
    });
    let legacyPipelineCalls = 0;
    registerAutoReconRoutes(app, {
      ROOT: root,
      validateCsrfToken: () => true,
      allowReconRequest: () => true,
      forgeSandboxRunner,
      getEngagementImpl: async () => ({
        id: 'ENG-ROUTE',
        status: 'active',
        roeSigned: true,
        scopeDomains: ['example.com'],
        scopeIps: [],
        exclusions: [],
        updatedAt: '2026-07-26T00:00:00.000Z',
      }),
      runPipeline: async () => {
        legacyPipelineCalls += 1;
        throw new Error('pipeline legado não pode executar no canário Forge');
      },
    });
    const route = routes.find((item) => (
      item.method === 'POST'
      && item.pathname === '/api/auto-forge/:forgeId/verdict'
    ));
    const request = Object.assign(new EventEmitter(), {
      params: { forgeId: pending.forgeId },
      body: { decision: 'approve', reason: 'fixture reviewed', engagementId: 'ENG-ROUTE' },
      principal: { sub: 'operator-fixture' },
    });
    const response = Object.assign(new EventEmitter(), {
      statusCode: 200,
      writableEnded: false,
      status(code) { this.statusCode = code; return this; },
      json(value) { this.body = value; this.writableEnded = true; return this; },
    });

    await route.handlers.at(-1)(request, response);

    assert.equal(response.statusCode, 200);
    assert.equal(response.body.ok, true);
    assert.equal(response.body.runtime.status, 'enabled_for_canary');
    assert.equal(legacyPipelineCalls, 0);
    assert.equal(sandboxContext.target, 'example.com');
    assert.equal(sandboxContext.engagementId, 'ENG-ROUTE');
    assert.match(sandboxContext.authorizationBindingSha256, /^[a-f0-9]{64}$/);
    assert.equal(response.body.dir, undefined);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('rota Forge falha fechado se engagement expirar imediatamente antes do canário', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-forge-route-expired-'));
  try {
    const { pending } = await createRouteForgeFixture(root, {
      id: 'route_expired_module',
      target: 'example.com',
    });
    const routes = [];
    const app = {
      get(pathname, ...handlers) { routes.push({ method: 'GET', pathname, handlers }); },
      post(pathname, ...handlers) { routes.push({ method: 'POST', pathname, handlers }); },
    };
    let engagementReads = 0;
    let sandboxCalls = 0;
    let legacyPipelineCalls = 0;
    const forgeSandboxRunner = strongForgeSandbox({
      async runModule(args) {
        sandboxCalls += 1;
        return {
          findings: [],
          sandboxAttestation: createForgeSandboxOperationAttestation({
            operation: 'runtime',
            operationId: args.operationId,
            challenge: args.attestationChallenge,
            runner: 'test-fixture',
          }),
        };
      },
    });
    registerAutoReconRoutes(app, {
      ROOT: root,
      validateCsrfToken: () => true,
      allowReconRequest: () => true,
      forgeSandboxRunner,
      getEngagementImpl: async () => {
        engagementReads += 1;
        if (engagementReads <= 2) {
          return {
            id: 'ENG-EXPIRES',
            status: 'active',
            roeSigned: true,
            scopeDomains: ['example.com'],
            scopeIps: [],
            exclusions: [],
            updatedAt: '2026-07-26T00:00:00.000Z',
          };
        }
        return {
          id: 'ENG-EXPIRES',
          status: 'closed',
          roeSigned: true,
          scopeDomains: ['example.com'],
          scopeIps: [],
          exclusions: [],
          updatedAt: '2026-07-26T00:00:01.000Z',
          closedAt: '2026-07-26T00:00:01.000Z',
        };
      },
      runPipeline: async () => {
        legacyPipelineCalls += 1;
      },
    });
    const route = routes.find((item) => (
      item.method === 'POST'
      && item.pathname === '/api/auto-forge/:forgeId/verdict'
    ));
    const request = Object.assign(new EventEmitter(), {
      params: { forgeId: pending.forgeId },
      body: {
        decision: 'approve',
        reason: 'fixture reviewed',
        engagementId: 'ENG-EXPIRES',
      },
      principal: { sub: 'operator-fixture' },
    });
    const response = Object.assign(new EventEmitter(), {
      statusCode: 200,
      writableEnded: false,
      status(code) { this.statusCode = code; return this; },
      json(value) { this.body = value; this.writableEnded = true; return this; },
    });

    await route.handlers.at(-1)(request, response);

    assert.equal(response.statusCode, 422);
    assert.equal(response.body.ok, false);
    assert.equal(response.body.runtime.status, 'activation_failed');
    assert.equal(engagementReads, 3);
    assert.equal(sandboxCalls, 0);
    assert.equal(legacyPipelineCalls, 0);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('canário Forge exige engagement formal ativo, assinado e no escopo', () => {
  const candidate = { target: 'https://app.example.com/login', moduleId: 'safe_module' };
  assert.throws(
    () => validateForgeCanaryEngagement({ candidate, engagement: null, engagementId: '' }),
    /engagementId formal é obrigatório/,
  );
  assert.throws(
    () => validateForgeCanaryEngagement({
      candidate,
      engagementId: 'ENG-1',
      engagement: {
        id: 'ENG-1',
        status: 'active',
        roeSigned: true,
        scopeDomains: ['other.example.com'],
        scopeIps: [],
        exclusions: [],
      },
    }),
    /fora da autorização/,
  );
  const valid = validateForgeCanaryEngagement({
    candidate,
    engagementId: 'ENG-1',
    engagement: {
      id: 'ENG-1',
      status: 'active',
      roeSigned: true,
      scopeDomains: ['*.example.com'],
      scopeIps: [],
      exclusions: [],
    },
  });
  assert.equal(valid.target, 'app.example.com');
  assert.equal(valid.checklist.ok, true);
});

test('createAutoPlan monta plano conservador com HexStrike intelligence', () => {
  const plan = createAutoPlan({
    target: 'example.com',
    mode: 'deep',
    requestedModules: ['hexstrike_orchestrator', 'sqlmap'],
    providers: [
      { id: 'codex', selected: true, installed: true, configured: true },
      { id: 'openrouter', selected: true, configured: true, defaultModel: 'z-ai/glm-4.5' },
    ],
    catalog: {
      hexstrike: { installed: true, reachable: false },
      modules: [
        { id: 'security_headers', class: 'passive', available: true },
        { id: 'email_security_deep', class: 'deep_passive', available: true },
        { id: 'api_contract_diff', class: 'active', available: true },
        { id: 'hexstrike_orchestrator', class: 'passive', available: true },
      ],
    },
  });

  assert.equal(plan.kind, 'ghostrecon.auto.plan');
  assert.equal(plan.commanders.roles.leader, 'codex');
  assert.equal(plan.commanders.roles.reviewer, 'openrouter');
  assert.equal(plan.commanders.openrouterModel, 'z-ai/glm-4.5');
  assert.ok(plan.modules.includes('hexstrike_orchestrator'));
  assert.ok(plan.modules.includes('email_security_deep'));
  assert.equal(plan.modules.includes('api_contract_diff'), false);
  assert.equal(plan.modules.includes('sqlmap'), false);
  assert.equal(plan.policy.intrusiveAllowed, false);
});

test('createAutoPlan nunca atribui papel a provedor não selecionado', () => {
  const plan = createAutoPlan({
    target: 'example.com',
    providers: [
      { id: 'codex', selected: true, installed: true, configured: true, reachable: true },
      { id: 'skynet', selected: false, installed: true, configured: true, reachable: true },
      { id: 'openrouter', selected: false, installed: true, configured: true, reachable: true },
    ],
  });
  assert.equal(plan.commanders.roles.leader, 'codex');
  assert.equal(plan.commanders.roles.implementer, 'codex');
  assert.equal(plan.commanders.roles.reviewer, 'codex');
});

test('decideWithCodex usa sandbox read-only e valida módulos do catálogo', async () => {
  let seenArgs = null;
  let seenEnv = null;
  const decision = {
    action: 'run_modules',
    objective: 'Analisar superfície web',
    reasoningSummary: ['HTTPS acessível'],
    evidenceRefs: [],
    requestedModules: ['security_headers'],
    rejectedModules: [],
    confidence: 0.9,
    assumptions: [],
    operatorQuestion: null,
    forgeRequest: null,
  };
  const out = await decideWithCodex({
    target: 'example.com',
    mode: 'balanced',
    catalog: { modules: [{ id: 'security_headers', class: 'passive', available: true }] },
    ragContext: { items: [] },
    root: process.cwd(),
    env: { PATH: process.env.PATH, OPENROUTER_API_KEY: 'must-not-leak' },
    execFileImpl: async (_command, args, opts) => {
      seenArgs = args;
      seenEnv = opts.env;
      const outputPath = args[args.indexOf('--output-last-message') + 1];
      await fs.writeFile(outputPath, JSON.stringify(decision), 'utf8');
      return { stdout: '', stderr: '' };
    },
  });
  assert.equal(out.ok, true);
  assert.deepEqual(out.decision.requestedModules, ['security_headers']);
  assert.ok(seenArgs.includes('--sandbox'));
  assert.equal(seenArgs[seenArgs.indexOf('--sandbox') + 1], 'read-only');
  assert.ok(seenArgs.includes('--ephemeral'));
  assert.equal(seenEnv.OPENROUTER_API_KEY, undefined);
});

test('OpenAI-compatible valida resposta e redige segredo do contexto', async () => {
  let requestBody = null;
  const out = await decideWithOpenAiCompatible({
    provider: 'local-test',
    baseUrl: 'http://local.test/v1',
    model: 'test-model',
    target: 'example.com',
    mode: 'balanced',
    catalog: { modules: [{ id: 'security_headers', class: 'passive', available: true }] },
    ragContext: { items: [{ name: 'notes/x.md', title: 'x', preview: 'token=super-secret-value-123456' }] },
    fetchImpl: async (_url, init) => {
      requestBody = String(init.body);
      return {
        ok: true,
        status: 200,
        json: async () => ({
          choices: [{ message: { content: JSON.stringify({
            action: 'run_modules', objective: 'headers', reasoningSummary: ['sinal'], evidenceRefs: [],
            requestedModules: ['security_headers'], rejectedModules: [], confidence: 0.8,
            assumptions: [], operatorQuestion: null, forgeRequest: null,
          }) } }],
          usage: { total_tokens: 10 },
        }),
      };
    },
  });
  assert.equal(out.ok, true);
  assert.ok(requestBody.includes('[REDACTED]'));
  assert.equal(requestBody.includes('super-secret-value-123456'), false);
});

test('OpenAI-compatible limita reparo de JSON a uma chamada adicional', async () => {
  let calls = 0;
  const decision = {
    action: 'finish', objective: 'done', reasoningSummary: ['ok'], evidenceRefs: [],
    requestedModules: [], rejectedModules: [], confidence: 0.9, assumptions: [], operatorQuestion: null, forgeRequest: null,
  };
  const out = await decideWithOpenAiCompatible({
    provider: 'repair-test', baseUrl: 'http://local.test/v1', model: 'test', target: 'example.com',
    catalog: { modules: [] }, ragContext: { items: [] },
    fetchImpl: async () => {
      calls += 1;
      return { ok: true, status: 200, json: async () => ({ choices: [{ message: { content: calls === 1 ? 'não-json' : JSON.stringify(decision) } }] }) };
    },
  });
  assert.equal(out.ok, true);
  assert.equal(out.transport.repaired, true);
  assert.equal(calls, 2);
});

test('conselho multi-IA executa proposta, revisão cruzada e quórum', async () => {
  const calls = [];
  const decision = {
    action: 'run_modules', objective: 'surface', reasoningSummary: ['consenso'], evidenceRefs: [],
    requestedModules: ['security_headers'], rejectedModules: [], confidence: 0.9,
    assumptions: [], operatorQuestion: null, forgeRequest: null,
  };
  const fetchImpl = async (url, init) => {
    calls.push({ url: String(url), body: String(init.body) });
    return { ok: true, status: 200, json: async () => ({ choices: [{ message: { content: JSON.stringify(decision) } }] }) };
  };
  const execFileImpl = async (_cmd, args) => {
    const outputPath = args[args.indexOf('--output-last-message') + 1];
    await fs.writeFile(outputPath, JSON.stringify(decision), 'utf8');
    return { stdout: '', stderr: '' };
  };
  const out = await runAgentCouncil({
    providers: [
      { id: 'codex', selected: true, installed: true, configured: true, reachable: true, usable: true },
      { id: 'openrouter', selected: true, installed: true, configured: true, reachable: true, usable: true, defaultModel: 'test/model' },
    ],
    target: 'example.com', mode: 'balanced',
    catalog: { modules: [{ id: 'security_headers', class: 'passive', available: true }] },
    ragContext: { items: [] }, root: process.cwd(), env: { OPENROUTER_API_KEY: 'test' },
    fetchImpl, execFileImpl,
  });
  assert.equal(out.proposals.filter((x) => x.ok).length, 2);
  assert.equal(out.reviews.filter((x) => x.ok).length, 2);
  assert.deepEqual(out.finalDecision.requestedModules, ['security_headers']);
  assert.ok(calls.some((x) => x.body.includes('PROPOSTAS_DOS_PARES')));
});

test('Module Forge salva proposta por autor sem habilitar pipeline', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-forge-test-'));
  try {
    const forge = await createPendingForgeRequest({
      root,
      requestRunId: 'auto-test',
      target: 'example.com',
      decision: {
        forgeRequest: {
          proposedId: 'new_passive_module', gap: 'lacuna', evidenceRefs: ['finding:1'], intrusive: false,
          expectedInputs: ['html'], expectedOutputs: ['finding'], testStrategy: 'fetch injetável',
          author: 'codex', approvals: ['openrouter'],
        },
        council: { selected: ['codex', 'openrouter'] },
      },
      council: { proposals: [], reviews: [] },
    });
    assert.match(forge.dir, /by-model\/codex\/pending\/forge-/);
    const verdict = JSON.parse(await fs.readFile(path.join(forge.dir, 'verdict.json'), 'utf8'));
    assert.equal(verdict.policy.pipelineEnabled, false);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('Claude Code roda sem tools e valida structured_output', async () => {
  let seenArgs = null;
  let seenEnv = null;
  let seenInput = null;
  const decision = {
    action: 'finish', objective: 'cobertura suficiente', reasoningSummary: ['sem lacuna'], evidenceRefs: [],
    requestedModules: [], rejectedModules: [], confidence: 0.85, assumptions: [], operatorQuestion: null, forgeRequest: null,
  };
  const out = await decideWithClaudeCode({
    target: 'example.com', mode: 'balanced', catalog: { modules: [] }, ragContext: { items: [] }, root: process.cwd(),
    env: { PATH: process.env.PATH, OPENROUTER_API_KEY: 'no-leak' },
    execFileImpl: async (_cmd, args, opts) => {
      seenArgs = args;
      seenEnv = opts.env;
      seenInput = opts.input;
      return { stdout: JSON.stringify({ structured_output: decision }) };
    },
  });
  assert.equal(out.decision.action, 'finish');
  assert.equal(seenArgs[seenArgs.indexOf('--tools') + 1], '');
  assert.equal(seenArgs.some((arg) => String(arg).includes('example.com')), false);
  assert.match(seenInput, /ALVO: example.com/);
  assert.equal(seenEnv.OPENROUTER_API_KEY, undefined);
});

test('observation bundle redige findings antes do conselho', () => {
  const bundle = buildAutoObservationBundle({
    plan: { modules: ['security_headers'] },
    events: [{ type: 'finding', finding: { type: 'secret', prio: 'high', value: 'token=super-secret-value-123456', url: 'https://example.com' } }],
  });
  assert.deepEqual(bundle.executedModules, ['security_headers']);
  assert.match(bundle.findings[0].value, /REDACTED/);
});

test('gerador Claude grava artefato somente no pending recebido', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-generate-test-'));
  const pendingDir = path.join(root, 'dynamic', 'by-model', 'claude-code', 'pending', 'forge-test');
  await fs.mkdir(pendingDir, { recursive: true });
  const artifact = {
    moduleCode: 'export const moduleManifest = { id: "new_passive_module" };\nexport async function run(){ return { findings: [] }; }',
    testCode: 'import test from "node:test";\nimport assert from "node:assert/strict";\ntest("ok",()=>assert.equal(1,1));',
    manifest: {
      id: 'new_passive_module', name: 'New passive', category: 'surface', intrusive: false,
      requiresAuth: false, requiresKali: false, timeoutMs: 10000, concurrency: 2, outputs: ['finding'],
    },
    implementationNotes: ['offline'],
  };
  try {
    const out = await generatePendingArtifact({
      provider: 'claude_code',
      request: { proposedId: 'new_passive_module', gap: 'gap', intrusive: false },
      target: 'example.com', root, pendingDir, env: { PATH: process.env.PATH },
      execFileImpl: async () => ({ stdout: JSON.stringify({ structured_output: artifact }) }),
    });
    assert.equal(out.ok, true);
    assert.equal(await fs.readFile(path.join(pendingDir, 'module.mjs'), 'utf8'), artifact.moduleCode);
    assert.equal(await fs.readFile(path.join(pendingDir, 'manifest.json'), 'utf8').then((x) => JSON.parse(x).intrusive), false);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('gates do Forge só delegam teste a sandbox forte injetada', async () => {
  const root = await fs.mkdtemp(path.join(process.cwd(), '.tmp-forge-gates-'));
  try {
    await Promise.all([
      fs.writeFile(path.join(root, 'package.json'), JSON.stringify({ type: 'module' })),
      fs.writeFile(path.join(root, 'forge-request.json'), JSON.stringify({ proposedId: 'safe_module', gap: 'parser local' })),
      fs.writeFile(path.join(root, 'manifest.json'), JSON.stringify({
        id: 'safe_module', name: 'Safe', category: 'surface', intrusive: false, requiresAuth: false,
        requiresKali: false, timeoutMs: 5000, concurrency: 1, outputs: ['finding'],
      })),
      fs.writeFile(path.join(root, 'module.mjs'), 'export const moduleManifest={id:"safe_module"};\nexport async function run(){return {findings:[]};}\n'),
      fs.writeFile(path.join(root, 'module.test.js'), 'import test from "node:test";\nimport assert from "node:assert/strict";\nimport {run} from "./module.mjs";\ntest("safe",async()=>assert.deepEqual(await run(),{findings:[]}));\n'),
      fs.writeFile(path.join(root, 'verdict.json'), JSON.stringify({ policy: { pipelineEnabled: false } })),
    ]);
    let isolatedCalls = 0;
    const result = await validateAndTestForgePackage(root, {
      isolatedRunner: strongForgeSandbox({
        async runTests(args) {
          isolatedCalls += 1;
          return {
            ok: true,
            code: 0,
            stdout: 'isolated',
            stderr: '',
            sandboxAttestation: createForgeSandboxOperationAttestation({
              operation: 'test',
              operationId: args.operationId,
              challenge: args.attestationChallenge,
              runner: 'test-fixture',
            }),
          };
        },
      }),
    });
    assert.equal(result.validation.ok, true);
    assert.equal(result.tests.ok, true, JSON.stringify(result.tests));
    assert.equal(result.tests.isolation.strong, true);
    assert.equal(isolatedCalls, 1);
    assert.equal(result.verdict.status, 'pending_ai_code_review');
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('gates bloqueiam child_process antes de executar teste', async () => {
  const root = await fs.mkdtemp(path.join(process.cwd(), '.tmp-forge-block-'));
  try {
    await Promise.all([
      fs.writeFile(path.join(root, 'forge-request.json'), JSON.stringify({ proposedId: 'bad_module', gap: 'parser' })),
      fs.writeFile(path.join(root, 'manifest.json'), JSON.stringify({
        id: 'bad_module', name: 'Bad', category: 'surface', intrusive: false, requiresAuth: false,
        requiresKali: false, timeoutMs: 5000, concurrency: 1, outputs: ['finding'],
      })),
      fs.writeFile(path.join(root, 'module.mjs'), 'import {spawn} from "node:child_process";\nexport function run(){return spawn("id");}\n'),
      fs.writeFile(path.join(root, 'module.test.js'), 'import test from "node:test";\nimport "./module.mjs";\ntest("x",()=>{});\n'),
      fs.writeFile(path.join(root, 'verdict.json'), '{}'),
    ]);
    const result = await validateAndTestForgePackage(root);
    assert.equal(result.ok, false);
    assert.ok(result.validation.errors.some((x) => x.includes('process_execution') || x.includes('imports')));
    assert.equal(result.tests.skipped, true);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('review de código exige quórum e mantém pipeline bloqueado', async () => {
  const root = await fs.mkdtemp(path.join(process.cwd(), '.tmp-forge-review-'));
  const review = { verdict: 'approve', summary: 'ok', issues: [], confidence: 0.9 };
  try {
    await Promise.all([
      fs.writeFile(path.join(root, 'forge-request.json'), '{}'),
      fs.writeFile(path.join(root, 'manifest.json'), '{}'),
      fs.writeFile(path.join(root, 'module.mjs'), 'export function run(){}'),
      fs.writeFile(path.join(root, 'module.test.js'), 'import test from "node:test";'),
      fs.writeFile(path.join(root, 'provenance.json'), JSON.stringify({ author: 'codex' })),
    ]);
    const artifactIntegrity = await computeForgeArtifactIntegrity(root);
    await Promise.all([
      fs.writeFile(path.join(root, 'validation-results.json'), JSON.stringify({
        ok: true,
        artifactIntegrity,
      })),
      fs.writeFile(path.join(root, 'test-results.json'), JSON.stringify({
        ok: true,
        artifactIntegrity,
      })),
      fs.writeFile(path.join(root, 'verdict.json'), JSON.stringify({
        validation: { ok: true, artifactIntegrity },
        tests: { ok: true, artifactIntegrity },
        policy: { pipelineEnabled: false },
      })),
    ]);
    const result = await reviewForgePackage({
      pendingDir: root,
      root: process.cwd(),
      providers: [
        { id: 'codex', selected: true, usable: true },
        { id: 'openrouter', selected: true, usable: true, defaultModel: 'test/model' },
        { id: 'skynet', selected: true, usable: true, defaultModel: 'ghost-test' },
      ],
      env: { OPENROUTER_API_KEY: 'test' },
      fetchImpl: async () => ({ ok: true, status: 200, json: async () => ({ choices: [{ message: { content: JSON.stringify(review) } }] }) }),
    });
    assert.equal(result.approved, true);
    assert.equal(result.status, 'pending_operator_approval');
    assert.equal(result.minimumQuorum, 2);
    assert.equal(result.independentVotes, 2);
    assert.equal(result.reviews.some((row) => row.provider === 'codex'), false);
    const verdict = JSON.parse(await fs.readFile(path.join(root, 'verdict.json'), 'utf8'));
    assert.equal(verdict.policy.pipelineEnabled, false);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('lifecycle ativa pacote aprovado e loader executa somente no alvo original', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-lifecycle-'));
  try {
    const pending = await createPendingForgeRequest({
      root, requestRunId: 'run', target: 'example.com',
      decision: { forgeRequest: { proposedId: 'approved_module', gap: 'gap', intrusive: false, approvals: ['codex'] }, council: {} },
      council: {}, authorOverride: 'codex',
    });
    await fs.writeFile(path.join(pending.dir, 'manifest.json'), JSON.stringify({
      id: 'approved_module',
      intrusive: false,
      requiresAuth: false,
      timeoutMs: 5000,
    }));
    await fs.writeFile(path.join(pending.dir, 'module.mjs'), 'export async function run({target}) { return {findings:[{type:"ai_test",prio:"low",score:20,value:"executed",url:`https://${target}/`}]}; }\n');
    await fs.writeFile(
      path.join(pending.dir, 'module.test.js'),
      "import test from 'node:test';\nimport { run } from './module.mjs';\ntest('safe', async () => { await run({ target: 'example.com' }); });\n",
    );
    const artifactIntegrity = await computeForgeArtifactIntegrity(pending.dir);
    await fs.writeFile(path.join(pending.dir, 'verdict.json'), JSON.stringify({
      status: 'pending_operator_approval',
      validation: { ok: true, artifactIntegrity },
      tests: {
        ok: true,
        artifactIntegrity,
        isolation: storedTestAttestation('approved-module'),
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
    }));
    const detail = await readForgePackage(root, pending.forgeId);
    assert.equal(detail.artifacts['manifest.json'].id, 'approved_module');
    assert.match(detail.artifacts['module.mjs'], /export/);
    const guards = forgeActivationGuards({ target: 'example.com', artifactIntegrity });
    const moved = await transitionForgePackage({
      root,
      forgeId: pending.forgeId,
      decision: 'approve',
      reason: 'reviewed',
      ...guards,
    });
    assert.equal(moved.state, 'active');
    assert.equal(moved.pipelineEnabled, false);
    assert.equal(typeof moved.activationId, 'string');
    assert.match(moved.dir, /active\/approved_module/);
    const findings = [];
    const events = [];
    let isolatedRuntimeCalls = 0;
    const runtime = await runActiveDynamicModules({
      ROOT: root, domain: 'example.com', modules: ['approved_module'],
      forgeCanaryId: moved.forgeId,
      forgeCanaryActivation: {
        activationId: moved.activationId,
        expectedTarget: moved.target,
        expectedArtifactIntegrity: moved.artifactIntegrity,
        engagementBinding: moved.engagementBinding,
      },
      pipe: () => {}, log: () => {}, emit: (event) => events.push(event), addFinding: (finding) => findings.push(finding),
    }, {
      root,
      isolatedRunner: strongForgeSandbox({
        async runModule(args) {
          isolatedRuntimeCalls += 1;
          return {
            findings: [{
              type: 'ai_test',
              prio: 'low',
              score: 20,
              value: 'executed',
              url: 'https://outside.invalid/',
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
    assert.equal(runtime.executed, 1);
    assert.equal(isolatedRuntimeCalls, 1);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].url, '');
    assert.match(findings[0].provenance.how, /Forge approved_module/);
    assert.match(findings[0].provenance.relation, /example\.com/);
    assert.ok(events.some((event) => event.type === 'dynamic_module_completed'));
    const firstRun = await recordForgeRuntimeResult({
      root,
      forgeId: pending.forgeId,
      activationId: moved.activationId,
      expectedTarget: moved.target,
      expectedArtifactIntegrity: moved.artifactIntegrity,
      engagementBinding: moved.engagementBinding,
      success: true,
      findings: findings.length,
    });
    assert.equal(firstRun.status, 'enabled_for_canary');
    assert.equal(firstRun.pipelineEnabled, true);
    const listed = await listForgePackages(root);
    assert.equal(listed[0].state, 'active');
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('evaluateAutoRun resume findings, warnings e erros', () => {
  const evaluation = evaluateAutoRun({
    plan: { target: 'example.com' },
    events: [
      { type: 'finding', finding: { prio: 'high' } },
      { type: 'log', level: 'warn', msg: 'offline' },
      { type: 'error', message: 'boom' },
    ],
  });

  assert.equal(evaluation.ok, false);
  assert.equal(evaluation.findings, 1);
  assert.equal(evaluation.highSignals, 1);
  assert.equal(evaluation.warnings, 1);
  assert.deepEqual(evaluation.errors, ['boom']);
});

test('evaluateAutoRun preserva sucesso parcial quando um erro recuperável foi ignorado', () => {
  const evaluation = evaluateAutoRun({
    plan: { target: 'example.com' },
    events: [
      { type: 'finding', finding: { prio: 'low' } },
      { type: 'error', recoverable: true, message: 'motor opcional indisponível' },
      {
        type: 'phase_outcome',
        phase: 'probe',
        status: 'timeout',
        recoverable: true,
        error: 'timeout cooperativo',
      },
    ],
  });

  assert.equal(evaluation.ok, true);
  assert.equal(evaluation.status, 'partial');
  assert.deepEqual(evaluation.errors, []);
  assert.deepEqual(evaluation.recoverableErrors, ['motor opcional indisponível']);
  assert.equal(evaluation.phaseFailures[0].phase, 'probe');
});

test('runAutoRecon emite plano e chama runPipeline com modulos planejados', async () => {
  const emitted = [];
  let pipelineCtx = null;
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-auto-run-'));
  try {
  const result = await runAutoRecon({
    body: {
      domain: 'example.com',
      mode: 'balanced',
      commanders: ['openrouter'],
      includeHexstrike: false,
      vigoliumSource: '/tmp/nao-autorizado',
      vigoliumModules: ['audit'],
      vigoliumOnly: 'audit',
      auth: { headers: { Authorization: 'Bearer should-not-pass' } },
    },
    ROOT: root,
    env: { OPENROUTER_API_KEY: 'sk-test', GHOSTRECON_AUTO_RAG_ENABLED: '0' },
    execFileImpl: async () => {
      throw new Error('not found');
    },
    fetchImpl: async () => ({ ok: false, status: 404 }),
    emit: (e) => emitted.push(e),
    runPipeline: async (ctx) => {
      pipelineCtx = ctx;
      ctx.emit({
        type: 'phase_outcome',
        phase: 'discovery',
        status: 'timeout',
        recoverable: true,
        settled: true,
        error: 'fixture timeout',
      });
      ctx.emit({ type: 'finding', finding: { prio: 'low', value: 'ok' } });
    },
  });

  assert.ok(emitted.some((e) => e.type === 'auto_plan'));
  assert.ok(emitted.some((e) => e.type === 'auto_evaluation'));
  assert.ok(pipelineCtx.modules.includes('subdomains'));
  assert.equal(pipelineCtx.modules.includes('security_headers'), false);
  assert.equal(pipelineCtx.modules.includes('hexstrike_orchestrator'), false);
  assert.equal(pipelineCtx.vigoliumSource, undefined);
  assert.equal(pipelineCtx.vigoliumModules, undefined);
  assert.equal(pipelineCtx.vigoliumOnly, undefined);
  assert.equal(pipelineCtx.auth, undefined);
  assert.equal(pipelineCtx.confirmActive, false);
  assert.equal(typeof pipelineCtx.phaseTimeoutsMs.discovery, 'number');
  assert.equal(result.evaluation.ok, true);
  assert.equal(result.evaluation.status, 'partial');
  assert.equal(result.evaluation.findings, 1);
  assert.equal(
    result.evaluation.moduleOutcomes.find((item) => item.moduleId === 'subdomains')?.status,
    'timeout',
  );
  assert.equal(
    result.evaluation.moduleOutcomes.find((item) => item.moduleId === 'subdomains')?.phase,
    'discovery',
  );
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('Auto funde outOfScope do operador com exclusions do engagement no plano e pipeline', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-auto-scope-merge-'));
  let pipelineCtx = null;
  const engagement = {
    id: 'ENG-AUTO-SCOPE',
    status: 'active',
    roeSigned: true,
    scopeDomains: ['example.com'],
    scopeIps: [],
    exclusions: ['roe-blocked.example.com'],
  };
  try {
    await runAutoRecon({
      body: {
        domain: 'example.com',
        mode: 'balanced',
        commanders: [],
        modules: ['subdomains'],
        engagementId: engagement.id,
        outOfScope: ['operator-blocked.example.com'],
      },
      ROOT: root,
      env: {
        GHOSTRECON_AUTO_RAG_ENABLED: '0',
        GHOSTRECON_AUTO_HEARTBEAT_MS: '60000',
      },
      getEngagementImpl: async () => engagement,
      runPipeline: async (ctx) => {
        pipelineCtx = ctx;
      },
      fetchImpl: async () => ({ ok: false, status: 503 }),
      execFileImpl: async () => {
        throw new Error('provider indisponível na fixture');
      },
    });

    assert.deepEqual(
      [...pipelineCtx.outOfScope].sort(),
      ['operator-blocked.example.com', 'roe-blocked.example.com'],
    );
    assert.deepEqual(
      pipelineCtx.scopePolicy.exclusions,
      ['roe-blocked.example.com'],
    );
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('Auto FrameSeven emite um único terminal parcial somente após o merge', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-auto-frameseven-'));
  const binary = path.join(root, 'FrameSeven', 'bin', 'frameseven', 'cli', 'v1');
  const outputDir = path.join(root, 'reports', 'frameseven-auto-fixture');
  const emitted = [];
  let frameSevenOptions = null;
  try {
    await fs.mkdir(path.dirname(binary), { recursive: true });
    await fs.writeFile(binary, '#!/bin/sh\nexit 0\n', { mode: 0o755 });
    await fs.chmod(binary, 0o755);

    const result = await runAutoRecon({
      body: {
        domain: 'example.com',
        mode: 'balanced',
        commanders: [],
        modules: ['frameseven_recon'],
        includeFrameSeven: true,
        autonomyLevel: 'assisted',
        approvalMode: 'interactive',
      },
      ROOT: root,
      env: {
        GHOSTRECON_AUTO_RAG_ENABLED: '0',
        GHOSTRECON_AUTO_HEARTBEAT_MS: '60000',
      },
      runPipeline: async ({ emit }) => {
        emit({ type: 'pipe', name: 'rdap', state: 'done' });
      },
      runFrameSevenImpl: async (options) => {
        frameSevenOptions = options;
        options.emit({ type: 'engine_started', engine: 'frameseven' });
        return {
          engine: 'frameseven',
          status: 'partial',
          code: 1,
          outputDir,
        };
      },
      readFrameSevenReportImpl: async () => ({
        reportErrors: [],
        incomplete: false,
        incomingFindings: [{
          type: 'fixture',
          prio: 'low',
          score: 10,
          value: 'partial evidence',
          url: 'https://example.com/',
        }],
        newFindings: [{
          type: 'fixture',
          prio: 'low',
          score: 10,
          value: 'partial evidence',
          url: 'https://example.com/',
        }],
        inputCount: 1,
        outputCount: 1,
        mergedCount: 0,
      }),
      emit: (event) => {
        emitted.push(event);
        if (event.type === 'auto_approval_required') {
          const active = getActiveAutoSession(event.sessionId);
          active?.resolveApproval(
            event.approval.approvalId,
            true,
            'fixture local aprovada',
          );
        }
      },
      fetchImpl: async () => ({ ok: false, status: 503 }),
      execFileImpl: async () => {
        throw new Error('provider indisponível na fixture');
      },
    });

    assert.equal(frameSevenOptions.deferDoneEvent, true);
    const terminals = emitted.filter((event) => (
      event.engine === 'frameseven'
      && ['engine_done', 'engine_partial', 'engine_failed', 'engine_timeout'].includes(event.type)
    ));
    assert.equal(terminals.length, 1);
    assert.equal(terminals[0].type, 'engine_partial');
    assert.equal(terminals[0].phase, 'scan');
    assert.equal(
      terminals[0].reportUrl,
      '/api/frameseven/reports/frameseven-auto-fixture/report.html',
    );
    assert.equal(
      result.evaluation.moduleOutcomes.find((item) => item.moduleId === 'frameseven_recon')?.status,
      'done',
    );
    assert.equal(
      result.evaluation.moduleOutcomes.find((item) => item.moduleId === 'frameseven_recon')?.partial,
      true,
    );
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('Auto falha fechado quando FrameSeven não confirma encerramento do subprocesso', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-auto-frameseven-unterminated-'));
  const binary = path.join(root, 'FrameSeven', 'bin', 'frameseven', 'cli', 'v1');
  const emitted = [];
  let pipelineCalls = 0;
  try {
    await fs.mkdir(path.dirname(binary), { recursive: true });
    await fs.writeFile(binary, '#!/bin/sh\nexit 0\n', { mode: 0o755 });
    await fs.chmod(binary, 0o755);

    await assert.rejects(
      runAutoRecon({
        body: {
          domain: 'example.com',
          mode: 'balanced',
          commanders: [],
          modules: ['frameseven_recon'],
          includeFrameSeven: true,
          autonomyLevel: 'assisted',
          approvalMode: 'interactive',
        },
        ROOT: root,
        env: {
          GHOSTRECON_AUTO_RAG_ENABLED: '0',
          GHOSTRECON_AUTO_HEARTBEAT_MS: '60000',
        },
        runPipeline: async () => {
          pipelineCalls += 1;
        },
        runFrameSevenImpl: async () => {
          const error = new Error('FrameSeven child did not terminate');
          error.code = 'FRAMESEVEN_PROCESS_UNTERMINATED';
          error.unterminated = true;
          error.recoverable = false;
          throw error;
        },
        emit: (event) => {
          emitted.push(event);
          if (event.type === 'auto_approval_required') {
            const session = getActiveAutoSession(event.sessionId);
            session?.resolveApproval(
              event.approval.approvalId,
              true,
              'fixture local aprovada',
            );
          }
        },
        fetchImpl: async () => ({ ok: false, status: 503 }),
        execFileImpl: async () => {
          throw new Error('provider indisponível na fixture');
        },
      }),
      (error) => error?.code === 'FRAMESEVEN_PROCESS_UNTERMINATED',
    );

    assert.equal(pipelineCalls, 1);
    assert.equal(
      emitted.some((event) => event.type === 'auto_evaluation'),
      false,
    );
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('Auto não inicia FrameSeven após falha terminal do Vigolium', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-auto-vigolium-fatal-'));
  const frameSevenBinary = path.join(root, 'FrameSeven', 'bin', 'frameseven', 'cli', 'v1');
  const vigoliumBinary = path.join(
    root,
    'engines',
    process.platform === 'win32' ? 'vigolium.exe' : 'vigolium',
  );
  const engagement = {
    id: 'ENG-AUTO-VIGOLIUM-FATAL',
    status: 'active',
    roeSigned: true,
    scopeDomains: ['example.com'],
    scopeIps: [],
    exclusions: [],
    window: {
      startsAt: new Date(Date.now() - 60_000).toISOString(),
      endsAt: new Date(Date.now() + 60_000).toISOString(),
    },
  };
  const cases = [
    { code: 'PROCESS_ABORTED', name: 'Error' },
    { code: 'PROCESS_UNTERMINATED', name: 'Error', unterminated: true },
    { code: 'VIGOLIUM_BINARY_IDENTITY_MISMATCH', name: 'Error' },
    { code: null, name: 'AbortError' },
  ];
  let frameSevenCalls = 0;
  try {
    await fs.mkdir(path.dirname(frameSevenBinary), { recursive: true });
    await fs.writeFile(frameSevenBinary, '#!/bin/sh\nexit 0\n', { mode: 0o755 });
    await fs.chmod(frameSevenBinary, 0o755);
    await fs.mkdir(path.dirname(vigoliumBinary), { recursive: true });
    await fs.writeFile(vigoliumBinary, '#!/bin/sh\nexit 0\n', { mode: 0o755 });
    await fs.chmod(vigoliumBinary, 0o755);

    for (const fixture of cases) {
      const emitted = [];
      const fatal = new Error(`Vigolium fatal fixture ${fixture.code || fixture.name}`);
      fatal.name = fixture.name;
      if (fixture.code) fatal.code = fixture.code;
      if (fixture.unterminated) fatal.unterminated = true;

      await assert.rejects(
        runAutoRecon({
          body: {
            domain: 'example.com',
            mode: 'balanced',
            commanders: [],
            modules: ['vigolium_dast', 'frameseven_recon'],
            includeFrameSeven: true,
            includeVigolium: true,
            autonomyLevel: 'authorized',
            approvalMode: 'interactive',
            engagementId: engagement.id,
          },
          ROOT: root,
          principal: {
            sub: 'red-fixture',
            role: 'red',
            scopes: ['recon.run', 'recon.intrusive'],
          },
          env: {
            GHOSTRECON_AUTO_RAG_ENABLED: '0',
            GHOSTRECON_AUTO_HEARTBEAT_MS: '60000',
          },
          getEngagementImpl: async () => engagement,
          runPipeline: async () => {
            throw fatal;
          },
          runFrameSevenImpl: async () => {
            frameSevenCalls += 1;
            return { status: 'done', code: 0, outputDir: root };
          },
          emit: (event) => {
            emitted.push(event);
            if (event.type === 'auto_approval_required') {
              const session = getActiveAutoSession(event.sessionId);
              session?.resolveApproval(
                event.approval.approvalId,
                true,
                'fixture local aprovada',
              );
            }
          },
          fetchImpl: async () => ({ ok: false, status: 503 }),
          execFileImpl: async () => {
            throw new Error('provider indisponível na fixture');
          },
        }),
        (error) => error === fatal,
      );

      assert.equal(
        emitted.some((event) => (
          event.engine === 'frameseven'
          && ['engine_started', 'engine_done', 'engine_partial'].includes(event.type)
        )),
        false,
      );
      assert.equal(
        emitted.some((event) => event.type === 'engine_started' && event.engine === 'vigolium'),
        true,
      );
      assert.equal(emitted.some((event) => event.type === 'auto_evaluation'), false);
    }

    assert.equal(frameSevenCalls, 0);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('Auto autenticado não libera o scan FrameSeven nem inicia novo ciclo após falha fatal do Vigolium', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-auto-auth-vigolium-fatal-'));
  const frameSevenBinary = path.join(root, 'FrameSeven', 'bin', 'frameseven', 'cli', 'v1');
  const vigoliumBinary = path.join(
    root,
    'engines',
    process.platform === 'win32' ? 'vigolium.exe' : 'vigolium',
  );
  const engagement = {
    id: 'ENG-AUTO-AUTH-VIGOLIUM-FATAL',
    status: 'active',
    roeSigned: true,
    scopeDomains: ['example.com'],
    scopeIps: [],
    exclusions: [],
    window: {
      startsAt: new Date(Date.now() - 60_000).toISOString(),
      endsAt: new Date(Date.now() + 60_000).toISOString(),
    },
  };
  const fatal = new Error('Vigolium binary identity changed');
  fatal.code = 'VIGOLIUM_BINARY_IDENTITY_MISMATCH';
  const emitted = [];
  let pipelineCalls = 0;
  let frameSevenBrowserCalls = 0;
  let frameSevenScanReleases = 0;

  try {
    await fs.mkdir(path.dirname(frameSevenBinary), { recursive: true });
    await fs.writeFile(frameSevenBinary, '#!/bin/sh\nexit 0\n', { mode: 0o755 });
    await fs.chmod(frameSevenBinary, 0o755);
    await fs.mkdir(path.dirname(vigoliumBinary), { recursive: true });
    await fs.writeFile(vigoliumBinary, '#!/bin/sh\nexit 0\n', { mode: 0o755 });
    await fs.chmod(vigoliumBinary, 0o755);

    await assert.rejects(
      runAutoRecon({
        body: {
          domain: 'example.com',
          mode: 'balanced',
          commanders: [],
          modules: ['vigolium_dast', 'frameseven_authenticated'],
          includeFrameSeven: true,
          frameSevenAuth: true,
          includeVigolium: true,
          autonomyLevel: 'authorized',
          approvalMode: 'interactive',
          engagementId: engagement.id,
        },
        ROOT: root,
        principal: {
          sub: 'red-fixture',
          role: 'red',
          scopes: ['recon.run', 'recon.intrusive'],
        },
        env: {
          GHOSTRECON_AUTO_RAG_ENABLED: '0',
          GHOSTRECON_AUTO_HEARTBEAT_MS: '60000',
        },
        getEngagementImpl: async () => engagement,
        runPipeline: async () => {
          pipelineCalls += 1;
          throw fatal;
        },
        runFrameSevenImpl: async (options) => {
          frameSevenBrowserCalls += 1;
          const approved = await options.waitForAuth?.({
            contextId: 'fixture-context',
            target: 'https://example.com/',
            signal: options.signal,
          });
          assert.equal(approved, true);
          await options.beforeScan?.({
            target: 'https://example.com/',
            cookies: [],
            headers: {},
            endpoints: [],
          }, { signal: options.signal });
          frameSevenScanReleases += 1;
          return { status: 'done', code: 0, outputDir: root };
        },
        emit: (event) => {
          emitted.push(event);
          if (event.type === 'auto_approval_required') {
            const session = getActiveAutoSession(event.sessionId);
            session?.resolveApproval(
              event.approval.approvalId,
              true,
              'fixture local aprovada',
            );
          }
        },
        fetchImpl: async () => ({ ok: false, status: 503 }),
        execFileImpl: async () => {
          throw new Error('provider indisponível na fixture');
        },
      }),
      (error) => error === fatal,
    );

    assert.equal(pipelineCalls, 1);
    assert.equal(frameSevenBrowserCalls, 1);
    assert.equal(frameSevenScanReleases, 0);
    assert.equal(
      emitted.some((event) => event.type === 'auto_iteration_started' && event.iteration > 1),
      false,
    );
    assert.equal(
      emitted.some((event) => event.type === 'auto_council_verdict' && event.phase === 'post_pipeline'),
      false,
    );
    assert.equal(emitted.some((event) => event.type === 'auto_evaluation'), false);
    assert.equal(
      emitted.some((event) => event.type === 'auto_session' && event.phase === 'failed'),
      true,
    );
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('Auto revalida engagement após aprovação e não inicia motores se a autorização mudou', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-auto-engagement-toctou-'));
  const binary = path.join(root, 'FrameSeven', 'bin', 'frameseven', 'cli', 'v1');
  const emitted = [];
  let engagementReads = 0;
  let pipelineCalls = 0;
  let frameSevenCalls = 0;
  try {
    await fs.mkdir(path.dirname(binary), { recursive: true });
    await fs.writeFile(binary, '#!/bin/sh\nexit 0\n', { mode: 0o755 });
    await fs.chmod(binary, 0o755);
    const active = {
      id: 'ENG-AUTO-TOCTOU',
      status: 'active',
      roeSigned: true,
      scopeDomains: ['example.com'],
      scopeIps: [],
      exclusions: [],
      window: {
        startsAt: new Date(Date.now() - 60_000).toISOString(),
        endsAt: new Date(Date.now() + 60_000).toISOString(),
      },
    };

    await assert.rejects(
      runAutoRecon({
        body: {
          domain: 'example.com',
          mode: 'balanced',
          commanders: [],
          modules: ['frameseven_recon'],
          includeFrameSeven: true,
          autonomyLevel: 'assisted',
          approvalMode: 'interactive',
          engagementId: active.id,
        },
        ROOT: root,
        env: {
          GHOSTRECON_AUTO_RAG_ENABLED: '0',
          GHOSTRECON_AUTO_HEARTBEAT_MS: '60000',
        },
        getEngagementImpl: async () => {
          engagementReads += 1;
          return engagementReads === 1 ? active : { ...active, status: 'paused' };
        },
        runPipeline: async () => {
          pipelineCalls += 1;
        },
        runFrameSevenImpl: async () => {
          frameSevenCalls += 1;
          return { status: 'done', code: 0, outputDir: root };
        },
        emit: (event) => {
          emitted.push(event);
          if (event.type === 'auto_approval_required') {
            const session = getActiveAutoSession(event.sessionId);
            session?.resolveApproval(
              event.approval.approvalId,
              true,
              'fixture local aprovada',
            );
          }
        },
        fetchImpl: async () => ({ ok: false, status: 503 }),
        execFileImpl: async () => {
          throw new Error('provider indisponível na fixture');
        },
      }),
      /Checklist AUTO bloqueou o plano em after_plan_approval|não está ativo/,
    );

    assert.equal(engagementReads, 2);
    assert.equal(pipelineCalls, 0);
    assert.equal(frameSevenCalls, 0);
    assert.ok(emitted.some((event) => (
      event.type === 'auto_preflight_revalidated'
      && event.stage === 'after_plan_approval'
      && event.bindingMatches === false
      && event.checklist?.ok === false
    )));
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('Auto autenticado revalida engagement após o pipeline e antes de continuar o scan FrameSeven', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-auto-auth-engagement-toctou-'));
  const binary = path.join(root, 'FrameSeven', 'bin', 'frameseven', 'cli', 'v1');
  const emitted = [];
  let engagementReads = 0;
  let pipelineCalls = 0;
  let authenticatedScanContinued = false;
  try {
    await fs.mkdir(path.dirname(binary), { recursive: true });
    await fs.writeFile(binary, '#!/bin/sh\nexit 0\n', { mode: 0o755 });
    await fs.chmod(binary, 0o755);
    const active = {
      id: 'ENG-AUTO-AUTH-TOCTOU',
      status: 'active',
      roeSigned: true,
      scopeDomains: ['example.com'],
      scopeIps: [],
      exclusions: [],
      window: {
        startsAt: new Date(Date.now() - 60_000).toISOString(),
        endsAt: new Date(Date.now() + 60_000).toISOString(),
      },
    };

    await assert.rejects(
      runAutoRecon({
        body: {
          domain: 'example.com',
          mode: 'balanced',
          commanders: [],
          modules: ['frameseven_authenticated'],
          includeFrameSeven: true,
          frameSevenAuth: true,
          autonomyLevel: 'authorized',
          approvalMode: 'interactive',
          engagementId: active.id,
        },
        ROOT: root,
        principal: {
          sub: 'red-fixture',
          role: 'red',
          scopes: ['recon.run', 'recon.intrusive'],
        },
        env: {
          GHOSTRECON_AUTO_RAG_ENABLED: '0',
          GHOSTRECON_AUTO_HEARTBEAT_MS: '60000',
        },
        getEngagementImpl: async () => {
          engagementReads += 1;
          return engagementReads < 6 ? active : { ...active, status: 'paused' };
        },
        runPipeline: async () => {
          pipelineCalls += 1;
        },
        runFrameSevenImpl: async (options) => {
          await options.waitForAuth();
          await options.beforeScan(
            { headers: { 'x-fixture-auth': 'present' }, cookies: [] },
            { signal: options.signal },
          );
          authenticatedScanContinued = true;
          return { status: 'done', code: 0, outputDir: root };
        },
        emit: (event) => {
          emitted.push(event);
          if (event.type === 'auto_approval_required') {
            const session = getActiveAutoSession(event.sessionId);
            session?.resolveApproval(
              event.approval.approvalId,
              true,
              'fixture local aprovada',
            );
          }
        },
        fetchImpl: async () => ({ ok: false, status: 503 }),
        execFileImpl: async () => {
          throw new Error('provider indisponível na fixture');
        },
      }),
      (error) => (
        error?.code === 'AUTO_ENGAGEMENT_CHANGED'
        || error?.code === 'AUTO_ENGAGEMENT_INVALIDATED'
      ),
    );

    assert.equal(engagementReads, 6);
    assert.equal(pipelineCalls, 1);
    assert.equal(authenticatedScanContinued, false);
    assert.ok(emitted.some((event) => (
      event.type === 'auto_preflight_revalidated'
      && event.stage === 'immediately_before_authenticated_frameseven_scan'
      && event.bindingMatches === false
    )));
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('runAutoRecon recusa overrides executáveis fora do plano hashado', async () => {
  await assert.rejects(
    runAutoRecon({
      body: { domain: 'example.com' },
      ROOT: process.cwd(),
      runPipeline: async () => {},
      pipelineOverrides: { vigoliumSource: '/tmp/source' },
    }),
    /pipelineOverrides não é permitido/,
  );
});

test('runAutoRecon recusa Vigolium -T explícito ou herdado do ambiente antes do catálogo', async () => {
  const base = {
    ROOT: process.cwd(),
    runPipeline: async () => {
      assert.fail('pipeline não pode executar com entrada Vigolium não selada');
    },
  };
  await assert.rejects(
    runAutoRecon({
      ...base,
      body: {
        domain: 'example.com',
        includeVigolium: true,
        vigoliumInputFile: '/tmp/spec-fora-do-plano.yaml',
        vigoliumInputType: 'openapi',
      },
      env: {},
    }),
    /Vigolium -T não é permitido no Auto/i,
  );
  await assert.rejects(
    runAutoRecon({
      ...base,
      body: {
        domain: 'example.com',
        includeVigolium: true,
      },
      env: {
        GHOSTRECON_VIGOLIUM_INPUT_FILE: '/tmp/env-fora-do-plano.yaml',
        GHOSTRECON_VIGOLIUM_INPUT_TYPE: 'openapi',
      },
    }),
    /Vigolium -T não é permitido no Auto/i,
  );
});

test('cliente Auto não interativo nega o plano exato sem executar pipeline', async () => {
  const emitted = [];
  let pipelineCalls = 0;
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-auto-noninteractive-'));
  try {
    const result = await runAutoRecon({
      body: {
        domain: 'example.com',
        autonomyLevel: 'assisted',
        approvalMode: 'deny',
        includeHexstrike: false,
      },
      ROOT: root,
      env: { GHOSTRECON_AUTO_RAG_ENABLED: '0' },
      execFileImpl: async () => {
        throw new Error('not found');
      },
      fetchImpl: async () => ({ ok: false, status: 404 }),
      emit: (event) => emitted.push(event),
      runPipeline: async () => {
        pipelineCalls += 1;
      },
    });

    assert.equal(pipelineCalls, 0);
    assert.ok(emitted.some((event) => event.type === 'auto_approval_required'));
    assert.ok(emitted.some((event) => (
      event.type === 'auto_approval_auto_denied'
      && event.reason === 'non_interactive_client'
    )));
    assert.ok(emitted.some((event) => event.type === 'auto_approval_denied'));
    assert.equal(result.evaluation.agentDecision.action, 'finish');
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('Forge corrige parecer request_changes, preserva revisão e volta ao conselho', async () => {
  const root = await fs.mkdtemp(path.join(process.cwd(), '.tmp-forge-correction-'));
  try {
    await Promise.all([
      fs.writeFile(path.join(root, 'forge-request.json'), JSON.stringify({ proposedId: 'corrected_module', gap: 'gap' })),
      fs.writeFile(path.join(root, 'manifest.json'), JSON.stringify({ id: 'corrected_module', intrusive: false, requiresKali: false })),
      fs.writeFile(path.join(root, 'module.mjs'), 'export const version = 1;\n'),
      fs.writeFile(path.join(root, 'module.test.js'), "import test from 'node:test';\ntest('v1', () => {});\n"),
      fs.writeFile(path.join(root, 'ai-reviews.json'), JSON.stringify({ status: 'changes_requested' })),
      fs.writeFile(path.join(root, 'validation-results.json'), '{}'),
      fs.writeFile(path.join(root, 'test-results.json'), '{}'),
      fs.writeFile(path.join(root, 'verdict.json'), JSON.stringify({ status: 'changes_requested', policy: { pipelineEnabled: false } })),
    ]);
    let reviewCalls = 0;
    const result = await runForgeCorrectionLoop({
      pendingDir: root,
      root: process.cwd(),
      provider: 'codex',
      target: 'example.com',
      providers: [],
      env: { GHOSTRECON_AUTO_FORGE_MAX_CORRECTIONS: '2' },
      initialReview: { status: 'changes_requested', approved: false },
      generateImpl: async ({ pendingDir }) => {
        await fs.writeFile(path.join(pendingDir, 'module.mjs'), 'export const version = 2;\n');
        return { ok: true };
      },
      validateImpl: async () => ({ ok: true, status: 'pending_ai_code_review' }),
      reviewImpl: async () => {
        reviewCalls += 1;
        return { status: 'pending_operator_approval', approved: true };
      },
    });
    assert.equal(result.ok, true);
    assert.equal(result.attempts, 1);
    assert.equal(reviewCalls, 1);
    assert.equal(await fs.readFile(path.join(root, 'revisions', 'revision-00', 'module.mjs'), 'utf8'), 'export const version = 1;\n');
    assert.equal(await fs.readFile(path.join(root, 'module.mjs'), 'utf8'), 'export const version = 2;\n');
    const history = JSON.parse(await fs.readFile(path.join(root, 'correction-history.json'), 'utf8'));
    assert.equal(history.status, 'pending_operator_approval');
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('Forge limita correções e mantém pipeline bloqueado quando tentativas acabam', async () => {
  const root = await fs.mkdtemp(path.join(process.cwd(), '.tmp-forge-correction-limit-'));
  try {
    await Promise.all([
      fs.writeFile(path.join(root, 'forge-request.json'), JSON.stringify({ proposedId: 'loop_module' })),
      fs.writeFile(path.join(root, 'manifest.json'), '{}'),
      fs.writeFile(path.join(root, 'module.mjs'), 'export default {};\n'),
      fs.writeFile(path.join(root, 'module.test.js'), "import test from 'node:test';\ntest('x', () => {});\n"),
      fs.writeFile(path.join(root, 'ai-reviews.json'), JSON.stringify({ status: 'changes_requested' })),
      fs.writeFile(path.join(root, 'verdict.json'), JSON.stringify({ status: 'changes_requested' })),
    ]);
    const result = await runForgeCorrectionLoop({
      pendingDir: root, root: process.cwd(), provider: 'codex', target: 'example.com',
      env: { GHOSTRECON_AUTO_FORGE_MAX_CORRECTIONS: '1' },
      initialReview: { status: 'changes_requested', approved: false },
      generateImpl: async () => ({ ok: true }),
      validateImpl: async () => ({ ok: true, status: 'pending_ai_code_review' }),
      reviewImpl: async () => ({ status: 'changes_requested', approved: false }),
    });
    assert.equal(result.status, 'correction_attempts_exhausted');
    assert.equal(result.attempts, 1);
    const verdict = JSON.parse(await fs.readFile(path.join(root, 'verdict.json'), 'utf8'));
    assert.equal(verdict.status, 'correction_attempts_exhausted');
    assert.equal(verdict.policy.pipelineEnabled, false);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});
