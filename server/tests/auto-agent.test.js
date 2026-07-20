import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { EventEmitter } from 'node:events';
import { PassThrough, Writable } from 'node:stream';

import { detectAutoProviders } from '../auto-agent/provider-detector.mjs';
import { createAutoPlan, evaluateAutoRun } from '../auto-agent/planner.mjs';
import { runAutoRecon } from '../auto-agent/orchestrator.mjs';
import { decideWithCodex, execFileClosedStdin } from '../auto-agent/providers/codex.mjs';
import { decideWithOpenAiCompatible } from '../auto-agent/providers/openai-compatible.mjs';
import { runAgentCouncil } from '../auto-agent/council/council-runner.mjs';
import { createPendingForgeRequest } from '../auto-agent/forge/forge-store.mjs';
import { decideWithClaudeCode } from '../auto-agent/providers/claude-code.mjs';
import { generatePendingArtifact } from '../auto-agent/forge/generate-artifact.mjs';
import { buildAutoObservationBundle } from '../auto-agent/observation-builder.mjs';
import { validateAndTestForgePackage } from '../auto-agent/forge/validate-package.mjs';
import { reviewForgePackage } from '../auto-agent/forge/code-review.mjs';
import { listForgePackages, readForgePackage, recordForgeRuntimeResult, transitionForgePackage } from '../auto-agent/forge/lifecycle.mjs';
import { runForgeCorrectionLoop } from '../auto-agent/forge/correction-loop.mjs';
import { runActiveDynamicModules } from '../auto-agent/forge/runtime-loader.mjs';
import { validateAgentDecision } from '../auto-agent/decision-contract.mjs';
import { autoSessionLimits, createAutoSession } from '../auto-agent/session-store.mjs';
import { CodexAppServerClient } from '../auto-agent/providers/codex-app-server.mjs';
import { registerAutoReconRoutes } from '../routes/auto-recon.mjs';
import { cancelActiveAutoSession, listActiveAutoSessions, registerActiveAutoSession, unregisterActiveAutoSession } from '../auto-agent/active-sessions.mjs';

test('execFileClosedStdin envia EOF para processos que leem stdin', async () => {
  const result = await execFileClosedStdin('/bin/sh', ['-c', 'read value || true; printf eof'], { timeout: 2_000 });
  assert.equal(result.stdout, 'eof');
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

test('createAutoPlan monta plano conservador com HexStrike intelligence', () => {
  const plan = createAutoPlan({
    target: 'example.com',
    mode: 'deep',
    requestedModules: ['hexstrike_orchestrator', 'sqlmap'],
    providers: [
      { id: 'codex', selected: true, installed: true, configured: true },
      { id: 'openrouter', selected: true, configured: true, defaultModel: 'z-ai/glm-4.5' },
    ],
    catalog: { hexstrike: { installed: true, reachable: false } },
  });

  assert.equal(plan.kind, 'ghostrecon.auto.plan');
  assert.equal(plan.commanders.roles.leader, 'codex');
  assert.equal(plan.commanders.roles.reviewer, 'openrouter');
  assert.equal(plan.commanders.openrouterModel, 'z-ai/glm-4.5');
  assert.ok(plan.modules.includes('hexstrike_orchestrator'));
  assert.ok(plan.modules.includes('api_contract_diff'));
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
    catalog: { modules: [{ id: 'security_headers', available: true }] },
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
    catalog: { modules: [{ id: 'security_headers', available: true }] },
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
    catalog: { modules: [{ id: 'security_headers', available: true }] },
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
      return { stdout: JSON.stringify({ structured_output: decision }) };
    },
  });
  assert.equal(out.decision.action, 'finish');
  assert.equal(seenArgs[seenArgs.indexOf('--tools') + 1], '');
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

test('gates do Forge validam e executam teste sem permissão de rede/escrita', async () => {
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
    const result = await validateAndTestForgePackage(root);
    assert.equal(result.validation.ok, true);
    assert.equal(result.tests.ok, true, JSON.stringify(result.tests));
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
      fs.writeFile(path.join(root, 'validation-results.json'), JSON.stringify({ ok: true })),
      fs.writeFile(path.join(root, 'test-results.json'), JSON.stringify({ ok: true })),
      fs.writeFile(path.join(root, 'verdict.json'), JSON.stringify({ policy: { pipelineEnabled: false } })),
    ]);
    const result = await reviewForgePackage({
      pendingDir: root,
      root: process.cwd(),
      providers: [{ id: 'openrouter', selected: true, usable: true, defaultModel: 'test/model' }],
      env: { OPENROUTER_API_KEY: 'test' },
      fetchImpl: async () => ({ ok: true, status: 200, json: async () => ({ choices: [{ message: { content: JSON.stringify(review) } }] }) }),
    });
    assert.equal(result.approved, true);
    assert.equal(result.status, 'pending_operator_approval');
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
    await fs.writeFile(path.join(pending.dir, 'manifest.json'), JSON.stringify({ id: 'approved_module', timeoutMs: 5000 }));
    await fs.writeFile(path.join(pending.dir, 'module.mjs'), 'export async function run({target}) { return {findings:[{type:"ai_test",prio:"low",score:20,value:"executed",url:`https://${target}/`}]}; }\n');
    await fs.writeFile(path.join(pending.dir, 'verdict.json'), JSON.stringify({
      status: 'pending_operator_approval',
      validation: { ok: true }, tests: { ok: true }, aiReview: { approved: true },
      policy: { pipelineEnabled: false, operatorApprovalRequired: true },
    }));
    const detail = await readForgePackage(root, pending.forgeId);
    assert.equal(detail.artifacts['manifest.json'].id, 'approved_module');
    assert.match(detail.artifacts['module.mjs'], /export/);
    const moved = await transitionForgePackage({ root, forgeId: pending.forgeId, decision: 'approve', reason: 'reviewed' });
    assert.equal(moved.state, 'active');
    assert.equal(moved.pipelineEnabled, true);
    assert.match(moved.dir, /active\/approved_module/);
    const findings = [];
    const events = [];
    const runtime = await runActiveDynamicModules({
      ROOT: root, domain: 'example.com', modules: ['approved_module'],
      pipe: () => {}, log: () => {}, emit: (event) => events.push(event), addFinding: (finding) => findings.push(finding),
    }, { root });
    assert.equal(runtime.executed, 1);
    assert.equal(findings.length, 1);
    assert.ok(events.some((event) => event.type === 'dynamic_module_completed'));
    const firstRun = await recordForgeRuntimeResult({ root, forgeId: pending.forgeId, success: true, findings: findings.length });
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
      ctx.emit({ type: 'finding', finding: { prio: 'low', value: 'ok' } });
    },
  });

  assert.ok(emitted.some((e) => e.type === 'auto_plan'));
  assert.ok(emitted.some((e) => e.type === 'auto_evaluation'));
  assert.ok(pipelineCtx.modules.includes('security_headers'));
  assert.equal(pipelineCtx.modules.includes('hexstrike_orchestrator'), false);
  assert.equal(result.evaluation.ok, true);
  assert.equal(result.evaluation.findings, 1);
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
