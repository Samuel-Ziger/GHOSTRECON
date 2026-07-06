import test from 'node:test';
import assert from 'node:assert/strict';

import { detectAutoProviders } from '../auto-agent/provider-detector.mjs';
import { createAutoPlan, evaluateAutoRun } from '../auto-agent/planner.mjs';
import { runAutoRecon } from '../auto-agent/orchestrator.mjs';

test('detectAutoProviders detecta comandos e OpenRouter sem executar IAs', async () => {
  const seen = [];
  const execFileImpl = async (bin, args) => {
    seen.push([bin, ...args]);
    if (args[0] === 'codex') return { stdout: 'codex' };
    if (args[0] === 'claude') return { stdout: 'claude' };
    throw new Error('not found');
  };
  const fetchImpl = async (url) => ({
    ok: String(url).includes(':8000'),
    status: String(url).includes(':8000') ? 200 : 404,
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
  const result = await runAutoRecon({
    body: {
      domain: 'example.com',
      mode: 'balanced',
      commanders: ['openrouter'],
      includeHexstrike: false,
    },
    ROOT: process.cwd(),
    env: { OPENROUTER_API_KEY: 'sk-test' },
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
});
