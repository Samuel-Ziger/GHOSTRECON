import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';

import { createAutoPlan } from '../auto-agent/planner.mjs';
import {
  normalizeAndValidateAgentDecision,
  validateAgentDecision,
} from '../auto-agent/decision-contract.mjs';
import {
  availableCatalogIds,
  buildAgentPrompt,
} from '../auto-agent/providers/shared.mjs';
import { decideWithCodex, execFileClosedStdin } from '../auto-agent/providers/codex.mjs';
import { runAgentCouncil } from '../auto-agent/council/council-runner.mjs';

function decision({
  action = 'run_modules',
  modules = ['security_headers'],
  confidence = 0.9,
  operatorQuestion = null,
  forgeRequest = null,
} = {}) {
  return {
    action,
    objective: 'authorized_recon',
    reasoningSummary: ['decisão de teste'],
    evidenceRefs: [],
    requestedModules: modules,
    rejectedModules: [],
    confidence,
    assumptions: [],
    operatorQuestion,
    forgeRequest,
  };
}

function openAiResponse(value) {
  return {
    ok: true,
    status: 200,
    json: async () => ({
      choices: [{ message: { content: JSON.stringify(value) } }],
    }),
  };
}

test('createAutoPlan respeita ações de controle e usa allowlist positiva', () => {
  const catalog = {
    modules: [
      { id: 'security_headers', class: 'passive', available: true },
      { id: 'operator_module', class: 'active', available: true },
      { id: 'intrusive_module', class: 'intrusive', available: true, manifest: { intrusive: true } },
      { id: 'offline_module', class: 'passive', available: false },
    ],
  };
  for (const action of ['finish', 'abstain', 'ask_operator', 'forge_module']) {
    const plan = createAutoPlan({
      target: 'example.test',
      catalog,
      agentDecision: { action, requestedModules: [] },
      autonomyLevel: 'authorized_opsec',
    });
    assert.deepEqual(plan.modules, [], `${action} não pode virar scan`);
    assert.equal(plan.moduleSelection.strategy, `control_action:${action}`);
  }

  for (const action of ['finish', 'abstain']) {
    const operatorOverride = createAutoPlan({
      target: 'example.test',
      catalog,
      requestedModules: ['operator_module'],
      agentDecision: { action, requestedModules: [] },
      autonomyLevel: 'authorized_opsec',
    });
    assert.deepEqual(operatorOverride.modules, ['operator_module']);
    assert.equal(operatorOverride.action, 'run_modules');
    assert.equal(operatorOverride.moduleSelection.strategy, `explicit_operator_override:${action}`);
    assert.equal(operatorOverride.moduleSelection.explicitOperatorOverride, true);
  }

  const plan = createAutoPlan({
    target: 'example.test',
    catalog,
    requestedModules: ['operator_module', 'not_in_catalog', 'offline_module'],
    agentDecision: {
      action: 'run_modules',
      requestedModules: ['security_headers', 'not_in_catalog', 'offline_module'],
    },
    autonomyLevel: 'authorized_opsec',
  });
  assert.deepEqual(plan.modules, ['security_headers', 'operator_module']);
  assert.deepEqual(plan.moduleSelection.operator.accepted, ['operator_module']);
  assert.deepEqual(
    plan.moduleSelection.operator.rejected.map((item) => [item.id, item.reason]),
    [
      ['not_in_catalog', 'module_not_in_catalog'],
      ['offline_module', 'module_unavailable'],
    ],
  );
  assert.equal(plan.modules.includes('intrusive_module'), false, 'autonomia não adiciona todos os intrusivos');
});

test('createAutoPlan normaliza aliases explícitos antes de validar o catálogo', () => {
  const plan = createAutoPlan({
    target: 'example.test',
    catalog: {
      modules: [
        { id: 'api_contract_diff', class: 'active', available: true },
      ],
    },
    requestedModules: ['api-contract-diff', 'api_contract_diff'],
    agentDecision: { action: 'abstain', requestedModules: [] },
    autonomyLevel: 'assisted',
  });

  assert.deepEqual(plan.modules, ['api_contract_diff']);
  assert.deepEqual(plan.moduleSelection.operator.accepted, ['api_contract_diff']);
  assert.deepEqual(plan.moduleSelection.operator.rejected, []);
  assert.equal(plan.moduleSelection.explicitOperatorOverride, true);
});

test('fallback determinístico filtra módulos active pela autonomia', () => {
  const catalog = {
    modules: [
      { id: 'security_headers', class: 'passive', available: true },
      { id: 'cors_audit', class: 'active', available: true },
      { id: 'websocket_recon', class: 'active', available: true },
    ],
  };
  const observation = createAutoPlan({
    target: 'example.test', mode: 'deep', catalog, autonomyLevel: 'observation',
  });
  assert.deepEqual(observation.modules, ['security_headers']);
  assert.equal(observation.moduleSelection.operator.rejected.length, 0);

  const assisted = createAutoPlan({
    target: 'example.test', mode: 'deep', catalog, autonomyLevel: 'assisted',
  });
  assert.equal(assisted.modules.includes('cors_audit'), true);
  assert.equal(assisted.modules.includes('websocket_recon'), true);
});

test('contrato normaliza aliases e aplica invariantes por ação', () => {
  const catalogModuleIds = ['security_headers'];
  for (const alias of ['request_modules', 'execute_modules']) {
    const result = normalizeAndValidateAgentDecision(decision({ action: alias }), { catalogModuleIds });
    assert.equal(result.ok, true);
    assert.equal(result.decision.action, 'run_modules');
  }

  assert.equal(validateAgentDecision(decision({ modules: [] }), { catalogModuleIds }).ok, false);
  assert.equal(validateAgentDecision(decision({ action: 'finish' }), { catalogModuleIds }).ok, false);
  assert.equal(validateAgentDecision(decision({
    action: 'ask_operator', modules: [], operatorQuestion: null,
  }), { catalogModuleIds }).ok, false);
  assert.equal(validateAgentDecision({
    ...decision({ action: 'abstain', modules: [] }),
    unexpected: true,
  }, { catalogModuleIds }).ok, false);
});

test('schema de transporte aceita aliases normalizados antes do contrato canônico', async () => {
  const schema = JSON.parse(await fs.readFile(
    new URL('../auto-agent/schemas/decision.schema.json', import.meta.url),
    'utf8',
  ));
  const actions = new Set(schema?.properties?.action?.enum || []);
  for (const action of ['run_modules', 'request_modules', 'execute_modules']) {
    assert.equal(actions.has(action), true, `schema deve aceitar ${action}`);
  }
});

test('catálogo aplica a matriz de autonomia e nunca libera destructive', () => {
  const catalog = {
    modules: [
      { id: 'passive', class: 'passive', available: true },
      { id: 'deep', class: 'deep_passive', available: true },
      { id: 'hexstrike', class: 'hexstrike_intel', available: true },
      { id: 'active', class: 'active', available: true },
      { id: 'intrusive', class: 'intrusive', available: true },
      { id: 'manifest_intrusive', class: 'active', available: true, manifest: { intrusive: true } },
      { id: 'destructive', class: 'destructive', available: true },
      { id: 'offline', class: 'passive', available: false },
    ],
  };
  assert.deepEqual(
    availableCatalogIds(catalog, { autonomyLevel: 'observation' }),
    ['passive', 'deep', 'hexstrike'],
  );
  assert.deepEqual(
    availableCatalogIds(catalog, { autonomyLevel: 'assisted' }),
    ['passive', 'deep', 'hexstrike', 'active'],
  );
  assert.deepEqual(
    availableCatalogIds(catalog, { autonomyLevel: 'authorized', allowIntrusive: false }),
    ['passive', 'deep', 'hexstrike', 'active'],
  );
  assert.deepEqual(
    availableCatalogIds(catalog, { autonomyLevel: 'authorized_opsec', allowIntrusive: true }),
    ['passive', 'deep', 'hexstrike', 'active', 'intrusive', 'manifest_intrusive'],
  );
});

test('prompt descreve política efetiva e nunca oferece destructive', () => {
  const prompt = buildAgentPrompt({
    target: 'example.test',
    mode: 'deep',
    autonomyLevel: 'observation',
    allowIntrusive: true,
    catalog: {
      modules: [
        { id: 'active', class: 'active', available: true },
        { id: 'destructive', class: 'destructive', available: true },
      ],
    },
  });
  assert.match(prompt, /NÍVEL DE AUTONOMIA: observation/);
  assert.match(prompt, /Nunca escolha módulos destrutivos/);
  assert.match(prompt, /"id":"active","class":"active","available":false/);
  assert.match(prompt, /"id":"destructive","class":"destructive","available":false/);
});

test('Codex recebe prompt por stdin, preserva autonomia e não o inclui no argv', async () => {
  let seenArgs;
  let seenOptions;
  const result = await decideWithCodex({
    target: 'example.test',
    mode: 'deep',
    catalog: {
      modules: [{ id: 'intrusive_module', class: 'intrusive', available: true }],
    },
    ragContext: { items: [] },
    root: process.cwd(),
    allowIntrusive: true,
    autonomyLevel: 'authorized',
    env: { PATH: process.env.PATH },
    execFileImpl: async (_command, args, options) => {
      seenArgs = args;
      seenOptions = options;
      const outputPath = args[args.indexOf('--output-last-message') + 1];
      await fs.writeFile(outputPath, JSON.stringify(decision({ modules: ['intrusive_module'] })), 'utf8');
      return { stdout: '', stderr: '' };
    },
  });
  assert.equal(result.ok, true);
  assert.equal(seenArgs.at(-1), '-');
  assert.equal(seenArgs.some((arg) => String(arg).includes('example.test')), false);
  assert.match(seenOptions.input, /NÍVEL DE AUTONOMIA: authorized/);
  assert.match(seenOptions.input, /Módulos intrusivos podem ser solicitados/);
  assert.equal(result.transport.promptTransport, 'stdin');
});

test('erro de subprocesso Codex não ecoa argumentos sensíveis', async () => {
  await assert.rejects(
    execFileClosedStdin('/bin/sh', ['-c', 'exit 2', 'prompt-sensitive-marker'], { timeout: 2_000 }),
    (error) => {
      assert.doesNotMatch(error.message, /prompt-sensitive-marker/);
      assert.match(error.message, /Command failed: \/bin\/sh/);
      return true;
    },
  );
});

test('conselho converte empate de módulos em ask_operator', async () => {
  const catalog = {
    modules: [
      { id: 'security_headers', class: 'passive', available: true },
      { id: 'dns_enrichment', class: 'passive', available: true },
    ],
  };
  const codexDecision = decision({ modules: ['security_headers'] });
  const openRouterDecision = decision({ modules: ['dns_enrichment'] });
  const result = await runAgentCouncil({
    providers: [
      { id: 'codex', selected: true, usable: true },
      { id: 'openrouter', selected: true, usable: true, defaultModel: 'test/model' },
    ],
    target: 'example.test',
    mode: 'deep',
    catalog,
    ragContext: { items: [] },
    root: process.cwd(),
    env: { OPENROUTER_API_KEY: 'test', GHOSTRECON_CODEX_APP_SERVER: '0' },
    execFileImpl: async (_command, args) => {
      const outputPath = args[args.indexOf('--output-last-message') + 1];
      await fs.writeFile(outputPath, JSON.stringify(codexDecision), 'utf8');
      return { stdout: '', stderr: '' };
    },
    fetchImpl: async () => openAiResponse(openRouterDecision),
  });
  assert.equal(result.finalDecision.action, 'ask_operator');
  assert.deepEqual(result.finalDecision.requestedModules, []);
  assert.deepEqual(
    [...result.finalDecision.council.conflicts.tiedModules].sort(),
    ['dns_enrichment', 'security_headers'],
  );
  assert.deepEqual(result.finalDecision.council.validationErrors, []);
});

test('conselho exige operador quando há maioria não unânime para intrusivo', async () => {
  const intrusiveDecision = decision({ modules: ['intrusive_module'] });
  const passiveDecision = decision({ action: 'finish', modules: [] });
  const result = await runAgentCouncil({
    providers: [
      { id: 'codex', selected: true, usable: true },
      { id: 'openrouter', selected: true, usable: true, defaultModel: 'test/model' },
      { id: 'local_model', selected: true, usable: true },
    ],
    target: 'example.test',
    mode: 'deep',
    catalog: {
      modules: [{ id: 'intrusive_module', class: 'intrusive', available: true }],
    },
    ragContext: { items: [] },
    root: process.cwd(),
    allowIntrusive: true,
    autonomyLevel: 'authorized',
    env: {
      OPENROUTER_API_KEY: 'test',
      GHOSTRECON_CODEX_APP_SERVER: '0',
      GHOSTRECON_LMSTUDIO_BASE_URL: 'http://local-model.test/v1',
    },
    execFileImpl: async (_command, args) => {
      const outputPath = args[args.indexOf('--output-last-message') + 1];
      await fs.writeFile(outputPath, JSON.stringify(intrusiveDecision), 'utf8');
      return { stdout: '', stderr: '' };
    },
    fetchImpl: async (url) => (
      String(url).includes('openrouter.ai')
        ? openAiResponse(intrusiveDecision)
        : openAiResponse(passiveDecision)
    ),
  });
  assert.equal(result.finalDecision.action, 'ask_operator');
  assert.deepEqual(result.finalDecision.requestedModules, []);
  assert.deepEqual(result.finalDecision.council.conflicts.riskDivergence, ['intrusive_module']);
});
