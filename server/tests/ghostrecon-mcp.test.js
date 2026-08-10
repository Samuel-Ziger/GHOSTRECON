import assert from 'node:assert/strict';
import test from 'node:test';

import {
  autoAutonomyToOpsecProfile,
  callTool,
  createFrameParser,
  handleRequest,
  normalizeAutoMcpOptions,
} from '../../mcp/ghostrecon-mcp.mjs';

test('MCP stdio negocia protocolo e publica ferramentas sem iniciar a API', async () => {
  const replies = [];
  const write = (message) => replies.push(message);
  const messages = [
    {
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: { protocolVersion: '2024-11-05' },
    },
    { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} },
    { jsonrpc: '2.0', id: 3, method: 'prompts/list', params: {} },
    { jsonrpc: '2.0', id: 4, method: 'unsupported/test', params: {} },
  ];
  for (const message of messages) await handleRequest(message, { write });
  const byId = new Map(replies.map((reply) => [reply.id, reply]));

  assert.deepEqual([...byId.keys()].sort(), [1, 2, 3, 4]);
  assert.equal(byId.get(1)?.result?.serverInfo?.name, 'ghostrecon');
  assert.equal(byId.get(1)?.result?.protocolVersion, '2024-11-05');
  assert.ok(byId.get(2)?.result?.tools?.some((tool) => tool.name === 'ghostrecon_plan_recon'));
  assert.ok(byId.get(3)?.result?.prompts?.some((prompt) => prompt.name === 'ghostrecon-plan-recon'));
  assert.equal(byId.get(4)?.error?.code, -32601);

  for (const toolName of ['ghostrecon_run_auto', 'ghostrecon_plan_auto']) {
    const autoTool = byId.get(2)?.result?.tools?.find((tool) => tool.name === toolName);
    assert.ok(autoTool, `${toolName} deve ser publicado`);
    assert.equal(autoTool.inputSchema.properties.autonomyLevel.default, 'observation');
    assert.equal(autoTool.inputSchema.properties.includeHexstrike.default, false);
    assert.equal(autoTool.inputSchema.properties.includeVigolium.default, false);
    assert.equal(autoTool.inputSchema.properties.includeFrameSeven.default, false);
    assert.equal(autoTool.inputSchema.properties.frameSevenAuth.default, false);
    assert.equal(autoTool.inputSchema.properties.vigoliumUseCodex.default, false);
  }

  for (const toolName of ['ghostrecon_auto_approve', 'ghostrecon_auto_deny']) {
    const tool = byId.get(2)?.result?.tools?.find((row) => row.name === toolName);
    assert.ok(tool, `${toolName} deve ser publicado`);
    assert.ok(tool.inputSchema.properties.sessionId);
    assert.ok(tool.inputSchema.properties.approvalId);
  }

  const runTool = byId.get(2)?.result?.tools?.find(
    (tool) => tool.name === 'ghostrecon_run_recon',
  );
  assert.deepEqual(runTool.inputSchema.properties.profile.enum, [
    'quick',
    'standard',
    'deep',
  ]);
  assert.deepEqual(runTool.inputSchema.properties.opsecProfile.enum, [
    'passive',
    'stealth',
    'standard',
    'aggressive',
  ]);
  assert.ok(runTool.inputSchema.properties.manualApprovalId);
  assert.ok(runTool.inputSchema.properties.manualApprovalHash);
});

test('MCP parser aceita NDJSON e framing Content-Length', () => {
  const messages = [];
  const feed = createFrameParser((message) => messages.push(message));
  const ndjson = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'ping' });
  const framed = JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'ping' });

  feed(Buffer.from(`${ndjson}\n`));
  feed(Buffer.from(`Content-Length: ${Buffer.byteLength(framed)}\r\n\r\n${framed}`));

  assert.deepEqual(messages.map((message) => message.id), [1, 2]);
});

test('MCP RUN intrusivo retorna approval_required sem aprovar nem iniciar stream', async () => {
  const calls = [];
  const client = {
    async ensureServer() {
      return { spawned: false, child: null };
    },
    async capabilities() {
      return {
        modules: [{ id: 'vigolium_dast', intrusive: true, category: 'engine' }],
      };
    },
    async postJson(pathname, body) {
      calls.push({ pathname, body });
      return {
        ok: true,
        requiresApproval: true,
        plan: {
          schemaVersion: 1,
          kind: 'ghostrecon.manual-recon.plan',
          hash: 'a'.repeat(64),
          target: body.domain,
          selectedModules: ['vigolium_dast'],
          expandedModules: ['vigolium_dast'],
          intrusiveModules: ['vigolium_dast'],
          execution: {
            profile: body.profile,
            opsecProfile: body.opsecProfile,
          },
          authentication: {
            pipeline: { enabled: false },
            vigolium: { enabled: false },
          },
          engines: {
            frameseven: { enabled: false },
            vigolium: { enabled: true, agent: 'none' },
          },
          requiresHumanApproval: true,
          unexpectedSecret: 'nao-deve-sair',
        },
        approval: {
          approvalId: 'approval-mcp-fixture',
          expiresAt: '2026-07-28T10:00:00.000Z',
        },
      };
    },
    async streamRecon() {
      assert.fail('stream não pode iniciar antes da aprovação separada');
    },
  };

  const result = await callTool('ghostrecon_run_recon', {
    target: 'lab.example.test',
    modules: ['vigolium_dast'],
    profile: 'deep',
    opsecProfile: 'aggressive',
    confirmActive: true,
    engagementId: 'ENG-LAB',
  }, { client });

  assert.equal(result.isError, undefined);
  assert.deepEqual(calls.map((call) => call.pathname), ['/api/recon/preflight']);
  const payload = JSON.parse(result.content[0].text);
  assert.equal(payload.status, 'approval_required');
  assert.equal(payload.approval.approvalId, 'approval-mcp-fixture');
  assert.equal(payload.approval.planHash, 'a'.repeat(64));
  assert.equal(payload.plan.execution.profile, 'deep');
  assert.equal(payload.plan.execution.opsecProfile, 'aggressive');
  assert.equal(payload.plan.unexpectedSecret, undefined);
  assert.match(payload.nextAction, /manualApprovalId\/manualApprovalHash/);
});

test('MCP RUN usa aprovação explícita já decidida sem preflight ou autoaprovação', async () => {
  let streamedBody = null;
  const client = {
    async ensureServer() {
      return { spawned: false, child: null };
    },
    async capabilities() {
      return {
        modules: [{ id: 'vigolium_dast', intrusive: true, category: 'engine' }],
      };
    },
    async postJson() {
      assert.fail('chamada posterior aprovada não deve emitir novo preflight/decision');
    },
    async streamRecon(body, onEvent) {
      streamedBody = body;
      onEvent({ type: 'done', target: body.domain });
      return { lines: 1, elapsedMs: 1 };
    },
  };

  const result = await callTool('ghostrecon_run_recon', {
    target: 'lab.example.test',
    modules: ['vigolium_dast'],
    profile: 'deep',
    opsecProfile: 'aggressive',
    confirmActive: true,
    engagementId: 'ENG-LAB',
    manualApprovalId: 'approval-mcp-fixture',
    manualApprovalHash: 'b'.repeat(64),
  }, { client });

  assert.equal(result.isError, undefined);
  assert.equal(streamedBody.profile, 'deep');
  assert.equal(streamedBody.opsecProfile, 'aggressive');
  assert.deepEqual(streamedBody.manualApproval, {
    approvalId: 'approval-mcp-fixture',
    planHash: 'b'.repeat(64),
  });
});

test('MCP separa perfil de execução do perfil OPSEC no plano', async () => {
  const client = {
    async ensureServer() {
      return { spawned: false, child: null };
    },
    async capabilities() {
      return {
        modules: [{ id: 'headers', intrusive: false, category: 'passive' }],
      };
    },
  };
  const result = await callTool('ghostrecon_plan_recon', {
    target: 'lab.example.test',
    modules: ['headers'],
    profile: 'deep',
    opsecProfile: 'passive',
  }, { client });
  const payload = JSON.parse(result.content[0].text);
  assert.equal(payload.profile, 'deep');
  assert.equal(payload.opsecProfile, 'passive');
  assert.equal(payload.opsec.profile, 'passive');
  assert.equal(payload.opsec.ok, true);
  assert.deepEqual(payload.opsec.blocked, []);

  const activeResult = await callTool('ghostrecon_plan_recon', {
    target: 'lab.example.test',
    modules: ['headers'],
    profile: 'deep',
    opsecProfile: 'standard',
    confirmActive: true,
  }, { client });
  const activePayload = JSON.parse(activeResult.content[0].text);
  assert.ok(activePayload.opsec.acknowledged.includes('evidence_verification'));
  assert.ok(activePayload.opsec.acknowledged.includes('active_param_discovery'));
  assert.ok(activePayload.opsec.acknowledged.includes('browser_xss_verify'));
});

test('MCP normaliza política AUTO sem confundir mode com perfil OPSEC', () => {
  const defaults = normalizeAutoMcpOptions({ target: 'lab.example.test', mode: 'deep' });
  assert.equal(defaults.autonomyLevel, 'observation');
  assert.equal(defaults.includeHexstrike, false);
  assert.equal(defaults.includeVigolium, false);
  assert.equal(defaults.includeFrameSeven, false);
  assert.equal(defaults.frameSevenAuth, false);
  assert.equal(defaults.vigoliumUseCodex, false);

  assert.equal(autoAutonomyToOpsecProfile('observation'), 'passive');
  assert.equal(autoAutonomyToOpsecProfile('assisted'), 'standard');
  assert.equal(autoAutonomyToOpsecProfile('authorized'), 'standard');
  assert.equal(autoAutonomyToOpsecProfile('authorized_opsec'), 'aggressive');
  assert.equal(autoAutonomyToOpsecProfile('invalida'), 'passive');

  assert.throws(
    () => normalizeAutoMcpOptions({ target: 'lab.example.test', frameSevenAuth: true }),
    /includeFrameSeven=true/,
  );
  assert.throws(
    () => normalizeAutoMcpOptions({ target: 'lab.example.test', vigoliumUseCodex: true }),
    /includeVigolium=true/,
  );
  assert.throws(
    () => normalizeAutoMcpOptions({ target: 'lab.example.test', includeVigolium: true }),
    /autonomia autorizada/,
  );
});

test('MCP run_auto envia motores opt-in e autonomia explicitamente ao backend', async () => {
  const captured = [];
  const client = {
    async ensureServer() {
      return { spawned: false, child: null };
    },
    async streamAutoRecon(body, onEvent) {
      captured.push(body);
      onEvent({ type: 'done', target: body.domain });
      return { lines: 1, elapsedMs: 1 };
    },
  };

  await callTool('ghostrecon_run_auto', {
    target: 'default.example.test',
    mode: 'deep',
  }, { client });
  assert.deepEqual(captured[0], {
    domain: 'default.example.test',
    mode: 'deep',
    commanders: [],
    modules: [],
    includeHexstrike: false,
    includeDeepPassive: true,
    autonomyLevel: 'observation',
    includeFrameSeven: false,
    frameSevenAuth: false,
    includeVigolium: false,
    vigoliumUseCodex: false,
    approvalMode: 'deny',
  });

  await callTool('ghostrecon_run_auto', {
    target: 'authorized.example.test',
    mode: 'quick',
    commanders: ['codex'],
    modules: ['headers', 'headers'],
    autonomyLevel: 'authorized_opsec',
    includeHexstrike: true,
    includeDeepPassive: false,
    includeFrameSeven: true,
    frameSevenAuth: true,
    includeVigolium: true,
    vigoliumUseCodex: true,
    confirmActive: true,
    openrouterModel: 'modelo-local',
    engagementId: 'eng-lab',
  }, { client });
  assert.deepEqual(captured[1], {
    domain: 'authorized.example.test',
    mode: 'quick',
    commanders: ['codex'],
    modules: ['headers', 'headers'],
    includeHexstrike: true,
    includeDeepPassive: false,
    autonomyLevel: 'authorized_opsec',
    includeFrameSeven: true,
    frameSevenAuth: true,
    includeVigolium: true,
    vigoliumUseCodex: true,
    approvalMode: 'deny',
    openrouterModel: 'modelo-local',
    engagementId: 'eng-lab',
  });
});

test('MCP Auto nega aprovação interativa sem deixar a sessão aguardando timeout', async () => {
  const client = {
    async ensureServer() {
      return { spawned: false, child: null };
    },
    async streamAutoRecon(body, onEvent) {
      assert.equal(body.approvalMode, 'deny');
      assert.equal(body.confirmActive, undefined);
      onEvent({
        type: 'auto_approval_required',
        sessionId: 'session-fixture',
        approval: {
          approvalId: 'approval-fixture',
          planHash: 'abc123',
          target: body.domain,
          module: 'http_probe',
          status: 'pending',
        },
      });
      onEvent({
        type: 'auto_approval_auto_denied',
        sessionId: 'session-fixture',
        approvalId: 'approval-fixture',
      });
      onEvent({ type: 'done', target: body.domain });
      return { lines: 3, elapsedMs: 1 };
    },
  };

  const result = await callTool('ghostrecon_run_auto', {
    target: 'approval.example.test',
    autonomyLevel: 'assisted',
    confirmActive: true,
  }, { client });

  assert.equal(result.isError, true);
  const payload = JSON.parse(result.content[0].text);
  assert.equal(payload.preconfirmationAccepted, false);
  assert.equal(payload.approvalRequired.planHash, 'abc123');
  assert.equal(payload.summary.approvalDenied, true);
});

test('MCP plan_auto aplica opt-ins ao catálogo e preserva a política de autonomia', async () => {
  const catalogCalls = [];
  const planCalls = [];
  const client = {
    async ensureServer() {
      return { spawned: false, child: null };
    },
  };
  const catalog = {
    modules: [
      { id: 'headers', source: 'ghostrecon', class: 'passive', available: true },
      { id: 'http_probe', source: 'ghostrecon', class: 'active', available: true },
      { id: 'frameseven_authenticated', source: 'frameseven', class: 'intrusive', available: true },
      { id: 'vigolium_dast', source: 'vigolium', class: 'intrusive', available: true },
    ],
    hexstrike: null,
    engines: {
      frameseven: {
        available: true,
        binary: '/fixture/frameseven',
        identity: { algorithm: 'sha256', sha256: 'a'.repeat(64), size: 123 },
      },
      vigolium: {
        available: true,
        binary: '/fixture/vigolium',
        source: null,
        identity: { algorithm: 'sha256', sha256: 'b'.repeat(64), size: 456 },
      },
    },
  };
  const planningModulesLoader = async () => ({
    async detectAutoProviders({ selected }) {
      return { providers: selected.map((id) => ({ id, selected: true })) };
    },
    async buildAutoToolCatalog(options) {
      catalogCalls.push(options);
      return catalog;
    },
    createAutoPlan(options) {
      planCalls.push(options);
      return {
        mode: options.mode,
        modules: [...options.requestedModules],
        policy: {},
      };
    },
  });
  const ragContextLoader = async () => ({ dir: '', items: [] });

  const defaults = await callTool('ghostrecon_plan_auto', {
    target: 'default-plan.example.test',
    mode: 'deep',
  }, {
    client,
    planningModulesLoader,
    ragContextLoader,
  });
  assert.equal(catalogCalls[0].includeHexstrike, false);
  assert.equal(catalogCalls[0].includeVigolium, false);
  assert.equal(catalogCalls[0].includeFrameSeven, false);
  assert.equal(catalogCalls[0].includeIntrusive, false);
  assert.deepEqual(planCalls[0].requestedModules, []);
  assert.equal(planCalls[0].autonomyLevel, 'observation');
  assert.equal(JSON.parse(defaults.content[0].text).opsec.profile, 'passive');

  const selected = await callTool('ghostrecon_plan_auto', {
    target: 'selected-plan.example.test',
    mode: 'quick',
    modules: ['headers'],
    autonomyLevel: 'authorized_opsec',
    includeHexstrike: true,
    includeVigolium: true,
    vigoliumUseCodex: true,
    includeFrameSeven: true,
    frameSevenAuth: true,
  }, {
    client,
    planningModulesLoader,
    ragContextLoader,
  });
  assert.equal(catalogCalls[1].includeHexstrike, true);
  assert.equal(catalogCalls[1].includeVigolium, true);
  assert.equal(catalogCalls[1].includeFrameSeven, true);
  assert.equal(catalogCalls[1].frameSevenAuth, true);
  assert.equal(catalogCalls[1].includeIntrusive, true);
  assert.deepEqual(planCalls[1].requestedModules, [
    'headers',
    'frameseven_authenticated',
    'vigolium_dast',
  ]);
  assert.equal(planCalls[1].autonomyLevel, 'authorized_opsec');
  const selectedPayload = JSON.parse(selected.content[0].text);
  assert.equal(selectedPayload.plan.autonomyLevel, 'authorized_opsec');
  assert.equal(selectedPayload.plan.policy.opsecProfile, 'aggressive');
  assert.equal(selectedPayload.opsec.profile, 'aggressive');
  assert.equal(selectedPayload.previewOnly, true);
  assert.equal(selectedPayload.exactRuntimePlan, false);
  assert.equal(selectedPayload.effectivePlan.requiresHumanApproval, true);
  assert.equal(selectedPayload.approval.planHash, selectedPayload.effectivePlan.hash);
});
