import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import test from 'node:test';

import { NeuroSploitManager } from '../integrations/neurosploit/manager.mjs';
import { registerNeuroSploitRoutes } from '../routes/neurosploit.mjs';
import { validateNeuroSploitProfileReady } from '../integrations/neurosploit/profile.mjs';
import { normalizeAutoNeuroSploitConfig } from '../auto-agent/orchestrator.mjs';
import { runAutoNeuroSploit } from '../integrations/neurosploit/auto-runner.mjs';

function fakeChild(pid = 4242) {
  const child = new EventEmitter();
  child.pid = pid;
  child.exitCode = null;
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.stdin = new PassThrough();
  return child;
}

test('NeuroSploit usa perfil Artex por ponte temporária sem persistir token', async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-neurosploit-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const binary = path.join(root, 'engines', 'neurosploit', 'neurosploit-rs', 'target', 'release', 'neurosploit');
  await fs.mkdir(path.dirname(binary), { recursive: true });
  await fs.writeFile(binary, '#!/bin/sh\n', { mode: 0o700 });
  const calls = [];
  const child = fakeChild();
  const manager = new NeuroSploitManager({
    root,
    spawnImpl(command, args, options) {
      calls.push({ command, args, options });
      return child;
    },
  });
  const snapshot = await manager.start({
    mode: 'run',
    target: 'https://lab.example.test',
    repository: '',
    engagementId: 'ENG-LAB',
    authorizationReference: 'ROE-42',
    environment: 'lab',
    policy: 'web',
    votes: 2,
    recon: 1,
    autoSessionId: 'session-auto-fixture',
    autoPlanHash: 'a'.repeat(64),
    autoContext: {
      schema: 'ghostrecon.neurosploit-auto-context.v1',
      token: 'context-secret-fixture',
      observedFindings: [{ id: 'prior-1', title: 'Prior evidence' }],
    },
  }, {
    owner: 'test:owner',
    profile: { id: 7, name: 'Codex privado', model: 'gpt-test' },
    artexToken: 'artex-session-super-secret',
    artexBaseUrl: 'http://127.0.0.1:8787',
    scopeHost: 'lab.example.test',
  });

  assert.equal(snapshot.profileId, 7);
  assert.equal(snapshot.autoSessionId, 'session-auto-fixture');
  assert.equal(snapshot.autoPlanHash, 'a'.repeat(64));
  assert.equal(calls.length, 1);
  assert.equal(calls[0].options.env.LITELLM_API_KEY, 'artex-session-super-secret');
  assert.equal(calls[0].options.env.LITELLM_BASE_URL, 'http://127.0.0.1:8787/api/internal/llm/profiles/7/v1');
  assert.doesNotMatch(JSON.stringify(calls[0].args), /artex-session-super-secret/);
  assert.match(calls[0].options.env.NEUROSPLOIT_RUN_ROOT, new RegExp(snapshot.id));

  child.stdout.write('  run id : ns-123-lab.example.test\n');
  child.stdout.write('  finding_json: {"id":"F-1","title":"Fixture","severity":"Low","validated":true}\n');
  child.stdout.write('  validated finding(s) · phase complete\n');
  await new Promise((resolve) => setTimeout(resolve, 40));
  const finished = await manager.snapshot(snapshot.id, { includeFeed: true });
  assert.equal(finished.done, true);
  assert.equal(finished.findings[0].id, 'F-1');
  assert.equal(finished.runId, 'ns-123-lab.example.test');
  const persisted = await fs.readFile(path.join(root, '.runtime', 'neurosploit', 'jobs', snapshot.id, 'job.json'), 'utf8');
  const autoContext = await fs.readFile(path.join(root, '.runtime', 'neurosploit', 'jobs', snapshot.id, 'project', 'auto-context.json'), 'utf8');
  assert.doesNotMatch(persisted, /artex-session-super-secret/);
  assert.doesNotMatch(persisted, /LITELLM_API_KEY/);
  assert.doesNotMatch(persisted, /Prior evidence|context-secret-fixture/);
  assert.match(autoContext, /ghostrecon\.neurosploit-auto-context\.v1/);
  assert.match(autoContext, /Prior evidence/);
  assert.doesNotMatch(autoContext, /context-secret-fixture/);
  assert.match(autoContext, /\[REDACTED\]/);
});

test('configuração NeuroSploit do Auto rejeita credenciais e aplica limites', () => {
  assert.throws(
    () => normalizeAutoNeuroSploitConfig({ profileId: 7, apiKey: 'never-here' }),
    /credenciais não podem ser enviadas/,
  );
  assert.deepEqual(normalizeAutoNeuroSploitConfig({
    profileId: 7,
    environment: 'lab',
    votes: 99,
    recon: 0,
    chainDepth: 9,
    maxAgents: 100,
    timeoutMs: 10,
    focus: 'api\nsem quebra',
  }), {
    profileId: 7,
    environment: 'lab',
    votes: 5,
    recon: 1,
    chainDepth: 6,
    maxAgents: 64,
    quick: false,
    timeoutMs: 60_000,
    focus: 'api sem quebra',
    objective: '',
    outOfScope: '',
    codexCli: false,
    mcpServers: [],
  });
});

test('configuração NeuroSploit sela Mind para Codex e rejeita MCP no bridge API', () => {
  assert.deepEqual(normalizeAutoNeuroSploitConfig({
    profileId: 8,
    codexCli: true,
    mcpServers: ['codex:mind', 'ghostrecon', 'codex:mind'],
  }).mcpServers, ['codex:mind', 'ghostrecon']);
  assert.throws(
    () => normalizeAutoNeuroSploitConfig({ profileId: 8, mcpServers: ['codex:mind'] }),
    /MCPs.*Codex CLI/i,
  );
});

test('NeuroSploit usa Mind somente dentro do Codex CLI e desliga a ponte Artex', async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-neurosploit-codex-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const binary = path.join(root, 'engines', 'neurosploit', 'neurosploit-rs', 'target', 'release', 'neurosploit');
  await fs.mkdir(path.dirname(binary), { recursive: true });
  await fs.writeFile(binary, '#!/bin/sh\n', { mode: 0o700 });
  const codexHome = path.join(root, 'codex-home');
  await fs.mkdir(codexHome, { recursive: true });
  await fs.writeFile(path.join(codexHome, 'config.toml'), [
    '[mcp_servers.mind]',
    'command = "node"',
    'env = { MIND_KEY = "must-remain-in-codex" }',
    '',
  ].join('\n'));
  const previousCodexHome = process.env.CODEX_HOME;
  process.env.CODEX_HOME = codexHome;
  t.after(() => {
    if (previousCodexHome === undefined) delete process.env.CODEX_HOME;
    else process.env.CODEX_HOME = previousCodexHome;
  });
  const calls = [];
  let script = '';
  const child = fakeChild();
  child.stdin.on('data', (chunk) => { script += chunk.toString('utf8'); });
  const manager = new NeuroSploitManager({
    root,
    spawnImpl(command, args, options) {
      calls.push({ command, args, options });
      return child;
    },
  });
  const job = await manager.start({
    mode: 'run', target: 'https://lab.example.test', repository: '',
    engagementId: 'ENG-LAB', authorizationReference: 'ROE-42', environment: 'lab', policy: 'web',
    codexCli: true, mcpServers: ['codex:mind'],
  }, {
    owner: 'test:owner',
    profile: { id: 9, name: 'Codex local', model: 'gpt-daybreak-blue-latest', format: 'chatgpt-plan' },
    artexToken: 'must-not-be-used', artexBaseUrl: 'http://127.0.0.1:8787', scopeHost: 'lab.example.test',
  });

  assert.equal(job.codexCli, true);
  assert.deepEqual(job.mcpServers, ['codex:mind']);
  assert.equal(calls[0].options.env.NEUROSPLOIT_CODEX_MCP_ALLOWLIST, 'codex:mind');
  assert.equal(calls[0].options.env.NEUROSPLOIT_CODEX_PERSONAL_MCPS, 'mind');
  assert.equal('LITELLM_API_KEY' in calls[0].options.env, false);
  assert.match(script, /\/sub on/);
  assert.match(script, /\/mcp on/);
  const persisted = await fs.readFile(path.join(root, '.runtime', 'neurosploit', 'jobs', job.id, 'job.json'), 'utf8');
  assert.doesNotMatch(persisted, /must-remain-in-codex|must-not-be-used|MIND_KEY/);
});

test('runner Auto entrega contexto redigido ao NeuroSploit e devolve achados ao mesmo stream', async () => {
  let launch = null;
  const emitted = [];
  const manager = {
    async start(input, runtime) {
      launch = { input, runtime };
      return { id: 'job-auto-1', profileId: 7, model: 'gpt-fixture' };
    },
    async waitForTerminal(_id, { onEvent }) {
      onEvent({ type: 'finding', finding: { id: 'NS-1', title: 'Validated gap', severity: 'Medium' } });
      return {
        id: 'job-auto-1', runId: 'ns-auto-1', phase: 'completed', exitCode: 0,
        findings: [{ id: 'NS-1', title: 'Validated gap', severity: 'Medium' }],
        cortex: { ok: true, imported: 1 }, reportReady: true,
      };
    },
  };
  const result = await runAutoNeuroSploit({
    root: '/fixture',
    sessionId: 'session-neuro-auto',
    requestRunId: 'auto-http-fixture',
    owner: 'operator-fixture',
    target: 'lab.example.test',
    engagementId: 'ENG-LAB',
    effectivePlan: {
      hash: 'b'.repeat(64),
      mode: 'balanced',
      autonomyLevel: 'authorized',
      selectedModules: ['subdomains'],
      expandedModules: ['subdomains', 'neurosploit_auto'],
      activeModules: [],
      intrusiveModules: ['neurosploit_auto'],
      engines: { neurosploit: { enabled: true, profileId: 7, environment: 'lab', timeoutMs: 60_000 } },
    },
    engineOutcomes: [{ engine: 'ghostrecon', status: 'done' }],
    moduleOutcomes: [{ moduleId: 'subdomains', status: 'done' }],
    findings: [{ id: 'G-1', title: 'Prior finding', token: 'must-redact' }],
    emit: (event) => emitted.push(event),
    manager,
    artexClient: {
      baseUrl: 'http://127.0.0.1:8787',
      async listProfiles() {
        return { profiles: [{ id: 7, name: 'Fixture', model: 'gpt-fixture', format: 'openai-responses', api_key_hint: '1234' }] };
      },
      async login() { return 'temporary-bridge-token'; },
    },
    async getEngagementImpl() {
      return {
        id: 'ENG-LAB', status: 'active', roeSigned: true,
        scopeDomains: ['lab.example.test'], scopeIps: [], exclusions: [],
      };
    },
  });

  assert.equal(result.jobId, 'job-auto-1');
  assert.equal(result.findings[0].id, 'NS-1');
  assert.equal(launch.input.autoSessionId, 'session-neuro-auto');
  assert.equal(launch.input.autoContext.schema, 'ghostrecon.neurosploit-auto-context.v1');
  assert.equal(launch.input.autoContext.completed.engines[0].engine, 'ghostrecon');
  assert.equal(launch.input.autoContext.observedFindings[0].token, '[REDACTED]');
  assert.equal(launch.runtime.artexToken, 'temporary-bridge-token');
  assert.ok(emitted.some((event) => event.type === 'neurosploit_job_started'));
  assert.ok(emitted.some((event) => event.type === 'finding' && event.finding?.id === 'NS-1'));
});

test('status NeuroSploit combina perfis API/Codex e isola jobs por proprietário', async () => {
  const routes = new Map();
  const app = {
    get(route, ...handlers) { routes.set(`GET ${route}`, handlers); },
    post(route, ...handlers) { routes.set(`POST ${route}`, handlers); },
  };
  const jobs = [
    { id: 'own', owner: 'test:owner' },
    { id: 'other', owner: 'test:other' },
  ];
  const manager = {
    async status() { return { installed: true, binaryReady: true, version: '4.4.3', modes: ['run'], jobs }; },
    owns(job, principal) { return Boolean(job && (job.owner === principal.sub || principal.role === 'admin')); },
  };
  registerNeuroSploitRoutes(app, {
    ROOT: '/tmp/fixture',
    validateCsrfToken: () => true,
    manager,
    artexClient: {
      async listProfiles() {
        return { profiles: [
          { id: 3, name: 'OpenAI API', model: 'gpt-api', format: 'openai-responses', api_key_hint: '1234' },
          { id: 4, name: 'Codex', model: 'gpt-codex', format: 'chatgpt-plan' },
        ] };
      },
      async chatGptPlanStatus() { return { connected: true }; },
    },
  });
  const req = {
    headers: {}, method: 'GET', originalUrl: '/api/neurosploit/status',
    principal: { sub: 'test:owner', role: 'red', scopes: ['ai.run'], _scopeSet: new Set(['ai.run']) },
    socket: { remoteAddress: '127.0.0.1' },
  };
  const res = { payload: null, json(payload) { this.payload = payload; return this; } };
  for (const handler of routes.get('GET /api/neurosploit/status') || []) {
    let nextCalled = false;
    await handler(req, res, () => { nextCalled = true; });
    if (!nextCalled) break;
  }
  assert.equal(res.payload.binaryReady, true);
  assert.deepEqual(res.payload.jobs.map((job) => job.id), ['own']);
  assert.equal(res.payload.profiles.find((profile) => profile.id === 3).credentialSource, 'ghostia-vault');
  assert.equal(res.payload.profiles.find((profile) => profile.id === 4).credentialSource, 'codex-plan');
  assert.equal(res.payload.profiles.find((profile) => profile.id === 4).ready, true);
});

test('NeuroSploit falha fechado para API sem chave e Codex desconectado', async () => {
  await assert.rejects(
    validateNeuroSploitProfileReady({ chatGptPlanStatus: async () => ({ connected: true }) }, {
      id: 1, model: 'gpt-api', format: 'openai-responses',
    }),
    /perfil de API sem credencial/,
  );
  await assert.rejects(
    validateNeuroSploitProfileReady({ chatGptPlanStatus: async () => ({ connected: false }) }, {
      id: 2, model: 'gpt-codex', format: 'chatgpt-plan',
    }),
    /perfil Codex desconectado/,
  );
  await assert.doesNotReject(
    validateNeuroSploitProfileReady({ chatGptPlanStatus: async () => ({ connected: true }) }, {
      id: 3, model: 'gpt-codex', format: 'chatgpt-plan',
    }),
  );
});
