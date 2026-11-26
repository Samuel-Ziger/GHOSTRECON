import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  normalizeHackbotBindings,
  publicHackbotBindings,
  readHackbotBindings,
  writeHackbotBindings,
} from '../integrations/hackbot/config.mjs';
import { HackbotClient, resolveHackbotRunTimeoutMs } from '../integrations/hackbot/client.mjs';
import { registerHackbotRoutes } from '../routes/hackbot.mjs';
import { listCodexMcpCatalog, validateCodexMcpSelection } from '../integrations/mcp/catalog.mjs';

const AGENTS = ['orchestrator', 'researcher', 'analyst', 'document_analyst', 'tutor'];

test('timeout HackBot acompanha a rodada multiagente sem corte prematuro da API Node', async () => {
  assert.equal(resolveHackbotRunTimeoutMs({}), 30 * 60_000 + 30_000);
  assert.equal(resolveHackbotRunTimeoutMs({ GHOSTRECON_HACKBOT_RUN_TIMEOUT: '7200' }), 2 * 60 * 60_000 + 30_000);
  assert.equal(resolveHackbotRunTimeoutMs({ GHOSTRECON_HACKBOT_RUN_TIMEOUT: '99999' }), 2 * 60 * 60_000 + 30_000);
  assert.equal(resolveHackbotRunTimeoutMs({ GHOSTRECON_HACKBOT_RUN_TIMEOUT: 'invalido' }), 30 * 60_000 + 30_000);

  let observedSignal = null;
  const client = new HackbotClient({
    runTimeoutMs: 42_000,
    fetchImpl: async (_url, init) => {
      observedSignal = init.signal;
      return { ok: true, async json() { return { ok: true }; } };
    },
  });
  await client.run({ prompt: 'fixture' });
  assert.equal(client.runTimeoutMs, 42_000);
  assert.ok(observedSignal instanceof AbortSignal);
});

function fixtureBindings() {
  return Object.fromEntries(AGENTS.map((name) => [name, {
    model: `${name}-model`,
    base_url: 'http://127.0.0.1:11434/v1',
    api_key_env: 'LOCAL_LLM_API_KEY',
  }]));
}

test('configuração HackBot separa modelos por agente sem persistir segredos', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-hackbot-config-'));
  const saved = await writeHackbotBindings(root, { bindings: fixtureBindings() });
  const loaded = await readHackbotBindings(root);
  assert.equal(saved.bindings.analyst.model, 'analyst-model');
  assert.deepEqual(loaded.bindings, saved.bindings);
  const publicConfig = publicHackbotBindings(loaded, { LOCAL_LLM_API_KEY: 'super-secret-value' });
  assert.equal(publicConfig.bindings.researcher.api_key_present, true);
  assert.doesNotMatch(JSON.stringify(publicConfig), /super-secret-value/);
  await fs.rm(root, { recursive: true, force: true });
});

test('configuração recusa provider HTTP remoto e nomes inválidos de variável', () => {
  const remote = fixtureBindings();
  remote.orchestrator.base_url = 'http://llm.example.test/v1';
  assert.throws(() => normalizeHackbotBindings({ bindings: remote }), /loopback/);
  const invalidEnv = fixtureBindings();
  invalidEnv.tutor.api_key_env = 'bad-key-name';
  assert.throws(() => normalizeHackbotBindings({ bindings: invalidEnv }), /variável de chave inválida/);
});

test('perfil GhostIA é persistido só por id e considerado pronto sem copiar chave', () => {
  const bindings = fixtureBindings();
  bindings.orchestrator = {
    source: 'artex',
    profile_id: 42,
    provider: 'anthropic',
    model: 'claude-sonnet',
  };
  const normalized = normalizeHackbotBindings({ bindings });
  assert.deepEqual(normalized.bindings.orchestrator, {
    source: 'artex',
    profile_id: 42,
    provider: 'anthropic',
    model: 'claude-sonnet',
    base_url: null,
    api_key_env: 'ARTEX_INTERNAL_SESSION',
    mcp_servers: [],
  });
  const publicConfig = publicHackbotBindings(normalized, {});
  assert.equal(publicConfig.bindings.orchestrator.configured, true);
  assert.equal(publicConfig.bindings.orchestrator.api_key_present, false);
  assert.equal(publicConfig.bindings.orchestrator.credential_source, 'ghostia-profile');
});

test('Codex CLI manté Mind como seleção por agente sem copiar credenciais', () => {
  const bindings = fixtureBindings();
  bindings.researcher = {
    source: 'codex-cli',
    model: 'gpt-daybreak-blue-latest',
    mcp_servers: ['codex:mind', 'ghostrecon', 'codex:mind'],
  };
  bindings.analyst = {
    source: 'codex-cli',
    model: 'gpt-daybreak-blue-latest',
    mcp_servers: [],
  };
  const normalized = normalizeHackbotBindings({ bindings });
  assert.deepEqual(normalized.bindings.researcher.mcp_servers, ['codex:mind', 'ghostrecon']);
  assert.deepEqual(normalized.bindings.analyst.mcp_servers, []);
  const serialized = JSON.stringify(normalized);
  assert.doesNotMatch(serialized, /MIND_KEY|mind-mcp\.mjs/);
  const publicConfig = publicHackbotBindings(normalized, {});
  assert.equal(publicConfig.bindings.researcher.credential_source, 'codex-login');
});

test('catálogo importa somente o nome do Mind do CODEX_HOME e recusa MCP desconhecido', async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-codex-mcp-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const codexHome = path.join(root, 'codex-home');
  await fs.mkdir(codexHome, { recursive: true });
  await fs.writeFile(path.join(codexHome, 'config.toml'), [
    '[mcp_servers.mind]',
    'command = "node"',
    'args = ["/private/mind-mcp.mjs"]',
    'env = { MIND_KEY = "secret-never-export" }',
    '[mcp_servers.mind.env]',
    'MIND_KEY = "secret-never-export"',
    '[mcp_servers.mind.tools.read_url]',
    'enabled = true',
    '',
  ].join('\n'));
  const env = { ...process.env, CODEX_HOME: codexHome };
  const catalog = await listCodexMcpCatalog({ root, env });
  assert.ok(catalog.some((item) => item.id === 'codex:mind' && item.origin === 'codex-user-config'));
  assert.equal(catalog.some((item) => item.id === 'codex:mind.env'), false);
  assert.equal(catalog.some((item) => item.id === 'codex:mind.tools.read_url'), false);
  assert.doesNotMatch(JSON.stringify(catalog), /secret-never-export|private\/mind-mcp/);
  assert.deepEqual(
    await validateCodexMcpSelection({ root, selected: ['codex:mind'], env }),
    ['codex:mind'],
  );
  await assert.rejects(
    validateCodexMcpSelection({ root, selected: ['codex:missing'], env }),
    /não cadastrado/,
  );
});

test('catálogo combina perfis GhostIA e presets de provedores', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-hackbot-models-'));
  const routes = new Map();
  const app = {
    get(route, ...handlers) { routes.set(`GET ${route}`, handlers); },
    post() {},
    delete() {},
  };
  registerHackbotRoutes(app, {
    ROOT: root,
    validateCsrfToken: () => true,
    client: { async status() { return {}; } },
    artexClient: {
      async listProfiles() {
        return { profiles: [{ id: '3', name: 'Claude privado', format: 'anthropic', model: 'claude-sonnet', api_key_hint: '…1234' }] };
      },
      async chatGptPlanStatus() { return { connected: true }; },
    },
  });
  const req = {
    headers: {},
    method: 'GET',
    originalUrl: '/api/hackbot/models',
    principal: { sub: 'test:owner', role: 'admin', scopes: ['*'], _scopeSet: new Set(['*']) },
    socket: { remoteAddress: '127.0.0.1' },
  };
  const res = { payload: null, json(payload) { this.payload = payload; return this; } };
  for (const handler of routes.get('GET /api/hackbot/models') || []) {
    let nextCalled = false;
    await handler(req, res, () => { nextCalled = true; });
    if (!nextCalled) break;
  }
  assert.equal(res.payload.artex_online, true);
  assert.ok(res.payload.models.some((item) => item.id === 'artex-profile-3' && item.source === 'artex'));
  assert.ok(res.payload.models.some((item) => item.id === 'codex-cli' && item.source === 'codex-cli'));
  assert.ok(Array.isArray(res.payload.mcp_servers));
  for (const id of ['openrouter-auto', 'deepseek-flash', 'kimi-k2-5', 'glm-4-6', 'claude-sonnet-openrouter']) {
    assert.ok(res.payload.models.some((item) => item.id === id), `preset ausente: ${id}`);
  }
  assert.doesNotMatch(JSON.stringify(res.payload), /provider-secret/);
  await fs.rm(root, { recursive: true, force: true });
});

test('rotas HackBot aplicam propriedade, CSRF e seleção direta de especialista', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-hackbot-route-'));
  const calls = [];
  const client = {
    async status() { return { ok: true, runtime_ready: true, dependencies: {} }; },
    async session(id) { return { ok: true, session: { id, entries: [] } }; },
    async run(body) {
      calls.push(body);
      return { ok: true, session: { id: body.session_id, entries: [{ role: 'assistant', content: 'ok', agent: body.agent }] }, outcome: { answer: 'ok' } };
    },
    async deleteSession() { return { ok: true }; },
  };
  const routes = new Map();
  const app = {
    get(route, ...handlers) { routes.set(`GET ${route}`, handlers); },
    post(route, ...handlers) { routes.set(`POST ${route}`, handlers); },
    delete(route, ...handlers) { routes.set(`DELETE ${route}`, handlers); },
  };
  registerHackbotRoutes(app, {
    ROOT: root,
    validateCsrfToken: (req) => req.headers['x-csrf-token'] === 'valid-csrf',
    client,
  });

  async function invoke(key, { body = {}, params = {}, headers = {} } = {}) {
    const [method, url] = key.split(' ');
    const req = {
      body,
      headers,
      method,
      originalUrl: url,
      params,
      principal: { sub: 'test:owner', role: 'admin', scopes: ['*'], _scopeSet: new Set(['*']) },
      socket: { remoteAddress: '127.0.0.1' },
    };
    const res = {
      statusCode: 200,
      payload: null,
      status(code) { this.statusCode = code; return this; },
      json(payload) { this.payload = payload; return this; },
    };
    for (const handler of routes.get(key) || []) {
      let nextCalled = false;
      await handler(req, res, () => { nextCalled = true; });
      if (!nextCalled) break;
    }
    return res;
  }

  try {
    const rejected = await invoke('POST /api/hackbot/conversations', { body: { agent: 'analyst' } });
    assert.equal(rejected.statusCode, 403);
    const createdResponse = await invoke('POST /api/hackbot/conversations', {
      body: { agent: 'analyst' }, headers: { 'x-csrf-token': 'valid-csrf' },
    });
    assert.equal(createdResponse.statusCode, 201);
    const created = createdResponse.payload;
    const runResponse = await invoke('POST /api/hackbot/conversations/:id/messages', {
      params: { id: created.conversation.id },
      body: { message: 'triage', agent: 'analyst' },
      headers: { 'x-csrf-token': 'valid-csrf' },
    });
    assert.equal(runResponse.statusCode, 200);
    assert.equal(calls[0].agent, 'analyst');
    assert.equal(calls[0].prompt, 'triage');
    assert.equal(calls[0].session_id, created.conversation.id);
    const compatibilityResponse = await invoke('POST /api/hackbot/conversations/:id/messages', {
      params: { id: created.conversation.id },
      body: { prompt: 'bundle antigo', agent: 'analyst' },
      headers: { 'x-csrf-token': 'valid-csrf' },
    });
    assert.equal(compatibilityResponse.statusCode, 200);
    assert.equal(calls[1].prompt, 'bundle antigo');
    const tooLarge = await invoke('POST /api/hackbot/conversations/:id/messages', {
      params: { id: created.conversation.id },
      body: { message: 'x'.repeat(64_001), agent: 'analyst' },
      headers: { 'x-csrf-token': 'valid-csrf' },
    });
    assert.equal(tooLarge.statusCode, 413);
    assert.match(tooLarge.payload.error, /64\.000 caracteres/);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});
