import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  autoRouteMindSkills,
  normalizeMindSkillRequest,
  publicMindSkillCatalog,
  resolveMindSkillPlan,
} from '../integrations/mind/skills.mjs';
import { writeHackbotBindings } from '../integrations/hackbot/config.mjs';
import { registerHackbotRoutes } from '../routes/hackbot.mjs';

const AGENTS = ['orchestrator', 'researcher', 'analyst', 'document_analyst', 'tutor'];

test('catálogo Mind expõe as nove skills nativas e separa risco ativo', () => {
  const skills = publicMindSkillCatalog();
  assert.equal(skills.length, 9);
  assert.deepEqual(skills.map((item) => item.id), [
    'artex', 'fullhunt', 'jevgrep', 'mdpsec-hunt', 'vulnhunt-fix-verify',
    'vulnhunt', 'ywh-gotchas', 'ywh-triage', 'ywh-write',
  ]);
  assert.equal(skills.find((item) => item.id === 'fullhunt').requiresEngagement, true);
  assert.equal(skills.find((item) => item.id === 'vulnhunt').requiresDocument, true);
});

test('roteador Mind escolhe fluxos por intenção sem misturar motores equivalentes', () => {
  assert.deepEqual(autoRouteMindSkills({ prompt: 'audita a segurança desse código' }), [
    'jevgrep', 'vulnhunt', 'ywh-gotchas',
  ]);
  assert.deepEqual(autoRouteMindSkills({ prompt: 'faz uma varredura autônoma no site inteiro' }), [
    'artex', 'ywh-gotchas', 'ywh-triage', 'ywh-write',
  ]);
  assert.deepEqual(autoRouteMindSkills({ prompt: 'esse IDOR é falso positivo?' }), [
    'ywh-gotchas', 'ywh-triage',
  ]);
  assert.throws(
    () => normalizeMindSkillRequest({ mode: 'manual', skills: ['artex', 'fullhunt'] }),
    /alternativas de exploração/,
  );
});

test('plano Mind normaliza o fluxo e declara requisitos antes da execução', () => {
  const plan = resolveMindSkillPlan({
    request: { mode: 'manual', skills: ['fullhunt', 'ywh-triage'], target: 'Example.COM', engagementId: 'ENG-1' },
    prompt: 'teste',
    agent: 'orchestrator',
  });
  assert.equal(plan.enabled, true);
  assert.equal(plan.requiresEngagement, true);
  assert.equal(plan.risk, 'active');
  assert.deepEqual(plan.workflow.map((item) => item.order), [1, 2]);
});

function makeApp() {
  const routes = new Map();
  return {
    routes,
    app: {
      get(route, ...handlers) { routes.set(`GET ${route}`, handlers); },
      post(route, ...handlers) { routes.set(`POST ${route}`, handlers); },
      delete(route, ...handlers) { routes.set(`DELETE ${route}`, handlers); },
    },
  };
}

async function invoke(routes, key, { body = {}, params = {}, headers = {} } = {}) {
  const [method, url] = key.split(' ');
  const req = {
    body, params, headers, method, originalUrl: url,
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

test('rota HackBot aplica gate Mind, envia plano congelado e sincroniza candidatos', async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-mind-route-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const bindings = Object.fromEntries(AGENTS.map((name) => [name, {
    source: 'codex-cli', model: 'gpt-daybreak-blue-latest', mcp_servers: ['codex:mind'],
  }]));
  await writeHackbotBindings(root, { bindings });
  const runs = [];
  const syncs = [];
  const client = {
    async status() { return { ok: true, runtime_ready: true, dependencies: {} }; },
    async session(id) { return { ok: true, session: { id, entries: [] } }; },
    async deleteSession() { return { ok: true }; },
    async run(body) {
      runs.push(body);
      const mindResult = { schema_version: 1, findings: [{ skill: 'fullhunt', title: 'candidato' }] };
      return {
        ok: true,
        session: { id: body.session_id, entries: [{ role: 'assistant', content: 'ok', mind_result: mindResult }] },
        outcome: { answer: 'ok', mind_result: mindResult },
      };
    },
  };
  const { app, routes } = makeApp();
  registerHackbotRoutes(app, {
    ROOT: root,
    validateCsrfToken: (req) => req.headers['x-csrf-token'] === 'valid',
    client,
    getEngagementImpl: async () => ({
      id: 'ENG-1', status: 'active', roeSigned: true,
      scopeDomains: ['example.com'], scopeIps: [], exclusions: [], window: null,
    }),
    syncMindResultToCortexImpl: async (input) => {
      syncs.push(input);
      return { ok: true, imported: 1 };
    },
  });
  const created = await invoke(routes, 'POST /api/hackbot/conversations', {
    body: { agent: 'orchestrator' }, headers: { 'x-csrf-token': 'valid' },
  });
  const id = created.payload.conversation.id;
  const missingConfirmation = await invoke(routes, 'POST /api/hackbot/conversations/:id/messages', {
    params: { id }, headers: { 'x-csrf-token': 'valid' },
    body: { message: 'hunt', agent: 'orchestrator', mind: { mode: 'manual', skills: ['fullhunt'], target: 'example.com', engagementId: 'ENG-1' } },
  });
  assert.equal(missingConfirmation.statusCode, 403);

  const response = await invoke(routes, 'POST /api/hackbot/conversations/:id/messages', {
    params: { id }, headers: { 'x-csrf-token': 'valid' },
    body: {
      message: 'hunt autorizado', agent: 'orchestrator',
      mind: { mode: 'manual', skills: ['fullhunt'], target: 'example.com', engagementId: 'ENG-1', authorizationConfirmed: true },
    },
  });
  assert.equal(response.statusCode, 200);
  assert.deepEqual(runs[0].mind_plan.skills, ['fullhunt']);
  assert.equal(runs[0].mind_plan.engagementValidated, true);
  assert.equal(syncs[0].target, 'example.com');
  assert.equal(response.payload.cortex_sync.imported, 1);

  const documentRequired = await invoke(routes, 'POST /api/hackbot/conversations/:id/messages', {
    params: { id }, headers: { 'x-csrf-token': 'valid' },
    body: { message: 'audite', agent: 'document_analyst', mind: { mode: 'manual', skills: ['vulnhunt'] } },
  });
  assert.equal(documentRequired.statusCode, 400);
  assert.match(documentRequired.payload.error, /exige um documento/);
});
