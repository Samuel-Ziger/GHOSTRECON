import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { ArtexClient } from '../integrations/artex/client.mjs';
import {
  ARTEX_CONTEXT_SCHEMA,
  ARTEX_PROMPT_VERSION,
  GHOSTIA_PRIVATE_PENTEST_PROMPT,
  approvedArtexContext,
  buildArtexContext,
  persistArtexContext,
  readArtexContext,
} from '../integrations/artex/context.mjs';
import {
  canAccessArtexConversation,
} from '../routes/artex.mjs';
import {
  ARTEX_PIPELINE_BRIEF_SCHEMA,
  buildArtexPipelinePrompt,
} from '../integrations/artex/pipeline-prompt.mjs';

test('contexto GhostIA redige segredos e só vira aprovado com plano vinculado', async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-artex-context-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const prepared = buildArtexContext({
    principal: { sub: 'operator-fixture' },
    request: {
      domain: 'lab.example.test',
      apiKey: 'api-secret',
      auth: { password: 'pw-secret', nested: { jwt: 'jwt-secret' } },
      modules: ['headers', 'tls'],
    },
  });

  assert.equal(prepared.schema, ARTEX_CONTEXT_SCHEMA);
  assert.equal(prepared.promptVersion, ARTEX_PROMPT_VERSION);
  assert.equal(prepared.stage, 'prepared');
  assert.equal(prepared.authorization.approvalRequired, true);
  assert.equal(prepared.ghostrecon.apiKey, '[REDACTED]');
  assert.equal(prepared.ghostrecon.auth.password, '[REDACTED]');
  assert.equal(prepared.ghostrecon.auth.nested.jwt, '[REDACTED]');
  assert.doesNotMatch(JSON.stringify(prepared), /api-secret|pw-secret|jwt-secret/);
  assert.match(prepared.systemPrompt, /pentest privado e expressamente autorizado/i);
  assert.match(prepared.systemPrompt, /MCP GHOSTRECON/);
  assert.match(prepared.systemPrompt, /Cortex/);

  const preparedFile = await persistArtexContext(root, prepared);
  const stat = await fs.stat(preparedFile);
  assert.equal(stat.mode & 0o077, 0, 'contexto persistido não pode ser legível por grupo/outros');
  assert.deepEqual((await readArtexContext(root, prepared.contextId)).context, prepared);
  await assert.rejects(() => readArtexContext(root, '../fora'), /contextId Artex inválido/);

  const approved = approvedArtexContext(prepared, {
    sessionId: 'session-fixture-12345678',
    iteration: 1,
    hash: 'a'.repeat(64),
    modules: ['headers'],
    approved: true,
  }, { modules: ['headers', 'headers'] });
  assert.equal(approved.stage, 'approved');
  assert.equal(approved.authorization.approvalRequired, false);
  assert.equal(approved.preparedContextId, prepared.contextId);
  assert.equal(approved.effectivePlan.hash, 'a'.repeat(64));
  assert.deepEqual(approved.ghostrecon.modules, ['headers']);
  assert.deepEqual(approved.effectivePlan.modules, ['headers']);
});

test('prompt Artex segue somente os módulos e a ordem do pipeline aprovado', () => {
  const result = buildArtexPipelinePrompt({
    target: 'lab.example.test',
    contextFile: '/runtime/context.json',
    approvedContext: {
      stage: 'approved',
      contextId: 'artex-1234567890abcdef12345678',
      authorization: { privatePentest: true },
    },
    effectivePlan: {
      target: 'lab.example.test',
      hash: 'b'.repeat(64),
      selectedModules: ['security_headers', 'subdomains', 'sqli_targeted_verify', 'risk_explainer'],
      moduleLimits: [
        { id: 'security_headers', phase: 'probe', class: 'active', source: 'ghostrecon', timeoutMs: 30_000 },
        { id: 'subdomains', phase: 'discovery', class: 'passive', source: 'ghostrecon', timeoutMs: 30_000 },
        { id: 'sqli_targeted_verify', phase: 'validation', class: 'intrusive', source: 'ghostrecon', timeoutMs: 60_000 },
        { id: 'risk_explainer', phase: 'finalize', class: 'passive', source: 'ghostrecon', timeoutMs: 30_000 },
      ],
      requiresHumanApproval: true,
      execution: { confirmActive: true, outOfScope: ['admin.example.test'] },
    },
  });

  assert.equal(result.brief.schema, ARTEX_PIPELINE_BRIEF_SCHEMA);
  assert.equal(result.brief.execution.selectedModuleCount, 4);
  assert.deepEqual(result.brief.execution.phases.map((phase) => phase.id), [
    'discovery', 'probe', 'validation', 'finalize',
  ]);
  assert.match(result.prompt, /avaliação defensiva privada/i);
  assert.match(result.prompt, /subdomains\[passive\]/);
  assert.match(result.prompt, /sqli_targeted_verify\[intrusive\]/);
  assert.match(result.prompt, /gate ativo\/intrusivo obrigatório/);
  assert.doesNotMatch(result.prompt, /cred_spray|webshell_probe/);
  assert.match(result.goal, /plano defensivo selado/);
  assert.match(result.goal, /discovery=\[subdomains\]/);
  assert.match(result.goal, /validation=\[sqli_targeted_verify\]/);
  assert.doesNotMatch(result.goal, /cred_spray|webshell_probe/);
});

test('cliente Artex permanece loopback-first e autentica sem expor a senha em URLs', async (t) => {
  const previousPassword = process.env.ARTEX_ADMIN_PASSWORD;
  const previousRemote = process.env.GHOSTRECON_ARTEX_ALLOW_REMOTE;
  process.env.ARTEX_ADMIN_PASSWORD = 'runtime-password-fixture';
  delete process.env.GHOSTRECON_ARTEX_ALLOW_REMOTE;
  t.after(() => {
    if (previousPassword === undefined) delete process.env.ARTEX_ADMIN_PASSWORD;
    else process.env.ARTEX_ADMIN_PASSWORD = previousPassword;
    if (previousRemote === undefined) delete process.env.GHOSTRECON_ARTEX_ALLOW_REMOTE;
    else process.env.GHOSTRECON_ARTEX_ALLOW_REMOTE = previousRemote;
  });

  assert.throws(
    () => new ArtexClient({ baseUrl: 'https://artex.example.test' }),
    /Artex remoto bloqueado/,
  );

  const calls = [];
  const fetchImpl = async (url, options) => {
    calls.push({ url: String(url), options });
    if (String(url).endsWith('/api/auth/login')) {
      return new Response(JSON.stringify({ token: 'session-token-fixture' }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }
    return new Response(JSON.stringify({ profiles: [] }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  };
  const client = new ArtexClient({ root: '/unused', baseUrl: 'http://127.0.0.1:8787', fetchImpl });
  const result = await client.listProfiles();
  assert.deepEqual(result, { profiles: [] });
  assert.equal(calls.length, 2);
  assert.equal(JSON.parse(calls[0].options.body).password, 'runtime-password-fixture');
  assert.equal(calls[1].options.headers.authorization, 'Bearer session-token-fixture');
  assert.doesNotMatch(calls.map((call) => call.url).join(' '), /runtime-password-fixture|session-token-fixture/);

  await client.testProfile({ profile_id: 7, provider: 'openai-responses', model: 'fixture-model' });
  await client.deleteProfile('7');
  await client.conversationMessageDetail('42', '9');
  await client.listModels({ provider: 'openai-responses', api_key: 'fixture-key' });
  await client.deleteConversation('42');
  assert.equal(calls[2].url, 'http://127.0.0.1:8787/api/llm/test');
  assert.equal(calls[2].options.method, 'POST');
  assert.equal(JSON.parse(calls[2].options.body).profile_id, 7);
  assert.equal(calls[3].url, 'http://127.0.0.1:8787/api/llm/profiles/7');
  assert.equal(calls[3].options.method, 'DELETE');
  assert.equal(calls[4].url, 'http://127.0.0.1:8787/api/conversations/42/messages/9');
  assert.equal(calls[5].url, 'http://127.0.0.1:8787/api/llm/models');
  assert.equal(calls[5].options.method, 'POST');
  assert.equal(calls[6].url, 'http://127.0.0.1:8787/api/conversations/42');
  assert.equal(calls[6].options.method, 'DELETE');

  const retryCalls = [];
  const retryClient = new ArtexClient({
    root: '/unused',
    baseUrl: 'http://127.0.0.1:8787',
    fetchImpl: async (url) => {
      retryCalls.push(String(url));
      const login = String(url).endsWith('/api/auth/login');
      return new Response(JSON.stringify(login ? { token: 'retry-token-fixture' } : { error: 'sessão recusada' }), {
        status: login ? 200 : 401,
        headers: { 'content-type': 'application/json' },
      });
    },
  });
  await assert.rejects(() => retryClient.listProfiles(), /sessão recusada/);
  assert.equal(retryCalls.filter((url) => url.endsWith('/api/llm/profiles')).length, 2, '401 pode renovar a sessão apenas uma vez');
});

test('conversas GhostIA ficam vinculadas ao principal GHOSTRECON', async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-artex-owner-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const dir = path.join(root, '.runtime', 'artex', 'conversations');
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  await fs.writeFile(path.join(dir, '42.json'), JSON.stringify({ id: '42', owner: 'alice' }), { mode: 0o600 });

  assert.equal(await canAccessArtexConversation(root, '42', { sub: 'alice', role: 'operator' }), true);
  assert.equal(await canAccessArtexConversation(root, '42', { sub: 'bob', role: 'operator' }), false);
  assert.equal(await canAccessArtexConversation(root, '99', { sub: 'alice', role: 'operator' }), false);
  assert.equal(await canAccessArtexConversation(root, '99', { sub: 'admin', role: 'admin' }), true);
  assert.equal(await canAccessArtexConversation(root, '../42', { sub: 'admin', role: 'admin' }), false);
});

test('contrato integrado mantém Artex no chat/provider e o remove do Modo Auto', async () => {
  const [route, controller, neuroDialog, ghostIaPage, launcher, registry, stack] = await Promise.all([
    fs.readFile(new URL('../routes/artex.mjs', import.meta.url), 'utf8'),
    fs.readFile(new URL('../../frontend/templates/index.html', import.meta.url), 'utf8'),
    fs.readFile(new URL('../../frontend/src/features/neurosploit/NeuroSploitAutoDialog.tsx', import.meta.url), 'utf8'),
    fs.readFile(new URL('../../frontend/src/features/artex/GhostIaPage.tsx', import.meta.url), 'utf8'),
    fs.readFile(new URL('../../frontend/src/features/artex/GhostIaLaunchCard.tsx', import.meta.url), 'utf8'),
    fs.readFile(new URL('../../frontend/src/page-registry.ts', import.meta.url), 'utf8'),
    fs.readFile(new URL('../../scripts/start-stack.mjs', import.meta.url), 'utf8'),
  ]);
  assert.match(route, /\/api\/artex\/chatgpt-plan\/models/);
  assert.match(route, /\/api\/artex\/chatgpt-plan\/connect', requireScope\('ai\.manage'\)/);
  assert.match(route, /\/api\/artex\/llm\/profiles\/:id\/test', requireScope\('ai\.manage'\)/);
  assert.match(route, /app\.delete\('\/api\/artex\/llm\/profiles\/:id', requireScope\('ai\.manage'\)/);
  assert.match(route, /\/api\/artex\/llm\/models', requireScope\('ai\.manage'\)/);
  assert.match(route, /app\.delete\('\/api\/artex\/conversations\/:id', requireScope\('ai\.run'\)/);
  assert.match(route, /\/api\/artex\/conversations\/:id\/messages\/:seq', requireScope\('ai\.run'\)/);
  assert.doesNotMatch(route, /\/api\/artex\/auto\//);
  assert.match(route, /canAccessArtexConversation\(ROOT, req\.params\.id, req\.principal\)/);
  assert.match(route, /writeConversationOwner\(ROOT, conversation\?\.id, req\.principal\)/);
  assert.doesNotMatch(controller, /parseArtexBlockRules|startArtexForApprovedAuto|activeArtexAuto/);
  assert.match(controller, /includeNeuroSploit/);
  assert.match(controller, /neurosploitProfileSelect/);
  assert.match(controller, /autoAllApplicableModulesToggle/);
  assert.match(controller, /body\.modules = \[\.\.\.new Set\(selectedModules\)\]/);
  assert.match(controller, /agentes Vigolium são mutuamente exclusivos/);
  assert.match(controller, /openStream\(\s*body,/);
  assert.match(neuroDialog, /Modo Auto · NeuroSploit/);
  assert.match(neuroDialog, /autoIncludeNeuroSploitToggle/);
  assert.match(neuroDialog, /Todos os módulos aplicáveis/);
  assert.match(ghostIaPage, /Testar provider/);
  assert.match(ghostIaPage, /Carregar opções de modelo/);
  assert.match(ghostIaPage, /ChatGPT Plan \/ Codex/);
  assert.match(ghostIaPage, /deleteConversation/);
  assert.match(ghostIaPage, /A próxima mensagem abrirá uma nova conversa/);
  assert.match(ghostIaPage, /messageDetail/);
  assert.match(launcher, /ghostia\.html/);
  assert.match(registry, /canonicalPath: '\/ghostia\.html'/);
  assert.match(stack, /spawnSync\('go', \['build', '-o', ARTEX_BIN, '\.\/cmd\/artex'\]/);
  assert.doesNotMatch(stack, /embedui/);
  assert.match(stack, /porta \$\{ARTEX_PORT\} ocupada por um serviço que não respondeu como Artex/);
  assert.match(GHOSTIA_PRIVATE_PENTEST_PROMPT, /nenhuma expansão|Nunca amplie/i);
});
