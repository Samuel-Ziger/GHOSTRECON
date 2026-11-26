import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createServer } from 'vite';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const vite = await createServer({
  root: ROOT,
  appType: 'custom',
  logLevel: 'silent',
  server: { middlewareMode: true },
});
after(async () => vite.close());

const tor = await vite.ssrLoadModule('/frontend/src/features/pages/tor-validator/model.ts');
const wifi = await vite.ssrLoadModule('/frontend/src/features/pages/wifi-pentest/model.ts');
const wifiService = await vite.ssrLoadModule('/frontend/src/features/pages/wifi-pentest/service.ts');
const postEx = await vite.ssrLoadModule('/frontend/src/features/pages/post-exploitation/model.ts');
const postExService = await vite.ssrLoadModule('/frontend/src/features/pages/post-exploitation/service.ts');
const artexService = await vite.ssrLoadModule('/frontend/src/features/artex/service.ts');

test('Tor nativo preserva endpoint file:// e formata os três estados', () => {
  assert.equal(tor.tunnelApiUrl('/api/tunnel/validate', 'file:'), 'http://127.0.0.1:3847/api/tunnel/validate');
  assert.equal(tor.tunnelApiUrl('api/tunnel/validate', 'https:'), '/api/tunnel/validate');
  assert.deepEqual(tor.formatTunnelValidation({
    validated: true,
    status: { active: true, tor: 'active', openvpn: 'inactive' },
    direct: { ok: true, ip: '198.51.100.2', code: 200 },
    tor: { ok: true, isTor: true, ip: '203.0.113.8', code: 200 },
  }), {
    direct: 'ok=true • ip=198.51.100.2 • code=200',
    directOk: true,
    services: 'active=true • tor=active • openvpn=inactive',
    servicesOk: true,
    summary: 'VALIDADO: tráfego via Tor ativo.',
    tor: 'ok=true • isTor=true • ip=203.0.113.8 • code=200',
    torOk: true,
    validated: true,
  });
});

test('Wi-Fi nativo preserva status, eventos, auth e o fallback file://', () => {
  assert.equal(wifiService.wifiApiUrl('/api/wifi/capabilities', 'file:'), 'http://127.0.0.1:3847/api/wifi/capabilities');
  assert.deepEqual(wifiService.wifiAuthHeaders({
    getItem: () => JSON.stringify({ ghostreconApiKey: 'wifi-key' }),
  }, { Accept: 'application/json' }), {
    Accept: 'application/json',
    'X-API-Key': 'wifi-key',
  });
  assert.deepEqual(wifi.wifiStatusLines({
    adapter: { found: true }, kali: true, preferredIface: 'wlan1', message: 'ready',
    tools: { aircrack: true, wifite: false },
  }), {
    alfa: true,
    iface: 'wlan1',
    kali: true,
    message: 'ready',
    tools: 'aircrack:✓ · wifite:✗',
  });
  assert.deepEqual(wifi.wifiEventLog({ type: 'done', ok: false, reason: 'cancelled', findingCount: 2 }), {
    message: 'done: cancelled findings=2', level: 'warn',
  });
});

test('serviço Wi-Fi preserva capabilities, CSRF e stream NDJSON', async () => {
  const requests = [];
  const responses = [
    new Response(JSON.stringify({ wifi: { kali: true, preferredIface: 'wlan1' } })),
    new Response(JSON.stringify({ token: 'csrf-wifi' })),
    new Response('{"type":"start"}\n{"type":"done","ok":true}\n', {
      headers: { 'Content-Type': 'application/x-ndjson' },
    }),
  ];
  const service = wifiService.createWifiPentestService({
    protocol: 'file:',
    storage: { getItem: () => JSON.stringify({ ghostreconApiKey: 'wifi-key' }) },
    fetchImpl: async (url, options = {}) => {
      requests.push({ url: String(url), options });
      return responses.shift();
    },
  });
  assert.deepEqual(await service.capabilities(), { kali: true, preferredIface: 'wlan1' });
  const stream = await service.stream({ targets: 'LabAP', labConfirm: true });
  const frames = [];
  for await (const frame of stream) frames.push(frame);
  assert.deepEqual(frames.filter((frame) => frame.ok).map((frame) => frame.value.type), ['start', 'done']);
  assert.equal(requests[1].url, 'http://127.0.0.1:3847/api/csrf-token');
  assert.equal(requests[2].url, 'http://127.0.0.1:3847/api/wifi/stream');
  assert.equal(requests[2].options.headers['X-CSRF-Token'], 'csrf-wifi');
  assert.equal(requests[2].options.headers['X-API-Key'], 'wifi-key');
});

test('modelo Post-Ex preserva progresso, ciclo, filtros, target e SearchSploit', () => {
  const progress = postEx.parsePostExProgress(JSON.stringify({
    shell: 'completed', linpeas: 'in-progress', invalid: 'completed', privesc: 'broken',
  }));
  assert.deepEqual(progress, { shell: 'completed', linpeas: 'in-progress' });
  assert.equal(postEx.completedPostExModules(progress), 1);
  assert.equal(postEx.nextPostExStatus('pending'), 'in-progress');
  assert.equal(postEx.nextPostExStatus('in-progress'), 'completed');
  assert.equal(postEx.nextPostExStatus('completed'), 'pending');
  assert.equal(postEx.postExFilterForTarget('ubuntu-lab'), 'linux');
  assert.equal(postEx.postExFilterForTarget('win-server'), 'windows');
  assert.equal(postEx.postExCardMatches({
    categories: 'linux windows', filter: 'linux', search: 'kernel',
    name: 'Privesc', sub: 'SUID · Kernel', badge: 'KERNEL',
  }), true);
  assert.equal(postEx.postExCardMatches({
    categories: 'general', filter: 'windows', search: '',
    name: 'Pivoting', sub: 'Ligolo', badge: 'LATERAL',
  }), false);
  assert.deepEqual(postEx.normalizeSearchSploitResults({ RESULTS_EXPLOIT: [{
    Title: 'Apache RCE', Path: 'remote/123.py', 'EDB-ID': 123,
  }] }), [{ edbId: '123', path: 'remote/123.py', title: 'Apache RCE', type: 'REMOTE' }]);
  assert.equal(postEx.postExApiUrl('/api/searchsploit', 'file:'), 'http://127.0.0.1:3847/api/searchsploit');
});

test('serviço Post-Ex consulta SearchSploit com filtro no endpoint correto', async () => {
  let request;
  const service = postExService.createPostExploitationService({
    protocol: 'file:',
    fetchImpl: async (url, options) => {
      request = { url: String(url), options };
      return new Response(JSON.stringify({ RESULTS_EXPLOIT: [{ Title: 'RCE', Path: 'webapps/1.py' }] }));
    },
  });
  const items = await service.searchSploit('Apache 2.4', ' -t webapps');
  assert.equal(request.url, 'http://127.0.0.1:3847/api/searchsploit?q=Apache+2.4+-t+webapps');
  assert.equal(request.options.signal instanceof AbortSignal, true);
  assert.equal(items[0].type, 'WEBAPPS');
});

test('serviço GhostIA testa provider e carrega detalhe sem expor chave', async () => {
  const requests = [];
  const responses = [
    new Response(JSON.stringify({ token: 'csrf-ghostia' })),
    new Response(JSON.stringify({ ok: true, result: { reply: 'OK', latency_ms: 12 } })),
    new Response(JSON.stringify({ ok: true, detail: 'resposta completa' })),
  ];
  const service = artexService.createArtexService({
    apiBase: () => 'http://127.0.0.1:3847',
    auth: () => null,
    fetchImpl: async (url, options = {}) => {
      requests.push({ url: String(url), options });
      return responses.shift();
    },
  });
  assert.equal((await service.testProfile(7)).result.reply, 'OK');
  assert.equal((await service.messageDetail(42, 9)).detail, 'resposta completa');
  assert.equal(requests[1].url, 'http://127.0.0.1:3847/api/artex/llm/profiles/7/test');
  assert.equal(requests[1].options.headers['X-CSRF-Token'], 'csrf-ghostia');
  assert.equal(requests[2].url, 'http://127.0.0.1:3847/api/artex/conversations/42/messages/9');
  assert.doesNotMatch(JSON.stringify(requests), /sk-proj|api_key/i);
});

test('serviço GhostIA apaga conversa com CSRF sem colocar o id fora da rota', async () => {
  const requests = [];
  const responses = [
    new Response(JSON.stringify({ token: 'csrf-delete-ghostia' })),
    new Response(JSON.stringify({ ok: true, result: { deleted: 42 } })),
  ];
  const service = artexService.createArtexService({
    apiBase: () => 'http://127.0.0.1:3847',
    auth: () => null,
    fetchImpl: async (url, options = {}) => {
      requests.push({ url: String(url), options });
      return responses.shift();
    },
  });
  assert.equal((await service.deleteConversation(42)).result.deleted, 42);
  assert.equal(requests[1].url, 'http://127.0.0.1:3847/api/artex/conversations/42');
  assert.equal(requests[1].options.method, 'DELETE');
  assert.equal(requests[1].options.headers['X-CSRF-Token'], 'csrf-delete-ghostia');
});

test('serviço GhostIA apaga perfil LLM com CSRF pela rota administrativa', async () => {
  const requests = [];
  const responses = [
    new Response(JSON.stringify({ token: 'csrf-delete-profile' })),
    new Response(JSON.stringify({ ok: true, result: { deleted: 7 } })),
  ];
  const service = artexService.createArtexService({
    apiBase: () => 'http://127.0.0.1:3847',
    auth: () => null,
    fetchImpl: async (url, options = {}) => {
      requests.push({ url: String(url), options });
      return responses.shift();
    },
  });
  assert.equal((await service.deleteProfile(7)).result.deleted, 7);
  assert.equal(requests[1].url, 'http://127.0.0.1:3847/api/artex/llm/profiles/7');
  assert.equal(requests[1].options.method, 'DELETE');
  assert.equal(requests[1].options.headers['X-CSRF-Token'], 'csrf-delete-profile');
});

test('as três páginas usam controllers React nativos sem executar scripts legados', async () => {
  const files = [
    'frontend/src/features/pages/tor-validator/TorValidatorPage.tsx',
    'frontend/src/features/pages/wifi-pentest/WifiPentestPage.tsx',
    'frontend/src/features/pages/post-exploitation/PostExploitationPage.tsx',
    'frontend/src/features/artex/GhostIaPage.tsx',
  ];
  for (const relative of files) {
    const source = await fs.readFile(path.join(ROOT, relative), 'utf8');
    assert.doesNotMatch(source, /executeScripts|dangerouslySetInnerHTML/);
    assert.match(source, /useNativePageDocument/);
  }
  const auxiliary = await fs.readFile(path.join(ROOT, 'frontend/src/features/pages/AuxiliaryPage.tsx'), 'utf8');
  assert.match(auxiliary, /post-exploitation\/PostExploitationPage/);
  assert.match(auxiliary, /tor-validator\/TorValidatorPage/);
  assert.match(auxiliary, /wifi-pentest\/WifiPentestPage/);
});
