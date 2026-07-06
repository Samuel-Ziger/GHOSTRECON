import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import {
  HexstrikeClient,
  isAllowedHexstrikePostPath,
  normalizeHexstrikePath,
  resolveHexstrikeBaseUrl,
} from '../integrations/hexstrike-client.mjs';
import {
  getHexstrikeCapabilities,
  resolveHexstrikeHome,
} from '../modules/hexstrike-capabilities.mjs';

test('hexstrike path normaliza caminhos seguros e bloqueia traversal', () => {
  assert.equal(normalizeHexstrikePath('/api/telemetry'), '/api/telemetry');
  assert.equal(normalizeHexstrikePath('/api/tools/nmap?x=1'), '/api/tools/nmap');
  assert.equal(normalizeHexstrikePath('api/tools/nmap'), null);
  assert.equal(normalizeHexstrikePath('/api/../secret'), null);
});

test('hexstrike relay permite tools/intelligence e bloqueia command genérico', () => {
  assert.equal(isAllowedHexstrikePostPath('/api/tools/nmap'), true);
  assert.equal(isAllowedHexstrikePostPath('/api/intelligence/analyze-target'), true);
  assert.equal(isAllowedHexstrikePostPath('/api/command'), false);
  assert.equal(isAllowedHexstrikePostPath('/admin'), false);
});

test('resolveHexstrikeBaseUrl usa env e remove slash final', () => {
  const prev = process.env.GHOST_HEXSTRIKE_URL;
  process.env.GHOST_HEXSTRIKE_URL = 'http://127.0.0.1:9999///';
  try {
    assert.equal(resolveHexstrikeBaseUrl(), 'http://127.0.0.1:9999');
  } finally {
    if (prev === undefined) delete process.env.GHOST_HEXSTRIKE_URL;
    else process.env.GHOST_HEXSTRIKE_URL = prev;
  }
});

test('HexstrikeClient telemetry usa fetch injetado', async () => {
  const seen = [];
  const client = new HexstrikeClient({
    baseUrl: 'http://hex.local',
    fetchImpl: async (url, opts) => {
      seen.push({ url, method: opts.method });
      return new Response(JSON.stringify({ uptime: 12 }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    },
  });
  const out = await client.telemetry();
  assert.equal(out.ok, true);
  assert.equal(out.data.uptime, 12);
  assert.deepEqual(seen, [{ url: 'http://hex.local/api/telemetry', method: 'GET' }]);
});

test('HexstrikeClient bloqueia POST fora da whitelist antes do fetch', async () => {
  let called = false;
  const client = new HexstrikeClient({
    fetchImpl: async () => {
      called = true;
      return new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } });
    },
  });
  const out = await client.post('/api/command', { command: 'id' });
  assert.equal(out.ok, false);
  assert.equal(out.status, 400);
  assert.equal(called, false);
});

test('resolveHexstrikeHome prefere IAs/hexstrike-ai sob a raiz', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-hex-'));
  const home = path.join(root, 'IAs', 'hexstrike-ai');
  await fs.mkdir(home, { recursive: true });
  await fs.writeFile(path.join(home, 'hexstrike_server.py'), '# test\n', 'utf8');
  assert.equal(resolveHexstrikeHome(root), home);
});

test('getHexstrikeCapabilities retorna instalado e reachable com mock', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-hex-'));
  const home = path.join(root, 'IAs', 'hexstrike-ai');
  await fs.mkdir(home, { recursive: true });
  await fs.writeFile(path.join(home, 'hexstrike_server.py'), '# test\n', 'utf8');
  await fs.writeFile(path.join(home, 'hexstrike_mcp.py'), '# test\n', 'utf8');
  await fs.writeFile(path.join(home, 'requirements.txt'), 'flask\n', 'utf8');

  const out = await getHexstrikeCapabilities({
    ghostRoot: root,
    baseUrl: 'http://hex.local',
    fetchImpl: async () => new Response(JSON.stringify({ uptime: 1 }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }),
  });

  assert.equal(out.ok, true);
  assert.equal(out.installed, true);
  assert.equal(out.reachable, true);
  assert.equal(out.checks.server, true);
  assert.equal(out.mcp.installed, true);
  assert.equal(out.baseUrl, 'http://hex.local');
});

