#!/usr/bin/env node
/**
 * Runner hermético dos testes em server/tests.
 * Por padrão exclui smokes de rede (ex.: pipeline-smoke.test.js).
 *
 *   node scripts/run-server-tests.mjs
 *   node scripts/run-server-tests.mjs --network
 *   node scripts/run-server-tests.mjs --include-network
 *   node scripts/run-server-tests.mjs --group=core|integrations
 */
import { spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const TESTS_DIR = path.join(ROOT, 'server', 'tests');
const NETWORK_TESTS = new Set([
  'pipeline-smoke.test.js',
]);
const INTEGRATION_TESTS = new Set([
  'forge-security.test.js',
  'forge-store-hardening.test.js',
  'frameseven-cleanup-settle.test.js',
  'frameseven-integration.test.js',
  'frameseven-tor-strict.test.js',
  'hexstrike-capabilities.test.js',
  'hexstrike-orchestrator.test.js',
  'vigolium-agent.test.js',
  'vigolium-auth-config.test.js',
  'vigolium-auth-transport-security.test.js',
  'vigolium-bridge.test.js',
  'vigolium-catalog.test.js',
  'vigolium-plan-expand.test.js',
  'vigolium-runtime-freeze.test.js',
  'vigolium-server-client.test.js',
  'vigolium-source-integrity.test.js',
  'vigolium-vps-profile.test.js',
]);

const args = new Set(process.argv.slice(2));
const networkOnly = args.has('--network');
const includeNetwork = args.has('--include-network');
const groupArg = [...args].find((arg) => arg.startsWith('--group='));
const group = groupArg?.slice('--group='.length) || 'all';
const listOnly = args.has('--list');

if (!['all', 'core', 'integrations'].includes(group)) {
  console.error(`Grupo de testes inválido: ${group}`);
  process.exit(2);
}
if ((networkOnly || includeNetwork) && group !== 'all') {
  console.error('Flags de rede não podem ser combinadas com --group.');
  process.exit(2);
}

const entries = await fs.readdir(TESTS_DIR);
const files = entries
  .filter((name) => name.endsWith('.test.js'))
  .filter((name) => {
    if (networkOnly) return NETWORK_TESTS.has(name);
    if (includeNetwork) return true;
    return !NETWORK_TESTS.has(name);
  })
  .filter((name) => {
    if (group === 'integrations') return INTEGRATION_TESTS.has(name);
    if (group === 'core') return !INTEGRATION_TESTS.has(name) && !name.startsWith('auto-');
    return true;
  })
  .sort()
  .map((name) => path.join(TESTS_DIR, name));

if (!files.length) {
  console.error('Nenhum teste selecionado.');
  process.exit(1);
}

if (listOnly) {
  for (const file of files) console.log(path.basename(file));
  process.exit(0);
}

const child = spawn(process.execPath, ['--test', ...files], {
  cwd: ROOT,
  stdio: 'inherit',
  windowsHide: true,
  env: process.env,
});

child.on('exit', (code, signal) => {
  if (signal) process.kill(process.pid, signal);
  process.exit(code ?? 1);
});
