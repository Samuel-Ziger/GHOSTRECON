#!/usr/bin/env node
/**
 * Runner hermético dos testes em server/tests.
 * Por padrão exclui smokes de rede (ex.: pipeline-smoke.test.js).
 *
 *   node scripts/run-server-tests.mjs
 *   node scripts/run-server-tests.mjs --network
 *   node scripts/run-server-tests.mjs --include-network
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

const args = new Set(process.argv.slice(2));
const networkOnly = args.has('--network');
const includeNetwork = args.has('--include-network');

const entries = await fs.readdir(TESTS_DIR);
const files = entries
  .filter((name) => name.endsWith('.test.js'))
  .filter((name) => {
    if (networkOnly) return NETWORK_TESTS.has(name);
    if (includeNetwork) return true;
    return !NETWORK_TESTS.has(name);
  })
  .sort()
  .map((name) => path.join(TESTS_DIR, name));

if (!files.length) {
  console.error('Nenhum teste selecionado.');
  process.exit(1);
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
