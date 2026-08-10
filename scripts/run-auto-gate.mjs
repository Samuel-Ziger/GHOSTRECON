#!/usr/bin/env node
/**
 * Gate local consolidado do Modo Auto.
 *
 * Fonte única da lista hermética do Auto (antes duplicada no package.json).
 * Além dos testes herméticos do Auto, o gate completo também executa:
 *   - preflight de smoke de import (carrega server/index.js sem abrir porta);
 *   - testes de CLI (server/tests/cli-*.test.js);
 *   - testes de MCP (server/tests/ghostrecon-mcp.test.js).
 *
 * Uso:
 *   node scripts/run-auto-gate.mjs                 # gate completo
 *   node scripts/run-auto-gate.mjs --hermetic-only # somente Auto hermético
 */
import { spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const TESTS_DIR = path.join(ROOT, 'server', 'tests');

// Lista hermética canônica do Modo Auto. Mantida aqui como fonte única;
// o script `test:auto:hermetic` reusa o modo `--hermetic-only`.
const HERMETIC_AUTO = [
  'auto-agent.test.js',
  'auto-planner-contract.test.js',
  'ui-consent-contract.test.js',
  'vigolium-plan-expand.test.js',
  'dispatcher-abort.test.js',
  'dispatcher-unterminated.test.js',
  'scoped-fetch.test.js',
  'scope.test.js',
  'auto-resume-budgets.test.js',
  'auto-cloud-consent.test.js',
  'auto-rag-partition-routes.test.js',
  'auto-rag-ttl.test.js',
  'auto-provider-abort.test.js',
  'auto-provider-turn-timeout.test.js',
  'auto-agent-turn-stall.test.js',
  'auto-approval-persist.test.js',
  'auto-resume-checkpoint.test.js',
  'auto-session-close.test.js',
  'auto-session-security.test.js',
  'auto-effective-plan.test.js',
  'auto-content-network-gates.test.js',
  'auto-strict-phase-gates.test.js',
  'engine-scope-transport.test.js',
  'module-runner.test.js',
  'process-cancellation.test.js',
  'auth-principal-restart.test.js',
  'auto-persist-failed.test.js',
  'auto-startup-reconcile.test.js',
  'auto-snapshot-partition.test.js',
  'auto-http-disconnect.test.js',
  'auto-post-pipeline-council-abort.test.js',
  'auto-cleanup-settle.test.js',
  'auto-terminal-persist.test.js',
  'frameseven-cleanup-settle.test.js',
  'auto-e2e-hermetic.test.js',
  'risk-classification-parity.test.js',
  'frameseven-tor-strict.test.js',
  'forge-store-hardening.test.js',
  'auto-run-report.test.js',
  'auto-catalog-readiness.test.js',
  'auto-rag-persist-failclosed.test.js',
];

const MCP_TESTS = ['ghostrecon-mcp.test.js'];

const args = new Set(process.argv.slice(2));
const hermeticOnly = args.has('--hermetic-only');

function runNode(nodeArgs, extraEnv = {}) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, nodeArgs, {
      cwd: ROOT,
      stdio: 'inherit',
      windowsHide: true,
      env: { ...process.env, ...extraEnv },
    });
    child.on('exit', (code, signal) => resolve({ code: signal ? 1 : code ?? 1, signal }));
  });
}

async function importSmoke() {
  console.log('\n[auto-gate] preflight: smoke de import (GHOSTRECON_NO_HTTP_LISTEN=1)');
  const { code } = await runNode(
    ['-e', "import('./server/index.js').then(() => { console.log('IMPORT_SMOKE_OK'); process.exit(0); }).catch((e) => { console.error('IMPORT_SMOKE_FAIL', e); process.exit(1); });"],
    { GHOSTRECON_NO_HTTP_LISTEN: '1' },
  );
  return code === 0;
}

async function collectFiles() {
  const entries = new Set(await fs.readdir(TESTS_DIR));
  const files = [];
  const missing = [];

  const add = (name) => {
    if (entries.has(name)) files.push(path.join(TESTS_DIR, name));
    else missing.push(name);
  };

  for (const name of HERMETIC_AUTO) add(name);

  if (!hermeticOnly) {
    for (const name of [...entries].filter((n) => /^cli-.*\.test\.js$/.test(n)).sort()) {
      files.push(path.join(TESTS_DIR, name));
    }
    for (const name of MCP_TESTS) add(name);
  }

  if (missing.length) {
    console.error(`[auto-gate] arquivos de teste ausentes: ${missing.join(', ')}`);
    process.exit(1);
  }
  return files;
}

async function main() {
  if (!hermeticOnly) {
    const ok = await importSmoke();
    if (!ok) {
      console.error('[auto-gate] smoke de import falhou; abortando gate.');
      process.exit(1);
    }
  }

  const files = await collectFiles();
  console.log(`\n[auto-gate] executando ${files.length} arquivo(s) de teste${hermeticOnly ? ' (hermetic-only)' : ' (gate completo: Auto + CLI + MCP)'}`);

  const { code, signal } = await runNode(['--test', ...files]);
  if (signal) process.kill(process.pid, signal);
  process.exit(code ?? 1);
}

main().catch((error) => {
  console.error('[auto-gate] erro inesperado:', error);
  process.exit(1);
});
