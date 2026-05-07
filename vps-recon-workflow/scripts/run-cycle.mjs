#!/usr/bin/env node
/**
 * Ciclo cron (a cada 6 h). Opcionalmente sincroniza Supabase antes do pipeline.
 */
import '../lib/env-bootstrap.mjs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');

const skip = String(process.env.WORKFLOW_SKIP_SUPABASE_SYNC ?? '0').trim() === '1';

function run(relScript) {
  const r = spawnSync(process.execPath, [path.join(ROOT, relScript)], {
    cwd: ROOT,
    stdio: 'inherit',
    env: process.env,
  });
  if (r.status !== 0 && r.status != null) {
    console.error(`[run-cycle] ${relScript} saiu com código ${r.status}`);
    process.exit(r.status);
  }
}

if (!skip) {
  run('scripts/sync-domains.mjs');
} else {
  console.error('[run-cycle] WORKFLOW_SKIP_SUPABASE_SYNC=1 — mantém o ficheiro WORKFLOW_DOMAINS_FILE actual');
}

run('scripts/run-pipeline.mjs');
