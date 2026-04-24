#!/usr/bin/env node
/**
 * GHOSTRECON CLI — cliente headless para o pipeline /api/recon/stream.
 *
 * Reaproveita 100% do pipeline existente (sem refactor):
 *  - fala com o server local (auto-spawn se não estiver a correr)
 *  - obtém CSRF token
 *  - stream NDJSON → stdout/arquivo
 *
 * Uso:
 *   ghostrecon run --target example.com --modules crtsh,http,github --output run.json
 *   ghostrecon run --target example.com --playbook api-first
 *   ghostrecon runs --target example.com --limit 10
 *   ghostrecon playbooks
 *   ghostrecon version
 *
 * Ver --help para lista completa.
 */

import { cliMain } from '../server/modules/cli/main.mjs';

cliMain(process.argv.slice(2)).then(
  (code) => {
    process.exit(typeof code === 'number' ? code : 0);
  },
  (err) => {
    process.stderr.write(`[ghostrecon] erro fatal: ${err?.stack || err?.message || err}\n`);
    process.exit(1);
  },
);
