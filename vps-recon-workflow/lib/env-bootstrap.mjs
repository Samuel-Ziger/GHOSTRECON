/**
 * Carrega variáveis antes de qualquer outro módulo que precise delas.
 * Usa o MESMO .env que o GHOSTRECON: cola/cópia aqui OU aponta GHOSTRECON_ENV_FILE.
 *
 * Ordem (primeiro que existir ganha para dotenv.config):
 * 1. GHOSTRECON_ENV_FILE=/caminho/para/.env
 * 2. <raiz-workflow>/.env
 * 3. <raiz-workflow>/../.env  (mono-repo GHOSTRECON)
 */
import fs from 'node:fs';
import path from 'node:path';
import dotenv from 'dotenv';
import { WORKFLOW_ROOT } from './paths.mjs';

let done = false;

export function resolveEnvCandidatePaths() {
  const explicit = String(process.env.GHOSTRECON_ENV_FILE || '').trim();
  /** @type {string[]} */
  const out = [];
  if (explicit) out.push(path.resolve(explicit));
  out.push(path.join(WORKFLOW_ROOT, '.env'));
  out.push(path.join(WORKFLOW_ROOT, '..', '.env'));
  return out;
}

export function bootstrapEnv() {
  if (done) return { path: process.env._WORKFLOW_ENV_SOURCE || '', already: true };
  done = true;

  for (const envPath of resolveEnvCandidatePaths()) {
    if (!envPath || !fs.existsSync(envPath)) continue;
    dotenv.config({ path: envPath });
    process.env._WORKFLOW_ENV_SOURCE = envPath;
    return { path: envPath, already: false };
  }

  console.warn(
    '[workflow] Sem .env — defina variáveis no ambiente ou crie um destes ficheiros:\n  ',
    resolveEnvCandidatePaths().join('\n   '),
  );
  return { path: '', already: false };
}

bootstrapEnv();
