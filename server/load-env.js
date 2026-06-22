/**
 * Carrega `.env` da raiz do repositório (pasta acima de `server/`),
 * independentemente do cwd ao correr `node server/index.js`.
 */
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';
import { augmentProcessPathFromCommonDirs } from './modules/tool-path.js';
import { githubTokenPreview, resolveGithubToken } from './modules/github-token.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const envPath = path.join(__dirname, '..', '.env');
const r = dotenv.config({ path: envPath });
if (r.error && !fs.existsSync(envPath)) {
  console.warn('[GHOSTRECON] Ficheiro .env não encontrado em:', envPath);
}

const autoPathAdded = augmentProcessPathFromCommonDirs();
if (autoPathAdded.length) {
  console.warn('[GHOSTRECON] PATH (automático): prefixadas', autoPathAdded.join(', '));
}

const ghTok = resolveGithubToken();
if (ghTok) {
  console.warn(`[GHOSTRECON] GITHUB_TOKEN carregado (${githubTokenPreview(ghTok)}) — API + git clone`);
} else if (fs.existsSync(envPath)) {
  console.warn(
    '[GHOSTRECON] GITHUB_TOKEN ausente no .env — git clone de repos candidatos pode pedir credenciais no terminal',
  );
}
