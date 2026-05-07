/**
 * Raiz do repositório GHOSTRECON (pasta onde estão server/, playbooks/, .env).
 * Por defeito: pasta pai do vps-recon-workflow. Override: GHOSTRECON_REPO_ROOT=/caminho/absoluto
 */
import path from 'node:path';
import { WORKFLOW_ROOT } from './paths.mjs';

export function ghostreconRootPath() {
  const env = String(process.env.GHOSTRECON_REPO_ROOT || '').trim();
  if (env) return path.resolve(env);
  return path.resolve(WORKFLOW_ROOT, '..');
}
