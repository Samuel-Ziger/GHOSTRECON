import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export const WORKFLOW_ROOT = path.resolve(__dirname, '..');

/**
 * Lista de alvos por defeito: `subdomains.txt` na raiz do repo GHOSTRECON quando o pacote está em `.../GHOSTRECON/vps-recon-workflow/`.
 */
export const DEFAULT_WORKFLOW_DOMAINS_REL = '../subdomains.txt';

export function resolveFromRoot(p) {
  return path.isAbsolute(String(p || '')) ? String(p) : path.join(WORKFLOW_ROOT, String(p || ''));
}
