import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { ghostreconRootPath } from './ghostrecon-root.mjs';

let resolvePlaybookFn = null;

async function getResolvePlaybook() {
  if (resolvePlaybookFn) return resolvePlaybookFn;
  const root = ghostreconRootPath();
  const url = pathToFileURL(path.join(root, 'server', 'modules', 'playbooks', 'loader.mjs')).href;
  const mod = await import(url);
  resolvePlaybookFn = mod.resolvePlaybook;
  return resolvePlaybookFn;
}

export async function resolvePlaybookProfile() {
  const name = String(process.env.WORKFLOW_PLAYBOOK || 'subdomain-hunt').trim();
  if (!name) return null;
  try {
    const resolvePlaybook = await getResolvePlaybook();
    const pb = await resolvePlaybook(name);
    const pr = pb?.profile != null ? String(pb.profile).trim().toLowerCase() : null;
    return pr || null;
  } catch {
    return null;
  }
}

export async function resolveModulesForRun() {
  const name = String(process.env.WORKFLOW_PLAYBOOK || 'subdomain-hunt').trim() || 'subdomain-hunt';
  const resolvePlaybook = await getResolvePlaybook();
  const pb = await resolvePlaybook(name);
  const modules = Array.isArray(pb.modules) ? pb.modules.map((m) => String(m).trim()).filter(Boolean) : [];
  return modules.length ? modules : ['subdomains', 'http'];
}
