import { resolvePlaybook } from './playbooks/loader.mjs';

export const VPS_FORBIDDEN_MODULES = new Set([
  'navegation',
  'navigator',
  'tor',
  'tor_strict',
  'tor-strict',
  'kali_proxychains',
  'proxychains',
  'shannon_whitebox',
  'shannon-whitebox',
  'pentestgpt_validate',
  'pentestgpt-validate',
  'vigolium_audit',
  'vigolium-audit',
  'vigolium_swarm',
  'vigolium-swarm',
  'vigolium_agent',
  'vigolium-agent',
  'vigolium_autopilot',
  'vigolium-autopilot',
  'vigolium_codex',
  'vigolium-codex',
]);

export function sanitizeVpsReconModules(modules = []) {
  const seen = new Set();
  const out = [];
  for (const item of modules || []) {
    const key = String(item || '').trim();
    if (!key || seen.has(key) || VPS_FORBIDDEN_MODULES.has(key)) continue;
    seen.add(key);
    out.push(key);
  }
  return out;
}

export async function resolveVpsReconModules({ playbook = 'full-recon', modules = [] } = {}) {
  if (Array.isArray(modules) && modules.length) {
    return { playbook: '', modules: sanitizeVpsReconModules(modules) };
  }
  const pb = await resolvePlaybook(playbook || 'full-recon');
  return {
    playbook: pb.name,
    modules: sanitizeVpsReconModules(pb.modules || []),
  };
}
