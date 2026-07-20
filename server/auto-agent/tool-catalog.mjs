import { listModuleManifests } from '../modules/module-registry.mjs';
import { getHexstrikeCapabilities } from '../modules/hexstrike-capabilities.mjs';
import { isIntrusive } from '../modules/opsec.mjs';
import { listActiveDynamicManifests } from './forge/runtime-loader.mjs';

export const AUTO_BASE_MODULES = Object.freeze([
  'subdomains',
  'rdap',
  'dns_enrichment',
  'security_headers',
  'robots_sitemap',
  'wellknown_security_txt',
  'wayback',
  'common_crawl',
  'js_intel',
  'client_surface_audit',
  'cors_audit',
  'header_intel',
  'chaining',
  'risk_explainer',
]);

export const AUTO_HEXSTRIKE_MODULES = Object.freeze([
  'hexstrike_orchestrator',
]);

export const AUTO_DEEP_PASSIVE_MODULES = Object.freeze([
  'email_security_deep',
  'api_contract_diff',
  'websocket_recon',
  'hpp_param_pollution',
  'dom_clobbering_audit',
  'secrets_context_ranker',
]);

function uniq(list) {
  return [...new Set((list || []).map((x) => String(x).trim()).filter(Boolean))];
}

export function classifyAutoModule(id, manifest = null) {
  const moduleId = String(id || manifest?.id || '').trim();
  const intrusive = Boolean(manifest?.intrusive) || isIntrusive(moduleId);
  if (intrusive) return 'intrusive';
  if (AUTO_HEXSTRIKE_MODULES.includes(moduleId)) return 'hexstrike_intel';
  if (AUTO_DEEP_PASSIVE_MODULES.includes(moduleId)) return 'deep_passive';
  return 'passive';
}

export async function buildAutoToolCatalog({
  includeHexstrike = true,
  includeDeepPassive = true,
  hexstrikeCapabilities = null,
  ghostRoot,
} = {}) {
  const manifests = listModuleManifests();
  const dynamicManifests = ghostRoot ? await listActiveDynamicManifests(ghostRoot).catch(() => []) : [];
  const manifestById = new Map(manifests.map((m) => [m.id, m]));
  const hexstrike = includeHexstrike
    ? (hexstrikeCapabilities || await getHexstrikeCapabilities({ ghostRoot }).catch((e) => ({ ok: false, message: e?.message || String(e) })))
    : null;

  const modules = [];
  for (const id of AUTO_BASE_MODULES) {
    modules.push({
      id,
      source: 'ghostrecon',
      enabledByDefault: true,
      class: classifyAutoModule(id, manifestById.get(id)),
      manifest: manifestById.get(id) || null,
    });
  }
  if (includeDeepPassive) {
    for (const id of AUTO_DEEP_PASSIVE_MODULES) {
      modules.push({
        id,
        source: 'ghostrecon',
        enabledByDefault: false,
        class: classifyAutoModule(id, manifestById.get(id)),
        manifest: manifestById.get(id) || null,
      });
    }
  }
  if (includeHexstrike) {
    for (const id of AUTO_HEXSTRIKE_MODULES) {
      modules.push({
        id,
        source: 'hexstrike',
        enabledByDefault: Boolean(hexstrike?.installed),
        class: 'hexstrike_intel',
        available: Boolean(hexstrike?.installed),
        reachable: Boolean(hexstrike?.reachable),
        manifest: manifestById.get(id) || null,
      });
    }
  }
  for (const manifest of dynamicManifests) {
    modules.push({
      id: manifest.id,
      source: 'ai-forge',
      enabledByDefault: false,
      class: classifyAutoModule(manifest.id, manifest),
      available: true,
      manifest,
    });
  }

  return {
    modules: uniq(modules.map((m) => m.id)).map((id) => modules.find((m) => m.id === id)),
    hexstrike,
    registry: [...manifests, ...dynamicManifests],
  };
}
