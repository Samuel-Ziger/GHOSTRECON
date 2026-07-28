import { listModuleManifests } from '../modules/module-registry.mjs';
import { getHexstrikeCapabilities } from '../modules/hexstrike-capabilities.mjs';
import { isIntrusive } from '../modules/opsec.mjs';
import { normalizeModuleId } from '../modules/module-ids.mjs';
import { listActiveDynamicManifests } from './forge/runtime-loader.mjs';
import {
  AUTO_ENGINE_CAPABILITIES,
  AUTO_LEGACY_CAPABILITIES,
  AUTO_PROHIBITED_CAPABILITY_IDS,
  autoCapabilityClass,
} from './pipeline-capabilities.mjs';
import {
  inspectFrameSevenBinaryIdentity,
  resolveFrameSevenBinary,
} from '../integrations/frameseven-adapter.mjs';
import { resolveVigoliumBinary } from '../../bridge/vigolium-config.mjs';
import { inspectVigoliumBinaryIdentity } from '../../bridge/vigolium-binary-integrity.mjs';
import fs from 'node:fs/promises';
import { constants as fsConstants } from 'node:fs';

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
  'websocket_recon',
  'hpp_param_pollution',
  'dom_clobbering_audit',
  'secrets_context_ranker',
]);

function uniq(list) {
  return [...new Set((list || []).map((x) => String(x).trim()).filter(Boolean))];
}

const AUTO_PROHIBITED_CAPABILITIES = new Set(AUTO_PROHIBITED_CAPABILITY_IDS);

function isVigoliumCapability(id) {
  return normalizeModuleId(id).startsWith('vigolium_');
}

export async function fingerprintAutoExecutable(file) {
  const resolved = String(file || '').trim();
  if (!resolved) return null;
  return inspectVigoliumBinaryIdentity(resolved)
    .then((identity) => Object.freeze(identity))
    .catch(() => null);
}

export function classifyAutoModule(id, manifest = null) {
  const moduleId = normalizeModuleId(id || manifest?.id);
  const legacyClass = autoCapabilityClass(moduleId);
  if (
    AUTO_PROHIBITED_CAPABILITIES.has(moduleId)
    || manifest?.destructive === true
    || manifest?.class === 'destructive'
    || legacyClass === 'destructive'
  ) return 'destructive';
  const intrusive = Boolean(manifest?.intrusive) || isIntrusive(moduleId);
  if (intrusive || manifest?.class === 'intrusive' || legacyClass === 'intrusive') return 'intrusive';
  // Enquanto manifest e pipeline legado coexistirem, divergências sempre
  // escolhem a classe mais conservadora.
  if (manifest?.class === 'active' || legacyClass === 'active') return 'active';
  if (manifest?.class === 'deep_passive' || legacyClass === 'deep_passive') return 'deep_passive';
  if (AUTO_HEXSTRIKE_MODULES.includes(moduleId)) return 'hexstrike_intel';
  if (AUTO_DEEP_PASSIVE_MODULES.includes(moduleId)) return 'deep_passive';
  return 'passive';
}

function mergeCapability(id, manifestById, legacyById) {
  const manifest = manifestById.get(id) || null;
  const legacy = legacyById.get(id) || null;
  if (!manifest) return legacy;
  if (!legacy) return manifest;
  const mergedClass = classifyAutoModule(id, {
    ...manifest,
    destructive: manifest.destructive === true || legacy.destructive === true,
    intrusive: manifest.intrusive === true || legacy.intrusive === true,
    class: manifest.class === 'destructive' || legacy.class === 'destructive'
      ? 'destructive'
      : manifest.class === 'intrusive' || legacy.class === 'intrusive'
        ? 'intrusive'
        : manifest.class === 'active' || legacy.class === 'active'
          ? 'active'
          : manifest.class === 'deep_passive' || legacy.class === 'deep_passive'
            ? 'deep_passive'
            : manifest.class || legacy.class,
  });
  return {
    ...legacy,
    ...manifest,
    id,
    class: mergedClass,
    intrusive: mergedClass === 'intrusive',
    destructive: mergedClass === 'destructive',
    requiresKali: manifest.requiresKali === true || legacy.requiresKali === true,
    requiresAuth: manifest.requiresAuth === true || legacy.requiresAuth === true,
  };
}

export async function buildAutoToolCatalog({
  includeHexstrike = false,
  includeDeepPassive = true,
  includeIntrusive = false,
  includeFrameSeven = false,
  frameSevenAuth = false,
  includeVigolium = false,
  hexstrikeCapabilities = null,
  vigoliumCapabilities = null,
  vigoliumRuntimeBinding = null,
  forgeRuntimeAvailable = true,
  ghostRoot,
  target = null,
  env = process.env,
} = {}) {
  const manifests = listModuleManifests();
  const dynamicManifests = ghostRoot
    ? await listActiveDynamicManifests(ghostRoot, { target }).catch(() => [])
    : [];
  const manifestById = new Map(manifests.map((m) => [m.id, m]));
  const legacyById = new Map(AUTO_LEGACY_CAPABILITIES.map((m) => [m.id, m]));
  const frameSevenBinary = includeFrameSeven && ghostRoot ? resolveFrameSevenBinary(ghostRoot, env) : null;
  const frameSevenExecutableFound = frameSevenBinary
    ? await fs.access(frameSevenBinary, fsConstants.X_OK).then(() => true).catch(() => false)
    : false;
  const vigolium = includeVigolium
    ? (
        vigoliumCapabilities
        || await resolveVigoliumBinary(ghostRoot, { env })
          .catch(() => ({ bin: null, source: null }))
      )
    : null;
  const vigoliumAvailable = Boolean(vigolium?.installed ?? vigolium?.bin ?? vigolium?.binary);
  const vigoliumBinary = vigolium?.binary || vigolium?.bin || null;
  const [frameSevenIdentity, vigoliumIdentity] = await Promise.all([
    frameSevenExecutableFound ? inspectFrameSevenBinaryIdentity(frameSevenBinary).catch(() => null) : null,
    vigoliumAvailable ? fingerprintAutoExecutable(vigoliumBinary) : null,
  ]);
  const frameSevenAvailable = frameSevenExecutableFound && Boolean(frameSevenIdentity);
  const hexstrike = includeHexstrike
    ? (hexstrikeCapabilities || await getHexstrikeCapabilities({ ghostRoot }).catch((e) => ({ ok: false, message: e?.message || String(e) })))
    : null;

  const modules = [];
  const includeGenericCapability = (id) => {
    const moduleId = normalizeModuleId(id);
    if (AUTO_PROHIBITED_CAPABILITIES.has(moduleId)) return false;
    if (AUTO_HEXSTRIKE_MODULES.includes(moduleId)) return false;
    if (AUTO_DEEP_PASSIVE_MODULES.includes(moduleId) && !includeDeepPassive) return false;
    if (isVigoliumCapability(moduleId) && !includeVigolium) return false;
    return true;
  };
  for (const id of AUTO_BASE_MODULES) {
    if (!includeGenericCapability(id)) continue;
    const manifest = mergeCapability(id, manifestById, legacyById);
    modules.push({
      id,
      source: 'ghostrecon',
      enabledByDefault: true,
      class: classifyAutoModule(id, manifest),
      available: true,
      manifest,
    });
  }
  if (includeDeepPassive) {
    for (const id of AUTO_DEEP_PASSIVE_MODULES) {
      const manifest = mergeCapability(id, manifestById, legacyById);
      modules.push({
        id,
        source: 'ghostrecon',
        enabledByDefault: false,
        class: classifyAutoModule(id, manifest),
        available: true,
        manifest,
      });
    }
  }
  for (const manifest of manifests) {
    if (modules.some((item) => item.id === manifest.id)) continue;
    if (!includeGenericCapability(manifest.id)) continue;
    const capability = mergeCapability(manifest.id, manifestById, legacyById);
    const moduleClass = classifyAutoModule(manifest.id, capability);
    const vigoliumCapability = isVigoliumCapability(manifest.id);
    if (moduleClass === 'destructive') continue;
    if (moduleClass === 'intrusive' && !includeIntrusive) continue;
    modules.push({
      id: manifest.id,
      source: vigoliumCapability ? 'vigolium' : capability?.source || 'ghostrecon',
      enabledByDefault: false,
      class: moduleClass,
      available: !vigoliumCapability || vigoliumAvailable,
      unavailableReason: vigoliumCapability && !vigoliumAvailable
        ? 'Vigolium binary not found'
        : null,
      manifest: capability,
    });
  }
  for (const capability of AUTO_LEGACY_CAPABILITIES) {
    if (modules.some((item) => item.id === capability.id)) continue;
    if (!includeGenericCapability(capability.id)) continue;
    if (capability.class === 'destructive') continue;
    if (capability.class === 'intrusive' && !includeIntrusive) continue;
    modules.push({
      id: capability.id,
      source: capability.source,
      enabledByDefault: false,
      class: capability.class,
      available: capability.source !== 'vigolium' || vigoliumAvailable,
      unavailableReason: capability.source === 'vigolium' && !vigoliumAvailable
        ? 'Vigolium binary not found'
        : null,
      manifest: capability,
    });
  }
  for (const capability of includeFrameSeven ? AUTO_ENGINE_CAPABILITIES : []) {
    if (capability.id === 'frameseven_authenticated' && frameSevenAuth !== true) continue;
    if (capability.class === 'destructive') continue;
    if (capability.class === 'intrusive' && !includeIntrusive) continue;
    modules.push({
      id: capability.id,
      source: capability.source,
      enabledByDefault: capability.id === 'frameseven_recon',
      class: capability.class,
      available: capability.source !== 'frameseven' || frameSevenAvailable,
      unavailableReason: capability.source === 'frameseven' && !frameSevenAvailable
        ? frameSevenExecutableFound
          ? 'FrameSeven binary identity could not be sealed'
          : 'FrameSeven binary not found'
        : null,
      manifest: {
        ...capability,
        engineIdentity: frameSevenIdentity,
      },
      engineIdentity: frameSevenIdentity,
    });
  }
  if (includeIntrusive) {
    for (const manifest of manifests.filter((m) => m.intrusive === true)) {
      if (!includeGenericCapability(manifest.id)) continue;
      if (!modules.some((item) => item.id === manifest.id)) {
        modules.push({
          id: manifest.id,
          source: isVigoliumCapability(manifest.id) ? 'vigolium' : 'ghostrecon',
          enabledByDefault: false,
          class: 'intrusive',
          available: !isVigoliumCapability(manifest.id) || vigoliumAvailable,
          unavailableReason: isVigoliumCapability(manifest.id) && !vigoliumAvailable
            ? 'Vigolium binary not found'
            : null,
          manifest,
        });
      }
    }
  }
  if (includeHexstrike) {
    for (const id of AUTO_HEXSTRIKE_MODULES) {
      modules.push({
        id,
        source: 'hexstrike',
        enabledByDefault: Boolean(hexstrike?.installed && hexstrike?.reachable),
        class: 'hexstrike_intel',
        available: Boolean(hexstrike?.installed && hexstrike?.reachable),
        reachable: Boolean(hexstrike?.reachable),
        unavailableReason: hexstrike?.installed && !hexstrike?.reachable
          ? 'HexStrike service is not reachable'
          : !hexstrike?.installed
            ? 'HexStrike is not installed'
            : null,
        manifest: manifestById.get(id) || null,
      });
    }
  }
  for (const manifest of dynamicManifests) {
    const manifestId = normalizeModuleId(manifest.id);
    if (AUTO_PROHIBITED_CAPABILITIES.has(manifestId)) continue;
    if (AUTO_HEXSTRIKE_MODULES.includes(manifestId)) continue;
    if (isVigoliumCapability(manifest.id) && !includeVigolium) continue;
    const moduleClass = manifest.destructive === true || manifest.class === 'destructive'
      ? 'destructive'
      : manifest.intrusive === true || manifest.class === 'intrusive'
        ? 'intrusive'
        : manifest.class === 'passive' || manifest.class === 'deep_passive'
          ? manifest.class
          : 'active';
    if (moduleClass === 'destructive') continue;
    if (moduleClass === 'intrusive' && !includeIntrusive) continue;
    modules.push({
      id: manifest.id,
      source: 'ai-forge',
      enabledByDefault: false,
      class: moduleClass,
      available: forgeRuntimeAvailable === true,
      unavailableReason: forgeRuntimeAvailable === true
        ? null
        : 'Forge strong sandbox unavailable',
      manifest,
      forgeId: manifest.forgeId,
      runtimeIntegrity: manifest.runtimeIntegrity,
    });
  }

  return {
    modules: uniq(modules.map((m) => m.id)).map((id) => modules.find((m) => m.id === id)),
    hexstrike,
    registry: [...manifests, ...dynamicManifests],
    engines: {
      frameseven: {
        available: frameSevenAvailable,
        binary: frameSevenBinary,
        identity: frameSevenIdentity,
      },
      vigolium: {
        available: vigoliumAvailable,
        binary: vigoliumBinary,
        source: vigolium?.resolveSource || vigolium?.source || null,
        identity: vigoliumIdentity,
        runtimeBinding: includeVigolium ? String(vigoliumRuntimeBinding || '') || null : null,
      },
      forge: {
        available: forgeRuntimeAvailable === true,
        runtime: 'strong_os_sandbox_required',
      },
    },
  };
}
